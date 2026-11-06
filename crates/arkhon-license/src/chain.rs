//! Root-signed documents: issuing-key certificates and the issuing-key revocation list.

use std::collections::BTreeSet;

use arkhon_crypto::codec::{domain, require_canonical, DecodeError, Decoder, Encoder};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

use crate::LicenseError;

const CERT_KIND: [u8; 4] = *b"ARIC";
const REV_KIND: [u8; 4] = *b"ARRL";
const VERSION: u16 = 1;

/// Verify `domain || message` under `key` (strict Ed25519: no malleable signatures, no weak keys).
pub(crate) fn verify_sig(
    key: &VerifyingKey,
    domain: &[u8],
    message: &[u8],
    sig: &[u8; 64],
) -> bool {
    let msg = [domain, message].concat();
    key.verify_strict(&msg, &Signature::from_bytes(sig)).is_ok()
}

pub(crate) fn sign(key: &SigningKey, domain: &[u8], message: &[u8]) -> [u8; 64] {
    key.sign(&[domain, message].concat()).to_bytes()
}

/// Root's statement that an issuing key may sign licenses and releases during a time window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuingCertificate {
    /// Unique serial (what the revocation list names).
    pub serial: u64,
    /// The issuing key's Ed25519 public key.
    pub issuing_public_key: [u8; 32],
    /// Start of the signing window (Unix seconds, inclusive).
    pub not_before: u64,
    /// End of the signing window (Unix seconds, inclusive).
    pub not_after: u64,
    /// Root key's signature over `domain::ISSUING_CERT || to-be-signed bytes`.
    pub root_signature: [u8; 64],
}

impl IssuingCertificate {
    /// Certify `issuing_public_key` with the offline root key.
    ///
    /// # Errors
    /// [`LicenseError::Invalid`] if `not_before > not_after`.
    pub fn issue(
        root: &SigningKey,
        serial: u64,
        issuing_public_key: &VerifyingKey,
        not_before: u64,
        not_after: u64,
    ) -> Result<Self, LicenseError> {
        if not_before > not_after {
            return Err(LicenseError::Invalid("validity window"));
        }
        let mut cert = Self {
            serial,
            issuing_public_key: issuing_public_key.to_bytes(),
            not_before,
            not_after,
            root_signature: [0; 64],
        };
        cert.root_signature = sign(root, domain::ISSUING_CERT, &cert.tbs_bytes());
        Ok(cert)
    }

    fn encode_tbs(&self, e: &mut Encoder) {
        e.u64(self.serial)
            .array(&self.issuing_public_key)
            .u64(self.not_before)
            .u64(self.not_after);
    }

    /// The to-be-signed bytes (everything but the signature).
    #[must_use]
    pub fn tbs_bytes(&self) -> Vec<u8> {
        let mut e = Encoder::new(CERT_KIND, VERSION);
        self.encode_tbs(&mut e);
        e.finish()
    }

    /// Canonical bytes.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut e = Encoder::new(CERT_KIND, VERSION);
        self.encode_tbs(&mut e);
        e.array(&self.root_signature);
        e.finish()
    }

    /// Parse canonical bytes. Does **not** check the signature.
    ///
    /// # Errors
    /// [`DecodeError`] for malformed or non-canonical input.
    pub fn from_bytes(data: &[u8]) -> Result<Self, DecodeError> {
        let mut d = Decoder::new(data, CERT_KIND, VERSION)?;
        let cert = Self {
            serial: d.u64()?,
            issuing_public_key: d.array()?,
            not_before: d.u64()?,
            not_after: d.u64()?,
            root_signature: d.array()?,
        };
        d.finish()?;
        if cert.not_before > cert.not_after {
            return Err(DecodeError::InvalidValue("validity window"));
        }
        require_canonical(data, &cert.to_bytes())?;
        Ok(cert)
    }

    /// Check the root signature and return the certified issuing key.
    ///
    /// # Errors
    /// [`LicenseError::UntrustedIssuer`].
    pub fn verify(&self, root: &VerifyingKey) -> Result<VerifyingKey, LicenseError> {
        if !verify_sig(
            root,
            domain::ISSUING_CERT,
            &self.tbs_bytes(),
            &self.root_signature,
        ) {
            return Err(LicenseError::UntrustedIssuer);
        }
        let key = VerifyingKey::from_bytes(&self.issuing_public_key)
            .map_err(|_| LicenseError::UntrustedIssuer)?;
        if key.is_weak() {
            return Err(LicenseError::UntrustedIssuer);
        }
        Ok(key)
    }

    /// True if `t` is inside the signing window.
    #[must_use]
    pub fn covers(&self, t: u64) -> bool {
        (self.not_before..=self.not_after).contains(&t)
    }
}

/// Root-signed list of revoked issuing-certificate serials. Versions only go up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevocationList {
    /// Monotonic version; the runtime refuses a lower version than it has seen.
    pub version: u64,
    /// When the list was signed (Unix seconds).
    pub issued_at: u64,
    /// Revoked certificate serials.
    pub revoked_serials: BTreeSet<u64>,
    /// Root key's signature over `domain::REVOCATION_LIST || to-be-signed bytes`.
    pub root_signature: [u8; 64],
}

impl RevocationList {
    /// Sign a list with the offline root key.
    #[must_use]
    pub fn sign(
        root: &SigningKey,
        version: u64,
        issued_at: u64,
        revoked_serials: BTreeSet<u64>,
    ) -> Self {
        let mut list = Self {
            version,
            issued_at,
            revoked_serials,
            root_signature: [0; 64],
        };
        list.root_signature = sign(root, domain::REVOCATION_LIST, &list.tbs_bytes());
        list
    }

    fn encode_tbs(&self, e: &mut Encoder) {
        e.u64(self.version)
            .u64(self.issued_at)
            .len(self.revoked_serials.len());
        for s in &self.revoked_serials {
            e.u64(*s);
        }
    }

    /// The to-be-signed bytes.
    #[must_use]
    pub fn tbs_bytes(&self) -> Vec<u8> {
        let mut e = Encoder::new(REV_KIND, VERSION);
        self.encode_tbs(&mut e);
        e.finish()
    }

    /// Canonical bytes.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut e = Encoder::new(REV_KIND, VERSION);
        self.encode_tbs(&mut e);
        e.array(&self.root_signature);
        e.finish()
    }

    /// Parse canonical bytes (serials strictly ascending). Does **not** check the signature.
    ///
    /// # Errors
    /// [`DecodeError`] for malformed or non-canonical input.
    pub fn from_bytes(data: &[u8]) -> Result<Self, DecodeError> {
        let mut d = Decoder::new(data, REV_KIND, VERSION)?;
        let version = d.u64()?;
        let issued_at = d.u64()?;
        let n = d.len(8)?;
        let mut revoked_serials = BTreeSet::new();
        let mut prev = None;
        for _ in 0..n {
            let s = d.u64()?;
            if prev.is_some_and(|p| p >= s) {
                return Err(DecodeError::NotSorted);
            }
            prev = Some(s);
            revoked_serials.insert(s);
        }
        let root_signature = d.array()?;
        d.finish()?;
        let list = Self {
            version,
            issued_at,
            revoked_serials,
            root_signature,
        };
        require_canonical(data, &list.to_bytes())?;
        Ok(list)
    }

    /// Check the root signature.
    ///
    /// # Errors
    /// [`LicenseError::BadRevocationList`].
    pub fn verify(&self, root: &VerifyingKey) -> Result<(), LicenseError> {
        if verify_sig(
            root,
            domain::REVOCATION_LIST,
            &self.tbs_bytes(),
            &self.root_signature,
        ) {
            Ok(())
        } else {
            Err(LicenseError::BadRevocationList)
        }
    }

    /// Check a newly offered list: genuine, and not older than `seen_version` (the highest version
    /// this computer has stored). Store `self.version` after this succeeds.
    ///
    /// # Errors
    /// [`LicenseError::BadRevocationList`] or [`LicenseError::RevocationListRollback`].
    pub fn verify_update(
        &self,
        root: &VerifyingKey,
        seen_version: u64,
    ) -> Result<(), LicenseError> {
        self.verify(root)?;
        if self.version < seen_version {
            return Err(LicenseError::RevocationListRollback {
                seen: seen_version,
                offered: self.version,
            });
        }
        Ok(())
    }

    /// True if `serial` is revoked.
    #[must_use]
    pub fn is_revoked(&self, serial: u64) -> bool {
        self.revoked_serials.contains(&serial)
    }
}

/// Establish trust in an issuing certificate: genuine revocation list, root-signed certificate,
/// not revoked, and `signed_at` inside its window. Returns the issuing key.
///
/// # Errors
/// [`LicenseError::BadRevocationList`], [`LicenseError::UntrustedIssuer`],
/// [`LicenseError::IssuerRevoked`] or [`LicenseError::IssuedOutsideCertificate`].
pub fn trusted_issuer(
    cert: &IssuingCertificate,
    root: &VerifyingKey,
    revocations: &RevocationList,
    signed_at: u64,
) -> Result<VerifyingKey, LicenseError> {
    revocations.verify(root)?;
    let key = cert.verify(root)?;
    if revocations.is_revoked(cert.serial) {
        return Err(LicenseError::IssuerRevoked {
            serial: cert.serial,
        });
    }
    if !cert.covers(signed_at) {
        return Err(LicenseError::IssuedOutsideCertificate);
    }
    Ok(key)
}
