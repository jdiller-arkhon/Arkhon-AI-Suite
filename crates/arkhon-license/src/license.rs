//! The license document and its signature.

use std::collections::{BTreeMap, BTreeSet};

use arkhon_crypto::codec::{domain, require_canonical, DecodeError, Decoder, Encoder};
use arkhon_tpm::{
    parse_sec1, BindingKind, HardwareFingerprint, FINGERPRINT_LEN,
    SEC1_UNCOMPRESSED_LEN as SEC1_LEN,
};
use ed25519_dalek::SigningKey;

use crate::chain::{sign, IssuingCertificate};
use crate::wrap::WrappedCek;
use crate::LicenseError;

const KIND: [u8; 4] = *b"ARLI";
const VERSION: u16 = 1;

/// Longest id or entitlement name, in bytes.
pub const MAX_NAME_LEN: usize = 256;

/// Everything a license says, before signing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LicenseBody {
    /// Unique license id.
    pub license_id: String,
    /// Customer (organization) id.
    pub customer_id: String,
    /// Entitled workspaces, e.g. `"inbox"`, `"docs"`.
    pub workspaces: BTreeSet<String>,
    /// Entitled engines (release manifests name one of these).
    pub engines: BTreeSet<String>,
    /// Entitled industry packs.
    pub packs: BTreeSet<String>,
    /// Releases dated after this (Unix seconds) are not covered.
    pub update_window_end: u64,
    /// Seats bought.
    pub seats: u32,
    /// Issue time (Unix seconds).
    pub issued_at: u64,
    /// Expiry time (Unix seconds, exclusive).
    pub expires_at: u64,
    /// Days the runtime may run without a successful online check or renewal file.
    pub offline_grace_days: u32,
    /// Required kind of device key.
    pub binding: BindingKind,
    /// Device P-256 public key (uncompressed SEC1).
    pub device_public_key: [u8; SEC1_LEN],
    /// Device hardware fingerprint (salted hashes).
    pub fingerprint: HardwareFingerprint,
    /// Engine CEKs wrapped to the device key, by engine name.
    pub wrapped_ceks: BTreeMap<String, WrappedCek>,
}

fn check_name(name: &str, field: &'static str) -> Result<(), LicenseError> {
    if name.is_empty() || name.len() > MAX_NAME_LEN {
        Err(LicenseError::Invalid(field))
    } else {
        Ok(())
    }
}

impl LicenseBody {
    /// Check the rules every license must follow (also applied on decode).
    ///
    /// # Errors
    /// [`LicenseError::Invalid`] naming the bad field.
    pub fn validate(&self) -> Result<(), LicenseError> {
        check_name(&self.license_id, "license id")?;
        check_name(&self.customer_id, "customer id")?;
        for (set, field) in [
            (&self.workspaces, "workspaces"),
            (&self.engines, "engines"),
            (&self.packs, "packs"),
        ] {
            for s in set {
                check_name(s, field)?;
            }
        }
        if self.seats == 0 {
            return Err(LicenseError::Invalid("seats"));
        }
        if self.expires_at <= self.issued_at {
            return Err(LicenseError::Invalid("expiry"));
        }
        parse_sec1(&self.device_public_key).map_err(|_| LicenseError::Invalid("device key"))?;
        if self
            .wrapped_ceks
            .keys()
            .any(|engine| !self.engines.contains(engine))
        {
            return Err(LicenseError::Invalid("engine keys"));
        }
        Ok(())
    }

    fn encode(&self, e: &mut Encoder) {
        e.str(&self.license_id)
            .str(&self.customer_id)
            .str_set(&self.workspaces)
            .str_set(&self.engines)
            .str_set(&self.packs)
            .u64(self.update_window_end)
            .u32(self.seats)
            .u64(self.issued_at)
            .u64(self.expires_at)
            .u32(self.offline_grace_days)
            .u8(self.binding.tag())
            .array(&self.device_public_key)
            .array(&self.fingerprint.to_bytes())
            .len(self.wrapped_ceks.len());
        for (engine, w) in &self.wrapped_ceks {
            e.str(engine);
            w.encode(e);
        }
    }

    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let license_id = d.string()?;
        let customer_id = d.string()?;
        let workspaces = d.str_set()?;
        let engines = d.str_set()?;
        let packs = d.str_set()?;
        let update_window_end = d.u64()?;
        let seats = d.u32()?;
        let issued_at = d.u64()?;
        let expires_at = d.u64()?;
        let offline_grace_days = d.u32()?;
        let binding = BindingKind::from_tag(d.u8()?).ok_or(DecodeError::InvalidValue("binding"))?;
        let device_public_key = d.array()?;
        let fingerprint = HardwareFingerprint::from_bytes(&d.array::<FINGERPRINT_LEN>()?);
        let n = d.len(4 + crate::wrap::WRAPPED_CEK_LEN)?;
        let mut wrapped_ceks = BTreeMap::new();
        let mut prev: Option<String> = None;
        for _ in 0..n {
            let engine = d.string()?;
            if prev.as_ref().is_some_and(|p| *p >= engine) {
                return Err(DecodeError::NotSorted);
            }
            prev = Some(engine.clone());
            wrapped_ceks.insert(engine, WrappedCek::decode(d)?);
        }
        Ok(Self {
            license_id,
            customer_id,
            workspaces,
            engines,
            packs,
            update_window_end,
            seats,
            issued_at,
            expires_at,
            offline_grace_days,
            binding,
            device_public_key,
            fingerprint,
            wrapped_ceks,
        })
    }

    /// Canonical bytes of the body alone.
    #[must_use]
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let mut e = Encoder::new(KIND, VERSION);
        self.encode(&mut e);
        e.finish()
    }
}

/// A signed license: body, the issuing certificate, and the issuing key's signature over both.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct License {
    /// What the license grants.
    pub body: LicenseBody,
    /// Certificate of the key that signed it.
    pub issuing_certificate: IssuingCertificate,
    /// Ed25519 over `domain::LICENSE || body bytes || u32 len || certificate bytes`.
    pub signature: [u8; 64],
}

impl License {
    /// Sign `body` with `issuing_key`, whose certificate is `cert` (license-server side).
    ///
    /// # Errors
    /// [`LicenseError::Invalid`] if the body breaks a rule or `issuing_key` doesn't match `cert`;
    /// [`LicenseError::IssuedOutsideCertificate`] if `body.issued_at` is outside `cert`'s window.
    pub fn sign(
        body: LicenseBody,
        cert: IssuingCertificate,
        issuing_key: &SigningKey,
    ) -> Result<Self, LicenseError> {
        body.validate()?;
        if issuing_key.verifying_key().to_bytes() != cert.issuing_public_key {
            return Err(LicenseError::Invalid("issuing key"));
        }
        if !cert.covers(body.issued_at) {
            return Err(LicenseError::IssuedOutsideCertificate);
        }
        let mut license = Self {
            body,
            issuing_certificate: cert,
            signature: [0; 64],
        };
        license.signature = sign(issuing_key, domain::LICENSE, &license.signed_bytes());
        Ok(license)
    }

    /// The bytes the signature covers (without the domain tag).
    #[must_use]
    pub fn signed_bytes(&self) -> Vec<u8> {
        let mut e = Encoder::new(KIND, VERSION);
        self.body.encode(&mut e);
        e.bytes(&self.issuing_certificate.to_bytes());
        e.finish()
    }

    /// Canonical bytes (what goes in a `.arkhon-license` file).
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = self.signed_bytes();
        out.extend_from_slice(&self.signature);
        out
    }

    /// Parse canonical bytes, rejecting anything non-canonical or structurally invalid.
    /// Does **not** check signatures, dates or the machine; call [`crate::verify`] for that.
    ///
    /// # Errors
    /// [`DecodeError`].
    pub fn from_bytes(data: &[u8]) -> Result<Self, DecodeError> {
        let mut d = Decoder::new(data, KIND, VERSION)?;
        let body = LicenseBody::decode(&mut d)?;
        let issuing_certificate = IssuingCertificate::from_bytes(d.bytes()?)?;
        let signature = d.array()?;
        d.finish()?;
        body.validate().map_err(|e| match e {
            LicenseError::Invalid(field) => DecodeError::InvalidValue(field),
            _ => DecodeError::InvalidValue("license"),
        })?;
        let license = Self {
            body,
            issuing_certificate,
            signature,
        };
        require_canonical(data, &license.to_bytes())?;
        Ok(license)
    }
}
