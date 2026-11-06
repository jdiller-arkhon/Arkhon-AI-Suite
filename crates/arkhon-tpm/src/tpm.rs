//! TPM 2.0 device key (cargo feature `tpm`), through `tss-esapi`.
//!
//! The key is a **primary** ECC NIST P-256 key in the owner hierarchy with `fixedTPM`,
//! `fixedParent`, `sensitiveDataOrigin`, `decrypt` and no `sign`/`restricted`, so it can do
//! `TPM2_ECDH_ZGen` and can never leave the chip. A primary key is derived deterministically from the
//! hierarchy seed and the template, so recreating it with the same template (including the
//! Arkhon-specific `unique` value) yields the same key: nothing needs to be stored, and clearing
//! the TPM destroys it (the customer then re-activates).
//!
//! Tested against `swtpm` (see the test below: set `ARKHON_TEST_TCTI`, e.g.
//! `swtpm:host=127.0.0.1,port=2321`). Not yet tested on physical TPMs; owner-hierarchy
//! authorization other than empty, and TPM lockout handling, are left for Phase 4.

use std::fmt;
use std::str::FromStr;
use std::sync::Mutex;

use p256::PublicKey;
use tss_esapi::attributes::ObjectAttributesBuilder;
use tss_esapi::handles::KeyHandle;
use tss_esapi::interface_types::algorithm::{HashingAlgorithm, PublicAlgorithm};
use tss_esapi::interface_types::ecc::EccCurve;
use tss_esapi::interface_types::resource_handles::Hierarchy;
use tss_esapi::structures::{
    EccParameter, EccPoint, EccScheme, HashScheme, KeyDerivationFunctionScheme, Public,
    PublicBuilder, PublicEccParametersBuilder,
};
use tss_esapi::tcti_ldr::TctiNameConf;
use tss_esapi::Context;

use crate::binding::{BindingError, BindingKind, DeviceKey, SharedSecret};

/// Domain-specific `unique` value so the Arkhon key differs from any other primary key.
const UNIQUE_LABEL: &[u8] = b"arkhon/v1/tpm-device-key";

fn hw(e: impl fmt::Display) -> BindingError {
    BindingError::Hardware(e.to_string())
}

fn template() -> Result<Public, BindingError> {
    use sha2::Digest;
    let ecc = PublicEccParametersBuilder::new()
        .with_ecc_scheme(EccScheme::EcDh(HashScheme::new(HashingAlgorithm::Sha256)))
        .with_curve(EccCurve::NistP256)
        .with_is_signing_key(false)
        .with_is_decryption_key(true)
        .with_restricted(false)
        .with_key_derivation_function_scheme(KeyDerivationFunctionScheme::Null)
        .build()
        .map_err(hw)?;
    let attrs = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_decrypt(true)
        .with_sign_encrypt(false)
        .with_restricted(false)
        .build()
        .map_err(hw)?;
    let unique_x = sha2::Sha256::digest(UNIQUE_LABEL).to_vec();
    PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Ecc)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(attrs)
        .with_ecc_parameters(ecc)
        .with_ecc_unique_identifier(EccPoint::new(
            EccParameter::try_from(unique_x).map_err(hw)?,
            EccParameter::default(),
        ))
        .build()
        .map_err(hw)
}

fn left_pad_32(v: &[u8]) -> Result<[u8; 32], BindingError> {
    if v.len() > 32 {
        return Err(BindingError::Hardware(
            "TPM returned an oversized coordinate".into(),
        ));
    }
    let mut out = [0u8; 32];
    out[32 - v.len()..].copy_from_slice(v);
    Ok(out)
}

/// A P-256 ECDH key that lives in the TPM.
pub struct TpmDeviceKey {
    ctx: Mutex<Context>,
    handle: KeyHandle,
    public: PublicKey,
}

impl fmt::Debug for TpmDeviceKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TpmDeviceKey")
            .field("public_key", &crate::binding::sec1_bytes(&self.public))
            .finish_non_exhaustive()
    }
}

impl TpmDeviceKey {
    /// Open the TPM named by `tcti` (e.g. `"device:/dev/tpmrm0"`, `"swtpm:port=2321"`) and load
    /// (re-derive) the Arkhon device key.
    ///
    /// # Errors
    /// [`BindingError::Hardware`] if the TPM is unavailable or refuses.
    pub fn open(tcti: &str) -> Result<Self, BindingError> {
        let conf = TctiNameConf::from_str(tcti).map_err(hw)?;
        let mut ctx = Context::new(conf).map_err(hw)?;
        let public_template = template()?;
        let created = ctx
            .execute_with_nullauth_session(|c| {
                c.create_primary(Hierarchy::Owner, public_template, None, None, None, None)
            })
            .map_err(hw)?;
        let Public::Ecc { unique, .. } = created.out_public else {
            return Err(BindingError::Hardware("TPM returned a non-ECC key".into()));
        };
        let mut sec1 = [0u8; 65];
        sec1[0] = 4;
        sec1[1..33].copy_from_slice(&left_pad_32(unique.x().value())?);
        sec1[33..].copy_from_slice(&left_pad_32(unique.y().value())?);
        let public = crate::binding::parse_sec1(&sec1)?;
        Ok(Self {
            ctx: Mutex::new(ctx),
            handle: created.key_handle,
            public,
        })
    }
}

impl DeviceKey for TpmDeviceKey {
    fn binding_kind(&self) -> BindingKind {
        BindingKind::Tpm
    }

    fn public_key(&self) -> PublicKey {
        self.public
    }

    fn ecdh(&self, peer: &PublicKey) -> Result<SharedSecret, BindingError> {
        let sec1 = crate::binding::sec1_bytes(peer);
        let point = EccPoint::new(
            EccParameter::try_from(&sec1[1..33]).map_err(hw)?,
            EccParameter::try_from(&sec1[33..]).map_err(hw)?,
        );
        let mut ctx = self
            .ctx
            .lock()
            .map_err(|_| BindingError::Hardware("TPM context poisoned".into()))?;
        let z = ctx
            .execute_with_nullauth_session(|c| c.ecdh_z_gen(self.handle, point))
            .map_err(hw)?;
        Ok(SharedSecret::new(left_pad_32(z.x().value())?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SoftwareDeviceKey;

    /// Runs only when `ARKHON_TEST_TCTI` names a TPM (e.g. swtpm); otherwise it is a no-op.
    #[test]
    fn tpm_ecdh_matches_software_peer() {
        let Ok(tcti) = std::env::var("ARKHON_TEST_TCTI") else {
            eprintln!("ARKHON_TEST_TCTI not set; skipping TPM test");
            return;
        };
        let tpm = TpmDeviceKey::open(&tcti).expect("open TPM");
        assert_eq!(tpm.binding_kind(), BindingKind::Tpm);
        let peer = SoftwareDeviceKey::generate();
        let a = tpm.ecdh(&peer.public_key()).unwrap();
        let b = peer.ecdh(&tpm.public_key()).unwrap();
        assert_eq!(a.as_bytes(), b.as_bytes());
        // Deterministic primary key: reopening gives the same public key.
        let first = tpm.public_key_sec1();
        drop(tpm);
        let again = TpmDeviceKey::open(&tcti).unwrap();
        assert_eq!(again.public_key_sec1(), first);
        assert!(format!("{again:?}").contains("TpmDeviceKey"));
        eprintln!("TPM ECDH verified against {tcti}");
    }
}
