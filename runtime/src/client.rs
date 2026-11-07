//! License-server client: request/response types for the device API (`server/openapi.yaml`) and a
//! small blocking HTTP implementation.
//!
//! **Only license metadata is ever sent**: activation key, license id, device public key,
//! fingerprint hashes and binding kind (plus the binary renewal request, which carries the same
//! kind of data). No customer content, prompts, documents or file names. The test
//! `requests_carry_only_allowed_fields` pins the exact field set of every request.

use std::fmt;
use std::time::Duration;

use arkhon_tpm::{BindingKind, DeviceKey, HardwareFingerprint};
use base64::Engine as _;
use serde::{Deserialize, Serialize};

pub(crate) fn b64(data: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(data)
}

pub(crate) fn unb64(s: &str) -> Option<Vec<u8>> {
    base64::engine::general_purpose::STANDARD.decode(s).ok()
}

/// The device description sent with activation and check-in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceInfo {
    /// Uncompressed SEC1 P-256 public key, base64.
    pub device_public_key: String,
    /// Salted fingerprint hashes (160 bytes), base64.
    pub fingerprint: String,
    /// `tpm`, `secure-enclave` or `software`.
    pub binding: String,
}

impl DeviceInfo {
    /// Describe this device.
    #[must_use]
    pub fn of(device: &dyn DeviceKey, fingerprint: &HardwareFingerprint) -> Self {
        Self {
            device_public_key: b64(&device.public_key_sec1()),
            fingerprint: b64(&fingerprint.to_bytes()),
            binding: binding_name(device.binding_kind()).to_owned(),
        }
    }
}

/// Wire name of a binding kind.
#[must_use]
pub fn binding_name(b: BindingKind) -> &'static str {
    b.as_str()
}

/// `POST /v1/activate`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActivateRequest {
    /// The activation key the customer typed.
    pub activation_key: String,
    /// This device.
    #[serde(flatten)]
    pub device: DeviceInfo,
}

/// `POST /v1/checkin`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckinRequest {
    /// License id.
    pub license_id: String,
    /// This device.
    #[serde(flatten)]
    pub device: DeviceInfo,
}

/// `POST /v1/deactivate`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeactivateRequest {
    /// License id.
    pub license_id: String,
    /// Device public key, base64.
    pub device_public_key: String,
}

/// Activation / check-in response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LicenseResponse {
    /// License id.
    pub license_id: String,
    /// Signed license bytes, base64.
    pub license: String,
    /// Root-signed revocation list, base64.
    pub revocation_list: String,
}

/// One entry of `GET /v1/releases`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseEntry {
    /// Engine name.
    pub engine: String,
    /// Release version.
    pub version: String,
    /// Release time (Unix seconds).
    pub released_at: i64,
    /// Signed manifest, base64.
    pub manifest: String,
}

#[derive(Deserialize)]
struct ReleasesResponse {
    releases: Vec<ReleaseEntry>,
}

#[derive(Deserialize)]
struct ErrorBody {
    error: String,
}

/// Why a call to the license server failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientError {
    /// The server couldn't be reached (offline, DNS, timeout, TLS).
    Network(String),
    /// The server answered with an error; `message` is its plain-language sentence.
    Rejected {
        /// HTTP status.
        status: u16,
        /// Server message.
        message: String,
    },
    /// The server's answer couldn't be understood.
    BadResponse,
}

impl fmt::Display for ClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ClientError::Network(e) => write!(
                f,
                "Couldn't reach the Arkhon license server. Check the internet connection. ({e})"
            ),
            ClientError::Rejected { message, .. } => f.write_str(message),
            ClientError::BadResponse => {
                f.write_str("The Arkhon license server sent an answer Arkhon couldn't read.")
            }
        }
    }
}

impl std::error::Error for ClientError {}

/// The device API of the License Manager.
pub trait LicenseServer {
    /// `POST /v1/activate`.
    ///
    /// # Errors
    /// [`ClientError`].
    fn activate(&self, req: &ActivateRequest) -> Result<LicenseResponse, ClientError>;
    /// `POST /v1/checkin`.
    ///
    /// # Errors
    /// [`ClientError`].
    fn checkin(&self, req: &CheckinRequest) -> Result<LicenseResponse, ClientError>;
    /// `POST /v1/deactivate`.
    ///
    /// # Errors
    /// [`ClientError`].
    fn deactivate(&self, req: &DeactivateRequest) -> Result<(), ClientError>;
    /// `POST /v1/offline/renew` (binary request → binary response).
    ///
    /// # Errors
    /// [`ClientError`].
    fn offline_renew(&self, request: &[u8]) -> Result<Vec<u8>, ClientError>;
    /// `GET /v1/releases?license_id=…`.
    ///
    /// # Errors
    /// [`ClientError`].
    fn releases(&self, license_id: &str) -> Result<Vec<ReleaseEntry>, ClientError>;
}

/// Largest response body accepted (licenses are a few KiB; release lists are small).
const MAX_BODY: u64 = 4 << 20;

/// Blocking HTTPS client for the License Manager.
#[derive(Debug, Clone)]
pub struct HttpLicenseServer {
    base: String,
    agent: ureq::Agent,
}

impl HttpLicenseServer {
    /// A client for `base_url` (e.g. `https://license.arkhon.example`) with connect/overall
    /// timeouts.
    #[must_use]
    pub fn new(base_url: &str, timeout: Duration) -> Self {
        let config = ureq::Agent::config_builder()
            .timeout_global(Some(timeout))
            .timeout_connect(Some(timeout.min(Duration::from_secs(10))))
            .http_status_as_error(false)
            .user_agent(concat!("arkhon-runtime/", env!("CARGO_PKG_VERSION")))
            .build();
        Self {
            base: base_url.trim_end_matches('/').to_owned(),
            agent: config.into(),
        }
    }

    fn finish(
        resp: Result<ureq::http::Response<ureq::Body>, ureq::Error>,
    ) -> Result<Vec<u8>, ClientError> {
        let mut resp = resp.map_err(|e| ClientError::Network(e.to_string()))?;
        let status = resp.status().as_u16();
        let body = resp
            .body_mut()
            .with_config()
            .limit(MAX_BODY)
            .read_to_vec()
            .map_err(|e| ClientError::Network(e.to_string()))?;
        if (200..300).contains(&status) {
            Ok(body)
        } else {
            let message = serde_json::from_slice::<ErrorBody>(&body).map_or_else(
                |_| format!("The license server refused (HTTP {status})."),
                |b| b.error,
            );
            Err(ClientError::Rejected { status, message })
        }
    }

    fn post_json<T: Serialize, R: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        body: &T,
    ) -> Result<R, ClientError> {
        let json = serde_json::to_vec(body).map_err(|_| ClientError::BadResponse)?;
        let resp = self
            .agent
            .post(format!("{}{path}", self.base))
            .content_type("application/json")
            .send(&json[..]);
        let bytes = Self::finish(resp)?;
        serde_json::from_slice(&bytes).map_err(|_| ClientError::BadResponse)
    }
}

impl LicenseServer for HttpLicenseServer {
    fn activate(&self, req: &ActivateRequest) -> Result<LicenseResponse, ClientError> {
        self.post_json("/v1/activate", req)
    }

    fn checkin(&self, req: &CheckinRequest) -> Result<LicenseResponse, ClientError> {
        self.post_json("/v1/checkin", req)
    }

    fn deactivate(&self, req: &DeactivateRequest) -> Result<(), ClientError> {
        self.post_json::<_, serde_json::Value>("/v1/deactivate", req)
            .map(|_| ())
    }

    fn offline_renew(&self, request: &[u8]) -> Result<Vec<u8>, ClientError> {
        let resp = self
            .agent
            .post(format!("{}/v1/offline/renew", self.base))
            .content_type("application/octet-stream")
            .send(request);
        Self::finish(resp)
    }

    fn releases(&self, license_id: &str) -> Result<Vec<ReleaseEntry>, ClientError> {
        let resp = self
            .agent
            .get(format!("{}/v1/releases", self.base))
            .query("license_id", license_id)
            .call();
        let bytes = Self::finish(resp)?;
        serde_json::from_slice::<ReleasesResponse>(&bytes)
            .map(|r| r.releases)
            .map_err(|_| ClientError::BadResponse)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use arkhon_license::RenewalRequest;
    use arkhon_tpm::{FingerprintSalt, RawComponents, SoftwareDeviceKey};
    use std::collections::BTreeSet;

    fn keys(v: &serde_json::Value) -> BTreeSet<String> {
        v.as_object().unwrap().keys().cloned().collect()
    }

    fn set(names: &[&str]) -> BTreeSet<String> {
        names.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn requests_carry_only_allowed_fields() {
        let dev = SoftwareDeviceKey::generate();
        let raw = RawComponents {
            machine_id: Some("secret-machine-id-value".into()),
            cpu: Some("cpu".into()),
            disk: None,
            board: None,
            mac: None,
        };
        let fp = HardwareFingerprint::from_raw(&FingerprintSalt([7; 32]), &raw);
        let device = DeviceInfo::of(&dev, &fp);
        let act = serde_json::to_value(ActivateRequest {
            activation_key: "AAAA-BBBB".into(),
            device: device.clone(),
        })
        .unwrap();
        assert_eq!(
            keys(&act),
            set(&[
                "activation_key",
                "device_public_key",
                "fingerprint",
                "binding"
            ])
        );
        let chk = serde_json::to_value(CheckinRequest {
            license_id: "lic".into(),
            device: device.clone(),
        })
        .unwrap();
        assert_eq!(
            keys(&chk),
            set(&["license_id", "device_public_key", "fingerprint", "binding"])
        );
        let de = serde_json::to_value(DeactivateRequest {
            license_id: "lic".into(),
            device_public_key: device.device_public_key.clone(),
        })
        .unwrap();
        assert_eq!(keys(&de), set(&["license_id", "device_public_key"]));
        // Raw identifiers never appear in any request; only salted hashes do.
        for v in [&act, &chk, &de] {
            assert!(!v.to_string().contains("secret-machine-id-value"));
        }
        assert_eq!(device.binding, "software");
        assert_eq!(unb64(&device.fingerprint).unwrap().len(), 160);
        // The binary renewal request has a fixed field list (see arkhon-license); check it holds
        // nothing but those fields by round-tripping and measuring.
        let req = RenewalRequest {
            license_id: "lic".into(),
            device_public_key: dev.public_key_sec1(),
            fingerprint: fp,
            revocation_version: 1,
            last_seen: 2,
            request_id: [9; 16],
        };
        let bytes = req.to_bytes();
        assert_eq!(RenewalRequest::from_bytes(&bytes).unwrap(), req);
        assert!(!String::from_utf8_lossy(&bytes).contains("secret-machine-id-value"));
    }

    #[test]
    fn unreachable_server_is_a_network_error() {
        // Port 9 on localhost: nothing listens; the connection is refused quickly.
        let c = HttpLicenseServer::new("http://127.0.0.1:9/", Duration::from_secs(2));
        let err = c.releases("x").unwrap_err();
        assert!(matches!(err, ClientError::Network(_)), "{err:?}");
        assert!(err.to_string().contains("internet"));
        assert_eq!(
            ClientError::Rejected {
                status: 403,
                message: "no".into()
            }
            .to_string(),
            "no"
        );
        assert_ne!(ClientError::BadResponse.to_string().len(), 0);
    }

    #[test]
    fn http_client_talks_to_the_device_api() {
        use axum::routing::{get, post};
        use axum::Json;
        let app = axum::Router::new()
            .route(
                "/v1/activate",
                post(|Json(v): Json<serde_json::Value>| async move {
                    if v["activation_key"] == "GOOD" {
                        Ok(Json(serde_json::json!({"license_id": "l", "license": "bGlj", "revocation_list": "cmw="})))
                    } else {
                        Err((
                            axum::http::StatusCode::NOT_FOUND,
                            Json(serde_json::json!({"error": "That activation key isn't valid."})),
                        ))
                    }
                }),
            )
            .route("/v1/checkin", post(|| async { "not json" }))
            .route(
                "/v1/deactivate",
                post(|| async { Json(serde_json::json!({"message": "ok"})) }),
            )
            .route(
                "/v1/offline/renew",
                post(|body: axum::body::Bytes| async move {
                    let mut v = body.to_vec();
                    v.reverse();
                    v
                }),
            )
            .route(
                "/v1/releases",
                get(|q: axum::extract::Query<std::collections::HashMap<String, String>>| async move {
                    Json(serde_json::json!({"license_id": q.0["license_id"], "releases": [
                        {"engine": "core", "version": "1", "released_at": 5, "manifest": "bQ=="}
                    ]}))
                }),
            )
            .route("/500", get(|| async { (axum::http::StatusCode::INTERNAL_SERVER_ERROR, "boom") }));
        let rt = tokio::runtime::Runtime::new().unwrap();
        let listener = rt
            .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
            .unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        rt.spawn(async move { axum::serve(listener, app).await });
        let c = HttpLicenseServer::new(&format!("{base}/"), Duration::from_secs(10));
        let dev = DeviceInfo {
            device_public_key: "pk".into(),
            fingerprint: "fp".into(),
            binding: "software".into(),
        };
        let ok = c
            .activate(&ActivateRequest {
                activation_key: "GOOD".into(),
                device: dev.clone(),
            })
            .unwrap();
        assert_eq!(ok.license, "bGlj");
        let err = c
            .activate(&ActivateRequest {
                activation_key: "BAD".into(),
                device: dev.clone(),
            })
            .unwrap_err();
        assert_eq!(
            err,
            ClientError::Rejected {
                status: 404,
                message: "That activation key isn't valid.".into()
            }
        );
        assert_eq!(
            c.checkin(&CheckinRequest {
                license_id: "l".into(),
                device: dev
            })
            .unwrap_err(),
            ClientError::BadResponse
        );
        c.deactivate(&DeactivateRequest {
            license_id: "l".into(),
            device_public_key: "pk".into(),
        })
        .unwrap();
        assert_eq!(c.offline_renew(b"abc").unwrap(), b"cba");
        let r = c.releases("lic 1").unwrap();
        assert_eq!(r[0].engine, "core");
        let plain = HttpLicenseServer::new(&base, Duration::from_secs(10));
        let e =
            HttpLicenseServer::finish(plain.agent.get(format!("{base}/500")).call()).unwrap_err();
        assert!(
            matches!(e, ClientError::Rejected { status: 500, .. }),
            "{e:?}"
        );
    }
}
