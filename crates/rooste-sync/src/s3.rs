//! S3-compatible object storage backend (AWS S3, Cloudflare R2, MinIO, Aliyun OSS)
//! using pure Safe Rust AWS Signature Version 4 (`sha2` + `hmac`) and `If-Match` optimistic locking.

use async_trait::async_trait;
use chrono::Utc;
use hmac::{Hmac, KeyInit, Mac};
use reqwest::StatusCode;
use rooste_core::SyncConfig;
use rooste_vault::LocalSyncCredentials;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::backend::{SyncBackend, build_http_client};
use crate::error::SyncError;

type HmacSha256 = Hmac<Sha256>;

/// Async S3-compatible sync backend using path-style URLs (`<endpoint>/<bucket>/<key>`).
pub struct S3Backend {
    client: reqwest::Client,
    endpoint: String,
    host_header: String,
    bucket: String,
    region: String,
    prefix: String,
    access_key: Zeroizing<String>,
    secret_key: Zeroizing<String>,
}

impl std::fmt::Debug for S3Backend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("S3Backend")
            .field("endpoint", &self.endpoint)
            .field("bucket", &self.bucket)
            .field("region", &self.region)
            .field("prefix", &self.prefix)
            .field("access_key", &"<redacted>")
            .field("secret_key", &"<redacted>")
            .finish()
    }
}

impl S3Backend {
    pub fn new(cfg: &SyncConfig, creds: &LocalSyncCredentials) -> Result<Self, SyncError> {
        let endpoint = cfg.endpoint.trim().trim_end_matches('/').to_owned();
        if !endpoint.starts_with("http://") && !endpoint.starts_with("https://") {
            return Err(SyncError::InvalidConfig(format!(
                "S3 endpoint must start with http:// or https://, got `{endpoint}`"
            )));
        }
        let host_header = extract_host_header(&endpoint)?;
        let access_key = creds
            .s3_access_key
            .as_ref()
            .filter(|s| !s.trim().is_empty())
            .cloned()
            .ok_or_else(|| SyncError::Auth("S3 Access Key is missing".into()))?;
        let secret_key = creds
            .s3_secret_key
            .as_ref()
            .filter(|s| !s.trim().is_empty())
            .cloned()
            .ok_or_else(|| SyncError::Auth("S3 Secret Key is missing".into()))?;
        let bucket = creds.s3_bucket.trim().to_owned();
        if bucket.is_empty() {
            return Err(SyncError::InvalidConfig(
                "S3 bucket name is required".into(),
            ));
        }
        let region = if creds.s3_region.trim().is_empty() {
            "us-east-1".to_owned()
        } else {
            creds.s3_region.trim().to_owned()
        };
        let prefix = cfg.prefix.trim().trim_matches('/').to_owned();
        let client = build_http_client()?;
        Ok(Self {
            client,
            endpoint,
            host_header,
            bucket,
            region,
            prefix,
            access_key,
            secret_key,
        })
    }

    fn canonical_uri(&self, relative_path: &str) -> String {
        let rel = relative_path.trim_start_matches('/');
        let key = if self.prefix.is_empty() {
            rel.to_owned()
        } else {
            format!("{}/{rel}", self.prefix)
        };
        format!(
            "/{}/{}",
            uri_encode_path(&self.bucket),
            uri_encode_path(&key)
        )
    }

    fn signed_request(
        &self,
        method: reqwest::Method,
        relative_path: &str,
        body: &[u8],
        if_match: Option<&str>,
    ) -> Result<reqwest::RequestBuilder, SyncError> {
        let now = Utc::now();
        let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
        let date_stamp = now.format("%Y%m%d").to_string();
        let payload_hash = hex::encode(Sha256::digest(body));
        let canonical_uri = self.canonical_uri(relative_path);
        let url = format!("{}{canonical_uri}", self.endpoint);

        let mut headers_for_sig: Vec<(&str, String)> = vec![
            ("host", self.host_header.clone()),
            ("x-amz-content-sha256", payload_hash.clone()),
            ("x-amz-date", amz_date.clone()),
        ];
        if let Some(etag) = if_match {
            headers_for_sig.push(("if-match", etag.to_owned()));
        }
        headers_for_sig.sort_by(|a, b| a.0.cmp(b.0));

        let canonical_headers: String = headers_for_sig
            .iter()
            .map(|(k, v)| format!("{k}:{}\n", v.trim()))
            .collect();
        let signed_headers: String = headers_for_sig
            .iter()
            .map(|(k, _)| *k)
            .collect::<Vec<_>>()
            .join(";");

        let canonical_request = format!(
            "{}\n{canonical_uri}\n\n{canonical_headers}\n{signed_headers}\n{payload_hash}",
            method.as_str()
        );
        let credential_scope = format!("{date_stamp}/{}/s3/aws4_request", self.region);
        let string_to_sign = format!(
            "AWS4-HMAC-SHA256\n{amz_date}\n{credential_scope}\n{}",
            hex::encode(Sha256::digest(canonical_request.as_bytes()))
        );

        let signing_key =
            derive_sigv4_key(self.secret_key.as_bytes(), &date_stamp, &self.region, "s3")?;
        let signature = hex::encode(hmac_sha256(&signing_key, string_to_sign.as_bytes())?);
        let authorization = format!(
            "AWS4-HMAC-SHA256 Credential={}/{credential_scope}, SignedHeaders={signed_headers}, Signature={signature}",
            self.access_key.as_str()
        );

        let mut req = self
            .client
            .request(method, &url)
            .header("x-amz-date", &amz_date)
            .header("x-amz-content-sha256", &payload_hash)
            .header("Authorization", authorization);
        if let Some(etag) = if_match {
            req = req.header("If-Match", etag);
        }
        if !body.is_empty() {
            req = req.body(body.to_vec());
        }
        Ok(req)
    }
}

fn extract_host_header(endpoint: &str) -> Result<String, SyncError> {
    let without_scheme = endpoint
        .strip_prefix("https://")
        .or_else(|| endpoint.strip_prefix("http://"))
        .ok_or_else(|| SyncError::InvalidConfig(format!("missing scheme in `{endpoint}`")))?;
    let host = without_scheme.split('/').next().unwrap_or_default();
    if host.is_empty() {
        return Err(SyncError::InvalidConfig(format!(
            "missing host in `{endpoint}`"
        )));
    }
    Ok(host.to_owned())
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Result<Vec<u8>, SyncError> {
    let mut mac = <HmacSha256 as KeyInit>::new_from_slice(key)
        .map_err(|e| SyncError::InvalidConfig(format!("HMAC init failed: {e}")))?;
    mac.update(data);
    Ok(mac.finalize().into_bytes().to_vec())
}

fn derive_sigv4_key(
    secret: &[u8],
    date_stamp: &str,
    region: &str,
    service: &str,
) -> Result<Vec<u8>, SyncError> {
    let mut k_secret = Zeroizing::new(Vec::with_capacity(4 + secret.len()));
    k_secret.extend_from_slice(b"AWS4");
    k_secret.extend_from_slice(secret);
    let k_date = hmac_sha256(&k_secret, date_stamp.as_bytes())?;
    let k_region = hmac_sha256(&k_date, region.as_bytes())?;
    let k_service = hmac_sha256(&k_region, service.as_bytes())?;
    hmac_sha256(&k_service, b"aws4_request")
}

fn uri_encode_path(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for byte in input.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b'/' => {
                out.push(byte as char);
            }
            other => {
                out.push('%');
                out.push_str(&format!("{other:02X}"));
            }
        }
    }
    out
}

#[async_trait]
impl SyncBackend for S3Backend {
    async fn get_blob(&self, relative_path: &str) -> Result<Option<(Vec<u8>, String)>, SyncError> {
        let req = self.signed_request(reqwest::Method::GET, relative_path, &[], None)?;
        let resp = req
            .send()
            .await
            .map_err(|e| SyncError::Network(e.to_string()))?;
        match resp.status() {
            StatusCode::OK => {
                let etag = resp
                    .headers()
                    .get("etag")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or_default()
                    .to_owned();
                let bytes = resp
                    .bytes()
                    .await
                    .map_err(|e| SyncError::Network(e.to_string()))?;
                Ok(Some((bytes.to_vec(), etag)))
            }
            StatusCode::NOT_FOUND => Ok(None),
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => {
                Err(SyncError::Auth("S3 credentials rejected".into()))
            }
            status => Err(SyncError::HttpStatus {
                status: status.as_u16(),
                body: resp.text().await.unwrap_or_default(),
            }),
        }
    }

    async fn put_blob(
        &self,
        relative_path: &str,
        data: &[u8],
        expected_etag: Option<&str>,
    ) -> Result<String, SyncError> {
        let req = self.signed_request(reqwest::Method::PUT, relative_path, data, expected_etag)?;
        let resp = req
            .send()
            .await
            .map_err(|e| SyncError::Network(e.to_string()))?;
        match resp.status() {
            StatusCode::OK | StatusCode::CREATED | StatusCode::NO_CONTENT => {
                let etag = resp
                    .headers()
                    .get("etag")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or_default()
                    .to_owned();
                Ok(etag)
            }
            StatusCode::PRECONDITION_FAILED | StatusCode::CONFLICT => {
                Err(SyncError::Conflict(resp.text().await.unwrap_or_default()))
            }
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => {
                Err(SyncError::Auth("S3 write access denied".into()))
            }
            status => Err(SyncError::HttpStatus {
                status: status.as_u16(),
                body: resp.text().await.unwrap_or_default(),
            }),
        }
    }

    async fn delete_blob(&self, relative_path: &str) -> Result<(), SyncError> {
        let req = self.signed_request(reqwest::Method::DELETE, relative_path, &[], None)?;
        let resp = req
            .send()
            .await
            .map_err(|e| SyncError::Network(e.to_string()))?;
        if resp.status().is_success() || resp.status() == StatusCode::NOT_FOUND {
            Ok(())
        } else {
            Err(SyncError::HttpStatus {
                status: resp.status().as_u16(),
                body: resp.text().await.unwrap_or_default(),
            })
        }
    }
}
