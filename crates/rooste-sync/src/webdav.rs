//! WebDAV sync backend (Synology NAS, Nextcloud, Jianguoyun, OwnCloud).
//!
//! Uses atomic temp-file upload (`.tmp.<uuid>`) followed by HTTP `MOVE` overwrite
//! and `If-Match` ETag checking on `manifest.enc`.

use async_trait::async_trait;
use reqwest::{Method, StatusCode};
use rooste_core::SyncConfig;
use rooste_vault::LocalSyncCredentials;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::backend::{SyncBackend, build_http_client};
use crate::error::SyncError;

/// Async WebDAV sync backend.
pub struct WebDavBackend {
    client: reqwest::Client,
    root_url: String,
    username: Zeroizing<String>,
    password: Zeroizing<String>,
}

impl std::fmt::Debug for WebDavBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebDavBackend")
            .field("root_url", &self.root_url)
            .field("username", &"<redacted>")
            .field("password", &"<redacted>")
            .finish()
    }
}

impl WebDavBackend {
    pub fn new(cfg: &SyncConfig, creds: &LocalSyncCredentials) -> Result<Self, SyncError> {
        let base = cfg.endpoint.trim().trim_end_matches('/');
        if !base.starts_with("http://") && !base.starts_with("https://") {
            return Err(SyncError::InvalidConfig(format!(
                "WebDAV URL must start with http:// or https://, got `{base}`"
            )));
        }
        let prefix = cfg.prefix.trim().trim_matches('/');
        let root_url = if prefix.is_empty() {
            base.to_owned()
        } else {
            format!("{base}/{prefix}")
        };
        let username = creds
            .webdav_user
            .as_ref()
            .filter(|s| !s.trim().is_empty())
            .cloned()
            .ok_or_else(|| SyncError::Auth("WebDAV username is missing".into()))?;
        let password = creds
            .webdav_password
            .as_ref()
            .cloned()
            .unwrap_or_else(|| Zeroizing::new(String::new()));
        let client = build_http_client()?;
        Ok(Self {
            client,
            root_url,
            username,
            password,
        })
    }

    fn item_url(&self, relative_path: &str) -> String {
        let rel = relative_path.trim_start_matches('/');
        format!("{}/{rel}", self.root_url)
    }

    fn auth(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        req.basic_auth(self.username.as_str(), Some(self.password.as_str()))
    }

    async fn ensure_parent_dirs(&self, relative_path: &str) -> Result<(), SyncError> {
        let mkcol = Method::from_bytes(b"MKCOL")
            .map_err(|e| SyncError::Network(format!("MKCOL method error: {e}")))?;
        let parts: Vec<&str> = relative_path.trim_start_matches('/').split('/').collect();
        if parts.len() <= 1 {
            return Ok(());
        }
        let mut current = self.root_url.clone();
        // Ensure root itself first.
        let _ = self
            .auth(self.client.request(mkcol.clone(), &current))
            .send()
            .await;
        for dir in &parts[..parts.len() - 1] {
            current.push('/');
            current.push_str(dir);
            let resp = self
                .auth(self.client.request(mkcol.clone(), &current))
                .send()
                .await
                .map_err(|e| SyncError::Network(e.to_string()))?;
            // 201 Created, 405 Method Not Allowed (already exists), 301/409 OK to ignore if dir exists.
            if resp.status() == StatusCode::UNAUTHORIZED || resp.status() == StatusCode::FORBIDDEN {
                return Err(SyncError::Auth("WebDAV MKCOL denied".into()));
            }
        }
        Ok(())
    }
}

#[async_trait]
impl SyncBackend for WebDavBackend {
    async fn get_blob(&self, relative_path: &str) -> Result<Option<(Vec<u8>, String)>, SyncError> {
        let url = self.item_url(relative_path);
        let resp = self
            .auth(self.client.get(&url))
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
                Err(SyncError::Auth("WebDAV authentication failed".into()))
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
        self.ensure_parent_dirs(relative_path).await?;
        let target_url = self.item_url(relative_path);

        // Optimistic lock verification before atomic move if caller supplied an expected ETag.
        if let Some(expected) = expected_etag {
            let head = self
                .auth(self.client.head(&target_url))
                .send()
                .await
                .map_err(|e| SyncError::Network(e.to_string()))?;
            if head.status() == StatusCode::OK {
                let remote_etag = head
                    .headers()
                    .get("etag")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or_default();
                if !remote_etag.is_empty() && remote_etag != expected {
                    return Err(SyncError::Conflict(format!(
                        "WebDAV ETag mismatch on {relative_path}: expected `{expected}`, got `{remote_etag}`"
                    )));
                }
            }
        }

        // Upload to sibling temporary path, then atomic MOVE overwrite.
        let tmp_rel = format!("{relative_path}.tmp.{}", Uuid::new_v4().simple());
        let tmp_url = self.item_url(&tmp_rel);
        let put_resp = self
            .auth(self.client.put(&tmp_url).body(data.to_vec()))
            .send()
            .await
            .map_err(|e| SyncError::Network(e.to_string()))?;
        if !put_resp.status().is_success() {
            if put_resp.status() == StatusCode::UNAUTHORIZED
                || put_resp.status() == StatusCode::FORBIDDEN
            {
                return Err(SyncError::Auth("WebDAV write denied".into()));
            }
            return Err(SyncError::HttpStatus {
                status: put_resp.status().as_u16(),
                body: put_resp.text().await.unwrap_or_default(),
            });
        }

        let move_method = Method::from_bytes(b"MOVE")
            .map_err(|e| SyncError::Network(format!("MOVE method error: {e}")))?;
        let mut move_req = self
            .auth(self.client.request(move_method, &tmp_url))
            .header("Destination", &target_url)
            .header("Overwrite", "T");
        if let Some(etag) = expected_etag
            && !etag.is_empty()
        {
            move_req = move_req.header("If-Match", etag);
        }
        let move_resp = move_req
            .send()
            .await
            .map_err(|e| SyncError::Network(e.to_string()))?;
        match move_resp.status() {
            StatusCode::CREATED | StatusCode::NO_CONTENT | StatusCode::OK => {
                let etag = move_resp
                    .headers()
                    .get("etag")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or_default()
                    .to_owned();
                Ok(etag)
            }
            StatusCode::PRECONDITION_FAILED | StatusCode::CONFLICT => {
                let _ = self.delete_blob(&tmp_rel).await;
                Err(SyncError::Conflict(
                    move_resp.text().await.unwrap_or_default(),
                ))
            }
            status => {
                let _ = self.delete_blob(&tmp_rel).await;
                Err(SyncError::HttpStatus {
                    status: status.as_u16(),
                    body: move_resp.text().await.unwrap_or_default(),
                })
            }
        }
    }

    async fn delete_blob(&self, relative_path: &str) -> Result<(), SyncError> {
        let url = self.item_url(relative_path);
        let resp = self
            .auth(self.client.delete(&url))
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
