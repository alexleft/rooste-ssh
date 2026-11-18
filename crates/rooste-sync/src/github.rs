//! GitHub private repository backend using GitHub Git Database REST API (`blobs`/`trees`/`commits`/`refs`).
//!
//! Bundles all `.enc` additions, updates, deletions, and `manifest.enc` into a **single atomic Git Commit**,
//! leveraging non-force branch ref updates (`PATCH /git/refs/heads/<branch>`) as an optimistic concurrency lock.

use async_trait::async_trait;
use base64ct::{Base64, Encoding};
use reqwest::StatusCode;
use rooste_core::SyncConfig;
use rooste_vault::LocalSyncCredentials;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::backend::{SyncBackend, build_http_client};
use crate::error::SyncError;

/// Async GitHub REST API sync backend.
pub struct GitHubBackend {
    client: reqwest::Client,
    /// Normalized API repo root, e.g. `https://api.github.com/repos/owner/repo`.
    repo_api_base: String,
    branch: String,
    prefix: String,
    pat: Zeroizing<String>,
}

impl std::fmt::Debug for GitHubBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GitHubBackend")
            .field("repo_api_base", &self.repo_api_base)
            .field("branch", &self.branch)
            .field("prefix", &self.prefix)
            .field("pat", &"<redacted>")
            .finish()
    }
}

impl GitHubBackend {
    pub fn new(cfg: &SyncConfig, creds: &LocalSyncCredentials) -> Result<Self, SyncError> {
        let pat = creds
            .github_pat
            .as_ref()
            .filter(|s| !s.trim().is_empty())
            .cloned()
            .ok_or_else(|| SyncError::Auth("GitHub PAT is missing".into()))?;
        let repo_api_base = normalize_github_repo_url(&cfg.endpoint)?;
        let branch = if cfg.branch.trim().is_empty() {
            "main".to_owned()
        } else {
            cfg.branch.trim().to_owned()
        };
        let prefix = cfg.prefix.trim().trim_matches('/').to_owned();
        let client = build_http_client()?;
        Ok(Self {
            client,
            repo_api_base,
            branch,
            prefix,
            pat,
        })
    }

    fn full_repo_path(&self, relative_path: &str) -> String {
        let rel = relative_path.trim_start_matches('/');
        if self.prefix.is_empty() {
            rel.to_owned()
        } else {
            format!("{}/{rel}", self.prefix)
        }
    }

    fn auth_headers(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        req.header("Authorization", format!("Bearer {}", self.pat.as_str()))
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
    }

    async fn get_branch_head_sha(&self) -> Result<Option<String>, SyncError> {
        let url = format!("{}/git/ref/heads/{}", self.repo_api_base, self.branch);
        let resp = self
            .auth_headers(self.client.get(&url))
            .send()
            .await
            .map_err(|e| SyncError::Network(e.to_string()))?;
        match resp.status() {
            StatusCode::OK => {
                let parsed: GitRefResp = resp
                    .json()
                    .await
                    .map_err(|e| SyncError::Network(e.to_string()))?;
                Ok(Some(parsed.object.sha))
            }
            StatusCode::NOT_FOUND | StatusCode::CONFLICT => Ok(None),
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => Err(SyncError::Auth(
                "GitHub token unauthorized or insufficient scope".into(),
            )),
            status => Err(SyncError::HttpStatus {
                status: status.as_u16(),
                body: resp.text().await.unwrap_or_default(),
            }),
        }
    }

    async fn get_commit_tree_sha(&self, commit_sha: &str) -> Result<String, SyncError> {
        let url = format!("{}/git/commits/{commit_sha}", self.repo_api_base);
        let resp = self
            .auth_headers(self.client.get(&url))
            .send()
            .await
            .map_err(|e| SyncError::Network(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(SyncError::HttpStatus {
                status: resp.status().as_u16(),
                body: resp.text().await.unwrap_or_default(),
            });
        }
        let parsed: GitCommitResp = resp
            .json()
            .await
            .map_err(|e| SyncError::Network(e.to_string()))?;
        Ok(parsed.tree.sha)
    }

    async fn create_blob(&self, data: &[u8]) -> Result<String, SyncError> {
        let url = format!("{}/git/blobs", self.repo_api_base);
        let body = CreateBlobReq {
            content: Base64::encode_string(data),
            encoding: "base64",
        };
        let resp = self
            .auth_headers(self.client.post(&url).json(&body))
            .send()
            .await
            .map_err(|e| SyncError::Network(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(SyncError::HttpStatus {
                status: resp.status().as_u16(),
                body: resp.text().await.unwrap_or_default(),
            });
        }
        let parsed: ShaResp = resp
            .json()
            .await
            .map_err(|e| SyncError::Network(e.to_string()))?;
        Ok(parsed.sha)
    }
}

/// Accept `https://api.github.com/repos/owner/repo`, `https://github.com/owner/repo`, or `owner/repo`.
pub fn normalize_github_repo_url(raw: &str) -> Result<String, SyncError> {
    let trimmed = raw.trim().trim_end_matches('/').trim_end_matches(".git");
    if trimmed.is_empty() {
        return Err(SyncError::InvalidConfig(
            "GitHub repository URL is empty".into(),
        ));
    }
    if trimmed.starts_with("https://api.github.com/repos/") {
        return Ok(trimmed.to_owned());
    }
    if let Some(rest) = trimmed
        .strip_prefix("https://github.com/")
        .or_else(|| trimmed.strip_prefix("http://github.com/"))
    {
        return Ok(format!("https://api.github.com/repos/{rest}"));
    }
    if trimmed.contains('/') && !trimmed.contains("://") {
        return Ok(format!("https://api.github.com/repos/{trimmed}"));
    }
    Err(SyncError::InvalidConfig(format!(
        "unrecognized GitHub repository format: `{raw}`"
    )))
}

#[derive(Deserialize)]
struct ContentsResp {
    sha: String,
    content: Option<String>,
    download_url: Option<String>,
}

#[derive(Deserialize)]
struct GitRefResp {
    object: ShaResp,
}

#[derive(Deserialize)]
struct GitCommitResp {
    tree: ShaResp,
}

#[derive(Deserialize)]
struct ShaResp {
    sha: String,
}

#[derive(Serialize)]
struct CreateBlobReq {
    content: String,
    encoding: &'static str,
}

#[derive(Serialize)]
struct TreeEntry {
    path: String,
    mode: &'static str,
    #[serde(rename = "type")]
    kind: &'static str,
    sha: Option<String>,
}

#[derive(Serialize)]
struct CreateTreeReq {
    #[serde(skip_serializing_if = "Option::is_none")]
    base_tree: Option<String>,
    tree: Vec<TreeEntry>,
}

#[derive(Serialize)]
struct CreateCommitReq {
    message: String,
    tree: String,
    parents: Vec<String>,
}

#[derive(Serialize)]
struct UpdateRefReq {
    sha: String,
    force: bool,
}

#[derive(Serialize)]
struct CreateRefReq {
    #[serde(rename = "ref")]
    git_ref: String,
    sha: String,
}

#[derive(Serialize)]
struct PutContentReq {
    message: String,
    content: String,
    branch: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    sha: Option<String>,
}

#[derive(Deserialize)]
struct PutContentResp {
    content: ShaResp,
}

#[async_trait]
impl SyncBackend for GitHubBackend {
    async fn get_blob(&self, relative_path: &str) -> Result<Option<(Vec<u8>, String)>, SyncError> {
        let path = self.full_repo_path(relative_path);
        let url = format!("{}/contents/{path}?ref={}", self.repo_api_base, self.branch);
        let resp = self
            .auth_headers(self.client.get(&url))
            .send()
            .await
            .map_err(|e| SyncError::Network(e.to_string()))?;
        match resp.status() {
            StatusCode::OK => {
                let item: ContentsResp = resp
                    .json()
                    .await
                    .map_err(|e| SyncError::Network(e.to_string()))?;
                if let Some(b64) = item.content {
                    let clean: String = b64.chars().filter(|c| !c.is_whitespace()).collect();
                    let bytes = Base64::decode_vec(&clean).map_err(|e| {
                        SyncError::Network(format!("invalid base64 from GitHub: {e}"))
                    })?;
                    return Ok(Some((bytes, item.sha)));
                }
                if let Some(dl) = item.download_url {
                    let raw = self
                        .auth_headers(self.client.get(&dl))
                        .send()
                        .await
                        .map_err(|e| SyncError::Network(e.to_string()))?
                        .bytes()
                        .await
                        .map_err(|e| SyncError::Network(e.to_string()))?;
                    return Ok(Some((raw.to_vec(), item.sha)));
                }
                Ok(None)
            }
            StatusCode::NOT_FOUND => Ok(None),
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => {
                Err(SyncError::Auth("GitHub authentication failed".into()))
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
        let path = self.full_repo_path(relative_path);
        let url = format!("{}/contents/{path}", self.repo_api_base);
        let req = PutContentReq {
            message: format!("rooste-vault: update {relative_path}"),
            content: Base64::encode_string(data),
            branch: self.branch.clone(),
            sha: expected_etag.map(ToOwned::to_owned),
        };
        let resp = self
            .auth_headers(self.client.put(&url).json(&req))
            .send()
            .await
            .map_err(|e| SyncError::Network(e.to_string()))?;
        match resp.status() {
            StatusCode::OK | StatusCode::CREATED => {
                let parsed: PutContentResp = resp
                    .json()
                    .await
                    .map_err(|e| SyncError::Network(e.to_string()))?;
                Ok(parsed.content.sha)
            }
            StatusCode::CONFLICT | StatusCode::UNPROCESSABLE_ENTITY => {
                Err(SyncError::Conflict(resp.text().await.unwrap_or_default()))
            }
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => {
                Err(SyncError::Auth("GitHub write denied".into()))
            }
            status => Err(SyncError::HttpStatus {
                status: status.as_u16(),
                body: resp.text().await.unwrap_or_default(),
            }),
        }
    }

    async fn commit_batch(
        &self,
        puts: Vec<(String, Vec<u8>)>,
        deletes: Vec<String>,
        manifest_bytes: Vec<u8>,
        expected_manifest_etag: Option<&str>,
    ) -> Result<String, SyncError> {
        let head_sha = self.get_branch_head_sha().await?;

        // If the remote repository is completely empty (no branch head yet), bootstrap via Contents API.
        if head_sha.is_none() {
            for (path, data) in puts {
                self.put_blob(&path, &data, None).await?;
            }
            return self
                .put_blob("manifest.enc", &manifest_bytes, expected_manifest_etag)
                .await;
        }
        let parent_sha = head_sha.unwrap();
        let base_tree_sha = self.get_commit_tree_sha(&parent_sha).await?;

        // Check manifest optimistic lock if caller provided an expected blob SHA.
        if let Some(expected) = expected_manifest_etag {
            let current_manifest_sha = self.get_blob("manifest.enc").await?.map(|(_, sha)| sha);
            if current_manifest_sha.as_deref() != Some(expected) {
                return Err(SyncError::Conflict(
                    "remote manifest.enc changed before atomic Git commit".into(),
                ));
            }
        }

        // Upload blobs via Git Data API.
        let mut tree_entries = Vec::with_capacity(puts.len() + deletes.len() + 1);
        for (rel, data) in puts {
            let blob_sha = self.create_blob(&data).await?;
            tree_entries.push(TreeEntry {
                path: self.full_repo_path(&rel),
                mode: "100644",
                kind: "blob",
                sha: Some(blob_sha),
            });
        }
        let manifest_blob_sha = self.create_blob(&manifest_bytes).await?;
        tree_entries.push(TreeEntry {
            path: self.full_repo_path("manifest.enc"),
            mode: "100644",
            kind: "blob",
            sha: Some(manifest_blob_sha.clone()),
        });
        for rel in deletes {
            // GitHub's Git Trees API rejects `sha: null` for paths that do not exist in the
            // base tree; skip any already-removed remote blob cleanly.
            if self.get_blob(&rel).await?.is_some() {
                tree_entries.push(TreeEntry {
                    path: self.full_repo_path(&rel),
                    mode: "100644",
                    kind: "blob",
                    sha: None,
                });
            }
        }

        // Create Git Tree.
        let tree_url = format!("{}/git/trees", self.repo_api_base);
        let tree_resp = self
            .auth_headers(self.client.post(&tree_url).json(&CreateTreeReq {
                base_tree: Some(base_tree_sha),
                tree: tree_entries,
            }))
            .send()
            .await
            .map_err(|e| SyncError::Network(e.to_string()))?;
        if !tree_resp.status().is_success() {
            return Err(SyncError::HttpStatus {
                status: tree_resp.status().as_u16(),
                body: tree_resp.text().await.unwrap_or_default(),
            });
        }
        let new_tree: ShaResp = tree_resp
            .json()
            .await
            .map_err(|e| SyncError::Network(e.to_string()))?;

        // Create Git Commit.
        let commit_url = format!("{}/git/commits", self.repo_api_base);
        let commit_resp = self
            .auth_headers(self.client.post(&commit_url).json(&CreateCommitReq {
                message: "rooste-vault: incremental sync".to_owned(),
                tree: new_tree.sha,
                parents: vec![parent_sha],
            }))
            .send()
            .await
            .map_err(|e| SyncError::Network(e.to_string()))?;
        if !commit_resp.status().is_success() {
            return Err(SyncError::HttpStatus {
                status: commit_resp.status().as_u16(),
                body: commit_resp.text().await.unwrap_or_default(),
            });
        }
        let new_commit: ShaResp = commit_resp
            .json()
            .await
            .map_err(|e| SyncError::Network(e.to_string()))?;

        // Fast-forward branch ref (`force: false` guarantees atomic optimistic lock).
        let ref_url = format!("{}/git/refs/heads/{}", self.repo_api_base, self.branch);
        let ref_resp = self
            .auth_headers(self.client.patch(&ref_url).json(&UpdateRefReq {
                sha: new_commit.sha.clone(),
                force: false,
            }))
            .send()
            .await
            .map_err(|e| SyncError::Network(e.to_string()))?;
        match ref_resp.status() {
            StatusCode::OK => Ok(manifest_blob_sha),
            StatusCode::UNPROCESSABLE_ENTITY | StatusCode::CONFLICT => Err(SyncError::Conflict(
                "GitHub branch ref rejected non-fast-forward update".into(),
            )),
            StatusCode::NOT_FOUND => {
                let create_url = format!("{}/git/refs", self.repo_api_base);
                let cr = self
                    .auth_headers(self.client.post(&create_url).json(&CreateRefReq {
                        git_ref: format!("refs/heads/{}", self.branch),
                        sha: new_commit.sha,
                    }))
                    .send()
                    .await
                    .map_err(|e| SyncError::Network(e.to_string()))?;
                if cr.status().is_success() {
                    Ok(manifest_blob_sha)
                } else {
                    Err(SyncError::HttpStatus {
                        status: cr.status().as_u16(),
                        body: cr.text().await.unwrap_or_default(),
                    })
                }
            }
            status => Err(SyncError::HttpStatus {
                status: status.as_u16(),
                body: ref_resp.text().await.unwrap_or_default(),
            }),
        }
    }

    async fn delete_blob(&self, relative_path: &str) -> Result<(), SyncError> {
        let Some((_, sha)) = self.get_blob(relative_path).await? else {
            return Ok(());
        };
        let path = self.full_repo_path(relative_path);
        let url = format!("{}/contents/{path}", self.repo_api_base);
        let body = serde_json::json!({
            "message": format!("rooste-vault: prune {relative_path}"),
            "sha": sha,
            "branch": self.branch,
        });
        let resp = self
            .auth_headers(self.client.delete(&url).json(&body))
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
