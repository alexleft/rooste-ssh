//! Non-blocking background sync actor running on the `tokio` runtime.
//!
//! Ensures the `egui` 60 FPS UI thread never performs synchronous network I/O.

use std::sync::Arc;

use rooste_core::SyncConfig;
use rooste_vault::{LocalSyncCredentials, VaultStore, VaultSummary};
use tokio::sync::{Mutex, mpsc};
use zeroize::Zeroizing;

use crate::backend::{SyncBackend, build_backend};
use crate::engine::{RemoteVaultSnapshot, SyncEngine, SyncProgress, SyncReport};

/// Commands sent from the UI thread to the background sync actor.
#[derive(Debug)]
pub enum SyncCommand {
    /// Verify connectivity & credentials against the configured backend.
    TestConnection {
        config: SyncConfig,
        creds: LocalSyncCredentials,
    },
    /// Fetch remote `vault.json` and `manifest.enc` for Scene B / Scene D recovery preview.
    InspectRemote {
        config: SyncConfig,
        creds: LocalSyncCredentials,
    },
    /// Run a full remote recovery (Scene B new device or Scene D wipe-and-resync).
    RecoverFromRemote {
        config: SyncConfig,
        creds: LocalSyncCredentials,
        snapshot: Box<RemoteVaultSnapshot>,
        dek: Zeroizing<[u8; 16]>,
        new_master_password: Option<Zeroizing<String>>,
        wipe_existing: bool,
    },
    /// Execute an incremental three-way sync cycle.
    SyncNow {
        config: SyncConfig,
        creds: LocalSyncCredentials,
    },
    /// Push updated `vault.json` header (after password reset or rekey).
    PushHeader {
        config: SyncConfig,
        creds: LocalSyncCredentials,
    },
}

/// Events sent from the background sync actor back to the UI thread.
#[derive(Debug)]
pub enum SyncEvent {
    Progress(SyncProgress),
    ConnectionTested(Result<(), String>),
    RemoteInspected(Result<RemoteVaultSnapshot, String>),
    Recovered {
        result: Result<(SyncReport, Option<VaultSummary>), String>,
    },
    Synced(Result<SyncReport, String>),
    HeaderPushed(Result<(), String>),
}

/// Handle held by the GUI application to drive background sync without blocking.
pub struct SyncActorHandle {
    tx: mpsc::UnboundedSender<SyncCommand>,
    rx: std::sync::mpsc::Receiver<SyncEvent>,
}

impl std::fmt::Debug for SyncActorHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SyncActorHandle").finish_non_exhaustive()
    }
}

impl SyncActorHandle {
    /// Spawn the background sync actor on `runtime`, sharing access to `store`.
    pub fn spawn(
        runtime: &tokio::runtime::Handle,
        store: Arc<Mutex<VaultStore>>,
        wake_ui: Arc<dyn Fn() + Send + Sync>,
    ) -> Self {
        let (cmd_tx, mut cmd_rx) = mpsc::unbounded_channel::<SyncCommand>();
        let (ev_tx, ev_rx) = std::sync::mpsc::channel::<SyncEvent>();

        runtime.spawn(async move {
            let engine = SyncEngine::default();
            while let Some(cmd) = cmd_rx.recv().await {
                let emit = |ev: SyncEvent| {
                    let _ = ev_tx.send(ev);
                    wake_ui();
                };
                match cmd {
                    SyncCommand::TestConnection { config, creds } => {
                        let res = match build_backend(&config, &creds) {
                            Ok(backend) => {
                                backend.test_connection().await.map_err(|e| e.to_string())
                            }
                            Err(e) => Err(e.to_string()),
                        };
                        emit(SyncEvent::ConnectionTested(res));
                    }
                    SyncCommand::InspectRemote { config, creds } => {
                        let res = match build_backend(&config, &creds) {
                            Ok(backend) => engine
                                .inspect_remote(backend.as_ref())
                                .await
                                .map_err(|e| e.to_string()),
                            Err(e) => Err(e.to_string()),
                        };
                        emit(SyncEvent::RemoteInspected(res));
                    }
                    SyncCommand::RecoverFromRemote {
                        config,
                        creds,
                        snapshot,
                        dek,
                        new_master_password,
                        wipe_existing,
                    } => {
                        let res = run_recover(
                            &engine,
                            &store,
                            &config,
                            &creds,
                            *snapshot,
                            dek,
                            new_master_password.as_deref().map(String::as_str),
                            wipe_existing,
                            &emit,
                        )
                        .await;
                        emit(SyncEvent::Recovered { result: res });
                    }
                    SyncCommand::SyncNow { config, creds } => {
                        let res = run_sync(&engine, &store, &config, &creds, &emit).await;
                        emit(SyncEvent::Synced(res));
                    }
                    SyncCommand::PushHeader { config, creds } => {
                        let res = run_push_header(&store, &config, &creds).await;
                        emit(SyncEvent::HeaderPushed(res));
                    }
                }
            }
        });

        Self {
            tx: cmd_tx,
            rx: ev_rx,
        }
    }

    pub fn send(&self, cmd: SyncCommand) {
        let _ = self.tx.send(cmd);
    }

    /// Drain all pending events without blocking the UI thread.
    pub fn poll(&self) -> Vec<SyncEvent> {
        let mut out = Vec::new();
        while let Ok(ev) = self.rx.try_recv() {
            out.push(ev);
        }
        out
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_recover(
    engine: &SyncEngine,
    store: &Arc<Mutex<VaultStore>>,
    config: &SyncConfig,
    creds: &LocalSyncCredentials,
    snapshot: RemoteVaultSnapshot,
    dek: Zeroizing<[u8; 16]>,
    new_master_password: Option<&str>,
    wipe_existing: bool,
    emit: &impl Fn(SyncEvent),
) -> Result<(SyncReport, Option<VaultSummary>), String> {
    let backend: Arc<dyn SyncBackend> = build_backend(config, creds).map_err(|e| e.to_string())?;
    let mut guard = store.lock().await;
    let backup = if wipe_existing {
        Some(guard.begin_reset_backup().map_err(|e| e.to_string())?)
    } else {
        None
    };
    let report = engine
        .recover_from_remote(
            &mut guard,
            backend.as_ref(),
            snapshot,
            dek,
            new_master_password,
            backup.as_deref(),
            |p| emit(SyncEvent::Progress(p)),
        )
        .await
        .map_err(|e| e.to_string())?;
    guard.local_config_mut().sync = config.clone();
    guard.local_config_mut().sync.enabled = true;
    guard
        .save_local_credentials(creds)
        .map_err(|e| e.to_string())?;
    guard.save_local_config().map_err(|e| e.to_string())?;
    let summary = guard.summary();
    Ok((report, summary))
}

async fn run_sync(
    engine: &SyncEngine,
    store: &Arc<Mutex<VaultStore>>,
    config: &SyncConfig,
    creds: &LocalSyncCredentials,
    emit: &impl Fn(SyncEvent),
) -> Result<SyncReport, String> {
    let backend = build_backend(config, creds).map_err(|e| e.to_string())?;
    let mut guard = store.lock().await;
    engine
        .sync(&mut guard, backend.as_ref(), |p| {
            emit(SyncEvent::Progress(p))
        })
        .await
        .map_err(|e| e.to_string())
}

async fn run_push_header(
    store: &Arc<Mutex<VaultStore>>,
    config: &SyncConfig,
    creds: &LocalSyncCredentials,
) -> Result<(), String> {
    let backend = build_backend(config, creds).map_err(|e| e.to_string())?;
    let header_bytes = {
        let guard = store.lock().await;
        guard
            .read_raw_blob("vault.json")
            .map_err(|e| e.to_string())?
            .ok_or_else(|| "vault.json missing locally".to_owned())?
    };
    let existing_etag = backend
        .get_blob("vault.json")
        .await
        .map_err(|e| e.to_string())?
        .map(|(_, e)| e);
    backend
        .put_blob("vault.json", &header_bytes, existing_etag.as_deref())
        .await
        .map_err(|e| e.to_string())?;
    Ok(())
}
