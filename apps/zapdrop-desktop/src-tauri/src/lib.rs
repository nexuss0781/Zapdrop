mod discovery;
mod explorer;
mod history;
mod identity;
pub mod mesh;
mod network;
mod pairing;
pub mod repair;
pub mod scheduler;
pub mod secure;
mod settings;
pub mod snapshot;
pub mod swarm;
mod transfer;
mod trust;

use discovery::{manual_peer, NetworkDiagnostics, PeerRecord};
use network::RuntimeState;
use pairing::{PairingOutcome, PairingRequestView};
use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use tauri::{Emitter, Manager};
use transfer::TransferRequest;
use trust::TrustedPeer;

const APP_VERSION: &str = env!("CARGO_PKG_VERSION");

pub struct AppState {
    pub runtime: Mutex<RuntimeState>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppInfo {
    pub name: &'static str,
    pub version: &'static str,
    pub phase: &'static str,
    pub platform: &'static str,
    pub local_only: bool,
    pub device_id: String,
    pub device_name: String,
    pub fingerprint: String,
    pub key_storage: String,
    pub data_directory: String,
    pub pairing_port: u16,
    pub trusted_peer_count: usize,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SettingsPatch {
    pub device_name: Option<String>,
    pub receive_directory: Option<String>,
    pub selected_interface: Option<String>,
    pub advertise_on_startup: Option<bool>,
    pub always_ask_before_receive: Option<bool>,
    pub default_conflict_policy: Option<String>,
}

#[tauri::command]
fn list_directory(path: Option<String>) -> Result<explorer::ExplorerLocation, String> {
    explorer::list_directory(path)
}

#[tauri::command]
fn inspect_sources(paths: Vec<String>) -> Result<Vec<explorer::SelectedSource>, String> {
    explorer::inspect_sources(paths)
}

#[tauri::command]
fn list_transfer_history(
    state: tauri::State<'_, AppState>,
) -> Result<Vec<history::TransferHistoryEntry>, String> {
    let runtime = state
        .runtime
        .lock()
        .map_err(|_| "runtime state is unavailable".to_string())?;
    Ok(runtime.history.list())
}

#[tauri::command]
fn clear_transfer_history(state: tauri::State<'_, AppState>) -> Result<(), String> {
    let runtime = state
        .runtime
        .lock()
        .map_err(|_| "runtime state is unavailable".to_string())?;
    runtime
        .history
        .clear()
        .map_err(|error| format!("could not clear transfer history: {error}"))
}

#[tauri::command]
fn list_pending_transfers(
    state: tauri::State<'_, AppState>,
) -> Result<Vec<transfer::IncomingTransferOffer>, String> {
    let runtime = state
        .runtime
        .lock()
        .map_err(|_| "runtime state is unavailable".to_string())?;
    Ok(runtime.pending_transfers())
}

#[tauri::command]
fn accept_transfer(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    transfer_id: String,
    conflict_policy: Option<String>,
    destination: Option<String>,
) -> Result<(), String> {
    let runtime = state
        .runtime
        .lock()
        .map_err(|_| "runtime state is unavailable".to_string())?;
    runtime
        .offers
        .accept(
            &transfer_id,
            conflict_policy.unwrap_or_else(|| runtime.settings.default_conflict_policy.clone()),
            destination,
            runtime.transfer_context(&app),
        )
        .map_err(|error| format!("could not accept transfer: {error}"))?;
    let _ = app.emit("incoming-transfer-accepted", transfer_id);
    Ok(())
}

#[tauri::command]
fn reject_transfer(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    transfer_id: String,
    reason: Option<String>,
) -> Result<(), String> {
    let runtime = state
        .runtime
        .lock()
        .map_err(|_| "runtime state is unavailable".to_string())?;
    runtime
        .offers
        .reject(
            &transfer_id,
            reason.unwrap_or_else(|| "rejected by user".to_string()),
        )
        .map_err(|error| format!("could not reject transfer: {error}"))?;
    let _ = app.emit("incoming-transfer-rejected", transfer_id);
    Ok(())
}

#[tauri::command]
fn get_app_info(state: tauri::State<'_, AppState>) -> Result<AppInfo, String> {
    let runtime = state
        .runtime
        .lock()
        .map_err(|_| "runtime state is unavailable".to_string())?;
    Ok(app_info(&runtime))
}

#[tauri::command]
fn get_settings(state: tauri::State<'_, AppState>) -> Result<settings::AppSettings, String> {
    let runtime = state
        .runtime
        .lock()
        .map_err(|_| "runtime state is unavailable".to_string())?;
    Ok(runtime.settings.clone())
}

#[tauri::command]
fn update_settings(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    patch: SettingsPatch,
) -> Result<settings::AppSettings, String> {
    let mut runtime = state
        .runtime
        .lock()
        .map_err(|_| "runtime state is unavailable".to_string())?;
    let previous_name = runtime.settings.device_name.clone();
    let previous_advertise = runtime.settings.advertise_on_startup;
    if let Some(value) = patch.device_name {
        runtime.settings.device_name = settings::normalize_device_name(&value);
    }
    if let Some(value) = patch.receive_directory {
        if value.trim().is_empty() {
            return Err("receive directory cannot be empty".to_string());
        }
        runtime.settings.receive_directory = value;
    }
    if patch.selected_interface.is_some() {
        runtime.settings.selected_interface = patch.selected_interface;
    }
    if let Some(value) = patch.advertise_on_startup {
        runtime.settings.advertise_on_startup = value;
    }
    if let Some(value) = patch.always_ask_before_receive {
        runtime.settings.always_ask_before_receive = value;
    }
    if let Some(value) = patch.default_conflict_policy {
        if !matches!(value.as_str(), "rename" | "overwrite" | "skip") {
            return Err("default conflict policy must be rename, overwrite, or skip".to_string());
        }
        runtime.settings.default_conflict_policy = value;
    }
    runtime
        .store
        .save(&runtime.settings)
        .map_err(|error| format!("could not save settings: {error}"))?;
    if previous_name != runtime.settings.device_name
        || previous_advertise != runtime.settings.advertise_on_startup
    {
        runtime.restart_discovery(&app);
    }
    let _ = app.emit("settings-updated", runtime.settings.clone());
    Ok(runtime.settings.clone())
}

#[tauri::command]
fn reset_identity(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<AppInfo, String> {
    let mut runtime = state
        .runtime
        .lock()
        .map_err(|_| "runtime state is unavailable".to_string())?;
    runtime.identity = identity::DeviceIdentity::reset(&runtime.store)
        .map_err(|error| format!("could not reset device identity: {error}"))?;
    runtime.restart_discovery(&app);
    let _ = app.emit("identity-reset", runtime.identity.clone());
    Ok(app_info(&runtime))
}

#[tauri::command]
fn list_peers(state: tauri::State<'_, AppState>) -> Result<Vec<PeerRecord>, String> {
    let runtime = state
        .runtime
        .lock()
        .map_err(|_| "runtime state is unavailable".to_string())?;
    Ok(runtime.peers())
}

#[tauri::command]
fn get_network_diagnostics(
    state: tauri::State<'_, AppState>,
) -> Result<NetworkDiagnostics, String> {
    let runtime = state
        .runtime
        .lock()
        .map_err(|_| "runtime state is unavailable".to_string())?;
    Ok(runtime.diagnostics())
}

#[tauri::command]
fn scan_network(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<Vec<PeerRecord>, String> {
    let runtime = state
        .runtime
        .lock()
        .map_err(|_| "runtime state is unavailable".to_string())?;
    let peers = runtime.peers();
    let _ = app.emit("scan-complete", peers.clone());
    Ok(peers)
}

#[tauri::command]
fn add_manual_endpoint(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    endpoint: String,
) -> Result<PeerRecord, String> {
    let mut runtime = state
        .runtime
        .lock()
        .map_err(|_| "runtime state is unavailable".to_string())?;
    let peer = manual_peer(&endpoint).map_err(|error| error.to_string())?;
    runtime.manual_peers.insert(peer.id.clone(), peer.clone());
    if let Some(discovery) = runtime.discovery.as_ref() {
        discovery.registry.upsert(peer.clone());
    }
    let _ = app.emit("peer-updated", peer.clone());
    Ok(peer)
}

#[tauri::command]
fn list_pending_pairings(
    state: tauri::State<'_, AppState>,
) -> Result<Vec<PairingRequestView>, String> {
    let runtime = state
        .runtime
        .lock()
        .map_err(|_| "runtime state is unavailable".to_string())?;
    Ok(runtime.pending_pairings())
}

#[tauri::command]
fn list_trusted_peers(state: tauri::State<'_, AppState>) -> Result<Vec<TrustedPeer>, String> {
    let runtime = state
        .runtime
        .lock()
        .map_err(|_| "runtime state is unavailable".to_string())?;
    Ok(runtime.trusted_peers())
}

#[tauri::command]
fn pair_with_peer(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    peer_id: String,
) -> Result<PairingOutcome, String> {
    let runtime = state
        .runtime
        .lock()
        .map_err(|_| "runtime state is unavailable".to_string())?;
    let outcome = runtime
        .pair_outbound(&peer_id)
        .map_err(|error| error.to_string())?;
    if outcome.status == "accepted" {
        let trusted = TrustedPeer::from_pairing(&outcome);
        runtime
            .trust
            .upsert(trusted.clone())
            .map_err(|error| format!("could not save trusted peer: {error}"))?;
        let _ = app.emit("peer-trust-updated", trusted);
    }
    let _ = app.emit("pairing-complete", outcome.clone());
    Ok(outcome)
}

#[tauri::command]
fn accept_pairing(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    request_id: String,
) -> Result<PairingOutcome, String> {
    let runtime = state
        .runtime
        .lock()
        .map_err(|_| "runtime state is unavailable".to_string())?;
    let pairing = runtime
        .pairing
        .as_ref()
        .ok_or_else(|| "pairing listener is unavailable".to_string())?;
    let trusted = pairing
        .accept(
            &request_id,
            &runtime.identity,
            &runtime.store,
            &runtime.settings.device_name,
        )
        .map_err(|error| error.to_string())?;
    runtime
        .trust
        .upsert(trusted.clone())
        .map_err(|error| format!("could not save trusted peer: {error}"))?;
    let outcome = PairingOutcome::accepted(&trusted);
    let _ = app.emit("peer-trust-updated", trusted);
    let _ = app.emit("pairing-complete", outcome.clone());
    Ok(outcome)
}

#[tauri::command]
fn reject_pairing(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    request_id: String,
    reason: Option<String>,
) -> Result<(), String> {
    let runtime = state
        .runtime
        .lock()
        .map_err(|_| "runtime state is unavailable".to_string())?;
    let pairing = runtime
        .pairing
        .as_ref()
        .ok_or_else(|| "pairing listener is unavailable".to_string())?;
    pairing
        .reject(
            &request_id,
            &runtime.identity,
            &runtime.store,
            &runtime.settings.device_name,
            reason.unwrap_or_else(|| "rejected by user".to_string()),
        )
        .map_err(|error| error.to_string())?;
    let _ = app.emit("pairing-rejected", request_id);
    Ok(())
}

#[tauri::command]
fn start_transfer(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    request: TransferRequest,
) -> Result<String, String> {
    let runtime = state
        .runtime
        .lock()
        .map_err(|_| "runtime state is unavailable".to_string())?;
    let transfer_id = runtime
        .start_transfer(&app, request)
        .map_err(|error| error.to_string())?;
    let _ = app.emit("transfer-started", transfer_id.clone());
    Ok(transfer_id)
}

#[tauri::command]
fn cancel_transfer(state: tauri::State<'_, AppState>, transfer_id: String) -> Result<(), String> {
    let runtime = state
        .runtime
        .lock()
        .map_err(|_| "runtime state is unavailable".to_string())?;
    runtime.cancel_transfer(&transfer_id);
    Ok(())
}

#[tauri::command]
fn cancel_recipient_transfer(
    state: tauri::State<'_, AppState>,
    transfer_id: String,
    peer_id: String,
) -> Result<(), String> {
    let runtime = state
        .runtime
        .lock()
        .map_err(|_| "runtime state is unavailable".to_string())?;
    runtime.transfer.cancel_recipient(&transfer_id, &peer_id);
    Ok(())
}

#[tauri::command]
fn revoke_trusted_peer(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    peer_id: String,
) -> Result<bool, String> {
    let runtime = state
        .runtime
        .lock()
        .map_err(|_| "runtime state is unavailable".to_string())?;
    let removed = runtime
        .trust
        .remove(&peer_id)
        .map_err(|error| format!("could not remove trusted peer: {error}"))?;
    if removed {
        let _ = app.emit("peer-trust-removed", peer_id);
    }
    Ok(removed)
}

fn app_info(runtime: &RuntimeState) -> AppInfo {
    AppInfo {
        name: "Zapdrop",
        version: APP_VERSION,
        phase: "Parallel local transfers",
        platform: std::env::consts::OS,
        local_only: true,
        device_id: runtime.identity.device_id.clone(),
        device_name: runtime.settings.device_name.clone(),
        fingerprint: runtime.identity.fingerprint.clone(),
        key_storage: runtime.identity.key_storage.clone(),
        data_directory: runtime.store.root().to_string_lossy().to_string(),
        pairing_port: runtime.pairing_port(),
        trusted_peer_count: runtime.trusted_peers().len(),
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            let runtime = RuntimeState::boot(app.handle().clone())
                .expect("failed to initialize Zapdrop runtime");
            app.manage(AppState {
                runtime: Mutex::new(runtime),
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            list_directory,
            inspect_sources,
            list_transfer_history,
            clear_transfer_history,
            list_pending_transfers,
            get_app_info,
            get_settings,
            update_settings,
            reset_identity,
            list_peers,
            get_network_diagnostics,
            scan_network,
            add_manual_endpoint,
            list_pending_pairings,
            list_trusted_peers,
            pair_with_peer,
            accept_pairing,
            reject_pairing,
            start_transfer,
            cancel_transfer,
            cancel_recipient_transfer,
            revoke_trusted_peer,
            accept_transfer,
            reject_transfer
        ])
        .run(tauri::generate_context!())
        .expect("error while running Zapdrop");
}
