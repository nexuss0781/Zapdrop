mod discovery;
mod identity;
mod network;
mod settings;

use discovery::{manual_peer, NetworkDiagnostics, PeerRecord};
use network::RuntimeState;
use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use tauri::{Emitter, Manager};

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
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SettingsPatch {
    pub device_name: Option<String>,
    pub receive_directory: Option<String>,
    pub selected_interface: Option<String>,
    pub advertise_on_startup: Option<bool>,
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

fn app_info(runtime: &RuntimeState) -> AppInfo {
    AppInfo {
        name: "Zapdrop",
        version: APP_VERSION,
        phase: "Settings and discovery",
        platform: std::env::consts::OS,
        local_only: true,
        device_id: runtime.identity.device_id.clone(),
        device_name: runtime.settings.device_name.clone(),
        fingerprint: runtime.identity.fingerprint.clone(),
        key_storage: runtime.identity.key_storage.clone(),
        data_directory: runtime.store.root().to_string_lossy().to_string(),
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            let runtime = RuntimeState::boot(app.handle().clone())
                .expect("failed to initialize Zapdrop runtime");
            app.manage(AppState {
                runtime: Mutex::new(runtime),
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            get_app_info,
            get_settings,
            update_settings,
            reset_identity,
            list_peers,
            get_network_diagnostics,
            scan_network,
            add_manual_endpoint,
        ])
        .run(tauri::generate_context!())
        .expect("error while running Zapdrop");
}
