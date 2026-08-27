use serde::Serialize;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppInfo {
    pub name: &'static str,
    pub version: &'static str,
    pub phase: &'static str,
    pub platform: &'static str,
    pub local_only: bool,
}

#[tauri::command]
fn get_app_info() -> AppInfo {
    AppInfo {
        name: "Zapdrop",
        version: env!("CARGO_PKG_VERSION"),
        phase: "Desktop scaffold",
        platform: std::env::consts::OS,
        local_only: true,
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![get_app_info])
        .run(tauri::generate_context!())
        .expect("error while running Zapdrop");
}
