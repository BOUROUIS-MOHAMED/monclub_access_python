use serde::{Deserialize, Serialize};
use std::env;
use std::sync::Mutex;
use tauri::{
    image::Image,
    menu::{MenuBuilder, MenuItemBuilder, SubmenuBuilder},
    tray::TrayIconBuilder,
    AppHandle, Manager,
};

// ─── Types for devices/presets from Python API ───

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DoorPreset {
    id: i64,
    #[serde(rename = "deviceId")]
    device_id: i64,
    #[serde(rename = "doorNumber")]
    door_number: i64,
    #[serde(rename = "pulseSeconds")]
    pulse_seconds: i64,
    #[serde(rename = "doorName")]
    door_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DeviceInfo {
    id: i64,
    name: Option<String>,
    #[serde(rename = "ipAddress", default)]
    ip_address: Option<String>,
    #[serde(rename = "accessDataMode", default)]
    access_data_mode: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DevicesResponse {
    devices: Vec<DeviceInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PresetsResponse {
    presets: Vec<DoorPreset>,
}

// ─── State ───

struct ApiPort(Mutex<u16>);

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct DesktopRuntimeContext {
    role: String,
    api_port: u16,
    product_name: String,
    tray_enabled: bool,
}

fn desktop_role() -> String {
    match env::var("MONCLUB_DESKTOP_ROLE")
        .unwrap_or_else(|_| "access".into())
        .trim()
        .to_lowercase()
        .as_str()
    {
        "tv" => "tv".into(),
        _ => "access".into(),
    }
}

fn default_api_port(role: &str) -> u16 {
    if role == "tv" { 8789 } else { 8788 }
}

fn desktop_api_port(role: &str) -> u16 {
    env::var("MONCLUB_LOCAL_API_PORT")
        .ok()
        .and_then(|raw| raw.trim().parse::<u16>().ok())
        .filter(|port| *port > 0)
        .unwrap_or_else(|| default_api_port(role))
}

fn desktop_product_name(role: &str) -> &'static str {
    if role == "tv" { "MonClub TV" } else { "MonClub Access" }
}

fn desktop_window_icon(role: &str) -> Result<Image<'static>, Box<dyn std::error::Error>> {
    if role == "tv" {
        Ok(Image::from_bytes(include_bytes!("../icons/tv-icon.png"))?)
    } else {
        Ok(Image::from_bytes(include_bytes!("../icons/32x32.png"))?)
    }
}

fn api_base(port: u16) -> String {
    format!("http://127.0.0.1:{}/api/v2", port)
}

// ─── HTTP helpers (blocking, runs on separate thread) ───

fn fetch_devices(port: u16) -> Vec<DeviceInfo> {
    let url = format!("{}/sync/cache/devices", api_base(port));
    reqwest::blocking::get(&url)
        .ok()
        .and_then(|r| r.json::<DevicesResponse>().ok())
        .map(|r| r.devices)
        .unwrap_or_default()
}

fn fetch_presets(port: u16, device_id: i64) -> Vec<DoorPreset> {
    let url = format!("{}/devices/{}/door-presets", api_base(port), device_id);
    reqwest::blocking::get(&url)
        .ok()
        .and_then(|r| r.json::<PresetsResponse>().ok())
        .map(|r| r.presets)
        .unwrap_or_default()
}

fn post_open_door(port: u16, device_id: i64, door_number: i64, pulse_seconds: i64) {
    let url = format!("{}/devices/{}/door/open", api_base(port), device_id);
    let body = serde_json::json!({
        "doorNumber": door_number,
        "pulseSeconds": pulse_seconds,
    });
    let _ = reqwest::blocking::Client::new().post(&url).json(&body).send();
}

fn post_sync_now(port: u16) {
    let url = format!("{}/sync/now", api_base(port));
    let _ = reqwest::blocking::Client::new()
        .post(&url)
        .json(&serde_json::json!({}))
        .send();
}

fn post_app_quit(port: u16) {
    let url = format!("{}/app/quit", api_base(port));
    let _ = reqwest::blocking::Client::new()
        .post(&url)
        .json(&serde_json::json!({}))
        .send();
}

fn post_tv_app_quit(port: u16) {
    let url = format!("{}/tv/app/quit", api_base(port));
    let _ = reqwest::blocking::Client::new()
        .post(&url)
        .json(&serde_json::json!({}))
        .send();
}

// ─── Tauri commands (callable from JS) ───

#[tauri::command]
fn set_api_port(state: tauri::State<'_, ApiPort>, port: u16) {
    let mut p = state.0.lock().unwrap();
    *p = port;
}

#[tauri::command]
fn get_desktop_runtime_context(state: tauri::State<'_, ApiPort>) -> DesktopRuntimeContext {
    let role = desktop_role();
    let api_port = state
        .0
        .lock()
        .map(|p| *p)
        .unwrap_or_else(|_| default_api_port(&role));
    DesktopRuntimeContext {
        role: role.clone(),
        api_port,
        product_name: desktop_product_name(&role).into(),
        tray_enabled: role == "access",
    }
}

#[tauri::command]
fn refresh_tray_menu(app: AppHandle, state: tauri::State<'_, ApiPort>) -> Result<(), String> {
    if desktop_role() != "access" {
        return Ok(());
    }
    let port = *state.0.lock().unwrap();
    let app_clone = app.clone();

    // Fetch data on a thread to not block the main thread
    std::thread::spawn(move || {
        let devices = fetch_devices(port);
        let _ = rebuild_tray_menu(&app_clone, port, &devices);
    });

    Ok(())
}

fn rebuild_tray_menu(
    app: &AppHandle,
    port: u16,
    devices: &[DeviceInfo],
) -> Result<(), Box<dyn std::error::Error>> {
    // ── Show ──
    let show_item = MenuItemBuilder::with_id("tray_show", "Afficher").build(app)?;
    // ── Sync Now ──
    let sync_item = MenuItemBuilder::with_id("tray_sync", "Synchroniser").build(app)?;

    // ── Open submenu (devices → presets) ──
    let mut open_sub = SubmenuBuilder::with_id(app, "tray_open", "Ouvrir porte");

    if devices.is_empty() {
        let no_dev = MenuItemBuilder::with_id("tray_no_devices", "Aucun appareil")
            .enabled(false)
            .build(app)?;
        open_sub = open_sub.item(&no_dev);
    } else {
        for dev in devices {
            let dev_name = dev
                .name
                .as_deref()
                .unwrap_or("Appareil");
            let dev_label = format!(
                "[{}] {}{}",
                dev.id,
                dev_name,
                dev.ip_address
                    .as_deref()
                    .map(|ip| format!(" ({})", ip))
                    .unwrap_or_default()
            );

            let presets = fetch_presets(port, dev.id);

            if presets.is_empty() {
                // No presets → single disabled item
                let item_id = format!("tray_dev_{}_nopreset", dev.id);
                let item = MenuItemBuilder::with_id(item_id, format!("{} — aucun preset", dev_label))
                    .enabled(false)
                    .build(app)?;
                open_sub = open_sub.item(&item);
            } else {
                // Device submenu with presets
                let mut dev_sub = SubmenuBuilder::with_id(app, format!("tray_dev_{}", dev.id), &dev_label);
                for preset in &presets {
                    let preset_label = format!(
                        "{} (porte #{}, {}s)",
                        preset.door_name, preset.door_number, preset.pulse_seconds
                    );
                    let item_id = format!(
                        "tray_open_{}_{}_{}",
                        dev.id, preset.door_number, preset.pulse_seconds
                    );
                    let item = MenuItemBuilder::with_id(item_id, preset_label).build(app)?;
                    dev_sub = dev_sub.item(&item);
                }
                let dev_menu = dev_sub.build()?;
                open_sub = open_sub.item(&dev_menu);
            }
        }
    }

    let open_menu = open_sub.build()?;

    // ── Separator + Quit ──
    let quit_item = MenuItemBuilder::with_id("tray_quit", "Quitter").build(app)?;

    let menu = MenuBuilder::new(app)
        .item(&show_item)
        .item(&open_menu)
        .item(&sync_item)
        .separator()
        .item(&quit_item)
        .build()?;

    // Update existing tray or ignore if not found
    if let Some(tray) = app.tray_by_id("main_tray") {
        let _ = tray.set_menu(Some(menu));
    }

    Ok(())
}

// ─── Setup tray on app start ───

fn setup_tray(app: &AppHandle, tooltip: &str) -> Result<(), Box<dyn std::error::Error>> {
    let icon = desktop_window_icon("access")?;

    let show_item = MenuItemBuilder::with_id("tray_show", "Afficher").build(app)?;
    let sync_item = MenuItemBuilder::with_id("tray_sync", "Synchroniser").build(app)?;
    let open_sub = SubmenuBuilder::with_id(app, "tray_open", "Ouvrir porte")
        .item(
            &MenuItemBuilder::with_id("tray_no_devices", "Chargement…")
                .enabled(false)
                .build(app)?,
        )
        .build()?;
    let quit_item = MenuItemBuilder::with_id("tray_quit", "Quitter").build(app)?;

    let menu = MenuBuilder::new(app)
        .item(&show_item)
        .item(&open_sub)
        .item(&sync_item)
        .separator()
        .item(&quit_item)
        .build()?;

    let app_handle = app.clone();

    TrayIconBuilder::with_id("main_tray")
        .icon(icon)
        .tooltip(tooltip)
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_menu_event(move |app, event| {
            let id = event.id().as_ref();
            let port = app
                .state::<ApiPort>()
                .0
                .lock()
                .map(|p| *p)
                .unwrap_or(8788);

            match id {
                "tray_show" => {
                    // Show & focus main window
                    if let Some(win) = app.get_webview_window("main") {
                        let _ = win.show();
                        let _ = win.unminimize();
                        let _ = win.set_focus();
                    }
                }
                "tray_sync" => {
                    let p = port;
                    std::thread::spawn(move || post_sync_now(p));
                }
                "tray_quit" => {
                    // Send quit to Python backend then exit Tauri
                    let p = port;
                    let app_clone = app.clone();
                    std::thread::spawn(move || {
                        post_app_quit(p);
                        // Small delay to let Python shutdown gracefully
                        std::thread::sleep(std::time::Duration::from_millis(500));
                        app_clone.exit(0);
                    });
                }
                _ if id.starts_with("tray_open_") => {
                    // Parse: tray_open_{deviceId}_{doorNumber}_{pulseSeconds}
                    let parts: Vec<&str> = id.strip_prefix("tray_open_").unwrap_or("").splitn(3, '_').collect();
                    if parts.len() == 3 {
                        if let (Ok(dev_id), Ok(door_num), Ok(pulse)) = (
                            parts[0].parse::<i64>(),
                            parts[1].parse::<i64>(),
                            parts[2].parse::<i64>(),
                        ) {
                            let p = port;
                            std::thread::spawn(move || post_open_door(p, dev_id, door_num, pulse));
                        }
                    }
                }
                _ => {}
            }
        })
        .on_tray_icon_event(move |tray, event| {
            if let tauri::tray::TrayIconEvent::DoubleClick { .. } = event {
                if let Some(win) = tray.app_handle().get_webview_window("main") {
                    let _ = win.show();
                    let _ = win.unminimize();
                    let _ = win.set_focus();
                }
            }
        })
        .build(&app_handle)?;

    Ok(())
}

// ─── Main entry point ───

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let role = desktop_role();
    let initial_api_port = desktop_api_port(&role);
    let setup_role = role.clone();
    let shell_role = role.clone();

    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .manage(ApiPort(Mutex::new(initial_api_port)))
        .invoke_handler(tauri::generate_handler![
            set_api_port,
            get_desktop_runtime_context,
            refresh_tray_menu
        ])
        .setup(move |app| {
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.set_title(desktop_product_name(&setup_role));
                if let Ok(icon) = desktop_window_icon(&setup_role) {
                    let _ = window.set_icon(icon);
                }
            }
            if setup_role == "access" {
                let handle = app.handle().clone();
                setup_tray(&handle, desktop_product_name(&setup_role))?;
            }
            Ok(())
        })
        .on_window_event(move |window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                if window.label() == "main" {
                    if shell_role == "access" {
                        api.prevent_close();
                        let _ = window.hide();
                    } else {
                        api.prevent_close();
                        let port = window
                            .app_handle()
                            .state::<ApiPort>()
                            .0
                            .lock()
                            .map(|p| *p)
                            .unwrap_or(8789);
                        let app_handle = window.app_handle().clone();
                        std::thread::spawn(move || {
                            post_tv_app_quit(port);
                            std::thread::sleep(std::time::Duration::from_millis(300));
                            app_handle.exit(0);
                        });
                    }
                }
            }
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
