use serde::{Deserialize, Serialize};
use std::env;
use std::sync::Mutex;
use tauri::{
    image::Image,
    menu::{MenuBuilder, MenuItemBuilder, SubmenuBuilder},
    tray::TrayIconBuilder,
    AppHandle, Emitter, Manager,
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

// ─── Types for TV screen bindings ───

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TvScreenInfo {
    id: i64,
    screen_label: String,
    #[serde(default)]
    monitor_label: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TvBindingsResponse {
    rows: Vec<TvScreenInfo>,
}

// ─── State ───

struct ApiPort(Mutex<u16>);
struct KeepBackgroundOnClose(Mutex<bool>);
const ACCESS_PANEL_LABEL: &str = "access-panel";
const ACCESS_PANEL_WIDTH: f64 = 428.0;
const ACCESS_PANEL_HEIGHT: f64 = 608.0;
const ACCESS_PANEL_MARGIN: f64 = 16.0;
const POPUP_LABEL: &str = "access_popup";

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct DesktopRuntimeContext {
    role: String,
    api_port: u16,
    product_name: String,
    tray_enabled: bool,
    /// B-001: Local API token for authenticating requests from this UI session.
    api_token: String,
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
    if role == "tv" {
        8789
    } else {
        8788
    }
}

fn desktop_api_port(role: &str) -> u16 {
    env::var("MONCLUB_LOCAL_API_PORT")
        .ok()
        .and_then(|raw| raw.trim().parse::<u16>().ok())
        .filter(|port| *port > 0)
        .unwrap_or_else(|| default_api_port(role))
}

fn desktop_product_name(role: &str) -> &'static str {
    if role == "tv" {
        "MonClub TV"
    } else {
        "MonClub Access"
    }
}

fn should_start_hidden() -> bool {
    matches!(
        env::var("MONCLUB_START_HIDDEN")
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase()
            .as_str(),
        "1" | "true" | "yes" | "on"
    )
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

fn local_api_token() -> String {
    env::var("MONCLUB_LOCAL_API_TOKEN").unwrap_or_default()
}

fn fetch_devices(port: u16) -> Vec<DeviceInfo> {
    let url = format!("{}/sync/cache/devices", api_base(port));
    reqwest::blocking::Client::new()
        .get(&url)
        .header("X-Local-Token", local_api_token())
        .send()
        .ok()
        .and_then(|r| r.json::<DevicesResponse>().ok())
        .map(|r| r.devices)
        .unwrap_or_default()
}

fn fetch_presets(port: u16, device_id: i64) -> Vec<DoorPreset> {
    let url = format!("{}/devices/{}/door-presets", api_base(port), device_id);
    reqwest::blocking::Client::new()
        .get(&url)
        .header("X-Local-Token", local_api_token())
        .send()
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
    let _ = reqwest::blocking::Client::new()
        .post(&url)
        .header("X-Local-Token", local_api_token())
        .json(&body)
        .send();
}

fn post_sync_now(port: u16) {
    let url = format!("{}/sync/now", api_base(port));
    let _ = reqwest::blocking::Client::new()
        .post(&url)
        .header("X-Local-Token", local_api_token())
        .json(&serde_json::json!({}))
        .send();
}

fn post_app_quit(port: u16) {
    let url = format!("{}/app/quit", api_base(port));
    let _ = reqwest::blocking::Client::new()
        .post(&url)
        .header("X-Local-Token", local_api_token())
        .json(&serde_json::json!({}))
        .send();
}

fn fetch_tv_bindings(port: u16) -> Vec<TvScreenInfo> {
    let url = format!("{}/tv/host/bindings", api_base(port));
    reqwest::blocking::Client::new()
        .get(&url)
        .header("X-Local-Token", local_api_token())
        .send()
        .ok()
        .and_then(|r| r.json::<TvBindingsResponse>().ok())
        .map(|r| r.rows)
        .unwrap_or_default()
}

fn post_tv_app_quit(port: u16) {
    let url = format!("{}/tv/app/quit", api_base(port));
    let _ = reqwest::blocking::Client::new()
        .post(&url)
        .header("X-Local-Token", local_api_token())
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
    let api_token = env::var("MONCLUB_LOCAL_API_TOKEN").unwrap_or_default();
    DesktopRuntimeContext {
        role: role.clone(),
        api_port,
        product_name: desktop_product_name(&role).into(),
        tray_enabled: role == "access" || role == "tv",
        api_token,
    }
}

#[tauri::command]
fn set_keep_background_on_close(state: tauri::State<'_, KeepBackgroundOnClose>, enabled: bool) {
    if let Ok(mut flag) = state.0.lock() {
        *flag = enabled;
    }
}

#[tauri::command]
fn destroy_access_panel_window(app: AppHandle) -> Result<(), String> {
    if let Some(window) = app.get_webview_window(ACCESS_PANEL_LABEL) {
        window.destroy().map_err(|err| err.to_string())?;
    }
    Ok(())
}

#[tauri::command]
fn focus_and_show_enrollment(app: AppHandle) -> Result<(), String> {
    if let Some(win) = app.get_webview_window("main") {
        let _ = win.show();
        let _ = win.unminimize();
        let _ = win.set_focus();
        win.emit("enroll-focus-requested", serde_json::Value::Null).map_err(|e: tauri::Error| e.to_string())?;
    }
    Ok(())
}

fn rebuild_tv_tray_menu(
    app: &AppHandle,
    bindings: &[TvScreenInfo],
) -> Result<(), Box<dyn std::error::Error>> {
    let show_item = MenuItemBuilder::with_id("tray_show", "Afficher").build(app)?;
    let quit_item = MenuItemBuilder::with_id("tray_quit", "Quitter").build(app)?;

    let mut msg_sub = SubmenuBuilder::with_id(app, "tray_tv_send_msg", "Envoyer un message");

    if bindings.is_empty() {
        let no_screen = MenuItemBuilder::with_id("tray_tv_msg_none", "Aucun écran")
            .enabled(false)
            .build(app)?;
        msg_sub = msg_sub.item(&no_screen);
    } else {
        for screen in bindings {
            let label = if !screen.screen_label.is_empty() {
                screen.screen_label.clone()
            } else if !screen.monitor_label.is_empty() {
                screen.monitor_label.clone()
            } else {
                format!("Écran #{}", screen.id)
            };
            let item_id = format!("tray_tv_msg_{}", screen.id);
            let item = MenuItemBuilder::with_id(item_id, &label).build(app)?;
            msg_sub = msg_sub.item(&item);
        }
    }

    let msg_menu = msg_sub.build()?;

    let menu = MenuBuilder::new(app)
        .item(&show_item)
        .item(&msg_menu)
        .separator()
        .item(&quit_item)
        .build()?;

    if let Some(tray) = app.tray_by_id("main_tray") {
        let _ = tray.set_menu(Some(menu));
    }

    Ok(())
}

#[tauri::command]
fn refresh_tv_tray_menu(app: AppHandle, state: tauri::State<'_, ApiPort>) -> Result<(), String> {
    if desktop_role() != "tv" {
        return Ok(());
    }
    let port = *state.0.lock().unwrap();
    let app_clone = app.clone();
    std::thread::spawn(move || {
        let bindings = fetch_tv_bindings(port);
        let _ = rebuild_tv_tray_menu(&app_clone, &bindings);
    });
    Ok(())
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
    // ── Scan Card ──
    let scan_item = MenuItemBuilder::with_id("tray_scan", "Scanner carte").build(app)?;

    // ── Open submenu (devices → presets) ──
    let mut open_sub = SubmenuBuilder::with_id(app, "tray_open", "Ouvrir porte");

    if devices.is_empty() {
        let no_dev = MenuItemBuilder::with_id("tray_no_devices", "Aucun appareil")
            .enabled(false)
            .build(app)?;
        open_sub = open_sub.item(&no_dev);
    } else {
        for dev in devices {
            let dev_name = dev.name.as_deref().unwrap_or("Appareil");
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
                let item =
                    MenuItemBuilder::with_id(item_id, format!("{} — aucun preset", dev_label))
                        .enabled(false)
                        .build(app)?;
                open_sub = open_sub.item(&item);
            } else {
                // Device submenu with presets
                let mut dev_sub =
                    SubmenuBuilder::with_id(app, format!("tray_dev_{}", dev.id), &dev_label);
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
    let panel_item = MenuItemBuilder::with_id("tray_panel", "Show panel").build(app)?;
    let popup_item = MenuItemBuilder::with_id("tray_popup", "Écran Notification").build(app)?;

    let menu = MenuBuilder::new(app)
        .item(&show_item)
        .item(&panel_item)
        .item(&popup_item)
        .item(&open_menu)
        .item(&sync_item)
        .item(&scan_item)
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

fn show_main_window(app: &AppHandle) {
    if let Some(win) = app.get_webview_window("main") {
        let _ = win.show();
        let _ = win.unminimize();
        let _ = win.set_focus();
    }
}

fn hide_access_panel_window(app: &AppHandle) {
    if let Some(win) = app.get_webview_window(ACCESS_PANEL_LABEL) {
        let _ = win.hide();
    }
}

fn access_panel_position(app: &AppHandle) -> Option<(f64, f64)> {
    let monitor = app
        .get_webview_window("main")
        .and_then(|window| window.current_monitor().ok().flatten())
        .or_else(|| {
            app.get_webview_window(ACCESS_PANEL_LABEL)
                .and_then(|window| window.current_monitor().ok().flatten())
        })
        .or_else(|| app.primary_monitor().ok().flatten())?;

    let work_area = monitor.work_area();
    let scale_factor = monitor.scale_factor();
    let x = (work_area.position.x as f64 / scale_factor)
        + (work_area.size.width as f64 / scale_factor)
        - ACCESS_PANEL_WIDTH
        - ACCESS_PANEL_MARGIN;
    let y = (work_area.position.y as f64 / scale_factor)
        + (work_area.size.height as f64 / scale_factor)
        - ACCESS_PANEL_HEIGHT
        - ACCESS_PANEL_MARGIN;

    Some((x.round(), y.round()))
}

fn show_access_panel_window(app: &AppHandle) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(win) = app.get_webview_window(ACCESS_PANEL_LABEL) {
        if let Some((x, y)) = access_panel_position(app) {
            let _ = win.set_position(tauri::Position::Logical(tauri::LogicalPosition::new(x, y)));
        }
        let _ = win.show();
        let _ = win.unminimize();
        let _ = win.set_focus();
        return Ok(());
    }

    let mut panel_builder = tauri::WebviewWindowBuilder::new(
        app,
        ACCESS_PANEL_LABEL,
        tauri::WebviewUrl::App("/tray-panel".into()),
    )
    .title("MonClub Access Panel")
    .inner_size(ACCESS_PANEL_WIDTH, ACCESS_PANEL_HEIGHT)
    .resizable(false)
    .decorations(false)
    .always_on_top(true)
    .skip_taskbar(true);

    if let Some((x, y)) = access_panel_position(app) {
        panel_builder = panel_builder.position(x, y);
    }

    let panel = panel_builder.build()?;

    let _ = panel.show();
    let _ = panel.set_focus();
    Ok(())
}

fn show_popup_window(app: &AppHandle) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(win) = app.get_webview_window(POPUP_LABEL) {
        let _ = win.show();
        let _ = win.unminimize();
        let _ = win.set_focus();
        return Ok(());
    }
    let win = tauri::WebviewWindowBuilder::new(
        app,
        POPUP_LABEL,
        tauri::WebviewUrl::App("/popup".into()),
    )
    .title("MonClub Access — Écran Notification")
    .inner_size(1024.0, 600.0)
    .resizable(true)
    .decorations(true)
    .always_on_top(true)
    .center()
    .build()?;
    let _ = win.show();
    let _ = win.set_focus();
    Ok(())
}

fn setup_access_tray(app: &AppHandle, tooltip: &str) -> Result<(), Box<dyn std::error::Error>> {
    let icon = desktop_window_icon("access")?;

    let show_item = MenuItemBuilder::with_id("tray_show", "Afficher").build(app)?;
    let panel_item = MenuItemBuilder::with_id("tray_panel", "Show panel").build(app)?;
    let popup_item = MenuItemBuilder::with_id("tray_popup", "Écran Notification").build(app)?;
    let sync_item = MenuItemBuilder::with_id("tray_sync", "Synchroniser").build(app)?;
    let scan_item = MenuItemBuilder::with_id("tray_scan", "Scanner carte").build(app)?;
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
        .item(&panel_item)
        .item(&popup_item)
        .item(&open_sub)
        .item(&sync_item)
        .item(&scan_item)
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
            let port = app.state::<ApiPort>().0.lock().map(|p| *p).unwrap_or(8788);

            match id {
                "tray_show" => {
                    hide_access_panel_window(&app);
                    show_main_window(&app);
                }
                "tray_panel" => {
                    let _ = show_access_panel_window(&app);
                }
                "tray_popup" => {
                    let _ = show_popup_window(&app);
                }
                "tray_sync" => {
                    let p = port;
                    std::thread::spawn(move || post_sync_now(p));
                }
                "tray_scan" => {
                    show_main_window(&app);
                    if let Some(win) = app.get_webview_window("main") {
                        let _ = win.emit("tray-scan-card", ());
                    }
                }
                "tray_quit" => {
                    let p = port;
                    let app_clone = app.clone();
                    std::thread::spawn(move || {
                        post_app_quit(p);
                        std::thread::sleep(std::time::Duration::from_millis(500));
                        app_clone.exit(0);
                    });
                }
                _ if id.starts_with("tray_open_") => {
                    let parts: Vec<&str> = id
                        .strip_prefix("tray_open_")
                        .unwrap_or("")
                        .splitn(3, '_')
                        .collect();
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
                hide_access_panel_window(&tray.app_handle());
                show_main_window(&tray.app_handle());
            }
        })
        .build(&app_handle)?;

    Ok(())
}

fn setup_tv_tray(app: &AppHandle, tooltip: &str) -> Result<(), Box<dyn std::error::Error>> {
    let icon = desktop_window_icon("tv")?;

    let show_item = MenuItemBuilder::with_id("tray_show", "Afficher").build(app)?;
    let quit_item = MenuItemBuilder::with_id("tray_quit", "Quitter").build(app)?;

    // Start with a placeholder submenu; refreshed by the frontend after boot
    let msg_placeholder = MenuItemBuilder::with_id("tray_tv_msg_none", "Chargement…")
        .enabled(false)
        .build(app)?;
    let msg_menu = SubmenuBuilder::with_id(app, "tray_tv_send_msg", "Envoyer un message")
        .item(&msg_placeholder)
        .build()?;

    let menu = MenuBuilder::new(app)
        .item(&show_item)
        .item(&msg_menu)
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
            let port = app.state::<ApiPort>().0.lock().map(|p| *p).unwrap_or(8789);

            if let Some(binding_id_str) = id.strip_prefix("tray_tv_msg_") {
                if let Ok(binding_id) = binding_id_str.parse::<i64>() {
                    let win_label = format!("tv-send-msg-{}", binding_id);
                    if let Some(existing) = app.get_webview_window(&win_label) {
                        let _ = existing.show();
                        let _ = existing.set_focus();
                    } else {
                        let url = format!("/tv-send-message?bindingId={}", binding_id);
                        let _ = tauri::WebviewWindowBuilder::new(
                            app,
                            &win_label,
                            tauri::WebviewUrl::App(url.into()),
                        )
                        .title("Envoyer un message")
                        .inner_size(460.0, 540.0)
                        .resizable(false)
                        .center()
                        .build();
                    }
                }
                return;
            }

            match id {
                "tray_show" => show_main_window(&app),
                "tray_quit" => {
                    let p = port;
                    let app_clone = app.clone();
                    std::thread::spawn(move || {
                        post_tv_app_quit(p);
                        std::thread::sleep(std::time::Duration::from_millis(300));
                        app_clone.exit(0);
                    });
                }
                _ => {}
            }
        })
        .on_tray_icon_event(move |tray, event| {
            if let tauri::tray::TrayIconEvent::DoubleClick { .. } = event {
                show_main_window(&tray.app_handle());
            }
        })
        .build(&app_handle)?;

    Ok(())
}

fn setup_tray(
    app: &AppHandle,
    role: &str,
    tooltip: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    if role == "tv" {
        setup_tv_tray(app, tooltip)
    } else {
        setup_access_tray(app, tooltip)
    }
}

// ─── Main entry point ───

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let role = desktop_role();
    let initial_api_port = desktop_api_port(&role);
    let start_hidden = should_start_hidden();
    let setup_role = role.clone();
    let shell_role = role.clone();

    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .manage(ApiPort(Mutex::new(initial_api_port)))
        .manage(KeepBackgroundOnClose(Mutex::new(true)))
        .invoke_handler(tauri::generate_handler![
            set_api_port,
            get_desktop_runtime_context,
            refresh_tray_menu,
            refresh_tv_tray_menu,
            set_keep_background_on_close,
            destroy_access_panel_window,
            focus_and_show_enrollment
        ])
        .setup(move |app| {
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.set_title(desktop_product_name(&setup_role));
                if let Ok(icon) = desktop_window_icon(&setup_role) {
                    let _ = window.set_icon(icon);
                }
            }
            let handle = app.handle().clone();
            setup_tray(&handle, &setup_role, desktop_product_name(&setup_role))?;
            if start_hidden {
                if let Some(window) = app.get_webview_window("main") {
                    let _ = window.hide();
                }
            }
            Ok(())
        })
        .on_window_event(move |window, event| {
            if window.label() == ACCESS_PANEL_LABEL {
                match event {
                    tauri::WindowEvent::CloseRequested { api, .. } => {
                        api.prevent_close();
                        let _ = window.hide();
                    }
                    tauri::WindowEvent::Focused(false) => {
                        let _ = window.hide();
                    }
                    _ => {}
                }
                return;
            }

            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                if window.label() == "main" {
                    if shell_role == "access" {
                        api.prevent_close();
                        hide_access_panel_window(&window.app_handle());
                        let _ = window.hide();
                    } else {
                        let keep_background = window
                            .app_handle()
                            .state::<KeepBackgroundOnClose>()
                            .0
                            .lock()
                            .map(|flag| *flag)
                            .unwrap_or(true);
                        if keep_background {
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
            }
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
