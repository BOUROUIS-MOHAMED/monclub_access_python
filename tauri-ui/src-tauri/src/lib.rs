use serde::{Deserialize, Serialize};
use std::env;
use std::sync::atomic::{AtomicU64, Ordering};
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
/// Persisted raw shortcut string for the scan action (e.g. "CTRL_SHIFT_S").
/// Saved at startup from the Python config, then re-registered inside
/// `do_register_shortcuts` so it survives every door-shortcut refresh.
struct CurrentScanShortcut(Mutex<Option<String>>);
const ACCESS_PANEL_LABEL: &str = "access-panel";
const ACCESS_PANEL_WIDTH: f64 = 428.0;
const ACCESS_PANEL_HEIGHT: f64 = 608.0;
const ACCESS_PANEL_MARGIN: f64 = 16.0;
const POPUP_LABEL: &str = "access_popup";
const SCAN_RESULT_LABEL: &str = "scan-result";
const FAVORITES_OVERLAY_LABEL: &str = "favorites-overlay";

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
    let favorites_item = MenuItemBuilder::with_id("tray_favorites", "Favoris").build(app)?;
    let popup_item = MenuItemBuilder::with_id("tray_popup", "Écran Notification").build(app)?;

    let menu = MenuBuilder::new(app)
        .item(&show_item)
        .item(&panel_item)
        .item(&favorites_item)
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

/// Open the scan-result popup in "scanning" state immediately when the shortcut
/// fires.  The popup listens for the "scan-shortcut-result" Tauri event and
/// transitions to result/error state on its own — no card param needed here.
/// 440 × 278 px matches the standard credit-card aspect ratio (1.586 : 1).
/// Destroys any previous instance first so only one is ever visible at a time.
fn show_scan_result_popup(app: &AppHandle) {
    if let Some(old) = app.get_webview_window(SCAN_RESULT_LABEL) {
        let _ = old.destroy();
    }
    match tauri::WebviewWindowBuilder::new(
        app,
        SCAN_RESULT_LABEL,
        tauri::WebviewUrl::App("/scan-result".into()),
    )
    .title("MonClub — Carte scannée")
    .inner_size(440.0, 278.0)
    .resizable(false)
    .decorations(false)
    .always_on_top(true)
    .center()
    .skip_taskbar(true)
    .build()
    {
        Ok(win) => {
            let _ = win.show();
            let _ = win.set_focus();
        }
        Err(e) => eprintln!("[scan-result] failed to open popup: {}", e),
    }
}

// ─── Favorites overlay — anchor-aware sizing and positioning ───
//
// 12 anchors: {right|left}-{top|center|bottom} and {top|bottom}-{left|center|right}.
// Vertical edges (right/left) → window is tall and narrow when collapsed,
// grows outward (away from the edge) when expanded.
// Horizontal edges (top/bottom) → window is wide and short when collapsed,
// grows perpendicular to the edge when expanded.

const FAV_MARGIN: f64 = 8.0;
// Collapsed dimension matches the handle pill's visual width (36px) so the
// window never shows a transparent strip beside the pill — that strip
// otherwise reads as a second "border" around the handle.
const FAV_VERT_COLLAPSED_W: f64 = 36.0;
const FAV_VERT_H: f64 = 400.0;
const FAV_VERT_EXPANDED_W: f64 = 320.0;
const FAV_HORZ_W: f64 = 400.0;
const FAV_HORZ_COLLAPSED_H: f64 = 36.0;
const FAV_HORZ_EXPANDED_H: f64 = 320.0;

fn fav_edge_of(anchor: &str) -> &'static str {
    if anchor.starts_with("right-") {
        "right"
    } else if anchor.starts_with("left-") {
        "left"
    } else if anchor.starts_with("top-") {
        "top"
    } else if anchor.starts_with("bottom-") {
        "bottom"
    } else {
        "right"
    }
}

/// Fetch the persisted `favorites_overlay_anchor` from Python's local API.
/// Falls back to "right-center" if the API is unreachable or the value is
/// missing/invalid. Runs on a blocking HTTP client — callers must not be
/// holding critical UI locks.
fn fetch_favorites_anchor(port: u16) -> String {
    #[derive(Deserialize)]
    struct ConfigResp {
        #[serde(default)]
        config: serde_json::Value,
    }
    let url = format!("{}/config", api_base(port));
    let anchor = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_millis(800))
        .build()
        .ok()
        .and_then(|c| c.get(&url).header("X-Local-Token", local_api_token()).send().ok())
        .and_then(|r| r.json::<ConfigResp>().ok())
        .and_then(|r| {
            r.config
                .get("favorites_overlay_anchor")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
        })
        .unwrap_or_else(|| "right-center".to_string());

    // Guard against unknown values.
    const ALLOWED: &[&str] = &[
        "right-top", "right-center", "right-bottom",
        "left-top", "left-center", "left-bottom",
        "top-left", "top-center", "top-right",
        "bottom-left", "bottom-center", "bottom-right",
    ];
    if ALLOWED.contains(&anchor.as_str()) {
        anchor
    } else {
        "right-center".to_string()
    }
}

fn favorites_overlay_size(anchor: &str, expanded: bool) -> (f64, f64) {
    match fav_edge_of(anchor) {
        "right" | "left" => {
            if expanded {
                (FAV_VERT_EXPANDED_W, FAV_VERT_H)
            } else {
                (FAV_VERT_COLLAPSED_W, FAV_VERT_H)
            }
        }
        _ => {
            if expanded {
                (FAV_HORZ_W, FAV_HORZ_EXPANDED_H)
            } else {
                (FAV_HORZ_W, FAV_HORZ_COLLAPSED_H)
            }
        }
    }
}

fn favorites_overlay_position(
    anchor: &str,
    sx: f64,
    sy: f64,
    sw: f64,
    sh: f64,
    w: f64,
    h: f64,
) -> (f64, f64) {
    let m = FAV_MARGIN;
    let (mut x, mut y) = match anchor {
        "right-top" => (sx + sw - w, sy + m),
        "right-center" => (sx + sw - w, sy + (sh - h) / 2.0),
        "right-bottom" => (sx + sw - w, sy + sh - h - m),
        "left-top" => (sx, sy + m),
        "left-center" => (sx, sy + (sh - h) / 2.0),
        "left-bottom" => (sx, sy + sh - h - m),
        "top-left" => (sx + m, sy),
        "top-center" => (sx + (sw - w) / 2.0, sy),
        "top-right" => (sx + sw - w - m, sy),
        "bottom-left" => (sx + m, sy + sh - h),
        "bottom-center" => (sx + (sw - w) / 2.0, sy + sh - h),
        "bottom-right" => (sx + sw - w - m, sy + sh - h),
        _ => (sx + sw - w, sy + (sh - h) / 2.0),
    };
    // Clamp into the work area so that a smaller-than-expected monitor or a
    // weird DPI setup can't push the window off the visible desktop.
    let max_x = sx + sw - w;
    let max_y = sy + sh - h;
    if x < sx { x = sx; }
    if y < sy { y = sy; }
    if x > max_x { x = max_x; }
    if y > max_y { y = max_y; }
    (x.round(), y.round())
}

/// Resolve the best monitor to place the overlay on. Prefers the monitor
/// the window is currently on; falls back to the primary monitor; finally
/// any available monitor. Returning None would leave the caller unable to
/// compute a sane position, which on Windows has manifested as the window
/// stuck at the default top-left corner.
fn resolve_favorites_monitor(app: &AppHandle) -> Option<tauri::Monitor> {
    if let Some(win) = app.get_webview_window(FAVORITES_OVERLAY_LABEL) {
        if let Ok(Some(m)) = win.current_monitor() {
            return Some(m);
        }
    }
    if let Ok(Some(m)) = app.primary_monitor() {
        return Some(m);
    }
    if let Ok(mut list) = app.available_monitors() {
        if !list.is_empty() {
            return Some(list.remove(0));
        }
    }
    None
}

/// Low-level layout setter. Writes size and position without hiding the
/// window first. Suitable for the initial-creation retry loop (where the
/// window is brand new and has nowhere old to "flash" from) and for places
/// that already manage their own visibility.
fn write_favorites_overlay_layout(
    app: &AppHandle,
    anchor: &str,
    expanded: bool,
) -> Result<(), String> {
    let Some(win) = app.get_webview_window(FAVORITES_OVERLAY_LABEL) else {
        return Ok(());
    };

    let monitor = resolve_favorites_monitor(app)
        .ok_or_else(|| "no monitor".to_string())?;

    let scale = monitor.scale_factor();
    let work = monitor.work_area();
    let sx = work.position.x as f64 / scale;
    let sy = work.position.y as f64 / scale;
    let sw = work.size.width as f64 / scale;
    let sh = work.size.height as f64 / scale;

    let (w, h) = favorites_overlay_size(anchor, expanded);
    let (x, y) = favorites_overlay_position(anchor, sx, sy, sw, sh, w, h);

    let size = tauri::Size::Logical(tauri::LogicalSize::new(w, h));
    let pos  = tauri::Position::Logical(tauri::LogicalPosition::new(x, y));

    win.set_size(size).map_err(|e| e.to_string())?;
    win.set_position(pos).map_err(|e| e.to_string())?;
    Ok(())
}

/// Public layout setter for anchor-change events. Cancels any in-flight
/// hover animation and briefly hides the window across the size/position
/// writes so the user never sees the half-applied intermediate state
/// (NEW size at OLD position) — that was the "flash at the ancient place"
/// the user reported when changing anchor in Settings.
fn apply_favorites_overlay_layout(
    app: &AppHandle,
    anchor: &str,
    expanded: bool,
) -> Result<(), String> {
    let Some(win) = app.get_webview_window(FAVORITES_OVERLAY_LABEL) else {
        return Ok(());
    };

    // Kill any in-flight expand/collapse animation so it can't overwrite
    // our final state with its stale interpolated values.
    FAV_ANIM_GEN.fetch_add(1, Ordering::SeqCst);

    let was_visible = win.is_visible().unwrap_or(true);
    if was_visible {
        let _ = win.hide();
    }
    let result = write_favorites_overlay_layout(app, anchor, expanded);
    if was_visible {
        let _ = win.show();
    }
    result
}

fn show_favorites_overlay_window(app: &AppHandle) -> Result<(), Box<dyn std::error::Error>> {
    // Read the persisted anchor — needed both for the first-time create (to
    // place the window correctly immediately, no top-left flash) and for
    // every re-show (the user may have changed it while the window was
    // hidden, and the previous layout may be stale or expanded).
    let port = app
        .state::<ApiPort>()
        .0
        .lock()
        .map(|p| *p)
        .unwrap_or(8788);
    let anchor = fetch_favorites_anchor(port);

    if let Some(win) = app.get_webview_window(FAVORITES_OVERLAY_LABEL) {
        if win.is_visible().unwrap_or(false) {
            let _ = win.hide();
        } else {
            // Re-show: always restore to the persisted anchor at the
            // collapsed size. Stops the window from reappearing at
            // the last (possibly-expanded) size or stale position.
            let _ = apply_favorites_overlay_layout(app, &anchor, false);
            let _ = win.show();
            let _ = win.set_focus();
        }
        return Ok(());
    }

    // First-time creation: compute the target position before build() so
    // the window never flashes at Tauri's default top-left corner.
    let monitor = resolve_favorites_monitor(app);
    let (init_w, init_h) = favorites_overlay_size(&anchor, false);
    let init_pos = monitor.map(|mon| {
        let scale = mon.scale_factor();
        let work = mon.work_area();
        let sx = work.position.x as f64 / scale;
        let sy = work.position.y as f64 / scale;
        let sw = work.size.width as f64 / scale;
        let sh = work.size.height as f64 / scale;
        favorites_overlay_position(&anchor, sx, sy, sw, sh, init_w, init_h)
    });

    let mut builder = tauri::WebviewWindowBuilder::new(
        app,
        FAVORITES_OVERLAY_LABEL,
        tauri::WebviewUrl::App("/favorites-overlay".into()),
    )
    .title("MonClub Favorites")
    .inner_size(init_w, init_h)
    .resizable(false)
    .decorations(false)
    .always_on_top(true)
    .skip_taskbar(true)
    .transparent(true)
    // `shadow(false)` disables the DWM-drawn shadow that Windows otherwise
    // paints around any borderless top-level window. Without this, the user
    // sees a faint dark rectangle outline around the transparent overlay
    // window that reads as a "second background" behind the orange pill.
    .shadow(false)
    .visible(false);
    if let Some((x, y)) = init_pos {
        builder = builder.position(x, y);
    }
    let win = builder.build()?;

    // Show the window FIRST so `current_monitor()` can resolve on the Win32
    // side, then re-apply the layout to lock in the correct logical
    // coordinates. Prior to this order we saw the window stuck at (0,0)
    // because apply_layout was called while the window was still invisible
    // and current_monitor/primary_monitor returned None on some systems.
    let _ = win.show();

    // Defer slightly so the OS has a chance to associate the HWND with its
    // monitor before we query it. Uses `write_*` (not `apply_*`) so we
    // don't hide/show the newly-created window and cause a startup flicker.
    {
        let app = app.clone();
        let anchor = anchor.clone();
        std::thread::spawn(move || {
            for delay_ms in [0_u64, 30, 90, 240] {
                if delay_ms > 0 {
                    std::thread::sleep(std::time::Duration::from_millis(delay_ms));
                }
                if write_favorites_overlay_layout(&app, &anchor, false).is_ok() {
                    break;
                }
            }
        });
    }
    Ok(())
}

#[tauri::command]
fn apply_favorites_overlay_anchor(
    app: AppHandle,
    anchor: String,
    expanded: bool,
) -> Result<(), String> {
    // Anchor changes from ConfigPage / initial mount are instant — the user
    // isn't in the middle of an animation, so snapping straight to the new
    // layout is fine (and avoids surprising the user with a slide).
    apply_favorites_overlay_layout(&app, &anchor, expanded)
}

// ── Animated expand / collapse ───────────────────────────────────────────
//
// Instant set_size() calls were the source of the "snap" the user saw on
// hover/unhover: the Rust window jumped to its final size while the CSS
// panel slide took ~280 ms. We now interpolate the window dimensions over
// ~260 ms with an ease-out-cubic curve. The CSS panel transition (≈280 ms)
// runs in parallel on the web side and both reach their destination at
// roughly the same moment.
//
// A simple generation counter lets a newer animation cancel an older one in
// flight — critical when the user sweeps the mouse in/out repeatedly.

static FAV_ANIM_GEN: AtomicU64 = AtomicU64::new(0);

const FAV_ANIM_DURATION_MS: u64 = 260;
const FAV_ANIM_FRAME_MS: u64 = 12;

fn ease_out_cubic(t: f64) -> f64 {
    let u = 1.0 - t;
    1.0 - u * u * u
}

fn animate_favorites_overlay(app: AppHandle, anchor: String, expanded: bool) {
    // Claim this animation's slot. Any previous one running in parallel
    // will see the counter advance and bail on its next frame.
    let my_gen = FAV_ANIM_GEN.fetch_add(1, Ordering::SeqCst) + 1;

    std::thread::spawn(move || {
        let Some(win) = app.get_webview_window(FAVORITES_OVERLAY_LABEL) else { return };
        let Some(monitor) = resolve_favorites_monitor(&app) else { return };

        let scale = monitor.scale_factor();
        let work = monitor.work_area();
        let sx = work.position.x as f64 / scale;
        let sy = work.position.y as f64 / scale;
        let sw_screen = work.size.width as f64 / scale;
        let sh_screen = work.size.height as f64 / scale;

        let Ok(cur_size) = win.inner_size() else { return };
        let start_w = (cur_size.width as f64) / scale;
        let start_h = (cur_size.height as f64) / scale;

        let (target_w, target_h) = favorites_overlay_size(&anchor, expanded);

        let frames = (FAV_ANIM_DURATION_MS / FAV_ANIM_FRAME_MS).max(1);

        for i in 1..=frames {
            if FAV_ANIM_GEN.load(Ordering::SeqCst) != my_gen {
                return; // a newer animation superseded this one
            }

            let t = i as f64 / frames as f64;
            let eased = ease_out_cubic(t);
            let cur_w = start_w + (target_w - start_w) * eased;
            let cur_h = start_h + (target_h - start_h) * eased;
            let (x, y) = favorites_overlay_position(
                &anchor, sx, sy, sw_screen, sh_screen, cur_w, cur_h,
            );

            let _ = win.set_size(tauri::Size::Logical(tauri::LogicalSize::new(cur_w, cur_h)));
            let _ = win.set_position(tauri::Position::Logical(tauri::LogicalPosition::new(x, y)));

            std::thread::sleep(std::time::Duration::from_millis(FAV_ANIM_FRAME_MS));
        }
        // Last frame (i == frames, eased == 1.0) already writes exact target
        // values — no post-loop snap call, which would hide/show the window
        // through apply_favorites_overlay_layout and cause a hover flicker.
    });
}

#[tauri::command]
fn expand_favorites_overlay(app: AppHandle, anchor: String) -> Result<(), String> {
    animate_favorites_overlay(app, anchor, true);
    Ok(())
}

#[tauri::command]
fn collapse_favorites_overlay(app: AppHandle, anchor: String) -> Result<(), String> {
    animate_favorites_overlay(app, anchor, false);
    Ok(())
}

// ── Global keyboard shortcuts for favorite door presets ─────────────────────
//
// The dashboard stores a per-preset shortcut like "CTRL_0" or "CTRL_SHIFT_1".
// When the user hits that combo anywhere on Windows, this handler fires the
// door-open API call and emits a Tauri event so any open window (overlay,
// main, …) can show a toast confirming the action.

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct FavoriteShortcutEntry {
    #[serde(rename = "favoriteId")]
    favorite_id: i64,
    #[serde(rename = "deviceId")]
    device_id: i64,
    #[serde(rename = "doorNumber")]
    door_number: i64,
    #[serde(rename = "pulseSeconds")]
    pulse_seconds: i64,
    #[serde(rename = "doorName")]
    door_name: String,
    #[serde(rename = "deviceName", default)]
    device_name: String,
    shortcut: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct FavoriteShortcutEvent {
    favorite_id: i64,
    door_name: String,
    device_name: String,
    shortcut: String,
    ok: bool,
    error: Option<String>,
}

// ─── Favorites API response (used for startup shortcut registration) ─────────

#[derive(Debug, Clone, Deserialize)]
struct FavoritePresetApi {
    id: i64,
    #[serde(rename = "deviceId")]
    device_id: i64,
    #[serde(rename = "doorNumber")]
    door_number: i64,
    #[serde(rename = "pulseSeconds")]
    pulse_seconds: i64,
    #[serde(rename = "doorName", default)]
    door_name: String,
    #[serde(rename = "deviceName", default)]
    device_name: String,
    #[serde(rename = "favoriteShortcut")]
    favorite_shortcut: Option<String>,
}

#[derive(Debug, Deserialize)]
struct FavoritesApiResponse {
    favorites: Vec<FavoritePresetApi>,
}

/// Convert a persisted shortcut string (e.g. "CTRL_SHIFT_0") into a Tauri
/// accelerator string the global-shortcut plugin accepts (e.g.
/// "CommandOrControl+Shift+Digit0"). Returns None if the token set doesn't
/// map to a recognised key.
///
/// The plugin uses `keyboard_types::Code` names for the key portion, not
/// raw characters — so "0" must become "Digit0", "A" must become "KeyA".
/// Using the raw characters silently fails to register and is why the
/// captured shortcut never fires.
fn parse_favorite_shortcut(raw: &str) -> Option<String> {
    let mut ctrl = false;
    let mut shift = false;
    let mut alt = false;
    let mut meta = false;
    let mut key: Option<String> = None;

    for tok in raw.split(|c: char| c == '_' || c == '+').map(|s| s.trim()) {
        if tok.is_empty() { continue; }
        let upper = tok.to_ascii_uppercase();
        match upper.as_str() {
            "CTRL" | "CONTROL" => ctrl = true,
            "SHIFT" => shift = true,
            "ALT" | "OPTION" => alt = true,
            "META" | "CMD" | "COMMAND" | "SUPER" | "WIN" => meta = true,
            // Named keys whose camelCase code names simple title-casing would mangle.
            "CAPSLOCK"   => key = Some("CapsLock".into()),
            "NUMLOCK"    => key = Some("NumLock".into()),
            "SCROLLLOCK" => key = Some("ScrollLock".into()),
            "PAGEUP"     => key = Some("PageUp".into()),
            "PAGEDOWN"   => key = Some("PageDown".into()),
            other => {
                if other.len() == 1 {
                    let c = other.chars().next().unwrap();
                    if c.is_ascii_digit() {
                        // "0" → "Digit0"
                        key = Some(format!("Digit{}", c));
                    } else if c.is_ascii_alphabetic() {
                        // "A" → "KeyA"
                        key = Some(format!("Key{}", c));
                    }
                } else if other.starts_with('F')
                    && other[1..].chars().all(|c| c.is_ascii_digit())
                {
                    // Function keys already use their plain F1..F24 code names.
                    key = Some(other.to_string());
                } else {
                    // Named keys — pass through as-is (e.g. "SPACE", "ENTER").
                    // The plugin may reject unknown names, which surfaces as
                    // "register failed" in the `skipped` array we return to JS.
                    key = Some(
                        other
                            .chars()
                            .enumerate()
                            .map(|(i, c)| if i == 0 { c } else { c.to_ascii_lowercase() })
                            .collect(),
                    );
                }
            }
        }
    }

    let key = key?;
    let mut parts = Vec::with_capacity(4);
    if ctrl  { parts.push("CommandOrControl"); }
    if shift { parts.push("Shift"); }
    if alt   { parts.push("Alt"); }
    if meta  { parts.push("Super"); }
    let joined: String = if parts.is_empty() {
        key
    } else {
        format!("{}+{}", parts.join("+"), key)
    };
    Some(joined)
}

/// If the accelerator ends with `DigitN`, also return a `NumpadN` variant so
/// shortcuts fire from both the top-row number keys and the numeric keypad.
fn numpad_variant(spec: &str) -> Option<String> {
    let key_part = match spec.rfind('+') {
        Some(pos) => &spec[pos + 1..],
        None => spec,
    };
    if key_part.starts_with("Digit") && key_part.len() == 6 && key_part.chars().last()?.is_ascii_digit() {
        let digit = &key_part[5..];
        let prefix = spec.rfind('+').map(|p| format!("{}+", &spec[..p])).unwrap_or_default();
        Some(format!("{}Numpad{}", prefix, digit))
    } else {
        None
    }
}

/// Core registration logic — called both from the Tauri command (overlay) and
/// from the startup background thread (tray-only mode).
fn do_register_shortcuts(app: &AppHandle, shortcuts: Vec<FavoriteShortcutEntry>) -> serde_json::Value {
    use tauri_plugin_global_shortcut::{GlobalShortcutExt, ShortcutState};

    eprintln!(
        "[fav-shortcuts] registering {} entries: {:?}",
        shortcuts.len(),
        shortcuts.iter().map(|e| (&e.favorite_id, &e.shortcut)).collect::<Vec<_>>()
    );

    let gs = app.global_shortcut();
    let _ = gs.unregister_all();

    let mut registered: Vec<serde_json::Value> = Vec::new();
    let mut skipped: Vec<serde_json::Value> = Vec::new();

    for entry in shortcuts {
        let Some(spec) = parse_favorite_shortcut(&entry.shortcut) else {
            skipped.push(serde_json::json!({
                "favoriteId": entry.favorite_id,
                "shortcut":   entry.shortcut,
                "reason":     "unparseable",
            }));
            continue;
        };

        // Register primary accelerator + numpad variant (if applicable).
        let mut specs = vec![spec.clone()];
        if let Some(np) = numpad_variant(&spec) {
            specs.push(np);
        }

        let mut any_ok = false;
        for sc in specs {
            let app_c = app.clone();
            let entry_c = entry.clone();
            match gs.on_shortcut(sc.as_str(), move |_app, _sc, ev| {
                if ev.state() != ShortcutState::Pressed { return; }
                let app = app_c.clone();
                let e = entry_c.clone();
                let _ = app.emit("favorite-shortcut-pressed", serde_json::json!({
                    "favoriteId": e.favorite_id,
                    "shortcut":   e.shortcut,
                }));
                std::thread::spawn(move || {
                    let port = app
                        .state::<ApiPort>()
                        .0
                        .lock()
                        .map(|p| *p)
                        .unwrap_or(8788);
                    let url = format!("{}/devices/{}/door/open", api_base(port), e.device_id);
                    let body = serde_json::json!({
                        "doorNumber":   e.door_number,
                        "pulseSeconds": e.pulse_seconds,
                    });
                    let (ok, err) = match reqwest::blocking::Client::new()
                        .post(&url)
                        .header("X-Local-Token", local_api_token())
                        .json(&body)
                        .send()
                    {
                        Ok(r) if r.status().is_success() => (true, None),
                        Ok(r) => (false, Some(format!("HTTP {}", r.status()))),
                        Err(e) => (false, Some(e.to_string())),
                    };
                    let payload = FavoriteShortcutEvent {
                        favorite_id: e.favorite_id,
                        door_name: e.door_name.clone(),
                        device_name: e.device_name.clone(),
                        shortcut: e.shortcut.clone(),
                        ok,
                        error: err,
                    };
                    let _ = app.emit("favorite-shortcut-triggered", payload);
                });
            }) {
                Ok(_) => { any_ok = true; }
                Err(e) => { eprintln!("[fav-shortcuts] failed {}: {}", sc, e); }
            }
        }

        if any_ok {
            registered.push(serde_json::json!({
                "favoriteId": entry.favorite_id,
                "shortcut":   entry.shortcut,
                "resolved":   spec,
            }));
        } else {
            skipped.push(serde_json::json!({
                "favoriteId": entry.favorite_id,
                "shortcut":   entry.shortcut,
                "reason":     "register failed",
            }));
        }
    }

    // ── Scan shortcut (re-registered after every door-shortcut refresh) ──
    // Stored in CurrentScanShortcut state; uses the same parser + numpad
    // variant logic as door shortcuts, but calls POST /api/v2/scan/quick.
    let scan_raw_opt: Option<String> = app
        .try_state::<CurrentScanShortcut>()
        .and_then(|s| s.0.lock().ok().and_then(|g| g.clone()));

    if let Some(scan_raw) = scan_raw_opt {
        if let Some(spec) = parse_favorite_shortcut(&scan_raw) {
            let mut specs = vec![spec.clone()];
            if let Some(np) = numpad_variant(&spec) {
                specs.push(np);
            }
            for sc in specs {
                let app_c = app.clone();
                let sc_raw_c = scan_raw.clone();
                eprintln!("[scan-shortcut] trying to register: {:?}", sc);
                match gs.on_shortcut(sc.as_str(), move |_app, _sc, ev| {
                    if ev.state() != ShortcutState::Pressed { return; }
                    let app = app_c.clone();
                    let sc_raw = sc_raw_c.clone();
                    // Open scanning popup immediately so the operator sees
                    // "place your card" before the HTTP request finishes.
                    show_scan_result_popup(&app);
                    let _ = app.emit("scan-shortcut-pressed", serde_json::json!({
                        "shortcut": sc_raw,
                    }));
                    // POST /scan/quick in a background thread — blocks until
                    // the card is read (or timeout).  Popup handles the result
                    // via the scan-shortcut-result event it listens for.
                    std::thread::spawn(move || {
                        let port = app
                            .state::<ApiPort>()
                            .0
                            .lock()
                            .map(|p| *p)
                            .unwrap_or(8788);
                        let url = format!("{}/scan/quick", api_base(port));
                        let (ok, card, err) = match reqwest::blocking::Client::new()
                            .post(&url)
                            .header("X-Local-Token", local_api_token())
                            .json(&serde_json::json!({}))
                            .timeout(std::time::Duration::from_secs(25))
                            .send()
                        {
                            Ok(r) if r.status().is_success() => {
                                let body: serde_json::Value = r.json().unwrap_or_default();
                                let c = body.get("card")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("")
                                    .to_string();
                                (true, c, None)
                            }
                            Ok(r) => {
                                let status = r.status().as_u16();
                                let body: serde_json::Value = r.json().unwrap_or_default();
                                let msg = body.get("error")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("scan failed")
                                    .to_string();
                                (false, String::new(), Some(format!("HTTP {}: {}", status, msg)))
                            }
                            Err(e) => (false, String::new(), Some(e.to_string())),
                        };
                        // Popup is already open (scanning state); deliver the result
                        // via event — it will transition to result/error state and
                        // auto-close. Also notifies any open overlay with a flash toast.
                        let _ = app.emit("scan-shortcut-result", serde_json::json!({
                            "ok":       ok,
                            "card":     card,
                            "error":    err,
                            "shortcut": sc_raw,
                        }));
                    });
                }) {
                    Ok(_) => eprintln!("[scan-shortcut] OK: {:?}", sc),
                    Err(e) => eprintln!("[scan-shortcut] FAILED {:?}: {}", sc, e),
                }
            }
            eprintln!("[scan-shortcut] registration done for: {}", scan_raw);
        } else {
            eprintln!("[scan-shortcut] could not parse shortcut: {:?}", scan_raw);
        }
    }

    eprintln!(
        "[fav-shortcuts] done: registered={} skipped={}",
        registered.len(), skipped.len(),
    );
    serde_json::json!({ "registered": registered, "skipped": skipped })
}

/// Fetch scan shortcut from the config API and save it to `CurrentScanShortcut` state.
///
/// GET /api/v2/config returns a flat JSON object — the fields are top-level,
/// not nested under a "config" key.
fn fetch_scan_shortcut(app: &AppHandle, port: u16) {
    let url = format!("{}/config", api_base(port));
    let sc: Option<String> = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(3))
        .build()
        .ok()
        .and_then(|c| c.get(&url).header("X-Local-Token", local_api_token()).send().ok())
        .and_then(|r| r.json::<serde_json::Value>().ok())
        .and_then(|v| {
            v.get("scan_shortcut")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
        });

    if let Ok(mut guard) = app.state::<CurrentScanShortcut>().0.lock() {
        *guard = sc.filter(|s| !s.trim().is_empty());
        eprintln!("[scan-shortcut] config fetched: {:?}", *guard);
    }
}

/// Fetch favorites from the local Python API and register shortcuts.
/// Also fetches the scan shortcut from the config so it is included in the
/// registration batch.  Returns true on success (API reachable).
fn fetch_and_register_shortcuts(app: &AppHandle, port: u16) -> bool {
    let url = format!("{}/sync/cache/favorites", api_base(port));
    let resp: FavoritesApiResponse = match reqwest::blocking::Client::new()
        .get(&url)
        .header("X-Local-Token", local_api_token())
        .timeout(std::time::Duration::from_secs(3))
        .send()
        .ok()
        .and_then(|r| if r.status().is_success() { r.json().ok() } else { None })
    {
        Some(r) => r,
        None => return false,
    };

    // Also fetch the scan shortcut so do_register_shortcuts includes it.
    fetch_scan_shortcut(app, port);

    let shortcuts: Vec<FavoriteShortcutEntry> = resp.favorites.into_iter()
        .filter_map(|f| {
            let sc = f.favorite_shortcut?.trim().to_string();
            if sc.is_empty() { return None; }
            Some(FavoriteShortcutEntry {
                favorite_id:  f.id,
                device_id:    f.device_id,
                door_number:  f.door_number,
                pulse_seconds: f.pulse_seconds,
                door_name:    f.door_name,
                device_name:  f.device_name,
                shortcut:     sc,
            })
        })
        .collect();

    eprintln!("[fav-shortcuts] startup: {} shortcuts from API", shortcuts.len());
    do_register_shortcuts(app, shortcuts);
    true
}

#[tauri::command]
fn register_favorite_shortcuts(
    app: AppHandle,
    shortcuts: Vec<FavoriteShortcutEntry>,
) -> Result<serde_json::Value, String> {
    Ok(do_register_shortcuts(&app, shortcuts))
}

#[tauri::command]
fn unregister_favorite_shortcuts(app: AppHandle) -> Result<(), String> {
    use tauri_plugin_global_shortcut::GlobalShortcutExt;
    app.global_shortcut().unregister_all().map_err(|e| e.to_string())
}

// TODO(Task 6): Register global shortcuts for favorite door presets.
// Requires adding tauri-plugin-global-shortcut to [dependencies] in Cargo.toml:
//   tauri-plugin-global-shortcut = "2"
// Then initialize with .plugin(tauri_plugin_global_shortcut::Builder::new().build())
// and implement register_favorite_shortcuts command that fetches favorites from
// the local API and binds each favoriteShortcut value via GlobalShortcutExt.

fn setup_access_tray(app: &AppHandle, tooltip: &str) -> Result<(), Box<dyn std::error::Error>> {
    let icon = desktop_window_icon("access")?;

    let show_item = MenuItemBuilder::with_id("tray_show", "Afficher").build(app)?;
    let panel_item = MenuItemBuilder::with_id("tray_panel", "Show panel").build(app)?;
    let favorites_item = MenuItemBuilder::with_id("tray_favorites", "Favoris").build(app)?;
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
        .item(&favorites_item)
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
                "tray_favorites" => {
                    let _ = show_favorites_overlay_window(&app);
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

// ─── Single-instance guard (per-role) ───

#[cfg(target_os = "windows")]
fn acquire_single_instance_lock(role: &str) -> bool {
    use std::ffi::OsStr;
    use std::iter::once;
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::{GetLastError, ERROR_ALREADY_EXISTS};
    use windows_sys::Win32::System::Threading::CreateMutexW;

    let mutex_name = format!("Local\\MonClubUI.{}", role);
    let wide: Vec<u16> = OsStr::new(&mutex_name).encode_wide().chain(once(0)).collect();
    unsafe {
        let handle = CreateMutexW(std::ptr::null(), 0, wide.as_ptr());
        if handle.is_null() {
            return true;
        }
        let last_err = GetLastError();
        if last_err == ERROR_ALREADY_EXISTS {
            return false;
        }
    }
    true
}

#[cfg(not(target_os = "windows"))]
fn acquire_single_instance_lock(_role: &str) -> bool {
    true
}

// ─── Main entry point ───

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let role = desktop_role();
    if !acquire_single_instance_lock(&role) {
        eprintln!(
            "MonClub UI ({}) is already running — exiting this duplicate instance.",
            role
        );
        return;
    }
    let initial_api_port = desktop_api_port(&role);
    let start_hidden = should_start_hidden();
    let setup_role = role.clone();
    let shell_role = role.clone();

    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_global_shortcut::Builder::new().build())
        .manage(ApiPort(Mutex::new(initial_api_port)))
        .manage(KeepBackgroundOnClose(Mutex::new(true)))
        .manage(CurrentScanShortcut(Mutex::new(None)))
        .invoke_handler(tauri::generate_handler![
            set_api_port,
            get_desktop_runtime_context,
            refresh_tray_menu,
            refresh_tv_tray_menu,
            set_keep_background_on_close,
            destroy_access_panel_window,
            focus_and_show_enrollment,
            apply_favorites_overlay_anchor,
            expand_favorites_overlay,
            collapse_favorites_overlay,
            register_favorite_shortcuts,
            unregister_favorite_shortcuts
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
            // Register shortcuts at startup so they work from the tray without
            // ever opening the favorites overlay window. Poll until the Python
            // API is ready (it may take a few seconds to start).
            if setup_role == "access" {
                let startup_handle = app.handle().clone();
                std::thread::spawn(move || {
                    for attempt in 0..20u32 {
                        if attempt > 0 {
                            std::thread::sleep(std::time::Duration::from_secs(3));
                        }
                        let port = startup_handle
                            .state::<ApiPort>()
                            .0
                            .lock()
                            .map(|p| *p)
                            .unwrap_or(8788);
                        if fetch_and_register_shortcuts(&startup_handle, port) {
                            eprintln!("[fav-shortcuts] startup done on attempt {}", attempt + 1);
                            return;
                        }
                        eprintln!("[fav-shortcuts] startup attempt {} failed, retrying…", attempt + 1);
                    }
                    eprintln!("[fav-shortcuts] startup gave up after 20 attempts");
                });
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

            if window.label() == FAVORITES_OVERLAY_LABEL {
                if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                    api.prevent_close();
                    let _ = window.hide();
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
