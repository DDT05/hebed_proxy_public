use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command};
use std::sync::{Arc, Mutex};
use std::thread;
use tauri::{Listener, Manager, State};

// ─── State ───────────────────────────────────────────────
struct ProxyState {
    child: Mutex<Option<Child>>,
    addon_path: Mutex<String>,
}

struct AuthState {
    server: Mutex<Option<thread::JoinHandle<()>>>,
    session: Arc<Mutex<Option<String>>>,
}

// ─── Windows-specific ────────────────────────────────────
#[cfg(target_os = "windows")]
mod windows_api {
    use std::path::PathBuf;
    use std::process::Command;

    pub fn broadcast_proxy_change() {
        unsafe {
            let user32 = libloading::Library::new("user32.dll").unwrap();
            let send_msg: libloading::Symbol<
                unsafe extern "system" fn(isize, u32, usize, *const u16, u32, u32, *mut u32) -> isize,
            > = user32.get(b"SendMessageTimeoutW").unwrap();
            let msg: Vec<u16> =
                "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\0"
                    .encode_utf16()
                    .collect();
            send_msg(0xFFFF, 0x001A, 0, msg.as_ptr(), 0, 200, std::ptr::null_mut());

            let wininet = libloading::Library::new("wininet.dll").unwrap();
            let set_option: libloading::Symbol<
                unsafe extern "system" fn(isize, u32, *const u8, u32) -> i32,
            > = wininet.get(b"InternetSetOptionW").unwrap();
            set_option(0, 39, std::ptr::null(), 0);
            set_option(0, 37, std::ptr::null(), 0);
        }
    }

    pub fn set_proxy_registry(enabled: bool) -> Result<(), String> {
        use winreg::enums::*;
        use winreg::RegKey;
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let (key, _disp) = hkcu
            .create_subkey(r"Software\Microsoft\Windows\CurrentVersion\Internet Settings")
            .map_err(|e| format!("Registry error: {}", e))?;
        if enabled {
            key.set_value("ProxyEnable", &1u32).map_err(|e| e.to_string())?;
            key.set_value("ProxyServer", &"localhost:8080").map_err(|e| e.to_string())?;
        } else {
            key.set_value("ProxyEnable", &0u32).map_err(|e| e.to_string())?;
        }
        broadcast_proxy_change();
        Ok(())
    }

    pub fn install_ca_cert() -> Result<String, String> {
        let cert_path = dirs::home_dir()
            .ok_or("Cannot find home directory")?
            .join(".mitmproxy") //.mitmdump?
            .join("mitmproxy-ca-cert.cer");
        if !cert_path.exists() {
            return Err(format!("CA cert not found at {}. Start proxy once to generate it.", cert_path.display()));
        }
        let output = Command::new("certutil")
            .args(["-addstore", "-user", "Root"])
            .arg(cert_path.to_str().unwrap_or(""))
            .output()
            .map_err(|e| format!("certutil failed: {}", e))?;
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }

    pub fn log_dir() -> PathBuf {
        // User-writable location under %LOCALAPPDATA% — NOT next to the exe:
        // perMachine installs place the exe under Program Files which is
        // read-only for normal users, so toggle_proxy would fail with
        // "Access is denied (os error 5)" when creating proxy.log etc.
        dirs::data_local_dir()
            .unwrap_or_else(|| dirs::data_dir().unwrap_or_else(|| PathBuf::from(".")))
            .join("com.hebed.proxy")
            .join("hebed-proxy")
    }
}

#[cfg(not(target_os = "windows"))]
mod windows_api {
    use std::path::PathBuf;
    pub fn set_proxy_registry(_: bool) -> Result<(), String> { Err("Windows-only".into()) }
    pub fn install_ca_cert() -> Result<String, String> { Err("Windows-only".into()) }
    pub fn log_dir() -> PathBuf { PathBuf::from("/tmp/hebed-proxy") }
}

// ─── Helpers ─────────────────────────────────────────────

fn resolve_addon_path(app: &tauri::AppHandle) -> String {
    // 1. Tauri bundled resource (production)
    if let Ok(res) = app.path().resource_dir() {
        let p = res.join("pii_redact.py");
        if p.exists() {
            return p.to_string_lossy().to_string();
        }
    }
    // 2. Current directory (npm run tauri dev runs from project root)
    if let Ok(cwd) = std::env::current_dir() {
        let p = cwd.join("pii_redact.py");
        if p.exists() {
            return p.to_string_lossy().to_string();
        }
    }
    // 3. Same directory as the executable (dev mode fallback)
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let p = dir.join("pii_redact.py");
            if p.exists() {
                return p.to_string_lossy().to_string();
            }
        }
    }
    // 4. Common locations
    for p in [r"C:\proxy_mvp\pii_redact.py", r"pii_redact.py"] {
        if std::path::Path::new(p).exists() {
            return p.to_string();
        }
    }
    // 5. Fallback — return current_dir path so error message is clear
    std::env::current_dir()
        .unwrap_or_default()
        .join("pii_redact.py")
        .to_string_lossy()
        .to_string()
}

fn ensure_log_dir() -> std::io::Result<PathBuf> {
    let dir = windows_api::log_dir();
    fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn find_mitmdump() -> Option<String> {
    // 1. Pip-installed mitmdump (shares Python env with Presidio)
    if let Ok(appdata) = std::env::var("APPDATA") {
        let pip = std::path::PathBuf::from(appdata)
            .join("Python").join("Python313").join("Scripts").join("mitmdump.exe");
        if pip.exists() {
            return Some(pip.to_string_lossy().to_string());
        }
    }
    // 2. Check PATH
    if let Ok(output) = Command::new("where").arg("mitmdump").output() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            let p = line.trim();
            if !p.is_empty() && std::path::Path::new(p).exists() {
                return Some(p.to_string());
            }
        }
    }
    // 3. Program Files
    for pf in &[std::env::var("ProgramFiles"), std::env::var("ProgramFiles(x86)")] {
        if let Ok(pf) = pf {
            let p = std::path::Path::new(pf)
                .join("mitmproxy").join("bin").join("mitmdump.exe");
            if p.exists() {
                return Some(p.to_string_lossy().to_string());
            }
        }
    }
    None
}

// ─── Tauri Commands ──────────────────────────────────────

#[tauri::command]
fn toggle_proxy(
    app: tauri::AppHandle,
    state: State<ProxyState>,
    on: bool,
) -> Result<String, String> {
    let mut guard = state.child.lock().map_err(|e| e.to_string())?;

    if on {
        if let Some(mut child) = guard.take() {
            let _ = child.kill();
        }

        let addon = resolve_addon_path(&app);
        *state.addon_path.lock().unwrap() = addon.clone();

        // Log file for mitmdump output
        let log_dir = ensure_log_dir().map_err(|e| e.to_string())?;
        let log_file = log_dir.join("proxy.log");
        let err_file = log_dir.join("proxy.err");

        let out = fs::File::create(&log_file).map_err(|e| e.to_string())?;
        let err = fs::File::create(&err_file).map_err(|e| e.to_string())?;

        let child = Command::new(&find_mitmdump().unwrap_or_else(|| "mitmdump".to_string()))
            .args(["--listen-port", "8080", "-s"])
            .arg(&addon)
            // Addon writes pii_events.log / files.log / prompts.log to PII_LOG_DIR.
            // MUST match windows_api::log_dir() so get_pii_events/get_prompt_events find them.
            .env("PII_LOG_DIR", &log_dir)
            // Strip PYTHONPATH/HOME: a polluted parent env (e.g. an agent venv on
            // PYTHONPATH) shadows the user site-packages that mitmdump/Presidio need
            // (pydantic_core._pydantic_core fails to load -> engine silently dead).
            .env_remove("PYTHONPATH")
            .env_remove("PYTHONHOME")
            .stdout(std::process::Stdio::from(out))
            .stderr(std::process::Stdio::from(err))
            .spawn()
            .map_err(|e| format!(
                "mitmdump not found. Install it: winget install mitmproxy\nError: {}",
                e
            ))?;

        *guard = Some(child);

        // Wait briefly and check it didn't crash immediately
        std::thread::sleep(std::time::Duration::from_millis(400));
        let check = guard.as_mut().unwrap();
        match check.try_wait() {
            Ok(Some(_status)) => {
                // Crashed — read error log
                let err_text = fs::read_to_string(&err_file).unwrap_or_default();
                *guard = None;
                return Err(format!("mitmdump crashed.\nAddon: {}\n{}", addon, err_text));
            }
            Ok(None) => {} // Still running — good
            Err(e) => return Err(format!("mitmdump status check failed: {}", e)),
        }

        windows_api::set_proxy_registry(true)?;

        Ok(format!("Proxy ON\nLog: {}", log_file.display()))
    } else {
        if let Some(mut child) = guard.take() {
            let _ = child.kill();
        }
        windows_api::set_proxy_registry(false)?;
        Ok("Proxy OFF".into())
    }
}

#[tauri::command]
fn get_proxy_status(state: State<ProxyState>) -> Result<serde_json::Value, String> {
    let mut guard = state.child.lock().map_err(|e| e.to_string())?;
    let running = match guard.as_ref() {
        Some(child) => {
            // Check if the process is still alive via OpenProcess
            let pid = child.id();
            check_process_alive(pid)
        }
        None => false,
    };

    // Watchdog: mitmdump died but registry proxy still ON → auto-disable
    // so the user regains internet instead of ERR_PROXY_CONNECTION_FAILED.
    let mut died = false;
    if !running && guard.is_some() {
        *guard = None;
        let _ = windows_api::set_proxy_registry(false);
        died = true;
    }

    Ok(serde_json::json!({
        "running": running,
        "port_listening": port_8080_listening(),
        "died": died,
        "addon": state.addon_path.lock().unwrap().clone(),
    }))
}

#[tauri::command]
fn start_auth_server(port: u16, state: State<'_, AuthState>) -> Result<(), String> {
    println!("[Rust::auth] binding to port {}", port);
    let listener = TcpListener::bind(format!("127.0.0.1:{}", port))
        .map_err(|e| format!("Cannot bind port {}: {}", port, e))?;
    listener.set_nonblocking(true).ok();
    println!("[Rust::auth] listening on 127.0.0.1:{}", port);

    let session = Arc::clone(&state.session);
    let handle = thread::spawn(move || {
        println!("[Rust::auth] thread started");
        // Listen for 2 minutes max
        let start = std::time::Instant::now();
        loop {
            if start.elapsed() > std::time::Duration::from_secs(120) {
                println!("[Rust::auth] timeout — shutting down");
                break;
            }
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let mut buf = [0u8; 4096];
                    if let Ok(n) = stream.read(&mut buf) {
                        let req = String::from_utf8_lossy(&buf[..n]);
                        if req.contains("GET /callback") {
                            println!("[Rust::auth] callback received!");
                            // Extract tokens from query string
                            let tokens: Vec<&str> = req
                                .lines()
                                .next()
                                .unwrap_or("")
                                .split(' ')
                                .nth(1)
                                .unwrap_or("")
                                .split('?')
                                .nth(1)
                                .unwrap_or("")
                                .split('&')
                                .collect();

                            let mut access_token = "";
                            let mut refresh_token = "";
                            for t in tokens {
                                if t.starts_with("access_token=") {
                                    access_token = &t[13..];  // "access_token=" = 13 chars
                                }
                                if t.starts_with("refresh_token=") {
                                    refresh_token = &t[14..];  // "refresh_token=" = 14 chars
                                }
                            }

                            if !access_token.is_empty() {
                                println!("[Rust::auth] tokens extracted — access_token len={}", access_token.len());
                                let json = format!(
                                    r#"{{"access_token":"{}","refresh_token":"{}"}}"#,
                                    access_token, refresh_token
                                );
                                *session.lock().unwrap() = Some(json);

                                // Send success response to browser
                                let _ = stream.write_all(
                                    b"HTTP/1.1 200 OK
                                    \nContent-Type: text/html
                                    \n
                                    \n\
                                    <html><body style='font-family:sans-serif;text-align:center;padding-top:80px;background:#0a0a0b;color:#e4e4e7'>\
                                    <h2>Signed in!</h2><p>Return to the HEBED Proxy.</p></body></html>"
                                );
                            }
                            break;
                        }
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(std::time::Duration::from_millis(100));
                }
                Err(_) => break,
            }
        }
    });

    *state.server.lock().unwrap() = Some(handle);
    Ok(())
}

#[tauri::command]
fn stop_auth_server(state: State<'_, AuthState>) -> Result<(), String> {
    if let Some(handle) = state.server.lock().unwrap().take() {
        // Thread will exit on its own (listener closed or timeout)
        drop(handle);
    }
    Ok(())
}

#[tauri::command]
fn get_auth_session(state: State<'_, AuthState>) -> Result<Option<String>, String> {
    let result = state.session.lock().unwrap().take();
    match &result {
        Some(json) => println!("[Rust::auth] get_auth_session -> consumed (len {})", json.len()),
        None => println!("[Rust::auth] get_auth_session -> empty (still polling)"),
    }
    Ok(result)
}

#[tauri::command]
fn get_pii_events(limit: Option<usize>) -> Result<Vec<serde_json::Value>, String> {
    let log_dir = ensure_log_dir().map_err(|e| e.to_string())?;
    let mut events = Vec::new();
    let max = limit.unwrap_or(50);

    // Read pii_events.log
    let pii_file = log_dir.join("pii_events.log");
    if pii_file.exists() {
        let content = fs::read_to_string(&pii_file).unwrap_or_default();
        for line in content.lines().rev().take(max) {
            if let Ok(ev) = serde_json::from_str::<serde_json::Value>(line.trim()) {
                events.push(ev);
            }
        }
    }

    // Read files.log
    let files_log = log_dir.join("files.log");
    if files_log.exists() {
        let content = fs::read_to_string(&files_log).unwrap_or_default();
        for line in content.lines().rev().take(max.saturating_sub(events.len())) {
            if let Ok(mut ev) = serde_json::from_str::<serde_json::Value>(line.trim()) {
                if let Some(obj) = ev.as_object_mut() {
                    obj.insert("event".into(), serde_json::Value::String("file_scan".into()));
                }
                events.push(ev);
            }
        }
    }

    Ok(events)
}

#[tauri::command]
fn get_prompt_events(limit: Option<usize>) -> Result<Vec<serde_json::Value>, String> {
    let log_dir = ensure_log_dir().map_err(|e| e.to_string())?;
    let mut events = Vec::new();
    let max = limit.unwrap_or(50);

    // Read prompts.log (intercepted + transformed prompt content, from addon's _log_prompt)
    let prompts_log = log_dir.join("prompts.log");
    if prompts_log.exists() {
        let content = fs::read_to_string(&prompts_log).unwrap_or_default();
        for line in content.lines().rev().take(max) {
            if let Ok(ev) = serde_json::from_str::<serde_json::Value>(line.trim()) {
                events.push(ev);
            }
        }
    }

    Ok(events)
}

#[tauri::command]
fn write_console_log(lines: Vec<String>) -> Result<(), String> {
    let log_dir = ensure_log_dir().map_err(|e| e.to_string())?;
    let console_file = log_dir.join("console.log");
    let mut content = fs::read_to_string(&console_file).unwrap_or_default();
    if content.len() > 1_000_000 {
        content = String::new(); // cap at ~1MB, restart on overflow
    }
    for line in lines {
        content.push_str(&line);
        content.push('\n');
    }
    fs::write(&console_file, content).map_err(|e| e.to_string())
}

// ── Supabase debug monitor ───────────────────────────────────
// Prints a message to the Rust terminal (visible in `npm run tauri dev`)
// AND appends it to hebed-proxy/console.log so the in-app "Show Logs"
// button shows the same trace. Used by supabase.ts to monitor every
// payload sent to the proxy_logs table.
#[tauri::command]
fn supabase_log(message: String) -> Result<(), String> {
    println!("[Supabase] {}", message);
    let log_dir = ensure_log_dir().map_err(|e| e.to_string())?;
    let console_file = log_dir.join("console.log");
    let mut content = fs::read_to_string(&console_file).unwrap_or_default();
    if content.len() > 1_000_000 {
        content = String::new();
    }
    content.push_str(&message);
    content.push('\n');
    fs::write(&console_file, content).map_err(|e| e.to_string())
}

#[tauri::command]
fn get_logs() -> Result<String, String> {
    let log_dir = ensure_log_dir().map_err(|e| e.to_string())?;

    // 0. WebView console capture (auth/PKCE debug trace)
    let console_file = log_dir.join("console.log");
    if console_file.exists() {
        let console = fs::read_to_string(&console_file).unwrap_or_default();
        if !console.trim().is_empty() {
            return Ok(format!("=== Console (WebView) ===\n{}", console));
        }
    }

    // 1. PII events log (structured, from addon's _log())
    let pii_file = log_dir.join("pii_events.log");
    if pii_file.exists() {
        let pii = fs::read_to_string(&pii_file).unwrap_or_default();
        if !pii.trim().is_empty() {
            return Ok(format!("=== PII Events ===\n{}", pii));
        }
    }

    // 2. Fallback: mitmdump stdout
    let log_file = log_dir.join("proxy.log");
    if log_file.exists() {
        let mut output = String::from("=== mitmdump stdout ===\n");
        let f = fs::File::open(&log_file).map_err(|e| e.to_string())?;
        for line in BufReader::new(f).lines().flatten() {
            if line.contains("[PII]") || line.contains("error") || line.contains("Error") || line.contains("listening") {
                output.push_str(&line);
                output.push('\n');
            }
        }
        if output != "=== mitmdump stdout ===\n" {
            // 3. Also check stderr
            let err_file = log_dir.join("proxy.err");
            if err_file.exists() {
                let err = fs::read_to_string(&err_file).unwrap_or_default();
                if !err.trim().is_empty() {
                    output.push_str("\n=== mitmdump stderr ===\n");
                    output.push_str(&err);
                }
            }
            return Ok(output);
        }
    }

    Ok("No PII events yet. Open ChatGPT and send a message containing an email or phone number.".into())
}

#[tauri::command]
fn install_cert() -> Result<String, String> {
    windows_api::install_ca_cert()
}

fn port_8080_listening() -> bool {
    std::net::TcpStream::connect("http://localhost:8080").is_ok()
}

#[cfg(target_os = "windows")]
fn check_process_alive(pid: u32) -> bool {
    unsafe {
        let kernel32 = match libloading::Library::new("kernel32.dll") {
            Ok(l) => l,
            Err(_) => return false,
        };
        let open: libloading::Symbol<unsafe extern "system" fn(u32, i32, u32) -> isize> =
            match kernel32.get(b"OpenProcess") {
                Ok(f) => f,
                Err(_) => return false,
            };
        let h = open(0x100000, 0, pid); // SYNCHRONIZE
        if h == 0 {
            return false; // can't open = dead
        }
        let wait: libloading::Symbol<unsafe extern "system" fn(isize, u32) -> u32> =
            match kernel32.get(b"WaitForSingleObject") {
                Ok(f) => f,
                Err(_) => return false,
            };
        let result = wait(h, 0);
        let close: libloading::Symbol<unsafe extern "system" fn(isize) -> i32> =
            kernel32.get(b"CloseHandle").unwrap();
        close(h);
        result != 0 // WAIT_OBJECT_0 = 0 = dead. Non-zero = alive.
    }
}

#[cfg(not(target_os = "windows"))]
fn check_process_alive(_pid: u32) -> bool {
    // On non-Windows, just check if we can signal the process
    // This is a best-effort fallback
    true
}

// ─── Entry Point ─────────────────────────────────────────

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .setup(|app| {
            // --prewarm mode: hide the window but keep the app + WebView2 alive.
            // Used by the login-time prewarm so the WebView2 browser process is
            // resident BEFORE the user launches dev -> dev render in ~2s instead
            // of ~37s cold boot.
            let prewarm = std::env::args().any(|a| a == "--prewarm");
            if prewarm {
                if let Some((_, win)) = app.webview_windows().into_iter().next() {
                    let _ = win.hide();
                    println!("[Rust] PREWARM mode: window hidden, WebView2 warming (browser process stays resident)");
                }
            }

            // Clean slate: disable any leftover proxy from previous crash
            #[cfg(target_os = "windows")]
            windows_api::set_proxy_registry(false).ok();

            // NOTE: we DO NOT re-navigate here. wry issues the initial navigation
            // when the window is created; calling navigate() again (especially
            // repeatedly) CANCELS the in-flight navigation and restarts WebView2's
            // environment init from scratch — turning a ~10s load into ~37s.
            // The page JS emits "app-loaded" once the module graph runs; that
            // event is used only for logging. The single 30s fallback below
            // fires ONLY if the page is genuinely stuck (never arrived), long
            // after the environment has booted, so it cannot reset anything.
            #[cfg(debug_assertions)]
            if let Some((label, win)) = app.webview_windows().into_iter().next() {
                println!("[Rust] nav-watchdog armed on window '{label}' (passive - no forced navigation)");
                let win = win.clone();
                let dev_url = app
                    .config()
                    .build
                    .dev_url
                    .as_ref()
                    .map(|u| u.to_string())
                    .unwrap_or_else(|| "http://127.0.0.1:1420".to_string());
                let (tx, rx) = std::sync::mpsc::channel::<()>();
                let _ = app.handle().listen("app-loaded", move |_| {
                    let _ = tx.send(());
                });
                std::thread::spawn(move || {
                    match rx.recv_timeout(std::time::Duration::from_secs(30)) {
                        Ok(()) => println!("[Rust] page loaded OK (app-loaded event)"),
                        Err(_) => {
                            println!("[Rust] app-loaded never fired after 30s - one-shot fallback navigate to {dev_url}");
                            if let Ok(parsed) = dev_url.parse::<url::Url>() {
                                let _ = win.navigate(parsed);
                            }
                        }
                    }
                });
            } else {
                println!("[Rust] WARN: no webview window found for nav-watchdog");
            }
            Ok(())
        })
        .on_window_event(|_window, event| {
            if let tauri::WindowEvent::Destroyed = event {
                // App closing — kill mitmdump, disable proxy
                #[cfg(target_os = "windows")]
                windows_api::set_proxy_registry(false).ok();
            }
        })
        .manage(ProxyState {
            child: Mutex::new(None),
            addon_path: Mutex::new(String::new()),
        })
        .manage(AuthState {
            server: Mutex::new(None),
            session: Arc::new(Mutex::new(None)),
        })
        .invoke_handler(tauri::generate_handler![
            toggle_proxy,
            get_proxy_status,
            get_logs,
            get_pii_events,
            get_prompt_events,
            write_console_log,
            supabase_log,
            start_auth_server,
            stop_auth_server,
            get_auth_session,
            install_cert,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}