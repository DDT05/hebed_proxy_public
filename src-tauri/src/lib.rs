use std::path::PathBuf;
use std::process::{Child, Command};
use std::sync::Mutex;
use tauri::State;

// -- type aliases for readability --
type WinBool = i32;
type WinHandle = isize;
type WinDword = u32;
type WinLparam = isize;
type WinWparam = usize;
type WinResult = isize;

struct ProxyState {
    child: Mutex<Option<Child>>,
    addon_path: String,
}

#[tauri::command]
fn toggle_proxy(state: State<ProxyState>) -> Result<String, String> {
    let mut guard = state.child.lock().map_err(|e| e.to_string())?;

    if guard.is_some() {
        let mut child = guard.take().unwrap();
        child.kill().map_err(|e| format!("Failed to kill: {}", e))?;
        child.wait().ok();
        set_system_proxy(false)?;
        Ok("Proxy OFF".to_string())
    } else {
        let addon = &state.addon_path;
        let log_dir = log_dir();
        std::fs::create_dir_all(&log_dir).ok();

        let child = Command::new("mitmdump")
            .args([
                "-s", addon,
                "-p", "8080",
                "--set", &format!("log_dir={}", log_dir.display()),
            ])
            .spawn()
            .map_err(|e| format!("Failed to start mitmdump: {}", e))?;

        std::thread::sleep(std::time::Duration::from_millis(1500));
        let crashed = check_process_alive(child.id());

        if crashed {
            set_system_proxy(false)?;
            let log_path = log_dir.join("proxy.log");
            let stderr = std::fs::read_to_string(&log_path).unwrap_or_default();
            return Err(format!(
                "mitmdump crashed after start.\nCheck: {}",
                stderr.lines().last().unwrap_or("no output")
            ));
        }

        *guard = Some(child);
        set_system_proxy(true)?;
        Ok(format!(
            "Proxy ON — logs at {}",
            log_dir.join("proxy.log").display()
        ))
    }
}

#[tauri::command]
fn install_cert() -> Result<String, String> {
    let cmd = Command::new("certutil")
        .args([
            "-user",
            "-addstore",
            "Root",
            cert_path().to_str().unwrap_or("mitmproxy-ca-cert.cer"),
        ])
        .output()
        .map_err(|e| format!("certutil failed: {}", e))?;

    if cmd.status.success() {
        Ok("Certificate installed".to_string())
    } else {
        let stderr = String::from_utf8_lossy(&cmd.stderr);
        Err(format!("certutil error: {}", stderr))
    }
}

#[tauri::command]
fn get_status(state: State<ProxyState>) -> Result<String, String> {
    let guard = state.child.lock().map_err(|e| e.to_string())?;
    if guard.is_some() {
        let listening = is_port_listening(8080);
        let log_path = log_dir().join("proxy.log");
        if listening {
            Ok(format!("Proxy ON — {}", log_path.display()))
        } else {
            Ok("Proxy ON (process alive but port not responding)".to_string())
        }
    } else {
        Ok("Proxy OFF".to_string())
    }
}

#[tauri::command]
fn show_logs() -> Result<String, String> {
    let path = log_dir().join("pii_events.log");
    let content = std::fs::read_to_string(&path).unwrap_or_default();
    if content.is_empty() {
        return Ok("No PII events yet. Browse ChatGPT/Claude and try again.".to_string());
    }
    Ok(content)
}


// ── helpers ──

fn cert_path() -> PathBuf {
    dirs().join("mitmproxy").join("mitmproxy-ca-cert.cer")
}

fn dirs() -> PathBuf {
    let base = std::env::var("USERPROFILE")
        .map(PathBuf::from)
.unwrap_or_else(|_| PathBuf::from("."));
    base.join(".mitmproxy")
}

fn log_dir() -> PathBuf {
    let local = std::env::var("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."));
    local.join("hebed-proxy")
}

fn set_system_proxy(enable: bool) -> Result<(), String> {
    // Registry
    let hkcu = winreg::RegKey::predef(winreg::enums::HKEY_CURRENT_USER);
    let (key, _) = hkcu
        .create_subkey(r"Software\Microsoft\Windows\CurrentVersion\Internet Settings")
        .map_err(|e| e.to_string())?;

    if enable {
        key.set_value("ProxyEnable", &1u32).map_err(|e| e.to_string())?;
        key.set_value("ProxyServer", &"127.0.0.1:8080")
            .map_err(|e| e.to_string())?;
    } else {
        key.set_value("ProxyEnable", &0u32).map_err(|e| e.to_string())?;
        key.delete_value("ProxyServer").ok();
    }

    // Broadcast via InternetSetOptionW
    unsafe {
        let lib = libloading::Library::new("wininet.dll").map_err(|e| e.to_string())?;

        type InternetSetOptionFn = unsafe extern "system" fn(
            *const u16,
            WinDword,
            *const u16,
            WinDword,
        ) -> WinBool;

        let func: libloading::Symbol<InternetSetOptionFn> =
            lib.get(b"InternetSetOptionW").map_err(|e| e.to_string())?;

        let null_wide: *const u16 = std::ptr::null();
        func(null_wide, 39, null_wide, 0); // INTERNET_OPTION_SETTINGS_CHANGED
        func(null_wide, 37, null_wide, 0); // INTERNET_OPTION_REFRESH
    }

    // Broadcast WM_SETTINGCHANGE
    unsafe {
        let lib = libloading::Library::new("user32.dll").map_err(|e| e.to_string())?;

        type SendMessageTimeoutFn = unsafe extern "system" fn(
            WinHandle,
            WinDword,
            WinWparam,
            *const u16,
        ) -> WinResult;

        let func: libloading::Symbol<SendMessageTimeoutFn> =
            lib.get(b"SendMessageTimeoutW").map_err(|e| e.to_string())?;

        let env: Vec<u16> = "Environment\0".encode_utf16().collect();
        func(0xFFFF, 0x001A, 0, env.as_ptr());
    }

    Ok(())
}

fn check_process_alive(pid: u32) -> bool {
    // Returns true if the process has already died
    unsafe {
        let lib = match libloading::Library::new("kernel32.dll") {
            Ok(l) => l,
            Err(_) => return true,
        };

        type OpenProcessFn =
            unsafe extern "system" fn(WinDword, WinBool, WinDword) -> WinHandle;

        let open: libloading::Symbol<OpenProcessFn> =
            match lib.get(b"OpenProcess") {
                Ok(f) => f,
                Err(_) => return false,
            };

        let h = open(0x100000, 0, pid); // SYNCHRONIZE
        if h == 0 {
            return true;
        }

        type WaitForSingleObjectFn =
            unsafe extern "system" fn(WinHandle, WinDword) -> WinDword;

        let wait: libloading::Symbol<WaitForSingleObjectFn> =
            match lib.get(b"WaitForSingleObject") {
                Ok(f) => f,
                Err(_) => return false,
            };

        let result = wait(h, 0);

        type CloseHandleFn = unsafe extern "system" fn(WinHandle) -> WinBool;
        let close: libloading::Symbol<CloseHandleFn> =
            lib.get(b"CloseHandle").unwrap();
        close(h);

        result == 0 // WAIT_OBJECT_0 = dead
    }
}

fn is_port_listening(port: u16) -> bool {
    std::net::TcpStream::connect_timeout(
        &format!("127.0.0.1:{}", port).parse().unwrap(),
        std::time::Duration::from_millis(500),
    )
    .is_ok()
}

// ── main ──

pub fn run() {
    let addon_path = std::env::current_dir()
        .unwrap_or_default()
        .join("pii_redact.py");

    tauri::Builder::default()
        .manage(ProxyState {
            child: Mutex::new(None),
            addon_path: addon_path.to_string_lossy().to_string(),
        })
        .invoke_handler(tauri::generate_handler![
            toggle_proxy,
            install_cert,
            get_status,
            show_logs,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}


