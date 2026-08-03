# Hebed Proxy

Desktop privacy proxy that redacts personally identifiable information (PII) from prompts and files before they reach ChatGPT or Claude. One click to protect, one click to restore.

Built with Tauri 2 (Rust + React), a mitmproxy-based Python addon with Presidio PII detection, and Supabase for event sync and auth.

---

## Table of Contents

- [What it does](#what-it-does)
- [Architecture overview](#architecture-overview)
- [Repository layout](#repository-layout)
- [Technology stack](#technology-stack)
- [Prerequisites](#prerequisites)
- [Development](#development)
  - [Run in dev mode](#run-in-dev-mode)
  - [Build installers](#build-installers)
- [How the proxy works](#how-the-proxy-works)
  - [Text interception](#text-interception)
  - [File interception](#file-interception)
  - [The redaction pipeline](#the-redaction-pipeline)
  - [Placeholder restore](#placeholder-restore)
- [Auth flow (PKCE via hebedai.com)](#auth-flow-pkce-via-hebedaicom)
- [Event sync to Supabase](#event-sync-to-supabase)
- [Logging and data files](#logging-and-data-files)
- [Configuration reference](#configuration-reference)
- [Known quirks and pitfalls](#known-quirks-and-pitfalls)
- [Windows-specific notes](#windows-specific-notes)
- [Packaging and release](#packaging-and-release)

---

## What it does

Hebed Proxy runs a local interception proxy (mitmproxy on port 8080) and sets the Windows system proxy to route traffic through it. When a supported LLM endpoint (ChatGPT, Claude, Anthropic API, or any OpenAI-compatible `/v1/chat/completions`) is called, the addon:

1. Scans the request body for PII (emails, phone numbers, credit cards, names, URLs, bank numbers, ...).
2. Replaces each hit with a placeholder token (for example `[EMAIL_ADDRESS_000]`).
3. Forwards the redacted request to the LLM provider.
4. Restores the original values when the provider echoes the placeholder back (best effort for text).
5. Logs every redaction event (text and file scans) to local JSONL log files and optionally to Supabase.

File uploads (PDF, DOCX, images, text) attached to ChatGPT and Claude are extracted, scanned, redacted, and rebuilt when `PII_REDACT_FILES=1`.

---

## Architecture overview

```
+------------------+        +---------------------------+
|  Tauri Desktop   |        |  Python addon (mitmproxy) |
|  app (Rust core) |        |  pii_redact.py            |
|                  |        |                           |
|  React UI        |  Tauri |  request() / response()   |
|  (Vite frontend) | <----> |  intercepts LLM traffic   |
|  App.tsx         | invoke |  Presidio + regex detect  |
|  supabase.ts     |  IPC   |  writes JSONL event logs  |
+------------------+        +---------------------------+
        |  ^                        |           ^
        |  | HTTPS (PKCE)           |           | spawn / kill
        v  |                        v           |
+---------------------------+    +----------------------------+
| hebedai.com (auth + web)  |    | Rust core (lib.rs)         |
| issues Supabase session   |    | toggle_proxy / install_cert|
| tokens for desktop app    |    | get_pii_events / logs      |
+---------------------------+    +----------------------------+
                                           |
                                           v
                                 +---------------------+
                                 | Supabase            |
                                 | proxy_logs table    |
                                 | (RLS per user)      |
                                 +---------------------+
```

Data flows:

1. User signs in (PKCE via hebedai.com). The desktop app receives access/refresh tokens and stores them with `supabase.auth.setSession`.
2. User toggles the proxy ON. Rust spawns `mitmdump -s pii_redact.py --listen-port 8080` and sets the Windows system proxy to `localhost:8080`.
3. The user's browser traffic (ChatGPT, Claude, ...) is intercepted. The addon redacts PII and logs events to JSONL files.
4. The React app polls `get_pii_events` / `get_prompt_events` (Rust reads the JSONL files) and pushes new rows to Supabase `proxy_logs` (auto every 60s, on sign-in, and via the Sync logs button).

---

## Repository layout

```
proxy_mvp/
├── src/                        # React + TypeScript frontend (Vite)
│   ├── App.tsx                 # Main UI: auth screen, toggle, sidebar, notifications
│   ├── main.tsx                # Entry point; console-to-file tee; app-loaded event
│   ├── lib/
│   │   └── supabase.ts         # Supabase client, PKCE auth, event push to proxy_logs
│   └── assets/                 # App logo (hebed-logo.png)
├── src-tauri/                  # Rust core
│   ├── src/
│   │   ├── main.rs             # Entry point (windows_subsystem = "windows" in release)
│   │   └── lib.rs              # All Tauri commands, proxy lifecycle, log dir, auth server
│   ├── icons/                  # Desktop/mobile app icons
│   ├── Cargo.toml
│   └── tauri.conf.json         # App config, bundle targets, NSIS/MSI settings
├── pii_redact.py               # mitmproxy addon (the actual PII engine)
├── package.json                # Frontend deps + scripts
├── vite.config.ts              # Vite config (port 1420, dep pre-bundling)
└── tsconfig.json
```

---

## Technology stack

### Frontend
| Dependency | Version | Purpose |
|---|---|---|
| React | 19.1 | UI |
| TypeScript | 5.8 | Type safety |
| Vite | 7 | Dev server / bundler |
| @tauri-apps/api | 2 | Tauri IPC (`invoke`) |
| @tauri-apps/plugin-opener | 2 | Open browser for PKCE |
| @supabase/supabase-js | 2.57 | Supabase client + auth |

### Rust backend
| Dependency | Version | Purpose |
|---|---|---|
| tauri | 2 | App shell, IPC, windowing |
| tauri-plugin-opener | 2 | Open external URLs |
| serde / serde_json | 1 | Serialization |
| dirs | 5 | User data dir resolution |
| url | 2 | URL parsing |
| winreg (Windows) | 0.52 | System proxy registry |
| libloading (Windows) | 0.8 | WinINet proxy change broadcast |

### Python addon
| Dependency | Version | Purpose |
|---|---|---|
| mitmproxy | pip | Interception proxy framework |
| presidio-analyzer | pip | PII detection (NER + regex) |
| presidio-anonymizer | pip | Placeholder generation |
| spacy (optional) | pip | NLP models (falls back to regex-only NoOpNlpEngine) |
| PyMuPDF / python-docx / Pillow | pip | File text extraction (PDF/DOCX/image) |

The addon is pure Python and runs inside mitmdump. It shares the same Python environment as Presidio (see [Windows-specific notes](#windows-specific-notes) for the `PYTHONPATH` pitfall).

### Backend services
| Service | Role |
|---|---|
| Supabase (project `gnzcvhyxiatcjofywkdq`) | Auth + `proxy_logs` table |
| hebedai.com | Auth middleware (PKCE sign-in page) |

---

## Prerequisites

- Windows 10/11 (primary target; macOS/Linux build support exists but is not exercised)
- [Rust toolchain](https://rustup.rs) (stable, edition 2021)
- [Node.js](https://nodejs.org) 18+ and npm
- Python 3.13 with:
  - `pip install mitmproxy presidio-analyzer presidio-anonymizer`
  - `pip install PyMuPDF python-docx Pillow` (file extraction)
  - `python -m spacy download en_core_web_sm` (optional, enables NER beyond regex)
- WebView2 runtime (preinstalled on Windows 11)
- NSIS + WiX toolset (auto-downloaded by Tauri on first bundle build)

---

## Development

### Run in dev mode

```bash
npm install
npm run tauri dev
```

This starts Vite on `http://127.0.0.1:1420` and launches the Tauri app pointed at it. Rust recompiles on `src-tauri` changes; Vite hot-reloads the frontend.

First run notes:

- The proxy toggle spawns `mitmdump`. If it is not on `PATH`, install it: `winget install mitmproxy` (or `pip install mitmproxy`).
- The first toggle ON generates the mitmproxy CA certificate in `~/.mitmproxy/`. Click "Install Certificate" in the sidebar once to trust it (required for HTTPS interception).
- `PII_LOG_DIR` is set by Rust to the app log directory; the addon writes `pii_events.log`, `files.log`, `prompts.log` there.

### Build installers

```bash
npm run tauri build
```

Outputs:

- `src-tauri/target/release/proxy_mvp.exe` (portable binary)
- `src-tauri/target/release/bundle/nsis/Hebed Proxy_0.1.0_x64-setup.exe`
- `src-tauri/target/release/bundle/msi/Hebed Proxy_0.1.0_x64_en-US.msi`

---

## How the proxy works

### Text interception

`pii_redact.py` matches request URLs against `ENDPOINTS`:

- `chatgpt.com/backend-api/f/conversation`
- `chatgpt.com/backend-anon/f/conversation`
- `chatgpt.com/unauth-mweb/conversation/updates`
- `claude.ai/api/organizations/*/chat_conversations/*/completion`
- `api.anthropic.com/v1/messages`
- any `/v1/chat/completions` (OpenAI-compatible)

For matched JSON bodies, `_scan_json` walks the structure, redacts string values (the `prompt` / messages parts), and rewrites the body. Form-encoded bodies go through `_scan_form`.

### File interception

`FILE_UPLOAD_ENDPOINTS`:

- `oaiusercontent.com/files/*/raw` (ChatGPT blob PUT)
- `claude.ai/api/organizations/*/*upload-file` (Claude multipart)
- `claude.ai/api/organizations/*/convert_document`

File bytes are extracted by content type (`_extract_text`), scanned, and redacted:

- PDF: text extracted with PyMuPDF, redacted, rebuilt (`_redact_pdf`)
- DOCX: text extracted, redacted, rebuilt (`_redact_docx`)
- Images: OCR via Pillow + pytesseract if available (`_redact_image`)
- Plain text: direct redaction

File-body modification is gated by `PII_REDACT_FILES=1` (default off, best effort).

### The redaction pipeline

```
raw text
  -> presidio_analyzer.analyze(text, language)      # entity + score list
  -> custom recognizers (email, phone, credit card, ...) via _register_custom_recognizers
  -> presidio_anonymizer.anonymize(text, results)   # [TYPE_INDEX] placeholders
  -> (placeholders, count) returned
```

Recognizer behavior when spaCy models are missing: the engine falls back to a `NoOpNlpEngine` (regex-only). The self-test at startup (`_self_test`) prints detected entity counts so you can verify the engine is alive.

### Placeholder restore

`response()` intercepts provider responses and replaces placeholder tokens with the original values (best effort for text completions). This makes the model's answer readable after redaction.

---

## Auth flow (PKCE via hebedai.com)

The desktop app does not run its own Supabase OAuth. Instead:

1. `startPkceAuth()` in `supabase.ts` picks a random port in `19950..19989` and asks Rust to start a tiny local HTTP server (`start_auth_server`).
2. The app opens `https://hebedai.com/auth/signin?source=proxy&port=<port>` (or `/auth/signup`) in the default browser.
3. hebedai.com performs the Supabase PKCE flow and redirects to the local server with the session tokens.
4. Rust stores the session JSON (`get_auth_session`) and the frontend polls for it (every 500 ms, 120 s timeout).
5. On success, `supabase.auth.setSession({ access_token, refresh_token })` is called and `onAuthChange` fires; the UI switches to the main toggle screen.

Key files: `src/lib/supabase.ts` (frontend), `lib.rs` `start_auth_server` / `stop_auth_server` / `get_auth_session` (Rust).

---

## Event sync to Supabase

`proxy_logs` table (project `gnzcvhyxiatcjofywkdq`) stores two event types (`event_type` check constraint):

- `text_redact` — from `prompts.log` via `get_prompt_events`
- `file_scan` — from `files.log` via `get_pii_events`

Sync entry point: `pushProxyLogsToSupabase()` in `src/lib/supabase.ts`. It:

1. Checks the session; aborts with "Not signed in" otherwise.
2. Reads `user_id` from the session and `organization_id` from `public.users`.
3. Fetches events from Rust (`get_pii_events` / `get_prompt_events`).
4. Dedupes against existing rows (flow_id + filename/label + ts).
5. Inserts fresh rows with `supabase.from("proxy_logs").insert(rows)`.

Triggers (in `App.tsx`):

- Immediately after sign-in.
- Every 60 seconds while signed in.
- Manual "Sync logs" button in the sidebar.

RLS: `proxy_logs` INSERT policy requires `auth.uid() = user_id`, so `user_id` must always be the session user's id (`session.user.id`). The anon key is bundled in the frontend (it is a publishable key; RLS protects the data).

---

## Logging and data files

All logs live in `%LOCALAPPDATA%\com.hebed.proxy\hebed-proxy\`:

| File | Written by | Contents |
|---|---|---|
| `proxy.log` | Rust `toggle_proxy` | mitmdump stdout |
| `proxy.err` | Rust `toggle_proxy` | mitmdump stderr + addon prints |
| `console.log` | `write_console_log` (frontend tee) + `supabase_log` | App console trace |
| `pii_events.log` | addon `_log` | raw redact/restore events |
| `files.log` | addon `_log_file_event` | file scan events |
| `prompts.log` | addon `_log_prompt` | prompt redaction events (original + redacted) |

Rust resolves this via `windows_api::log_dir()` and sets `PII_LOG_DIR` to the same directory when spawning mitmdump, so the addon and the Tauri commands (`get_pii_events`, `get_prompt_events`, `get_logs`) always agree on the location. This must stay user-writable; do not move it next to the executable (Program Files installs are read-only, see Known quirks).

---

## Configuration reference

Environment variables (read by the addon):

| Variable | Default | Effect |
|---|---|---|
| `PII_LOG_DIR` | set by Rust | Directory for `pii_events.log`, `files.log`, `prompts.log` |
| `PII_REDACT_FILES` | `0` | Set to `1` to modify uploaded file bodies |
| `PII_DEBUG` | `0` | Set to `1` to dump raw request bodies |
| `PYTHONPATH` / `PYTHONHOME` | removed by Rust | Stripped when spawning mitmdump to avoid shadowing the user site-packages (Presidio) |

App config (`src-tauri/tauri.conf.json`):

- `productName`: Hebed Proxy
- `identifier`: `com.hebed.proxy`
- Window: 420x680, non-resizable
- Bundle targets: all (NSIS + MSI + icons)
- `bundle.resources`: `pii_redact.py` is bundled alongside the exe

Frontend environment (`.env` / build-time):

- `VITE_SUPABASE_ANON_KEY` — Supabase anon key (falls back to a bundled default)

---

## Known quirks and pitfalls

- **Blank window on cold start / WebView2**: do not force-kill `msedgewebview2.exe`; it corrupts the `EBWebView` profile and causes permanent blank windows. Keep the app warm instead. If the window is blank, wipe `%LOCALAPPDATA%\com.hebed.proxy\EBWebView` and restart.
- **Vite IPv6**: Vite must bind `127.0.0.1` (set in `vite.config.ts`), not `::1`; WebView2 silently fails on IPv6-only navigation.
- **Do not navigate twice in `setup()`**: re-navigating the WebView cancels the in-flight navigation and restarts WebView2 environment init (10s load becomes ~37s). A passive 30s watchdog handles genuinely stuck pages.
- **`PYTHONPATH` pollution**: if the parent process has a venv on `PYTHONPATH`, it shadows `pydantic_core` and Presidio silently dies (NoOpNlpEngine). Rust strips `PYTHONPATH`/`PYTHONHOME` when spawning mitmdump.
- **Log dir must be user-writable**: `%LOCALAPPDATA%\com.hebed.proxy\hebed-proxy`. Installing perMachine and writing next to the exe causes "Access is denied (os error 5)" on toggle. Keep `installMode: currentUser`.
- **AV false positives on NSIS installer**: unsigned NSIS installers with LZMA compression can trip Defender's ML heuristic (Wacatac.B!ml). Use `zlib` compression + publisher metadata (already configured); code-sign for production distribution.
- **WindowsApps enumeration**: `std::fs::read_dir` on `C:\Program Files\WindowsApps` hangs; use PowerShell `Get-Command` instead.
- **McAfee/F-Secure**: third-party AV can lock `.exe` files (cargo build fails to overwrite) and kill `mitmdump` child processes. Add exclusions if present.

---

## Windows-specific notes

- **System proxy**: `windows_api::set_proxy_registry` writes `ProxyEnable`/`ProxyServer` under `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings` and broadcasts the change via WinINet (`InternetSetOptionW`). The proxy is disabled on app close and at startup (crash cleanup).
- **CA certificate**: generated by mitmproxy in `~/.mitmproxy/mitmproxy-ca-cert.cer` on first proxy start. `install_cert` runs `certutil -addstore -user Root <cert>`.
- **mitmdump discovery** (`find_mitmdump`): checks `%LOCALAPPDATA%\Programs\Python\Python313\Scripts\mitmdump.exe`, then `where mitmdump`, then `%USERPROFILE%\Downloads\mitmproxy\bin\mitmdump.exe`.
- **Windows Defender scanning in dev**: new builds of `proxy_mvp.exe` can be locked briefly by Defender; retry or add a folder exclusion for `src-tauri\target`.

---

## Packaging and release

1. Bump `version` in `src-tauri/tauri.conf.json` and `package.json`.
2. `npm run tauri build` (frontend build + Rust release + NSIS/MSI bundling).
3. Tag and push: `git tag -a vX.Y.Z -m "..." && git push origin vX.Y.Z`.
4. Create a GitHub release and attach `Hebed Proxy_<ver>_x64-setup.exe` and `Hebed Proxy_<ver>_x64_en-US.msi` from `src-tauri/target/release/bundle/`.

For public distribution, sign the installer with a code-signing certificate (or Azure Trusted Signing) to avoid SmartScreen/AV heuristics, and consider submitting the binary to Microsoft WDSI for whitelisting.
