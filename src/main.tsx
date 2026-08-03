import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";

// ── Console → file capture ──────────────────────────────────
// Tee console.log/warn/error to hebed-proxy/console.log via the
// write_console_log command, so the app's "Show Logs" button can
// display the auth/PKCE debug trace without needing DevTools.
(async () => {
  try {
    const { invoke } = await import("@tauri-apps/api/core");
    let buffer: string[] = [];
    let flushing = false;

    const flush = async () => {
      if (flushing || buffer.length === 0) return;
      flushing = true;
      const lines = buffer.splice(0, buffer.length);
      try {
        await invoke("write_console_log", { lines });
      } catch { /* dev-mode / non-tauri: ignore */ }
      flushing = false;
    };
    setInterval(flush, 1500);

    const tee = (level: string) => {
      const orig = (console as any)[level].bind(console);
      (console as any)[level] = (...args: any[]) => {
        orig(...args);
        const line = `[${new Date().toLocaleTimeString()}][${level.toUpperCase()}] ${args
          .map((a) => (typeof a === "string" ? a : safeJson(a)))
          .join(" ")}`;
        buffer.push(line);
        if (buffer.length >= 50) flush();
      };
    };
    const safeJson = (a: any) => {
      try { return JSON.stringify(a); } catch { return String(a); }
    };
    tee("log");
    tee("warn");
    tee("error");
  } catch { /* non-Tauri environment */ }
})();

ReactDOM.createRoot(document.getElementById("root") as HTMLElement).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);

// Signal the Rust nav-watchdog that the page actually loaded.
// If this never fires, lib.rs force-navigates the WebView (fixes the
// blank-window-on-cold-start where WebView2 drops the initial navigation).
(async () => {
  try {
    const { emit } = await import("@tauri-apps/api/event");
    await emit("app-loaded");
  } catch { /* non-Tauri env */ }
})();
