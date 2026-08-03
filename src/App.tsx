import { useState, useEffect, useCallback, useRef } from "react";
import { invoke } from "@tauri-apps/api/core";
import {
  startPkceAuth,
  signOut,
  getSession,
  onAuthChange,
  pushProxyLogsToSupabase,
} from "./lib/supabase";
import "./App.css";
import hebedLogo from "/src-tauri/icons/64x64.png";

interface ProxyStatus {
  running: boolean;
  died: boolean;
  addon: string;
}

interface Notification {
  id: number;
  msg: string;
  type: "success" | "error" | "info";
}

function AuthScreen({
  onSignIn,
  onSignUp,
  loading,
}: {
  onSignIn: () => void;
  onSignUp: () => void;
  loading: boolean;
}) {
  return (
    <div className="auth-screen">
      <div className="auth-card">
        <div className="auth-card-header">
          <img src={hebedLogo} alt="HEBED" className="auth-logo" />
          <p className="auth-sub"></p>
        </div>
        <div className="auth-card-body">
          <button className="auth-btn google" onClick={onSignIn} disabled={loading}>
            {loading ? "Opening browser…" : "Sign in"}
          </button>

          <div className="auth-divider">
            <span>Or sign up</span>
          </div>

          <button className="auth-btn submit" onClick={onSignUp} disabled={loading}>
            {loading ? "Opening browser…" : "Sign up"}
          </button>
        </div>
      </div>
    </div>
  );
}

function App() {
  const [session, setSession] = useState<any>(null);
  const [authLoading, setAuthLoading] = useState(true);
  const [authInProgress, setAuthInProgress] = useState(false);
  const [isOn, setIsOn] = useState(false);
  const [loading, setLoading] = useState(false);
  const [logs, setLogs] = useState("");
  const [showLogs, setShowLogs] = useState(false);
  const [certInstalled, setCertInstalled] = useState(false);
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [notifications, setNotifications] = useState<Notification[]>([]);
  const notifId = useRef(0);

  // ── Notifications: boxed toasts, auto-dismiss after 3s ──────
  const dismissNotif = useCallback((id: number) => {
    setNotifications((n) => n.filter((x) => x.id !== id));
  }, []);
  const notify = useCallback(
    (msg: string, type: Notification["type"] = "info") => {
      const id = ++notifId.current;
      setNotifications((n) => [...n.slice(-3), { id, msg, type }]); // keep max 4
      setTimeout(() => dismissNotif(id), 3000);
    },
    [dismissNotif]
  );

  useEffect(() => {
    console.log("[App] checking existing session...");
    getSession().then((s) => {
      console.log("[App] getSession result:", s ? s.user.email : "NONE", "| authLoading -> false");
      setSession(s);
      setAuthLoading(false);
    });
    const unsub = onAuthChange((s) => {
      console.log("[App] onAuthChange FIRED:", s ? s.user.email : "NONE");
      setSession(s);
      console.log("[App] session state updated ->", s ? "logged in" : "logged out");
    });
    return () => unsub.data.subscription.unsubscribe();
  }, []);

  useEffect(() => {
    if (!session) return;
    const check = async () => {
      try {
        const s = await invoke<ProxyStatus>("get_proxy_status");
        setIsOn(s.running);
        if (s.died) notify("Proxy crashed — toggle ON to restart.", "error");
      } catch { /* */ }
    };
    check();
    const interval = setInterval(check, 3000);
    return () => clearInterval(interval);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [session]);

  // Auto-sync captured events (files.log / prompts.log) → Supabase proxy_logs.
  // Runs once on sign-in, then every 60s while logged in, so the workflow
  // "capture → POST proxy_logs" completes end-to-end without manual action.
  const [syncing, setSyncing] = useState(false);
  const runSync = useCallback(async () => {
    if (!session || syncing) return;
    setSyncing(true);
    try {
      const res = await pushProxyLogsToSupabase({ limit: 200 });
      const files = res.files.ok ? `files:${res.files.pushed}` : `files:ERR ${res.files.error}`;
      const prompts = res.prompts.ok ? `prompts:${res.prompts.pushed}` : `prompts:ERR ${res.prompts.error}`;
      console.log(`[App] sync done — ${files} | ${prompts}`);
      notify(`Synced ${files} | ${prompts}`, res.files.ok && res.prompts.ok ? "success" : "error");
    } catch (e) {
      console.error("[App] sync error:", e);
      notify("Sync error: " + String(e), "error");
    } finally {
      setSyncing(false);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [session, syncing, notify]);

  useEffect(() => {
    if (!session) return;
    runSync();
    const interval = setInterval(runSync, 60000);
    return () => clearInterval(interval);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [session]);

  const handleSignIn = async () => {
    console.log("[App] handleSignIn — starting PKCE flow...");
    setAuthInProgress(true);
    try {
      const s = await startPkceAuth("/auth/signin");
      console.log("[App] PKCE result:", s ? "session OK: " + s.user.email : "NULL");
      if (s) {
        setSession(s); // direct state update — guarantees toggle screen appears
        console.log("[App] setSession called directly with:", s.user.email);
        notify("Signed in as " + s.user.email, "success");
      } else {
        console.log("[App] PKCE returned null — no session to set");
        notify("Sign in cancelled.", "info");
      }
    } catch (e) {
      console.error("[App] handleSignIn error:", e);
      notify("Auth error: " + String(e), "error");
    } finally {
      setAuthInProgress(false);
    }
  };

  const handleSignUp = async () => {
    console.log("[App] handleSignUp — starting PKCE flow...");
    setAuthInProgress(true);
    try {
      const s = await startPkceAuth("/auth/signup");
      console.log("[App] PKCE result:", s ? "session OK: " + s.user.email : "NULL");
      if (s) {
        setSession(s); // direct state update — guarantees toggle screen appears
        console.log("[App] setSession called directly with:", s.user.email);
        notify("Signed up as " + s.user.email, "success");
      } else {
        console.log("[App] PKCE returned null — no session to set");
        notify("Sign up cancelled.", "info");
      }
    } catch (e) {
      console.error("[App] handleSignUp error:", e);
      notify("Auth error: " + String(e), "error");
    } finally {
      setAuthInProgress(false);
    }
  };

  const handleToggle = async () => {
    setLoading(true);
    try {
      const result = await invoke<string>("toggle_proxy", { on: !isOn });
      setIsOn(!isOn);
      notify(result, !isOn ? "success" : "info");
    } catch (err) {
      notify(String(err), "error");
    } finally {
      setLoading(false);
    }
  };

  const handleInstallCert = async () => {
    notify("Installing certificate...", "info");
    try {
      const result = await invoke<string>("install_cert");
      setCertInstalled(true);
      notify(result, "success");
    } catch (err) {
      notify(String(err), "error");
    }
  };

  const handleShowLogs = async () => {
    try {
      const result = await invoke<string>("get_logs");
      setLogs(result);
      setShowLogs(!showLogs);
    } catch (err) {
      setLogs(String(err));
      setShowLogs(true);
    }
  };

  const handleSignOut = async () => {
    setSidebarOpen(false);
    try {
      await signOut();
      notify("Signed out.", "info");
    } catch (e) {
      notify("Sign out error: " + String(e), "error");
    }
  };

  console.log("[App] render: authLoading=", authLoading, "session=", !!session, "-> showing", authLoading ? "Loading" : session ? "MAIN (toggle)" : "AUTH (login)");
  if (authLoading) {
    return <div className="app"><p style={{ color: "#71717a" }}>Loading…</p></div>;
  }

  if (!session) {
    return (
      <>
        <AuthScreen
          onSignIn={handleSignIn}
          onSignUp={handleSignUp}
          loading={authInProgress}
        />
        <NotificationStack notifications={notifications} onDismiss={dismissNotif} />
      </>
    );
  }

  return (
    <div className="app">
      <div className="top-bar">
        <button className="hamburger" onClick={() => setSidebarOpen(true)} aria-label="Menu">
          ≡
        </button>
      </div>

      <div className="status-bar">
        <div className="dot" data-active={isOn} />
        <span>{isOn ? "Protected" : "Off"}</span>
      </div>

      <div className="hero">
        <h1 className="title">
          <span className="dim">Tap to HEBED</span>
        </h1>
      </div>

      <button
        className={`shazam ${isOn ? "active" : ""} ${loading ? "loading" : ""}`}
        onClick={handleToggle}
        disabled={loading}
      >
        <div className="shazam-inner">
          <span className="icon">{isOn ? "■" : "●"}</span>
        </div>
      </button>

      {showLogs && (
        <div className="log-viewer">
          <pre>{logs || "No logs yet."}</pre>
        </div>
      )}

      {/* Sidebar (≡ menu): user, sign out, secondary actions */}
      {sidebarOpen && (
        <>
          <div className="sidebar-overlay" onClick={() => setSidebarOpen(false)} />
          <div className="sidebar">
            <div className="sidebar-header">
              <span className="sidebar-title">Settings</span>
              <button className="sidebar-close" onClick={() => setSidebarOpen(false)} aria-label="Close">
                ×
              </button>
            </div>
            <div className="sidebar-user">
              <div className="sidebar-email">{session.user.email}</div>
            </div>
            <div className="sidebar-actions">
              {!certInstalled && (
                <button className="action-btn" onClick={handleInstallCert}>
                  Install Certificate
                </button>
              )}
              <button className="action-btn" onClick={handleShowLogs}>
                {showLogs ? "Hide Logs" : "Show Logs"}
              </button>
              <button className="action-btn" onClick={runSync} disabled={syncing}>
                {syncing ? "Syncing…" : "Sync logs"}
              </button>
              <button className="action-btn danger" onClick={handleSignOut}>
                Sign Out
              </button>
            </div>
          </div>
        </>
      )}

      <NotificationStack notifications={notifications} onDismiss={dismissNotif} />
    </div>
  );
}

function NotificationStack({
  notifications,
  onDismiss,
}: {
  notifications: Notification[];
  onDismiss: (id: number) => void;
}) {
  if (notifications.length === 0) return null;
  return (
    <div className="notification-stack">
      {notifications.map((n) => (
        <div key={n.id} className={`notification ${n.type}`}>
          <span className="notification-msg">{n.msg}</span>
          <button className="notification-close" onClick={() => onDismiss(n.id)} aria-label="Dismiss">
            ×
          </button>
        </div>
      ))}
    </div>
  );
}

export default App;
