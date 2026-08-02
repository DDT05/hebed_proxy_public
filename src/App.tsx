import { useState, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";
import {
  startPkceAuth,
  signOut,
  getSession,
  onAuthChange,
  pushProxyLogsToSupabase,
} from "./lib/supabase";
import "./App.css";

interface ProxyStatus {
  running: boolean;
  died: boolean;
  addon: string;
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
          <div className="auth-icon">&#8645;</div>
          <h1>HEBED</h1>
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
  const [statusMsg, setStatusMsg] = useState("");
  const [logs, setLogs] = useState("");
  const [showLogs, setShowLogs] = useState(false);
  const [certInstalled, setCertInstalled] = useState(false);

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
        if (s.died) setStatusMsg("Proxy crashed — toggle ON to restart.");
      } catch { /* */ }
    };
    check();
    const interval = setInterval(check, 3000);
    return () => clearInterval(interval);
  }, [session]);

  // Auto-sync captured events (files.log / prompts.log) → Supabase proxy_logs.
  // Runs once on sign-in, then every 60s while logged in, so the workflow
  // "capture → POST proxy_logs" completes end-to-end without manual action.
  const [syncMsg, setSyncMsg] = useState("");
  const [syncing, setSyncing] = useState(false);
  const runSync = async () => {
    if (!session || syncing) return;
    setSyncing(true);
    try {
      const res = await pushProxyLogsToSupabase({ limit: 200 });
      const files = res.files.ok ? `files:${res.files.pushed}` : `files:ERR ${res.files.error}`;
      const prompts = res.prompts.ok ? `prompts:${res.prompts.pushed}` : `prompts:ERR ${res.prompts.error}`;
      console.log(`[App] sync done — ${files} | ${prompts}`);
      setSyncMsg(`Synced ${files} | ${prompts}`);
    } catch (e) {
      console.error("[App] sync error:", e);
      setSyncMsg("Sync error: " + String(e));
    } finally {
      setSyncing(false);
    }
  };
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
        setStatusMsg("Signed in as " + s.user.email);
      } else {
        console.log("[App] PKCE returned null — no session to set");
        setStatusMsg("Sign in cancelled.");
      }
    } catch (e) {
      console.error("[App] handleSignIn error:", e);
      setStatusMsg("Auth error: " + String(e));
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
        setStatusMsg("Signed up as " + s.user.email);
      } else {
        console.log("[App] PKCE returned null — no session to set");
        setStatusMsg("Sign up cancelled.");
      }
    } catch (e) {
      console.error("[App] handleSignUp error:", e);
      setStatusMsg("Auth error: " + String(e));
    } finally {
      setAuthInProgress(false);
    }
  };

  const handleToggle = async () => {
    setLoading(true);
    setStatusMsg("");
    try {
      const result = await invoke<string>("toggle_proxy", { on: !isOn });
      setIsOn(!isOn);
      setStatusMsg(result);
    } catch (err) {
      setStatusMsg(String(err));
    } finally {
      setLoading(false);
    }
  };

  const handleInstallCert = async () => {
    setStatusMsg("Installing certificate...");
    try {
      const result = await invoke<string>("install_cert");
      setCertInstalled(true);
      setStatusMsg(result);
    } catch (err) {
      setStatusMsg(String(err));
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

  console.log("[App] render: authLoading=", authLoading, "session=", !!session, "-> showing", authLoading ? "Loading" : session ? "MAIN (toggle)" : "AUTH (login)");
  if (authLoading) {
    return <div className="app"><p style={{ color: "#71717a" }}>Loading…</p></div>;
  }

  if (!session) {
    return (
      <AuthScreen
        onSignIn={handleSignIn}
        onSignUp={handleSignUp}
        loading={authInProgress}
      />
    );
  }

  return (
    <div className="app">
      <div className="top-bar">
        <span className="top-email">{session.user.email}</span>
        <button className="auth-btn small" onClick={() => signOut()}>
          Sign Out
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

      <div className="actions">
        {!isOn && !certInstalled && (
          <button className="action-btn" onClick={handleInstallCert}>
            Install Certificate (first time only)
          </button>
        )}
        <button className="action-btn" onClick={handleShowLogs}>
          {showLogs ? "Hide Logs" : "Show Logs"}
        </button>
        <button className="action-btn" onClick={runSync} disabled={syncing}>
          {syncing ? "Syncing…" : "Sync logs"}
        </button>
      </div>

      {syncMsg && (
        <div className={`toast ${syncMsg.includes("ERR") ? "error" : "success"}`}>
          {syncMsg}
        </div>
      )}

      {showLogs && (
        <div className="log-viewer">
          <pre>{logs || "No logs yet."}</pre>
        </div>
      )}

      {statusMsg && (
        <div className={`toast ${statusMsg.includes("Signed") || statusMsg.includes("ON") || statusMsg.includes("successfully") ? "success" : "error"}`}>
          {statusMsg}
        </div>
      )}
    </div>
  );
}

export default App;
