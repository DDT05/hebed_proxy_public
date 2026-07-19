import { useState, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";
import "./App.css";

function App() {
  const [isOn, setIsOn] = useState(false);
  const [loading, setLoading] = useState(false);
  const [statusMsg, setStatusMsg] = useState("");
  const [certInstalled, setCertInstalled] = useState(false);
  const [logs, setLogs] = useState("");
  const [showLogs, setShowLogs] = useState(false);

  useEffect(() => {
    invoke<{ running: boolean }>("get_proxy_status")
      .then((s) => setIsOn(s.running))
      .catch(() => {});
  }, []);

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
      const result = await invoke<string>("show_logs");
      setLogs(result);
      setShowLogs(!showLogs);
    } catch (err) {
      setLogs(String(err));
      setShowLogs(true);
    }
  };

  return (
    <div className="app">
      <div className="status-bar">
        <div className="dot" data-active={isOn} />
        <span>{isOn ? "Protected" : "Off"}</span>
      </div>

      <div className="hero">
        <p className="label">HEBED PRIVACY PROXY</p>
        <h1 className="title">
          One tap to anonymize<span className="dim"> ChatGPT &amp; Claude</span>
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

      <p className="hint">
        {isOn
          ? "Proxy active — browse ChatGPT and Claude normally."
          : "Tap to enable — one click, no settings."}
      </p>

      <div className="actions">
        {!isOn && !certInstalled && (
          <button className="action-btn" onClick={handleInstallCert}>
            🔐 Install Certificate (first time only)
          </button>
        )}
        <button className="action-btn" onClick={handleShowLogs}>
          📋 {showLogs ? "Hide Logs" : "Show Logs"}
        </button>
      </div>

      {showLogs && (
        <div className="log-viewer">
          <pre>{logs || "No logs yet."}</pre>
        </div>
      )}

      {statusMsg && (
        <div className={`toast ${statusMsg.includes("ON") || statusMsg.includes("CertInstalled") ? "success" : "error"}`}>
          {statusMsg}
        </div>
      )}

      <div className="providers">
        <span>ChatGPT</span>
        <span className="divider">·</span>
        <span>Claude</span>
        <span className="divider">·</span>
        <span>OpenAI API</span>
      </div>
    </div>
  );
}

export default App;
