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
    const check = () => {
      invoke<{ running: boolean; died: boolean }>("get_proxy_status")
        .then((s) => {
          setIsOn(s.running);
          if (s.died) {
            setStatusMsg("⚠ Proxy crashed — system proxy auto-disabled. Toggle ON to restart.");
          }
        })
        .catch(() => {});
    };
    check(); // initial
    const interval = setInterval(check, 3000); // watchdog poll
    return () => clearInterval(interval);
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
      const result = await invoke<string>("get_logs");
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
        <h1 className="title">
        <span className="dim"> Tap to HEBED </span></h1>
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
    </div>
  );
}

export default App;
