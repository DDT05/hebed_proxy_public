"""watchdog_mitmdump.py — Keep mitmdump alive when F-Secure kills it.

Self-contained. Run this alongside the proxy_mvp Tauri app:
    python watchdog_mitmdump.py

Monitors mitmdump every 2 seconds. Restarts it if F-Secure (or anything)
kills the process. Press Ctrl+C to stop.
"""

import subprocess
import time
import sys
import os

MITMDUMP = os.path.join(
    os.environ["APPDATA"], "Python", "Python313", "Scripts", "mitmdump.exe"
)
ADDON = os.path.join(os.path.dirname(os.path.abspath(__file__)), "pii_redact.py")
PORT = "8080"


def is_running():
    """Check if a mitmdump process exists."""
    try:
        result = subprocess.run(
            ["tasklist", "/fi", "imagename eq mitmdump.exe", "/fo", "csv", "/nh"],
            capture_output=True, text=True, timeout=5,
        )
        return "mitmdump.exe" in result.stdout
    except Exception:
        return False


def start_mitmdump():
    """Launch mitmdump. Returns the Popen handle or None."""
    try:
        proc = subprocess.Popen(
            [MITMDUMP, "--listen-port", PORT, "-s", ADDON],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        print(f"[watchdog] Started mitmdump (PID {proc.pid})")
        return proc
    except Exception as e:
        print(f"[watchdog] Failed to start mitmdump: {e}", file=sys.stderr)
        return None


def port_in_use(port):
    """Check if something is already listening on the port."""
    import socket
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            return s.connect_ex(("127.0.0.1", int(port))) == 0
    except Exception:
        return False


def main():
    print(f"[watchdog] Watching mitmdump on port {PORT}...")
    print(f"[watchdog] Addon: {ADDON}")
    print(f"[watchdog] Press Ctrl+C to stop.\n")

    proc = None
    restarts = 0

    # Don't start if the Tauri app already has mitmdump running on this port
    if port_in_use(PORT):
        print(f"[watchdog] Port {PORT} already in use — Tauri app likely running. Monitoring only.")

    try:
        while True:
            if is_running():
                time.sleep(2)
                continue

            # Check if Tauri app is handling it (port still in use from previous instance)
            if port_in_use(PORT):
                print(f"[watchdog] Port {PORT} in use but no mitmdump process — Tauri app managing it.")
                time.sleep(2)
                continue

            # mitmdump is dead - restart it
            restarts += 1
            print(f"[watchdog] mitmdump died! Restarting (attempt #{restarts})...")
            proc = start_mitmdump()
            time.sleep(3)

    except KeyboardInterrupt:
        print(f"\n[watchdog] Stopped. {restarts} restart(s).")
        if proc and proc.poll() is None:
            proc.terminate()
            proc.wait(timeout=5)