"""Hebed Proxy engine launcher.

Frozen entry point (PyInstaller) that runs mitmdump with the PII redaction
addon. The launcher is bundled inside the installer so a fresh machine needs
NO Python, mitmproxy, or Presidio installed — everything ships with the app.

Arguments are forwarded verbatim to mitmdump, e.g.:
    hebed-proxy-engine --listen-port 8080 -s <absolute path to pii_redact.py>

Environment:
    PII_LOG_DIR   log directory for pii_events.log / files.log / prompts.log
    PII_REDACT_FILES=1  also modify uploaded file bodies
    PII_DEBUG=1         dump raw request bodies
"""

import os
import sys

# When frozen, bundled packages live in _MEIPASS; make sure imports resolve.
if getattr(sys, "frozen", False):
    bundle_dir = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    sys.path.insert(0, bundle_dir)

    # Point Python's SSL machinery at the bundled CA bundle (certifi). Without
    # this, requests/urllib3 in the frozen engine fail every outbound HTTPS
    # call with CERTIFICATE_VERIFY_FAILED "unable to get local issuer
    # certificate" (e.g. spaCy model downloads, tldextract PSL fetches).
    _cacert = os.path.join(bundle_dir, "certifi", "cacert.pem")
    if os.path.exists(_cacert):
        os.environ.setdefault("SSL_CERT_FILE", _cacert)
        os.environ.setdefault("SSL_CERT_DIR", "")

from mitmproxy.tools.main import mitmdump  # noqa: E402

if __name__ == "__main__":
    sys.exit(mitmdump())
