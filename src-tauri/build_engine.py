"""Build the self-contained Hebed Proxy engine with PyInstaller.

Produces dist/hebed-proxy-engine/hebed-proxy-engine.exe (onedir) containing
mitmdump + the PII addon's full dependency chain (mitmproxy, Presidio,
spaCy + en_core_web_sm, PyMuPDF, python-docx, Pillow, pytesseract).

Run with:  C:\\Python313\\python.exe build_engine.py
Output:    dist/hebed-proxy-engine/  (bundled into the Tauri installer)
"""

import os
import subprocess
import sys

PY = sys.executable
ROOT = os.path.dirname(os.path.abspath(__file__))
LAUNCHER = os.path.join(ROOT, "engine_launcher.py")
OUT = os.path.join(ROOT, "dist", "hebed-proxy-engine")
WORK = os.path.join(ROOT, "build", "engine")

# Collect data + binaries from packages that ship non-Python assets.
# --collect-all pulls in package data, submodules, binaries, and metadata.
COLLECT = [
    "mitmproxy",
    "presidio_analyzer",
    "presidio_anonymizer",
    "spacy",
    "en_core_web_sm",
    "fr_core_news_sm",
    "de_core_news_sm",
    "it_core_news_sm",
    "tldextract",  # includes .tld_set_snapshot data (EmailRecognizer needs it)
    "certifi",     # cacert.pem for outbound HTTPS (spaCy/tldextract fetches)
    "fitz",
    "pytesseract",
]

HIDDEN = [
    # mitmproxy plugin loading / entry points
    "mitmproxy.addons",
    "mitmproxy.contentviews",
    "mitmproxy.protocol",
    "mitmproxy.tools",
    "mitmproxy.platform",
    # presidio
    "presidio_analyzer.recognizer_registry",
    "presidio_analyzer.nlp_engine",
    "presidio_analyzer.predefined_recognizers",
    # spacy
    "spacy.cli",
    "spacy.lang",
    # docx / pdf / ocr
    "docx",
    "PIL",
    "pytesseract",
]

cmd = [
    PY, "-m", "PyInstaller",
    "--noconfirm",
    "--clean",
    "--onedir",
    "--name", "hebed-proxy-engine",
    "--distpath", os.path.join(ROOT, "dist"),
    "--workpath", WORK,
    "--specpath", WORK,
    "--console",
    # Version metadata + icon reduce AV ML false positives (Wacatac.B!ml)
    "--version-file", os.path.join(ROOT, "engine_version_file.txt"),
    "--icon", os.path.join(ROOT, "icons", "icon.ico"),
]
for c in COLLECT:
    cmd.append(f"--collect-all={c}")
for h in HIDDEN:
    cmd.append(f"--hidden-import={h}")

# Explicitly include tldextract's hidden .tld_set_snapshot data file.
# --collect-all can skip dotfiles; EmailRecognizer crashes without it.
_tld_dir = None
try:
    import tldextract as _tld
    _tld_dir = os.path.dirname(os.path.abspath(_tld.__file__))
except Exception:
    pass
if _tld_dir:
    snap = os.path.join(_tld_dir, ".tld_set_snapshot")
    if os.path.exists(snap):
        cmd.append(f"--add-data={snap};tldextract")

cmd.append(LAUNCHER)

print("Running:", " ".join(cmd))
r = subprocess.run(cmd, cwd=ROOT)
if r.returncode != 0:
    sys.exit(f"PyInstaller failed: {r.returncode}")

exe = os.path.join(OUT, "hebed-proxy-engine.exe")
print("\nEngine built:", exe, os.path.getsize(exe), "bytes")
