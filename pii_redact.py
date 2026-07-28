"""
pii_redact.py --- mitmproxy addon for PII anonymization.

Architecture (synced with anonymize.py):
  - NlpEngineProvider + spaCy for multi-language NER (en/fr/de/it)
  - Graceful fallback to NoOpNlpEngine if spaCy models not installed
  - All 12 custom recognizers from the reference implementation
  - Custom placeholder-based redaction: reversible for response restoration
  - AnonymizerEngine imported and available for direct-use mode

Run: mitmdump --listen-port 8080 -s pii_redact.py
"""

import json
import os
import re
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path

# Fix: Python313 user site-packages may not be on sys.path when the base
# Python install is missing (mitmdump uses a pip launcher that resolves to a
# Python that may have been relocated).  Inject it so Presidio + spaCy import.
_site = os.path.join(os.environ.get("APPDATA", ""), "Python", "Python313", "site-packages")
if os.path.isdir(_site) and _site not in sys.path:
    sys.path.insert(0, _site)

from mitmproxy import http
from urllib.parse import parse_qs, urlencode, unquote

# ---------------------------------------------------------------------------
# Language: default "en", can be overridden. Custom regex recognizers are
# language-agnostic; the language setting affects spaCy NER only.
# ---------------------------------------------------------------------------
DEFAULT_LANGUAGE = "en"

# ---------------------------------------------------------------------------
# Log helpers --- structured PII events (consumed by proxy_mvp Tauri app)
# ---------------------------------------------------------------------------
_log_lock = threading.Lock()
_log_file: str | None = None


def _log_path():
    global _log_file
    if _log_file is None:
        log_dir = os.environ.get(
            "PII_LOG_DIR",
            str(Path(__file__).resolve().parent),
        )
        _log_file = os.path.join(log_dir, "pii_events.log")
    return _log_file


def _log(event: dict):
    """Append a structured PII event to pii_events.log."""
    entry = {"ts": datetime.now(timezone.utc).isoformat(), **event}
    try:
        with _log_lock:
            with open(_log_path(), "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except Exception:
        pass  # never crash the proxy for logging


# ---------------------------------------------------------------------------
# Presidio engine --- warmed in background at startup
# ---------------------------------------------------------------------------
_engine = None          # AnalyzerEngine ready when != None
_anonymizer = None      # AnonymizerEngine (available for direct-use mode)
_engine_ready = threading.Event()


def _init_engine():
    """Initialize Presidio AnalyzerEngine with multi-language NER.

    Tries NlpEngineProvider with spaCy first (en/fr/de/it NER).
    Falls back to NoOpNlpEngine (regex-only, instant) if models missing.
    """
    global _engine, _anonymizer

    try:
        from presidio_analyzer import (
            AnalyzerEngine,
            Pattern,
            PatternRecognizer,
        )
        from presidio_anonymizer import AnonymizerEngine

        # --- Try spaCy NlpEngineProvider first ---
        nlp_engine = None
        try:
            from presidio_analyzer.nlp_engine import NlpEngineProvider

            # Resolve config: Tauri copies addon into target/debug/ but not the YAML.
            # Walk up from addon: debug/ → target/ → src-tauri/ → project root.
            addon_dir = Path(__file__).resolve().parent
            candidates = [
                addon_dir / "spacy_en_fr_de_it.yaml",
                addon_dir.parent / "spacy_en_fr_de_it.yaml",
                addon_dir.parent.parent / "spacy_en_fr_de_it.yaml",
                addon_dir.parent.parent.parent / "spacy_en_fr_de_it.yaml",
            ]
            config_path = next((c for c in candidates if c.exists()), None)
            if config_path:
                provider = NlpEngineProvider(conf_file=str(config_path))
                nlp_engine = provider.create_engine()
                print("[PII] spaCy NlpEngine loaded (en/fr/de/it NER)", file=sys.stderr, flush=True)
            else:
                print("[PII] spaCy config not found, falling back to NoOpNlpEngine",
                      file=sys.stderr, flush=True)
        except Exception as e:
            print(f"[PII] spaCy NlpEngine unavailable ({e}), falling back to NoOpNlpEngine",
                  file=sys.stderr, flush=True)

        # --- Fallback: NoOpNlpEngine (regex-only) ---
        if nlp_engine is None:
            from presidio_analyzer.nlp_engine import NoOpNlpEngine
            nlp_engine = NoOpNlpEngine(
                models=[{"lang_code": "en", "model_name": "no_op"}]
            )
            print("[PII] NoOpNlpEngine loaded (regex-only mode)", file=sys.stderr, flush=True)

        # --- Create engines ---
        _engine = AnalyzerEngine(
            nlp_engine=nlp_engine,
            supported_languages=["en", "fr", "de", "it"],
        )
        _anonymizer = AnonymizerEngine()

        # --- Custom recognizers (all 12 from reference implementation) ---
        _register_custom_recognizers(_engine)

        # --- Self-test: verify engine detects known PII ---
        _self_test(_engine)

        _engine_ready.set()
        print("[PII] engine ready", file=sys.stderr, flush=True)

    except Exception as e:
        print(f"[PII] engine init failed: {e}", file=sys.stderr, flush=True)
        _engine_ready.set()  # don't block forever


def _self_test(engine):
    """Run a quick self-test to verify PII detection works."""
    test_text = "my email is john@doe.com and phone number +4176573231311"
    try:
        results = engine.analyze(text=test_text, language="en")
        if results:
            found = [f"{r.entity_type}({r.score:.2f})" for r in results]
            print(f"[PII] self-test: {len(results)} match(es) -> {found}", file=sys.stderr, flush=True)
        else:
            print("[PII] self-test: 0 matches (ENGINE RETURNED EMPTY — recognizers may not be active)",
                  file=sys.stderr, flush=True)
    except Exception as e:
        print(f"[PII] self-test ERROR: {e}", file=sys.stderr, flush=True)
        import traceback
        traceback.print_exc(file=sys.stderr)


def _register_custom_recognizers(engine):
    """Register all custom regex recognizers --- synced with edit1_py.txt."""
    from presidio_analyzer import Pattern, PatternRecognizer

    recognizers = [
        # 1. IBAN
        PatternRecognizer(
            supported_entity="IBAN",
            name="iban",
            patterns=[Pattern(
                name="iban",
                regex=r"\b[A-Z]{2}\s?\d{2}\s?[A-Z0-9]{4}\s?[A-Z0-9]{4}\s?[A-Z0-9]{4}\s?[A-Z0-9]{1,8}\b",
                score=0.95,
            )],
        ),
        # 2. International phone numbers (+XX XXX XXX XXXX)
        PatternRecognizer(
            supported_entity="PHONE_NUMBER",
            name="phone_international",
            patterns=[Pattern(
                name="phone_intl",
                regex=r"\+\d{1,3}[-.\s]?\d{1,4}[-.\s]?\d{1,4}[-.\s]?\d{1,9}\b",
                score=0.85,
            )],
        ),
        # 3. US phone numbers (XXX) XXX-XXXX
        PatternRecognizer(
            supported_entity="PHONE_NUMBER",
            name="phone_us",
            patterns=[Pattern(
                name="phone_us",
                regex=r"\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",
                score=0.80,
            )],
        ),
        # 4. Email addresses
        PatternRecognizer(
            supported_entity="EMAIL_ADDRESS",
            name="email",
            patterns=[Pattern(
                name="email",
                regex=r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
                score=0.95,
            )],
        ),
        # 5. French phone numbers (0X XX XX XX XX or +33 X XX XX XX)
        PatternRecognizer(
            supported_entity="PHONE_NUMBER",
            name="phone_french",
            patterns=[Pattern(
                name="phone_fr",
                regex=r"\+?33[\s.-]?\d[\s.-]?\d{2}[\s.-]?\d{2}[\s.-]?\d{2}\b",
                score=0.80,
            )],
        ),
        # 6. Italian phone numbers (+39 XX XXX XXXX or 0XX XXX XXXX)
        PatternRecognizer(
            supported_entity="PHONE_NUMBER",
            name="phone_italian",
            patterns=[Pattern(
                name="phone_it",
                regex=r"\+?39[\s.-]?\d{2,3}[\s.-]?\d{3,4}[\s.-]?\d{3,4}\b",
                score=0.80,
            )],
        ),
        # 7. Italian fiscal code (Codice Fiscale)
        # Format: 6 letters + 2 digits + 1 letter + 4 digits + 1 letter + 2 digits + 1 letter
        PatternRecognizer(
            supported_entity="IT_FISCAL_CODE",
            name="it_fiscal_code",
            patterns=[Pattern(
                name="it_cf",
                regex=r"\b[A-Z]{6}\d{2}[A-Z]\d{3}[A-Z]\d{2}[A-Z]\b",
                score=0.70,
            )],
        ),
        # 8. Credit card numbers
        PatternRecognizer(
            supported_entity="CREDIT_CARD",
            name="credit_card",
            patterns=[Pattern(
                name="credit_card",
                regex=r"\b(?:\d{4}[-\s]?){3}\d{4}\b|\b(?:\d{4}[-\s]?){2}\d{4}[-\s]?\d{4}\b|\b\d{13,19}\b",
                score=0.85,
            )],
        ),
        # 9. French social security number (N° Sécurité Sociale)
        # Score intentionally low to avoid false positives in IBANs, phone numbers, etc.
        PatternRecognizer(
            supported_entity="FR_SSN",
            name="fr_ssn",
            patterns=[Pattern(
                name="fr_ssn",
                regex=r"(?<![A-Z0-9])(?<!\d)[12]\d{2}[0123456789]\d{2}[0-9]{2}\d{3}[0-9]{5}[0-9]{2}[0-9]{3}(?!\d)",
                score=0.50,
            )],
        ),
        # 10. German ID card (Personalausweis / Reisepass)
        PatternRecognizer(
            supported_entity="DE_ID",
            name="de_id",
            patterns=[Pattern(
                name="de_passport",
                regex=r"\bDE\d{7,9}\b",
                score=0.60,
            )],
        ),
        # 11. US SSN (XXX-XX-XXXX) --- retained from previous pii_redact.py
        PatternRecognizer(
            supported_entity="US_SSN",
            name="us_ssn",
            patterns=[Pattern(
                name="us_ssn",
                regex=r"\b\d{3}-\d{2}-\d{4}\b",
                score=0.85,
            )],
        ),
        # 12. Generic person name pattern (common first+last name combinations)
        # Low confidence; relies on spaCy NER for high-confidence PERSON detection
        PatternRecognizer(
            supported_entity="PERSON",
            name="person_name_pattern",
            patterns=[Pattern(
                name="person_fullname",
                regex=r"\b[A-Z][a-z]{2,}\s[A-Z][a-z]{2,}\b",
                score=0.30,
            )],
        ),
    ]

    for rec in recognizers:
        engine.registry.add_recognizer(rec)


# Start background init
threading.Thread(target=_init_engine, daemon=True).start()

# ---------------------------------------------------------------------------
# PII store --- maps flow_id -> {placeholder: original_value}
# ---------------------------------------------------------------------------
_pii_store: dict[str, dict[str, str]] = {}


def _redact(text: str, language: str = DEFAULT_LANGUAGE) -> tuple[str, dict[str, str]]:
    """Detect PII and replace with numbered placeholders.

    Returns (redacted_text, {placeholder: original_value}).
    """
    if not text or not text.strip():
        return text, {}

    if _engine is None:
        # Wait up to 3 seconds for engine init to complete
        if _engine_ready.wait(timeout=3.0):
            pass  # engine is ready now, proceed
        else:
            print("[PII] engine not ready after 3s", file=sys.stderr, flush=True)
            return text, {}

    try:
        results = _engine.analyze(text=text, language=language)
    except Exception as e:
        print(f"[PII] analyze error: {e}", file=sys.stderr, flush=True)
        return text, {}

    if not results:
        return text, {}

    # Sort by start position, deduplicate overlapping spans
    results = sorted(results, key=lambda r: r.start)

    store: dict[str, str] = {}
    counters: dict[str, int] = {}
    parts: list[str] = []
    last_end = 0

    for r in results:
        if r.start < last_end:
            continue  # skip overlapping

        entity = r.entity_type
        idx = counters.get(entity, 0)
        counters[entity] = idx + 1

        placeholder = f"[{entity}_{idx:03d}]"
        store[placeholder] = text[r.start : r.end]

        parts.append(text[last_end : r.start])
        parts.append(placeholder)
        last_end = r.end

    parts.append(text[last_end:])
    redacted = "".join(parts)

    # Log structured event
    entities_found = [
        {"type": r.entity_type, "score": round(r.score, 3)}
        for r in results
    ]
    _log({
        "event": "redact",
        "entities": entities_found,
        "original_len": len(text),
        "redacted_len": len(redacted),
    })

    return redacted, store


# ---------------------------------------------------------------------------
# JSON body scanner --- traverses known LLM API request structures
# ---------------------------------------------------------------------------
def _scan_json(body: dict) -> tuple[bytes, int]:
    """Scan JSON body for PII in known LLM API fields. Returns (new_body, count)."""
    count = 0
    texts_found = 0
    samples: list[str] = []

    def _scan(text: str, label: str) -> tuple[str, dict[str, str]]:
        nonlocal texts_found, count
        texts_found += 1
        redacted, store = _redact(text)
        preview = text[:120].replace("\n", "\\n")
        if store:
            count += 1
            print(f"[PII] {label}: {preview}", flush=True)
        else:
            samples.append(f"{label}: {preview}")
        return redacted, store

    # OpenAI-style: messages[].content.parts[]
    for i, msg in enumerate(body.get("messages", [])):
        content = msg.get("content", {})
        parts = content.get("parts", [])
        new_parts = []
        for j, part in enumerate(parts):
            if isinstance(part, str) and part.strip():
                redacted, store = _scan(part, f"msg[{i}].parts[{j}]")
                if store:
                    _pii_store[flow_id()] = store
                new_parts.append(redacted)
            else:
                new_parts.append(part)
        if new_parts != parts:
            content["parts"] = new_parts

        # Also check if content itself is a string
        c = msg.get("content")
        if isinstance(c, str) and c.strip():
            redacted, store = _scan(c, f"msg[{i}].content")
            if store:
                _pii_store[flow_id()] = store
                msg["content"] = redacted

    # Direct prompt field
    if isinstance(body.get("prompt"), str) and body["prompt"].strip():
        redacted, store = _scan(body["prompt"], "prompt")
        if store:
            _pii_store[flow_id()] = store
            body["prompt"] = redacted

    if texts_found > 0 and count == 0:
        print(f"[PII] scanned {texts_found} field(s), no PII:", file=sys.stderr, flush=True)
        for s in samples:
            print(f"  {s}", file=sys.stderr, flush=True)

    return json.dumps(body).encode(), count


# ---------------------------------------------------------------------------
# Form-data scanner --- handles application/x-www-form-urlencoded endpoints
# ---------------------------------------------------------------------------
def _scan_form(data: bytes) -> tuple[bytes, int]:
    """Scan URL-encoded form data for PII in the 'prompt' field.
    Returns (new_body_bytes, count)."""
    text = data.decode("utf-8", errors="replace")
    params = parse_qs(text, keep_blank_values=True)

    count = 0
    prompt_vals = params.get("prompt", [])
    new_vals = []
    for val in prompt_vals:
        decoded = unquote(val)
        if decoded.strip():
            redacted, store = _redact(decoded)
            if store:
                _pii_store[flow_id()] = store
                count += 1
                new_vals.append(redacted)
                print(f"[PII] form.prompt: {decoded[:120]}", flush=True)
            else:
                new_vals.append(decoded)
                print(f"[PII] form.prompt (no PII): {decoded[:120]}", file=sys.stderr, flush=True)
        else:
            new_vals.append(decoded)

    if count > 0:
        params["prompt"] = new_vals
        # Rebuild: urlencode preserves the original parameter order well enough
        new_text = urlencode(params, doseq=True)
        return new_text.encode("utf-8"), count

    return data, 0


# ---------------------------------------------------------------------------
# Debug: dump raw request body (set PII_DEBUG=1 to enable)
# ---------------------------------------------------------------------------
_PII_DEBUG = os.environ.get("PII_DEBUG", "0") == "1"


def _dump_structure(obj, indent="", max_depth=4, _depth=0):
    """Recursively print JSON structure with string previews."""
    if _depth > max_depth:
        print(f"{indent}...", file=sys.stderr, flush=True)
        return
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, str):
                preview = v[:200].replace("\n", "\\n")
                print(f"{indent}{k}: \"{preview}\"", file=sys.stderr, flush=True)
            elif isinstance(v, (list, dict)):
                print(f"{indent}{k}: [{_count(v)}]", file=sys.stderr, flush=True)
                _dump_structure(v, indent + "  ", max_depth, _depth + 1)
            else:
                print(f"{indent}{k}: {v}", file=sys.stderr, flush=True)
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            if isinstance(item, str):
                preview = item[:200].replace("\n", "\\n")
                print(f"{indent}[{i}]: \"{preview}\"", file=sys.stderr, flush=True)
            elif isinstance(item, (dict, list)):
                print(f"{indent}[{i}]:", file=sys.stderr, flush=True)
                _dump_structure(item, indent + "  ", max_depth, _depth + 1)
            else:
                print(f"{indent}[{i}]: {item}", file=sys.stderr, flush=True)


def _count(obj):
    """Return len(obj) as string, or '?'."""
    try:
        return str(len(obj))
    except Exception:
        return "?"


# ---------------------------------------------------------------------------
# Endpoint matcher --- only intercept known LLM API endpoints
# ---------------------------------------------------------------------------
ENDPOINTS = [
    (r"chatgpt\.com/backend-anon/f/conversation",       1),
    ("chatgpt.com/backend-api/f/conversation",           1),
    (r"chatgpt\.com/unauth-mweb/conversation/updates",   1),
    (r"claude\.ai/api/organizations/[^/]+/chat_conversations/[^/]+/completion", 1),
    ("api.anthropic.com/v1/messages",                    1),
    ("/v1/chat/completions",                             1),
]

# Thread-local flow ID
_flow = threading.local()


def flow_id() -> str:
    return getattr(_flow, "id", "")


# ---------------------------------------------------------------------------
# mitmproxy handlers
# ---------------------------------------------------------------------------
def request(flow: http.HTTPFlow):
    """Intercept outgoing requests to LLM APIs, redact PII from bodies."""
    url = flow.request.pretty_url
    matched = any(re.search(p, url) for p, _ in ENDPOINTS)
    if not matched:
        return

    _flow.id = flow.id
    content_type = flow.request.headers.get("content-type", "")

    # Always log URL + content-type for debugging
    path = url.split("chatgpt.com", 1)[-1] if "chatgpt.com" in url else url
    print(f"[PII] {flow.id} ct={content_type[:40]} url={path[:120]}", file=sys.stderr, flush=True)

    try:
        # --- Form-encoded (ChatGPT unauth-mweb) ---
        if "application/x-www-form-urlencoded" in content_type:
            new_body, count = _scan_form(flow.request.content)
            if count > 0:
                flow.request.content = new_body
                print(f"[PII] redacted {count} field(s) in {flow.id}", flush=True)
            else:
                print(f"[PII] form: no PII in {flow.id}", file=sys.stderr, flush=True)
            return

        # --- JSON body (ChatGPT backend-api, Claude, etc.) ---
        body = json.loads(flow.request.content)

        if _PII_DEBUG:
            print(f"[PII] DEBUG {flow.id} url={url}", file=sys.stderr, flush=True)
            _dump_structure(body, indent="  ")

        new_body, count = _scan_json(body)
        if count > 0:
            flow.request.content = new_body
            print(f"[PII] redacted {count} field(s) in {flow.id}", flush=True)
        else:
            print(f"[PII] scanned: no PII in {flow.id}", file=sys.stderr, flush=True)
    except json.JSONDecodeError:
        print(f"[PII] skip: non-JSON body in {flow.id}", file=sys.stderr, flush=True)
    except Exception as e:
        print(f"[PII] ERROR in request: {e}", file=sys.stderr, flush=True)


def response(flow: http.HTTPFlow):
    """Restore original PII values in the API response."""
    try:
        store = _pii_store.pop(flow.id, None)
        if store:
            text = flow.response.get_text()
            if text:
                for placeholder, original in store.items():
                    text = text.replace(placeholder, original)
                flow.response.set_text(text)
                _log({"event": "restore", "placeholders": len(store)})
    except Exception as e:
        print(f"[PII] ERROR in response: {e}", file=sys.stderr, flush=True)
