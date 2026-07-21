import json, re
from mitmproxy import http

PII_PATTERNS = [
    (r'\b[\w\.-]+@[\w\.-]+\.\w+\b',     'EMAIL'),
    (r'\b\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b', 'CARD'),
    (r'\b\+?\d[\d\s\-\.\(\)]{6,}\d\b',  'PHONE'),
    (r'\b[A-Z]{2}\d{6,9}\b',            'DOC_ID'),
]

_pii_store: dict[str, dict[str, str]] = {}

def _redact_text(text: str, store: dict) -> str:
    for pattern, label in PII_PATTERNS:
        def replacer(m, lbl=label, s=store):
            p = f'[{lbl}_{len(s):03d}]'
            s[p] = m.group(0)
            return p
        text = re.sub(pattern, replacer, text)
    return text

def request(flow: http.HTTPFlow):
    url = flow.request.pretty_url

    # --- ChatGPT ---
    if "chatgpt.com/backend-api/f/conversation" in url:
        try:
            body = json.loads(flow.request.content)
        except json.JSONDecodeError:
            return
        store: dict[str, str] = {}
        modified = False
        for msg in body.get("messages", []):
            content = msg.get("content", {})
            parts = content.get("parts", [])
            new_parts = []
            for part in parts:
                if isinstance(part, str):
                    redacted = _redact_text(part, store)
                    if redacted != part:
                        modified = True
                    new_parts.append(redacted)
                else:
                    new_parts.append(part)
            if new_parts != parts:
                content["parts"] = new_parts
        if modified:
            flow.request.content = json.dumps(body).encode()
            _pii_store[flow.id] = store
            print(f"[PII] ChatGPT: redacted {len(store)} items in {flow.id}")

    # --- Claude (dynamic org & conversation UUIDs) ---
    elif re.search(r'claude\.ai/api/organizations/[^/]+/chat_conversations/[^/]+/completion', url):
        try:
            body = json.loads(flow.request.content)
        except json.JSONDecodeError:
            return
        store: dict[str, str] = {}
        modified = False
        if isinstance(body.get("prompt"), str):
            redacted = _redact_text(body["prompt"], store)
            if redacted != body["prompt"]:
                body["prompt"] = redacted
                modified = True
        if modified:
            flow.request.content = json.dumps(body).encode()
            _pii_store[flow.id] = store
            print(f"[PII] Claude: redacted {len(store)} items in {flow.id}")

    # --- Standard API ---
    elif "/v1/chat/completions" in url:
        try:
            body = json.loads(flow.request.content)
        except json.JSONDecodeError:
            return
        store: dict[str, str] = {}
        modified = False
        for msg in body.get("messages", []):
            content = msg.get("content")
            if isinstance(content, str):
                redacted = _redact_text(content, store)
                if redacted != content:
                    msg["content"] = redacted
                    modified = True
        if modified:
            flow.request.content = json.dumps(body).encode()
            _pii_store[flow.id] = store
            print(f"[PII] API: redacted {len(store)} items in {flow.id}")

def response(flow: http.HTTPFlow):
    store = _pii_store.pop(flow.id, None)
    if not store:
        return
    text = flow.response.get_text()
    for placeholder, original in store.items():
        text = text.replace(placeholder, original)
    flow.response.set_text(text)