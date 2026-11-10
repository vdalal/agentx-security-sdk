"""The flow rule: a sensitive value that one protected tool returned, leaving through a later call.

Within one run, the values a protected tool RETURNED are scanned and the sensitive ones are kept
in this process's memory. A later protected call that sends data out of the company and carries
one of them in its content is stopped (or, when watching, recorded as a would-block).

Nothing here is written anywhere. The raw values live in memory for the run only; what reaches
the local record is the shape: the kind of value and the names of the two tools.

What counts as sensitive, and what counts as sending out, is three ways each:
  * a value is sensitive by its shape (an email, a card number, a private key), by the name of the
    field it came back under (`address`, `api_key`), or because the developer marked the tool
    with `returns_sensitive=True`;
  * a call sends out when it names somewhere outside the company (a URL, a host, a recipient's
    domain), when its name says so (`send_`, `post_`, `upload_`), or when the developer marked it
    with `sends_out=True`.

A value that appears only where a call is addressed (`to=`, a URL's host) is addressing, not
content: emailing a customer at their own address is the job, not a leak.

Not caught: data that is reworded, summarised or encoded before it leaves, and sensitive values
of a kind none of the three ways names (a bank account number, most national ids).
"""

import ipaddress
import json
import re
from collections import OrderedDict

POLICY_ID = "flow_rule"
POLICY_NAME = "Sensitive Data Leaving"

MAX_VALUES_PER_RUN = 500
MAX_RUNS = 64
MAX_SCAN_CHARS = 256 * 1024
MIN_TEXT_LEN = 6
MIN_FLAGGED_LEN = 20
# A long text field is kept as its lines and sentences, so a quoted excerpt still matches.
_LONG_TEXT = 200
_MIN_PIECE = 20
_MAX_DEPTH = 12

# Shapes the egress scrubber does not carry. A private key's header line is enough: a key that
# leaves always leaves with it.
_EXTRA_SHAPES = (
    # Every repeat bounded: an unbounded `[...]+@` takes quadratic time over a long run of text
    # with no `@` in it, and this scan runs on every protected tool's return.
    ("email", re.compile(r"[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63}){1,8}")),
    ("private key",re.compile(r"-----BEGIN (?:[A-Z0-9]+ ){0,3}PRIVATE KEY-----")),
    ("GitHub token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{20,}\b|\bgithub_pat_[0-9A-Za-z_]{20,}\b")),
)
_SHAPE_LABELS = {"EMAIL": "email", "PHONE": "phone number", "SSN": "social security number",
                 "CREDIT_CARD": "card number", "AWS_KEYS": "AWS key"}
_DIGIT_KINDS = {"phone number", "social security number", "card number"}

# A field named like a secret. Two strengths:
#   * STRONG: one of its words is a secret word (`password`, `client_secret`, `credentials`), it
#     holds a secret compound (`database_url`), or it is a bare `token`/`cookie`. Its value is a
#     secret whatever it looks like.
#   * WEAK: its last word is `token` or `key` (`github_token`, `service_role_key`) and the word
#     before is not an ordinary one (`next_page_token`, `sort_key`). Its value counts only when it
#     LOOKS like a secret (`_looks_like_secret`), so `issue_key: "PROJ-1234"` and
#     `flag_key: "new-checkout"` are ordinary values. One rule about the value, not a word list.
# A trailing `value`/`raw`/`pem`/`b64`/... word is read past: `api_key_value` is `api_key`.
_SECRET_NAME_WORDS = frozenset({
    "secret", "secrets", "password", "passwords", "passwd", "pwd", "passphrase", "credential",
    "credentials", "creds", "dsn", "authorization", "bearer", "apikey", "privatekey",
})
_SECRET_COMPOUNDS = (
    "database_url", "connection_string", "conn_str", "set_cookie",
)
_SECRET_NAMES = frozenset({"token", "cookie", "cookies", "session_cookie"})
_SECRET_LAST_WORDS = frozenset({"token", "tokens", "key", "keys"})
_TRAILING_FORM_WORDS = frozenset({"value", "raw", "pem", "b64", "base64", "str", "string", "hex",
                                  "encoded", "der", "bytes", "text"})
_ORDINARY_BEFORE_KEY = frozenset({
    "page", "next", "continuation", "cursor", "sort", "partition", "range", "cache",
    "idempotency", "dedup", "dedupe", "primary", "foreign", "public", "publishable", "object",
    "row", "s3", "lookup", "group", "shard", "hash", "map", "dict", "index", "sync", "csrf",
})

# Where a call is addressed. A value found only here is addressing, not content.
_RECIPIENT_WORDS = frozenset({"to", "cc", "bcc", "recipient", "recipients", "reply_to", "replyto",
                              "send_to", "to_email", "to_address", "destination", "toaddresses"})
_ADDRESS_NAMES = frozenset({"email", "email_address", "phone", "phone_number", "number", "mobile"})
_URL_NAMES = frozenset({"url", "uri", "endpoint", "webhook", "webhook_url", "link", "href"})
_HOST_NAMES = frozenset({"host", "hostname", "domain", "server"})

_URL_RE = re.compile(r"\b[a-z][a-z0-9+.-]{1,15}://([^\s/?#'\"<>]{1,255})", re.IGNORECASE)
_EMAIL_DOMAIN_RE = re.compile(r"[A-Za-z0-9._%+-]{1,64}@([A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63}){1,8})")
_DIGIT_RUN_RE = re.compile(r"\+?\d(?:[\s.\-()]{0,2}\d){6,22}")
_INSIDE_SUFFIXES = (".local", ".internal", ".lan", ".corp", ".svc", ".cluster.local", ".localhost")


def _name_words(name):
    """The words of a field or argument name: `authToken` -> auth, token; `api_key` -> api, key."""
    text = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", str(name))
    return [w for w in re.split(r"[^A-Za-z0-9]+", text.lower()) if w]


def _secret_strength(name):
    """2 for a strong secret name, 1 for a weak one, 0 for neither (see above)."""
    words = _name_words(name)
    while len(words) > 1 and words[-1] in _TRAILING_FORM_WORDS:
        words.pop()
    joined = "_".join(words)
    if joined in _SECRET_NAMES or _SECRET_NAME_WORDS.intersection(words):
        return 2
    if any(c in joined for c in _SECRET_COMPOUNDS):
        return 2
    if len(words) >= 2 and words[-1] in _SECRET_LAST_WORDS and words[-2] not in _ORDINARY_BEFORE_KEY:
        return 1
    return 0


def _is_secret_name(name):
    return _secret_strength(name) > 0


def _looks_like_secret(value):
    """16 characters or more, no spaces, letters mixed with digits or symbols: the shape of a key
    or a token, and not of an issue id, a flag name or a word."""
    v = value.strip()
    return (len(v) >= 16 and not any(c.isspace() for c in v) and any(c.isalpha() for c in v)
            and any(not c.isalpha() for c in v))


# A customer-data field read by its LAST word, so `billing_address`, `homeAddress` and
# `customer_phone` count and `email_template` or `phone_count` do not. Names are only matched
# whole (`first_name`), because `product_name` is not a person.
_PII_LAST_WORDS = frozenset({"email", "phone", "mobile", "ssn", "address", "dob", "passport"})
_PII_ENDINGS = ("date_of_birth", "phone_number", "card_number", "credit_card", "social_security")
# A machine's address is not a person's: `ip_address`, `server_address`, `wallet_address`.
_MACHINE_BEFORE_ADDRESS = frozenset({
    "ip", "ipv4", "ipv6", "mac", "server", "listen", "bind", "remote", "local", "host", "node",
    "network", "wallet", "contract", "socket", "peer", "gateway", "broadcast", "memory", "base",
})


def _is_pii_name(name, pii_field_names):
    words = _name_words(name)
    joined = "_".join(words)
    if str(name).lower() in pii_field_names or joined in pii_field_names:
        return True
    if not words:
        return False
    if words[-1] == "address" and len(words) >= 2 and words[-2] in _MACHINE_BEFORE_ADDRESS:
        return False
    return words[-1] in _PII_LAST_WORDS or joined.endswith(_PII_ENDINGS)


def _norm_text(value):
    return " ".join(str(value).lower().split())


def _digits(value):
    return re.sub(r"\D", "", str(value))


def mask(kind, value):
    """A value as the stop shows it: enough to recognise, never the whole thing."""
    value = str(value)
    if kind == "email" and "@" in value:
        local, _, domain = value.partition("@")
        return f"{local[:1]}***@{domain}"
    if kind in _DIGIT_KINDS:
        return f"ending {_digits(value)[-4:]}"
    if len(value) <= 8:
        return value[:2] + "***"
    return value[:4] + "***"


def _pieces(text):
    """A long text as the lines and sentences someone might quote from it."""
    out = []
    for line in text.splitlines():
        for part in re.split(r"(?<=[.!?;])\s+", line):
            part = part.strip()
            if len(part) >= _MIN_PIECE:
                out.append(part)
    return out


def sensitive_values(result, shapes, pii_field_names, returns_sensitive=False):
    """The sensitive values in one tool's return, as (kind, raw value) pairs.

    `shapes` is [(category, compiled pattern, validator or None)] from the egress scrubber;
    `pii_field_names` are the field names the product treats as customer data. A JSON string is
    read as the structure it encodes, so a tool that returns `json.dumps(row)` keeps its field
    names. Scans at most MAX_SCAN_CHARS of text and MAX_VALUES_PER_RUN values."""
    found = []
    seen = set()
    budget = [MAX_SCAN_CHARS]
    free = [False]   # inside a JSON document already charged as text

    def add(kind, value):
        # One entry per value: its shape and its field name both find an email, and counting it
        # twice would spend the cap on half as many values.
        if len(found) < MAX_VALUES_PER_RUN and value not in seen:
            seen.add(value)
            found.append((kind, value))

    def scan_text(text, field):
        if not free[0]:
            if budget[0] <= 0:
                return
            # Charged once, as text, before anything else: the strings inside a JSON document
            # are then read free, so the cap bounds both the text read and the time spent.
            text = text[:budget[0]]
            budget[0] -= len(text)
        stripped = text.strip()
        # JSON inside JSON (a Lambda `body`) is read too: its text is part of a document already
        # charged, and the depth cap bounds the nesting.
        if stripped[:1] in "{[" and len(stripped) > 1:
            try:
                parsed = json.loads(stripped)
            except (ValueError, RecursionError):
                parsed = None
            if isinstance(parsed, (dict, list)):
                was_free, free[0] = free[0], True
                try:
                    walk(parsed, field, 1)
                finally:
                    free[0] = was_free
                return
        for category, pattern, validator in shapes:
            if category == "EMAIL":
                continue   # read by the bounded pattern in _EXTRA_SHAPES instead
            for m in pattern.finditer(text):
                hit = m.group(0)
                if validator is None or validator(hit):
                    add(_SHAPE_LABELS.get(category, category.lower()), hit)
        for kind, pattern in _EXTRA_SHAPES:
            if kind == "email" and "@" not in text:
                continue
            for m in pattern.finditer(text):
                add(kind, m.group(0))
        named, min_len = None, MIN_TEXT_LEN
        if field is not None:
            low = str(field).lower()
            if _is_pii_name(field, pii_field_names):
                named = f"field `{low}`"
            elif _secret_strength(field) == 2 or (
                    _secret_strength(field) == 1 and _looks_like_secret(stripped)):
                named = f"secret field `{low}`"
        if named is None and returns_sensitive:
            # Prose only: a status word, a date or an id under a flagged tool is not the private
            # text the flag is for, and a short word would match ordinary sentences later.
            named, min_len = "flagged by the developer", MIN_FLAGGED_LEN
            if " " not in stripped:
                named = None
        if named is not None and len(stripped) >= min_len:
            if len(stripped) > _LONG_TEXT:
                for piece in _pieces(stripped):
                    add(named, piece)
            else:
                add(named, stripped)

    def walk(node, field, depth):
        if depth > _MAX_DEPTH or len(found) >= MAX_VALUES_PER_RUN or (
                budget[0] <= 0 and not free[0]):
            return
        if isinstance(node, str):
            scan_text(node, field)
        elif isinstance(node, bytes):
            scan_text(node.decode("utf-8", "replace"), field)
        elif isinstance(node, dict):
            for k, v in list(node.items())[:5000]:
                walk(v, k, depth + 1)
        elif isinstance(node, (list, tuple, set, frozenset)):
            for v in list(node)[:5000]:
                walk(v, field, depth + 1)
        elif isinstance(node, (int, float)) and not isinstance(node, bool) and field is not None:
            # A number under a customer-data field (`phone: 4155551234`) is that data.
            if _is_pii_name(field, pii_field_names) and len(str(node)) >= MIN_TEXT_LEN:
                walk(str(node), field, depth)

    walk(result, None, 0)
    return found


def remember(run_values, source_tool, pairs):
    """Add (kind, value) pairs from `source_tool` to this run's store, oldest dropped past the cap.
    The store maps a matching key to (kind, source tool, masked value, digits or text)."""
    for kind, value in pairs:
        if kind in _DIGIT_KINDS:
            key, mode = _digits(value), "digits"
            if len(key) < 7:
                continue
        else:
            key, mode = _norm_text(value), "text"
            if len(key) < MIN_TEXT_LEN:
                continue
        held = run_values.pop((mode, key), None)
        if held is not None and held[1] == source_tool:
            # The same value seen again from the same tool (its shape first, then its field
            # name): keep the first reading, which names the value more plainly ("an email").
            kind = held[0]
        run_values[(mode, key)] = (kind, source_tool, mask(kind, value))
        while len(run_values) > MAX_VALUES_PER_RUN:
            run_values.popitem(last=False)


def new_run_store():
    return OrderedDict()


def _bare_host(host):
    """`user@[::1]:8080` -> `::1`, `api.x.com:443` -> `api.x.com`."""
    host = host.strip().lower()
    if "@" in host:
        host = host.rsplit("@", 1)[1]
    if host.startswith("["):
        return host[1:].split("]", 1)[0]
    if host.count(":") == 1:
        host = host.split(":", 1)[0]
    return host.rstrip(".")


def _is_inside_host(host):
    host = _bare_host(host)
    if not host:
        return True
    if host == "localhost" or host.endswith(_INSIDE_SUFFIXES):
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return "." not in host and ":" not in host   # a bare name (`db`, `redis`) is a local one
    return ip.is_private or ip.is_loopback or ip.is_link_local


def _arg_role(name):
    """'recipient', 'address', 'url', 'host' or None for content."""
    low = str(name).lower()
    words = set(_name_words(name))
    if low in _RECIPIENT_WORDS or "recipient" in low or "recipients" in words:
        return "recipient"
    if low in _URL_NAMES or low.endswith("_url") or low.endswith("url") and len(low) <= 12:
        return "url"
    if low in _HOST_NAMES:
        return "host"
    if low in _ADDRESS_NAMES:
        return "address"
    return None


def _text_of(value):
    if isinstance(value, str):
        return value
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    for render in (lambda v: json.dumps(v, default=str, ensure_ascii=False), str, repr):
        try:
            return render(value)
        except Exception:   # noqa: BLE001 -- an object whose own str() raises (a detached ORM row)
            continue
    return ""


# Text that IS a sending command: it starts with one (`curl -d @rows.json https://x`), or is a
# shell running one (`bash -c "curl ..."`, `$(curl ...)`). Then the URL is where the call goes.
# A command quoted inside prose (a ticket body with `curl https://...` in backticks, "Raleigh
# (NC)") is only mentioned, so the rest of a text argument is never searched; a command or script
# ARGUMENT is (below), since there every URL is where it goes.
_SENDING_COMMAND_RE = re.compile(
    r"^\s*(?:(?:sudo\s+)?|(?:ba|z|da)?sh\s+-c\s+[\"']?\s*|pwsh\s+-c\s+[\"']?\s*|\$\(\s*)"
    r"(?:curl|wget|iwr|irm|invoke-webrequest|invoke-restmethod|httpie|xh|scp|rsync|sftp|ftp|nc)\b",
    re.IGNORECASE)
# An argument that holds a command or a script: every URL in it is where it goes (`cd /tmp &&
# curl ...`, `requests.post("https://...")`).
_COMMAND_NAMES = frozenset({"command", "cmd", "script", "shell", "code", "commandline",
                            "command_line"})
_URL_ONLY_RE = re.compile(r"^\s*[a-z][a-z0-9+.-]{1,15}://\S+\s*$", re.IGNORECASE)


def _role_at(name, depth):
    """An argument's role where it sits. A recipient (`to`, `*recipient*`), a URL or a host
    argument is addressing at any depth (`request={"options": {"url": ...}}`); an `email` or
    `phone` argument only at the top: inside a payload it is the record being sent, not where
    the call goes (`body={"customer": {"email": ...}}`)."""
    if name is None:
        return None
    role = _arg_role(name)
    if role in ("recipient", "url", "host"):
        return role
    if role == "address":
        return role if depth == 0 else None
    if depth == 0 and str(name).lower() in _COMMAND_NAMES:
        return "command"
    return None


def split_call(arguments):
    """(content text, outside destinations) for one call's bound arguments.

    Content is every value except where the call is addressed (see `_role_at`): a recipient, a
    top-level address argument, a host argument, and the host of a URL argument (the rest of that
    URL is content, since a query string carries data). A destination is only where the call
    goes: those arguments, a top-level value that is only a URL, every URL in a command argument
    (`cd /tmp && curl ... https://x`), and the URL of text that IS a sending command (`curl ...`,
    `bash -c "curl ..."`). A URL mentioned in other text, a quoted command included, is content."""
    content, outside = [], []

    def note_host(host):
        if host and not _is_inside_host(host):
            outside.append(_bare_host(host))

    def visit(name, value, depth):
        role = _role_at(name, depth)
        if role is None and depth < _MAX_DEPTH:
            if isinstance(value, dict):
                for k, v in list(value.items())[:5000]:
                    visit(k, v, depth + 1)
                return
            if isinstance(value, (list, tuple)):
                for v in list(value)[:5000]:
                    visit(None, v, depth + 1)
                return
        text = _text_of(value)[:MAX_SCAN_CHARS]
        if role in ("recipient", "address"):
            for dom in _EMAIL_DOMAIN_RE.findall(text):
                note_host(dom)
            return
        if role == "host":
            note_host(text)
            return
        if role == "url":
            m = _URL_RE.search(text)
            if m:
                note_host(m.group(1))
                content.append(text[m.end():])
            else:
                content.append(text)
            return
        if (role == "command" or _SENDING_COMMAND_RE.match(text)
                or (depth == 0 and _URL_ONLY_RE.match(text))):
            for m in _URL_RE.finditer(text):
                note_host(m.group(1))
        content.append(text)

    for name, value in (arguments or {}).items():
        visit(name, value, 0)
    return "\n".join(content), outside


def recipient_domains(arguments, limit=8):
    """The distinct, sorted domains of the email addresses a call is addressed to (`to=`,
    `message={"to": ...}`, `toRecipients[].emailAddress.address`), inside the company or not.
    Domains only, never the address. [] when the call names no recipient. Never raises."""
    found = set()

    def visit(name, value, depth):
        if depth > _MAX_DEPTH or len(found) >= limit:
            return
        role = _role_at(name, depth)
        if role in ("recipient", "address"):
            for dom in _EMAIL_DOMAIN_RE.findall(_text_of(value)[:MAX_SCAN_CHARS]):
                found.add(dom.lower().rstrip("."))
            return
        if isinstance(value, dict):
            for k, v in list(value.items())[:5000]:
                visit(k, v, depth + 1)
        elif isinstance(value, (list, tuple)):
            for v in list(value)[:5000]:
                visit(None, v, depth + 1)

    try:
        for name, value in (arguments or {}).items():
            visit(name, value, 0)
    except Exception:
        return []
    return sorted(found)[:limit]


def find_leak(run_values, arguments, *, name_sends, flagged_sends):
    """The first remembered value this call would send out, as a dict, or None.

    The call must send out (a destination outside the company, a sending name, or the developer's
    flag) and carry the value in its content."""
    if not run_values:
        return None
    content, outside = split_call(arguments)
    if outside:
        how = f"to `{outside[0]}`, outside the company"
    elif flagged_sends:
        how = "(a tool marked as sending data out)"
    elif name_sends:
        how = "(a tool whose name says it sends data out)"
    else:
        return None
    if not content:
        return None
    text = _norm_text(content)
    runs = None
    for (mode, key), (kind, source, masked) in reversed(run_values.items()):
        if mode == "text":
            if key in text:
                return {"kind": kind, "source_tool": source, "masked": masked, "how": how}
        else:
            if runs is None:
                runs = [_digits(r) for r in _DIGIT_RUN_RE.findall(content)]
            # A country code on either side: `+1 415 555 1234` leaving after `(415) 555-1234`
            # was read, or the other way round.
            if any(r == key or (len(r) >= 7 and abs(len(r) - len(key)) <= 3
                                and (r.endswith(key) or key.endswith(r))) for r in runs):
                return {"kind": kind, "source_tool": source, "masked": masked, "how": how}
    return None


_SECRET_KINDS = {"AWS key", "private key", "GitHub token"}


def category(leak):
    """The block category the local record and the session summary count under."""
    kind = leak["kind"]
    return "SECRETS_LEAK" if kind in _SECRET_KINDS or kind.startswith("secret field") else "PII_EXFILTRATION"


def _describe(leak):
    kind = leak["kind"]
    if kind == "flagged by the developer":
        return "text marked as sensitive"
    if kind.startswith(("field ", "secret field ")):
        return f"the value of {kind}"
    return f"{'an' if kind[:1].lower() in 'aeiou' else 'a'} {kind}"


def challenge(leak, exit_tool):
    """What the agent is told when the rule stops a call. It names the kind of value and the two
    tools, never the value, masked or not: the local record keeps this text."""
    return (f"This call would send {_describe(leak)}, which `{leak['source_tool']}` returned "
            f"earlier in this run, out through `{exit_tool}` {leak['how']}.")


def safe_path(leak):
    """A path that runs. The value itself is stopped wherever it goes, its owner included, so the
    path is to leave it out or name it without it. Names no value: the local record keeps it."""
    kind = leak["kind"]
    if kind in _SECRET_KINDS or kind.startswith("secret field"):
        return "Leave the secret out of the call: it does not leave the company in any form."
    if kind in _DIGIT_KINDS:
        return "Leave the number out of the call, or refer to it by its last four digits."
    if kind == "email":
        return ("Leave the address out of the call, or refer to the person without it, such as "
                "by name.")
    return "Leave the value out of the call, or describe it without quoting it."
