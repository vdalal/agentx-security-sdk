"""WHICH TEXT IN A CALL IS A STATEMENT. The one place both doors ask that question.

🔴 THIS MODULE IS THE SHARED QUESTION, NOT A SHARED VERDICT, AND THE DISTINCTION IS THE
ARCHITECTURE. Two doors need to agree on *which argument of a call carries a statement*. They
deliberately do NOT agree on *whether that statement is dangerous*: the keyless shield answers
with regex, the gateway answers with a real parser on top, and the gateway is allowed to be
sharper. So what lives here is the name rule and the text extraction. No detector, no policy,
no verdict.

Before this module the gateway could not ask the question at all. It was handed a flattened
text blob with the argument names already discarded, so it read a ticket note as SQL and blocked
ordinary English sentences ("delete bob from the attendee list") for paying customers while the
keyless shield correctly allowed them. Closing that is what this module is for.

⚠️ THE GATEWAY DOES NOT LOAD THIS FILE. An earlier draft of this docstring said it path-loaded
it at boot, which was the plan and is not what shipped: the gateway's image is built from its own
directory as the build context, so no file from this package can enter that image at all. It
therefore carries its OWN reader for the same question, and the two are held to the same ANSWERS
by a corpus rather than to the same source. Believing the retired claim would lead a maintainer
to treat this module as the single authority and edit only here.

🔴 STDLIB ONLY, AND NO RELATIVE IMPORTS. EVER. Being honest about where the rule bites, because
an earlier draft justified it with a path-load that does not happen: nothing in the product loads
THIS file by path today. What is real is the SIBLING case. `scripts/assurance_report.py`
path-loads `db.py` to read two constants without running `agentx_sdk/__init__.py` (which imports
`decorators` and everything under it), and a path-loaded module has NO package context. During
the change that created this file exactly that import was added to `db.py`, it broke that script,
and the failure surfaced as an unrelated drift test complaining about agent ids. `db.py` reaches
THIS module, so an import added here travels straight back into that path-load.
`sdk_tests/test_statement_module_is_importable_alone.py` pins THIS file's half. ⚠️ The `db.py`
half -- that its imports must stay function-local -- has no test of its own; it is caught
incidentally by a drift test whose message talks about agent ids, which is why the breakage was
confusing the first time. Do not "tidy" an import into either file to satisfy a linter.

Keeping the rule also keeps the shared-file route open if the gateway's build context ever moves,
which is the only thing that would let both doors read one copy.

That constraint is why this module is the LEAF: `_name_tokens` lives here and `db.py` imports it
from here, rather than this file reaching sideways into `db`.

🔴 AND IT MUST STAY SIDE-EFFECT FREE. Measured: importing the package in a clean directory
creates no files, makes no network call and leaves nothing behind. Importing this module must
never start doing so, because it is read by tooling whose whole job is to describe a tree without
touching it -- a report generator that wrote a ledger into a customer's repo as a side effect of
describing itself is a defect this project has already had once.
"""
import datetime
import decimal
import json
import math
import numbers
import os
import re
import uuid
from urllib.parse import unquote


def _name_tokens(raw):
    """Split identifier-ish text into whole lowercase tokens. Pure. Returns a SET.

    🔴 ONE COPY, BECAUSE THE RULE WAS LEARNED EXPENSIVELY. `_classify_target` originally tested
    `needle in haystack` and read tool names like an anagram -- `send_feedback` classified as DB
    because "fee(db)ack" contains "db". The fix was to compare whole TOKENS, and it is the whole
    correctness of every name-matching rule that uses it. A second matcher written from scratch
    (the amount-hint matcher) would have had to re-learn it, and `discount_id` matching "count" is
    the same bug wearing a different hat. So every caller comes through here.

    camelCase is a boundary too: MCP servers and JS tools are routinely `sendHttpRequest`, which
    is ONE token under a punctuation-only split. Split before lowercasing, because the case IS
    the boundary.

    ⚠️ THERE IS A SECOND, DELIBERATELY DIFFERENT TOKENIZER IN THIS PACKAGE, AND THEY MUST NOT BE
    "CONSOLIDATED" CASUALLY. `decorators._name_tokens` returns a LIST and also splits
    letter<->digit runs (`s3upload` -> `s`, `3`, `upload`); this one returns a SET and does not,
    so `s3upload` stays one token. The callers depend on both differences: this function's result
    is intersected with a frozenset (`&`), which a list does not support, and splitting digits
    here would change `_classify_target`'s answers (`s3` stops being a token). Reconciling them
    is a behaviour change that needs its own corpus, filed rather than smuggled into this move.
    """
    raw = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", str(raw or ""))
    return {t for t in re.split(r"[^a-z0-9]+", raw.lower()) if t}


# The argument names that DECLARE their value to be a statement, so a grammar-reading floor may
# read it. Everything else in a call is prose and is left alone.
#
# What it gives up, stated: a statement smuggled into a text field
# (`profile_notes="...; DROP TABLE users;"`) is not read, because whether that field is
# ever pasted into SQL is a fact about the tool's insides the floor cannot see. That trade
# is deliberate: the text an agent writes for a living is left alone.
#
# The vocabulary is the one tools USE, singular and plural: the reference filesystem server's
# `read_multiple_files(paths=...)` and `move_file(source, destination)`, an HTTP tool's
# `target`. A name outside it reads as prose, so a missing word is a floor gone quiet on a
# real server; the first cut had `path` and not `paths`, `url` and not `target`, and lost
# the path floor on two of the filesystem server's own tools.
_STATEMENT_ARG_NAMES = frozenset((
    "sql", "query", "queries", "statement", "statements", "stmt", "code",
    "command", "commands", "cmd", "shell", "script", "scripts", "bash", "exec", "execute",
    "args", "argv", "program", "executable",
    "path", "paths", "file", "files", "filename", "filenames", "filepath", "filepaths",
    "dir", "dirs", "directory", "directories",
    "source", "sources", "src", "destination", "destinations", "dest", "dst",
    "target", "targets",
    "url", "urls", "uri", "uris", "endpoint", "endpoints", "host", "hosts", "http", "fetch",
))


_WIRE_DEPTH = 32
_WIRE_DROP = object()


def _decimal_wire_text(value):
    """A Decimal as text that can be read as ONE number: written out in full ("1.5E+3" is
    "1500"), and one with exactly three places after the point and up to three before gets a
    fourth, "0" ("1.500" is "1.5000"). The gateway holds text such as "1.500" because a person
    may have meant one thousand five hundred; a Decimal is exact, so its text must not read as
    that guess (review). The value is unchanged, and the old text stays inside the new one, so a
    rule's words still find it. Never a float, which would change the amount."""
    # 🔴 Not written out past 1000 places either way: `1E+100000000` became a hundred million
    # characters, the request failed, the client read an unreachable gateway and fail-open ran
    # the tool (scoped review of 6a614901). As its short text the gateway holds it as unreadable.
    # Not lower: at 30, `1E-31` (about 0, which ran) was held as not a number (last review).
    if not value.is_finite() or abs(value.adjusted()) > 1000:
        return str(value)
    text = format(value, "f")
    if re.fullmatch(r"-?[1-9]\d{0,2}\.\d{3}", text):
        text += "0"
    return text


def _wire_leaf(value):
    """ONE value that is not a dict, list, tuple or set, as JSON can carry it, or `_WIRE_DROP`.

    🔴 THE ONE LIST OF LEAF TYPES. `args`, `query` and `rule_args` all come through here, so a type
    added for one reaches the others (two hand-kept lists had already parted: numpy and Fraction
    reached `rule_args` and not `args`). A Decimal, a date, a time and a UUID go as their text; a
    non-finite float as its text (`requests` encodes with allow_nan=False, so `inf` raised there,
    the client read an unreachable gateway and fail-open ran the tool); any other real number
    (numpy's int64 and float64, a Fraction) as the number it is. Anything else (bytes, a
    timedelta, a client, a database connection) is `_WIRE_DROP`: its `str` is not an argument a
    rule names, and can carry a password in a DSN."""
    if value is None or isinstance(value, (bool, int, str)):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else str(value)
    if isinstance(value, decimal.Decimal):
        return _decimal_wire_text(value)
    if isinstance(value, (datetime.date, datetime.time, uuid.UUID)):
        return str(value)
    # A path as the text the OS reads (`os.fspath`), in `args` and `query` alike: left out of
    # `args` and written into `query` as its `str`, a Windows path there was JSON-escaped
    # (`C:\\\\Users\\\\...`) and the path check missed `.aws\\credentials`, which main's
    # `PureWindowsPath('C:/...')` spelling caught; and the two sides differed, so prose beside a
    # path was read as a statement (scoped review of c3b5fa21).
    if isinstance(value, os.PathLike):
        try:
            text = os.fspath(value)
        except Exception:
            return _WIRE_DROP
        return text if isinstance(text, str) else _WIRE_DROP
    if isinstance(value, numbers.Integral):
        return int(value)
    if isinstance(value, numbers.Real):
        f = float(value)
        return f if math.isfinite(f) else str(f)
    return _WIRE_DROP


def _json_key(key):
    """A dict key spelled as `json.dumps` spells it (`None` is "null", `True` is "true"), so a
    call's keys read the same as they did before this walk built the dict."""
    if isinstance(key, str):
        return key
    if key is None:
        return "null"
    if isinstance(key, bool):
        return "true" if key else "false"
    if isinstance(key, (int, float)):
        try:
            return json.dumps(key)
        except Exception:
            pass
    return str(key)


def _wire_tree(value, depth=0, done=None, too_deep=None, text=False):
    """`value` as JSON can carry it, or `_WIRE_DROP`: each leaf by `_wire_leaf`, a dict with its keys
    spelled as JSON spells them, a tuple as a list, a set as a list sorted by `repr` (two calls with
    the same set send the same text). A leaf JSON cannot carry is LEFT OUT, alone: before, one such
    leaf beside an amount (`payment={"amount": 250000, "memo": b"x"}`) made the whole object
    unencodable, `args` dropped it, amount and all, and the transfer floor read 0 and ran the call.

    `text=True` is `query`, the text the keyword and path checks read: there such a leaf STAYS as
    it is, for the caller to write as its `str` (`[Path("/etc/passwd")]`, `[b"rm -rf /"]` reached
    that text before this walk, and left out they reached no check: review of de7a47df).

    Each container is walked once, so a graph of shared or looping references costs its size and
    not its paths; one inside itself is left out where it repeats.

    Past `_WIRE_DEPTH`, a container is `too_deep` (`_WIRE_DROP` for `rule_args`) or, by default,
    goes on AS IT WAS: a statement nested 40 deep reached `query` before this walk existed, so it
    must not be cut there now."""
    if not isinstance(value, (dict, list, tuple, set, frozenset)):
        wired = _wire_leaf(value)
        return value if text and wired is _WIRE_DROP else wired
    if depth > _WIRE_DEPTH:
        return value if too_deep is None else too_deep
    done = {} if done is None else done
    if id(value) in done:
        return done[id(value)]
    done[id(value)] = _WIRE_DROP  # while it is being walked: a value inside itself is left out
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            key = _json_key(k)
            if text and key in out:
                # Two keys that spell the same (`1` and `"1"`): rebuilt, the second overwrote the
                # first, and `{1: "rm -rf /", "1": "ls"}` left the command out of the text the
                # checks read. As it was, `json.dumps` writes both (scoped review of c3b5fa21).
                done[id(value)] = value
                return value
            w = _wire_tree(v, depth + 1, done, too_deep, text)
            if w is not _WIRE_DROP:
                out[key] = w
    else:
        items = sorted(value, key=repr) if isinstance(value, (set, frozenset)) else value
        out = [w for w in (_wire_tree(v, depth + 1, done, too_deep, text) for v in items)
               if w is not _WIRE_DROP]
    done[id(value)] = out
    return out


def _rule_wire_tree(value):
    """`rule_args`: the same walk, with anything past the depth limit left out."""
    return _wire_tree(value, too_deep=_WIRE_DROP)


def _wire_value(value):
    """ONE argument value in the shape the gateway is sent (`_wire_tree`). Used by the flattened
    text below AND the decorator's `args`, so the gateway's "is `query` exactly these arguments?"
    comparison sees the same value on both sides; `rule_args` is built by the same walk.

    A tuple or set used to reach the gateway not at all: this function returned None for it, so
    `crawl(urls=("https://x/",))` sent only a placeholder and no gateway check saw the address.

    A `Decimal` is how Python holds money, and JSON cannot encode one, so it was dropped from both
    `args` and the text: `refund(amount=Decimal("250000"), currency="usd")` read as 0 on the
    gateway's transfer floor and ran where the int form is held. As text the floor reads it.
    Never raises: an argument that is itself a leaf JSON cannot carry, or one this cannot walk,
    goes on as it was, for the encoder to accept or drop."""
    try:
        wired = _wire_tree(value)
    except Exception:
        return list(value) if isinstance(value, tuple) else value
    return value if wired is _WIRE_DROP else wired


def _coerce_arg_value(value):
    """Coerce ONE argument value into the text the keyless keyword shield scans, or
    None to skip it. The single home for value flattening, shared by the decorator's
    arg loop and the agentx-mcp proxy's _flatten_call so the two feeders can't drift:
    str as-is, bool/int/float stringified, dict/list (and a tuple or set, as a list) as
    compact JSON, with anything inside that JSON cannot carry (a path, bytes) written as its
    `str`, never left out: this is what the checks read."""
    original = value
    try:
        value = _wire_tree(value, text=True)
    except Exception:
        value = list(value) if isinstance(value, tuple) else value
    if isinstance(value, str):
        return value
    if isinstance(value, (bool, int, float)):   # bool is an int subclass; str() is identical
        return str(value)
    if isinstance(value, (dict, list)):
        try:
            # ensure_ascii=False so non-ASCII codepoints survive into the flattened text
            # the shield scans. Otherwise json would escape an invisible-Unicode carrier (a
            # bidi override / Tags-block char) smuggled inside a NESTED arg into \uXXXX TEXT,
            # slipping it past _detect_invisible_unicode. The ASCII-pattern detectors (keyword
            # / SSRF / destructive-SQL) are unaffected -- their targets were already ASCII.
            return json.dumps(value, ensure_ascii=False, default=str)
        except Exception:
            return str(original)
    return None


def _statement_text(arguments, tool_name=None, head=None, declared=None):
    """The declared statement text of one call, joined. See `_statement_parts`."""
    return " ".join(_statement_parts(arguments, tool_name=tool_name, head=head, declared=declared))


def _statement_parts(arguments, tool_name=None, head=None, declared=None):
    """The text the grammar-reading floors may read for ONE call: `head` (the proxy puts
    the tool name in front, the decorator does not), then the values of the arguments whose
    NAME declares a statement, in argument order, or whose name is in `declared` (what the
    tool's schema said, see `_schema_declared_args`). The read set is the STRING LEAVES under
    a declared name, at any depth, each as its own text: a list of paths is read path by
    path. A dict under a declared name is read by its own keys when any key declares itself
    (`files=[{path, content}]` reads each `path` and no `content`; `command={"program",
    "args"}` reads `args`), and reads all its string leaves when none does (`query={"text",
    "values"}`, the statement in structured form). Known and recorded rather than fixed, four
    review rounds in: that gate is by key NAME, not by kind family, so a `dir` or `host`
    sibling silences a `line`/`text` leaf, and a file item keyed `name` instead of `path` has
    its `content` read; the rule that ends this is the schema declaring an argument to be
    TEXT, which is not built. An undeclared dict is walked for the same reason (a nested
    `params.sql` is read); an undeclared list of strings is prose and is not. Returns
    "" when nothing is declared, so a call made of prose reads as empty to every rail rather
    than as a sentence to scan. (`_statement_parts` returns the same texts as a list, empty
    when nothing is declared; `_statement_text` joins it.)

    One fallback, and it is still a declaration: a tool whose own NAME carries one of the
    tokens (`run_sql`, `execute_query`, `shell_exec`) and declares no argument by name has
    declared all of its string arguments (`run_sql(q=..., db=...)` reads both).

    Pure. A value whose json and str both raise is skipped, as `_coerce_arg_value`'s callers
    already do. A dict inside itself, a value too deep to walk, or a mapping that raises when read
    raises: the tool does not run, and the call is never checked half read."""
    parts = []
    if head:
        parts.append(str(head))
    by_schema = declared or ()

    def _leaves(value):
        # The string leaves under a declared name, each its own text: a list of paths is
        # its paths one by one (never a JSON dump, which doubles every backslash and hid
        # `C:\Users\me\.aws\credentials` from the path floor); a dict inside it is read by
        # ITS OWN keys (`files[i].path` is read, `files[i].content` is not: GitHub's
        # `push_files(files=[{path, content}])` carried prose back into the rails when a
        # declared value was dumped whole).
        if isinstance(value, dict):
            # A dict with a declaring key of its own is read by those keys (`files[i]` has
            # `path`, so `content` stays out). One with none is the statement itself in
            # structured form, `query={"text": "DROP TABLE users", "values": []}` (the
            # node-postgres shape), and every string leaf in it is read; reading it by
            # keys read nothing, which round 3 of the review found.
            if any(_name_tokens(str(k)) & _STATEMENT_ARG_NAMES for k in value):
                _walk(value, False)
            else:
                for item in value.values():
                    _leaves(item)
        elif isinstance(value, (list, tuple)):
            for item in value:
                _leaves(item)
        else:
            _append(value)

    def _walk(mapping, top):
        for name, value in mapping.items():
            is_statement = bool(_name_tokens(str(name)) & _STATEMENT_ARG_NAMES) or (
                top and name in by_schema)
            if is_statement:
                _leaves(value)
            elif isinstance(value, dict):
                _walk(value, False)
            elif isinstance(value, (list, tuple)):
                for item in value:
                    if isinstance(item, dict):
                        _walk(item, False)

    def _append(value):
        try:
            coerced = _coerce_arg_value(value)
        except Exception:
            return
        if coerced is not None:
            parts.append(coerced)

    if isinstance(arguments, dict):
        before = len(parts)
        _walk(arguments, True)
        if len(parts) == before and tool_name and (
                _name_tokens(str(tool_name)) & _STATEMENT_ARG_NAMES):
            # A tool that names its kind (`run_sql`, `execute_query`) and declares no
            # argument by name has declared ALL its strings: `run_sql(q=..., db=...)` reads
            # both (`db="prod"` matches no rail, so nothing is lost). The first cut read
            # exactly one string and nothing when there were two, which lost the SQL floor
            # on that tool the moment it took a second string.
            # A list of strings counts too: `run_sql(stmts=["DROP TABLE users"])` declared
            # nothing on either door before. A dict is still walked by `_walk` only.
            for v in arguments.values():
                if isinstance(v, str):
                    _append(v)
                elif isinstance(v, (list, tuple)):
                    for item in v:
                        if isinstance(item, str):
                            _append(item)
    # A list, one text per declared value: a reader that must not let one argument's value
    # complete another's (a command beside a `directory`) reads them apart.
    return parts


# A host is read only from inside an explicit scheme://URL, never from a bare token, so a
# number or a word elsewhere in the text cannot become a host. The keyless SSRF floor in
# `decorators` asks this and re-exports the pattern under the same name; the gateway carries
# a byte-identical copy, and a consistency test holds the two together.
_SSRF_URL_RE = re.compile(r"\b[a-z][a-z0-9+.\-]*://([^\s/'\"<>]+)", re.IGNORECASE)


# For http, https, ws, wss and ftp, the URL parser browsers and Node `fetch` use skips ANY run of
# `/` and `\` after the colon: `http:\\h/`, `http:/h/` and `http:///h/` all go to `h`. A run of
# ONE OR MORE is read as `://` before either host reader looks. Left alone on purpose: no slash at
# all (`http:8080` in ordinary text would read as an address) and `file:` (`file:///etc/passwd`
# has no host). Those parsers also delete every tab, CR and LF before reading, so the run may
# carry them (`https:<TAB>//h` goes to `h`); it still needs one real slash. The gateway carries
# a byte-identical copy.
_URL_SLASH_RUN_RE = re.compile(r"(?<![a-z0-9+.\-])(https?|wss?|ftp):[\t\r\n]*[/\\][/\\\t\r\n]*",
                               re.IGNORECASE)


def _url_slashes(text):
    return _URL_SLASH_RUN_RE.sub(r"\1://", text)


# The authority runs to the first whitespace, `/`, `?` or `#`. Group 1 stops earlier, at a
# quote, an angle bracket or a backslash; group 2 is whatever follows that stop, up to the
# same end. Group 2 is empty for an ordinary URL and for `"https://a.com"` in a shell command.
# Group 3 is any text glued on after a tab, CR or LF: clients delete those three characters
# before parsing, so that text is part of the host they send to.
_DEST_URL_RE = re.compile(
    r"\b[a-z][a-z0-9+.\-]*://([^\s/?#'\"<>\\]*)([^\s/?#]*)((?:[\t\r\n]+[^\s/?#]+)*)",
    re.IGNORECASE)


def destination_url_hosts(text):
    """The host each scheme://URL in `text` is sent to, for a check that ALLOWS on it.

    🔴 THE RULE: WHERE HTTP CLIENTS DISAGREE ABOUT THE HOST, THE HOST IS UNREADABLE. Two
    rounds of review each found a URL whose host this function read one way and a real client
    read another (`https://evil.com?x=@api.github.com`, then `https://api.github.com\\@evil.com`
    and `https://api.github.com'@evil.com`), each an allowlist bypass. Clients themselves
    disagree on `\\`, quotes and angle brackets (httpx, urllib3 and curl send the backslash form
    to different hosts), so no single reading is right. An `@` after one of those characters
    therefore yields "" (unreadable), which the allowlist refuses for any agent it limits.
    So does text glued on after a tab, CR or LF: clients delete those characters, so
    `https://api.github.com<TAB>@evil.com` goes to `evil.com` and
    `https://api.github.com<TAB>evil.com` to `api.github.comevil.com`.

    `?` and `#` end the authority before the `user:password@` part is dropped, so an `@` in a
    query or fragment is never a userinfo. The ledger reads this too, so a query value never
    reaches it. The SSRF floor still reads `url_hosts`, deliberately: changing what it decodes
    would move one door's verdicts without the other's. Returned as written; the caller
    normalises."""
    text = _url_slashes(str(text or ""))
    if "://" not in text:
        return []
    hosts = []
    for m in _DEST_URL_RE.finditer(text):
        if "@" in m.group(2) or m.group(3):
            hosts.append("")                  # see the rule above: unreadable, fails closed
            continue
        netloc = m.group(1).rsplit("@", 1)[-1]
        if netloc.startswith("["):            # bracketed IPv6: [::1]:port
            hosts.append(netloc[1:].split("]")[0])
        else:
            hosts.append(netloc.split(":")[0])
    return hosts


def url_hosts(text):
    """The host of every scheme://URL in `text`, in order and exactly as written.

    The `user:password@` part is dropped, a bracketed IPv6 address is unwrapped, and a port
    is cut. The result is NOT lowercased or otherwise cleaned, because the SSRF floor decodes
    it as written.

    Up to two readings per URL, the same two the gateway's `_hosts_in_urls` yields, so the two
    doors judge the same hosts. Reading 1 keeps a `?` or `#` straight after the host attached
    (`http://2130706433?x=1` gives `2130706433?x=1`, which decodes to nothing). Reading 2 cuts
    at `?`, `#` or `\\` before dropping the userinfo, cuts trailing punctuation and
    percent-decodes, and is added only when it differs, so it can add a block and never remove
    one. Any caller that STORES a host or ALLOWS on one must use `destination_url_hosts`
    instead; this is for the SSRF floor only."""
    text = _url_slashes(str(text or ""))
    if "://" not in text:
        return []
    hosts = []
    for m in _SSRF_URL_RE.finditer(text):
        raw = m.group(1)
        netloc = raw.split("@")[-1]
        if netloc.startswith("["):            # bracketed IPv6: [::1]:port
            host = netloc[1:].split("]")[0]
        else:
            host = netloc.split(":")[0]
        hosts.append(host)
        cut = re.split(r"[?#\\]", raw, maxsplit=1)[0].split("@")[-1]
        if cut.startswith("["):
            host2 = cut[1:].split("]")[0]
        else:
            host2 = re.split(r"[()\[\]{},;|`]", cut.split(":")[0], maxsplit=1)[0]
            if "%" in host2:
                host2 = unquote(host2)
        if host2 and host2 != host:
            hosts.append(host2)
    return hosts
