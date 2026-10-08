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
import json
import re
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


def _coerce_arg_value(value):
    """Coerce ONE argument value into the text the keyless keyword shield scans, or
    None to skip it. The single home for value flattening, shared by the decorator's
    arg loop and the agentx-mcp proxy's _flatten_call so the two feeders can't drift:
    str as-is, bool/int/float stringified, dict/list as compact JSON."""
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
            return json.dumps(value, ensure_ascii=False)
        except Exception:
            return str(value)
    return None


def _statement_text(arguments, tool_name=None, head=None, declared=None):
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
    than as a sentence to scan.

    One fallback, and it is still a declaration: a tool whose own NAME carries one of the
    tokens (`run_sql`, `execute_query`, `shell_exec`) and declares no argument by name has
    declared all of its string arguments (`run_sql(q=..., db=...)` reads both).

    Pure; never raises on any argument shape (a value whose json and str both raise is
    skipped, as `_coerce_arg_value`'s callers already do)."""
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
            for v in arguments.values():
                if isinstance(v, str):
                    _append(v)
    return " ".join(parts)


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
