"""Which keys an agent holds, read from its own environment, never the key itself.

The SDK runs inside the agent's process, so it can see the credentials the agent was started
with. This module turns them into descriptions a person can read: the provider, the kind of
key, the environment variable it came from, its last four characters and a short id to tell two
keys apart. The value itself never leaves this module: nothing here returns it, logs it or
writes it.

Two rules decide what may be described:

* A **recognised key shape** (``KEY_KINDS``) is long and random, so its last four characters
  and a 12-character sha256 prefix say nothing usable about it.
* Anything else, a connection string's password above all, gets NO fingerprint and no hash: a
  short hash of a weak password can be guessed. A connection string is described by
  ``user@host`` only, and the user only when the string also carries a password (``user:pw@``),
  because a bare ``token@host`` puts the secret where the user goes.

``KEY_KINDS`` is pinned row for row to ``ts-sdk/src/credentials.ts`` by
``sdk_tests/test_credentials.py``: one table, two languages.
"""
from __future__ import annotations

import hashlib
import os
import re
from typing import Dict, List, Mapping, Optional

# (provider, kind, label, pattern, live). `pattern` must match the WHOLE value. `live` is True
# or False only where the provider issues test keys beside live ones (Stripe); None elsewhere.
# Prefixes are the providers' documented ones; each row says what a person reads. GitHub's
# installation tokens may be a ~520-character JWT with dots (`ghs_APPID_JWT`; GitHub's own regex
# `ghs_[A-Za-z0-9\.\-_]{36,}`), and Slack's rotating tokens put `xoxe.` before the same three
# prefixes. `[.]`, not `\.`, so the TypeScript copy is the same string. OpenAI's older keys are a
# bare `sk-`, a shape other providers issue too, so only one carrying `T3BlbkFJ` (base64 for
# "OpenAI", in every OpenAI key) is named OpenAI; any other `sk-` value is left undescribed.
KEY_KINDS = (
    ("Stripe", "secret_live", "live secret key", r"sk_live_[0-9A-Za-z]{20,}", True),
    ("Stripe", "secret_test", "test secret key", r"sk_test_[0-9A-Za-z]{20,}", False),
    ("Stripe", "restricted_live", "live restricted key", r"rk_live_[0-9A-Za-z]{20,}", True),
    ("Stripe", "restricted_test", "test restricted key", r"rk_test_[0-9A-Za-z]{20,}", False),
    ("AWS", "access_key_long_lived", "long-lived access key", r"AKIA[0-9A-Z]{16}", None),
    ("AWS", "access_key_temporary", "temporary access key", r"ASIA[0-9A-Z]{16}", None),
    ("GitHub", "pat_classic", "personal access token (classic)", r"ghp_[0-9A-Za-z]{36}", None),
    ("GitHub", "pat_fine_grained", "fine-grained personal access token", r"github_pat_[0-9A-Za-z_]{60,}", None),
    ("GitHub", "oauth", "OAuth token", r"gho_[0-9A-Za-z]{36}", None),
    ("GitHub", "app_installation", "app installation token", r"ghs_[0-9A-Za-z._-]{36,}", None),
    ("GitHub", "app_user", "app user token", r"ghu_[0-9A-Za-z]{36}", None),
    ("GitHub", "app_refresh", "app refresh token", r"ghr_[0-9A-Za-z]{36,}", None),
    ("OpenAI", "project_key", "project key", r"sk-proj-[0-9A-Za-z_-]{20,}", None),
    ("OpenAI", "service_account_key", "service account key", r"sk-svcacct-[0-9A-Za-z_-]{20,}", None),
    ("OpenAI", "admin_key", "admin key", r"sk-admin-[0-9A-Za-z_-]{20,}", None),
    ("OpenAI", "api_key_older", "API key (older format)", r"sk-[0-9A-Za-z]{20}T3BlbkFJ[0-9A-Za-z]{20}", None),
    ("Anthropic", "api_key", "API key", r"sk-ant-api[0-9]{2}-[0-9A-Za-z_-]{20,}", None),
    ("Anthropic", "admin_key", "admin key", r"sk-ant-admin[0-9]{2}-[0-9A-Za-z_-]{20,}", None),
    ("Slack", "bot_token", "bot token", r"(?:xoxe[.])?xoxb-[0-9A-Za-z-]{20,}", None),
    ("Slack", "user_token", "user token", r"(?:xoxe[.])?xoxp-[0-9A-Za-z-]{20,}", None),
    ("Slack", "app_token", "app-level token", r"(?:xoxe[.])?xapp-[0-9A-Za-z-]{20,}", None),
    ("Slack", "refresh_token", "refresh token", r"xoxe-[0-9A-Za-z-]{20,}", None),
    ("Slack", "workflow_token", "workflow token", r"xwfp-[0-9A-Za-z-]{20,}", None),
    ("Google", "api_key", "API key", r"AIza[0-9A-Za-z_-]{35}", None),
)

# Connection-string schemes and the provider each names. Pinned to the TypeScript side too.
CONNECTION_SCHEMES = (
    ("postgres", "Postgres"),
    ("postgresql", "Postgres"),
    ("mysql", "MySQL"),
    ("mongodb", "MongoDB"),
    ("mongodb+srv", "MongoDB"),
    ("redis", "Redis"),
    ("rediss", "Redis"),
)

# Run names that raise the "live key in a dev or test run" flag. The run's name is free text
# (AGENTX_ENVIRONMENT, ^[a-z0-9_-]{1,32}$); any name outside this set raises nothing.
DEV_ENVIRONMENTS = ("dev", "development", "test", "testing", "local", "staging")

_COMPILED = tuple((p, k, lbl, re.compile(pat), live) for p, k, lbl, pat, live in KEY_KINDS)
_SCHEMES = dict(CONNECTION_SCHEMES)
_SKIP_PREFIX = "AGENTX_"   # our own settings: the AgentX key is not one of the agent's powers


def _fingerprint(value: str) -> Dict[str, str]:
    return {"last4": value[-4:], "id": hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]}


def _connection(name: str, value: str) -> Optional[Dict[str, object]]:
    scheme, sep, rest = value.partition("://")
    provider = _SCHEMES.get(scheme.lower()) if sep else None
    if not provider:
        return None
    parts = re.split(r"[/?#]", rest, maxsplit=1)
    authority = parts[0]
    # An `@` after the first `/`, `?` or `#` makes the string ambiguous: a token holding one of
    # those characters, unencoded, would be cut at it and read as the host. Described as nothing.
    if len(parts) > 1 and "@" in parts[1]:
        return None
    user = ""
    if "@" in authority:
        userinfo, authority = authority.rsplit("@", 1)
        name_part, colon, password = userinfo.partition(":")
        if colon and password:                  # user:password@ -> the user is a name
            user = name_part
    # A key in the user place is not a name: MongoDB's AWS sign-in puts the access key id there
    # (`AKIA...:secret@host/?authMechanism=MONGODB-AWS`). The host alone is said (scoped review).
    if user and any(rx.search(user) for _p, _k, _l, rx, _lv in _COMPILED):
        user = ""
    host = authority.split(":", 1)[0] if not authority.startswith("[") else authority.split("]", 1)[0] + "]"
    if not host:
        return None
    account = "%s@%s" % (user, host) if user else host
    return {"provider": provider, "kind": "connection_string", "label": "connection string",
            "source": name, "live": None, "account": account}


def describe(name: str, value: str) -> Optional[Dict[str, object]]:
    """One environment variable as a held credential, or None when it is not one we recognise.

    The returned dict never contains `value`. Keys: provider, kind, label, source, live, and
    either last4 + id (a recognised key shape) or account (a connection string or AWS profile).
    """
    if not isinstance(value, str) or not name or name.startswith(_SKIP_PREFIX):
        return None
    v = value.strip()
    if not v:
        return None
    if name == "AWS_PROFILE":
        return {"provider": "AWS", "kind": "profile", "label": "named profile",
                "source": name, "live": None, "account": v}
    for provider, kind, label, rx, live in _COMPILED:
        if rx.fullmatch(v):
            return dict({"provider": provider, "kind": kind, "label": label, "source": name,
                         "live": live}, **_fingerprint(v))
    return _connection(name, v)


def held_in(environ: Mapping[str, str]) -> List[Dict[str, object]]:
    """Every recognised credential in `environ`, sorted by provider then variable name."""
    found = [d for d in (describe(k, v) for k, v in environ.items()) if d]
    return sorted(found, key=lambda d: (str(d["provider"]), str(d["source"])))


# --- which held key a tool uses, read from its source --------------------------------------
#
# A tool's source is read ONCE, when it is wrapped. Two kinds of evidence, and only these:
#   "reads"  the tool's own body reads the key's variable (os.environ[...], os.getenv(...)).
#   "client" the body uses a provider's client (calls it, or uses it as `client.x`), and the key
#            that client was given is shown BY THE CODE ITSELF: the variable read where it is made
#            (`OpenAI(api_key=os.environ["X"])`, `StripeClient(os.environ["X"])`) or passed per
#            call (`client.with_options(api_key=os.environ["X"])`), or, for OpenAI() / Anthropic()
#            given no key at all, the one variable that constructor reads (DEFAULT_ENV). Nothing
#            that depends on how else a library finds a key (a key set on the module, boto3's or
#            Google's own search order) is evidence. The same rule as the TypeScript SDK. Never
#            "the only key of that provider".
# Anything else is "not known": a call is never linked to a key by a guess.
#
# The source is PARSED (`ast`), never scanned as text: a syntax tree has no comments, keeps a
# docstring or any other string as a value rather than as names, and holds the decorator line
# apart from the body, so none of them can be read as evidence. Source that does not parse
# (a lambda's line, generated code) gives no evidence at all.

# A provider's PACKAGE, by its top-level name. A name in a tool is the provider's only when an
# import from that package bound it (`import stripe`, `from openai import OpenAI`, `import boto3
# as b`), in the tool's module or in the tool itself; a name nothing imported from the package
# (`from robots import motor`) is never the provider's, whatever it is called. The providers name
# the same strings KEY_KINDS and CONNECTION_SCHEMES use, so a hint can only ever point at a key
# this module can describe.
CLIENT_PACKAGES = (
    ("stripe", "Stripe"), ("boto3", "AWS"), ("aioboto3", "AWS"), ("botocore", "AWS"),
    ("openai", "OpenAI"), ("anthropic", "Anthropic"), ("slack_sdk", "Slack"), ("github", "GitHub"),
    ("google.generativeai", "Google"), ("google.genai", "Google"), ("googleapiclient", "Google"),
    ("psycopg", "Postgres"), ("psycopg2", "Postgres"), ("asyncpg", "Postgres"),
    ("pymysql", "MySQL"), ("MySQLdb", "MySQL"), ("mysql.connector", "MySQL"),
    ("pymongo", "MongoDB"), ("motor", "MongoDB"), ("redis", "Redis"),
)
_PACKAGES = dict(CLIENT_PACKAGES)

# The variables a CONSTRUCTOR reads when the code passes it no key, per its library's
# documentation, in the order the library tries them: the first one held is the one linked.
# Keyed by the exact constructor, never by provider (AzureOpenAI or AnthropicBedrock read other
# credentials). A constructor not listed reads none we can name, so it links nothing.
DEFAULT_ENV = (
    ("openai.OpenAI", ("OPENAI_API_KEY",)),
    ("openai.AsyncOpenAI", ("OPENAI_API_KEY",)),
    ("anthropic.Anthropic", ("ANTHROPIC_API_KEY",)),
    ("anthropic.AsyncAnthropic", ("ANTHROPIC_API_KEY",)),
)
_DEFAULTS = dict(DEFAULT_ENV)

# Keywords that never carry a key. The default is used only for a construction whose every
# argument is a literal or one of these: a `**`, a `*`, a variable or any other keyword
# (`default_headers` may carry an Authorization header) may be a key arriving another way.
NO_KEY_KWARGS = frozenset(("base_url", "timeout", "max_retries", "organization"))

# Keyword arguments that carry a credential. When a call passes one (or reads a variable in a
# positional argument), the key is what it passes, and the library's default is NOT used.
CREDENTIAL_KWARGS = frozenset((
    "api_key", "key", "token", "auth", "auth_token", "access_token", "login_or_token",
    "secret_key", "aws_access_key_id", "aws_secret_access_key", "aws_session_token",
    "password", "dsn", "url", "host", "credentials",
))
# Per module, read once: what each module-level name means (see _module_info).
_MODULES: Dict[str, Dict[str, tuple]] = {}


def _source(obj) -> str:
    import inspect
    try:
        return inspect.getsource(obj)
    except Exception:
        return ""


def _parse(src: str):
    import ast
    import textwrap
    try:
        return ast.parse(textwrap.dedent(src))
    except (SyntaxError, ValueError):
        return None


def _is_environ(node) -> bool:
    import ast
    return (isinstance(node, ast.Name) and node.id == "environ") or (
        isinstance(node, ast.Attribute) and node.attr == "environ"
        and isinstance(node.value, ast.Name) and node.value.id == "os")


def _first_text(args):
    import ast
    if args and isinstance(args[0], ast.Constant) and isinstance(args[0].value, str):
        return args[0].value
    return None


def _env_reads(nodes) -> List[str]:
    """Variable names read as `os.environ["X"]`, `os.environ.get("X")`, `os.getenv("X")` (or
    with `environ` / `getenv` imported by name)."""
    import ast
    found = set()
    for top in nodes:
        for n in ast.walk(top):
            name = None
            # A read only: `os.environ["X"] = ...` and `del os.environ["X"]` set or drop it.
            if isinstance(n, ast.Subscript) and isinstance(n.ctx, ast.Load) and _is_environ(n.value):
                key = n.slice.value if type(n.slice).__name__ == "Index" else n.slice   # py<3.9
                if isinstance(key, ast.Constant) and isinstance(key.value, str):
                    name = key.value
            elif isinstance(n, ast.Call):
                f = n.func
                if (isinstance(f, ast.Attribute) and f.attr == "get" and _is_environ(f.value)) or (
                        isinstance(f, ast.Name) and f.id == "getenv") or (
                        isinstance(f, ast.Attribute) and f.attr == "getenv"
                        and isinstance(f.value, ast.Name) and f.value.id == "os"):
                    name = _first_text(n.args)
            if name and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
                found.add(name)
    return sorted(found)


def _package_provider(module: Optional[str]) -> Optional[str]:
    """The provider whose package `module` (dotted) belongs to, or None."""
    if not module:
        return None
    parts = module.split(".")
    for i in range(len(parts), 0, -1):
        hit = _PACKAGES.get(".".join(parts[:i]))
        if hit:
            return hit
    return None


def _imports(stmts) -> Dict[str, Optional[tuple]]:
    """The names `stmts` bind by importing, each to (provider, dotted origin), or None when it is
    not a provider's (or two imports disagree). Only the statements given, not inside them."""
    import ast
    out: Dict[str, Optional[tuple]] = {}

    def put(name, value):
        out[name] = value if out.get(name, value) == value else None

    for n in stmts:
        if isinstance(n, ast.Import):
            for a in n.names:
                prov = _package_provider(a.name)
                origin = a.name if a.asname else a.name.split(".")[0]
                put(a.asname or a.name.split(".")[0], (prov, origin) if prov else None)
        elif isinstance(n, ast.ImportFrom):
            for a in n.names:
                if a.name == "*":
                    continue
                origin = "%s.%s" % (n.module, a.name) if n.module else a.name
                # `from google import genai` imports a provider's MODULE from a parent package.
                prov = None if n.level else (_package_provider(n.module) or _package_provider(origin))
                put(a.asname or a.name, (prov, origin) if prov else None)
    return out


def _bound_names(nodes) -> set:
    """Every name `nodes` bind themselves other than by importing: assignment targets (tuples,
    walrus, `for`, `with ... as`), parameters of the tool and of anything nested in it, nested
    `def` and `class` names, `except ... as` and `match` capture names."""
    import ast
    out = set()
    for top in nodes:
        for n in ast.walk(top):
            if isinstance(n, ast.Name) and isinstance(n.ctx, (ast.Store, ast.Del)):
                out.add(n.id)
            elif isinstance(n, ast.arg):
                out.add(n.arg)
            elif isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                out.add(n.name)
            elif isinstance(n, ast.ExceptHandler) and n.name:
                out.add(n.name)
            elif type(n).__name__ in ("MatchAs", "MatchStar") and getattr(n, "name", None):
                out.add(n.name)
            elif type(n).__name__ == "MatchMapping" and getattr(n, "rest", None):
                out.add(n.rest)
    return out


def _loaded(nodes) -> set:
    import ast
    return {n.id for top in nodes for n in ast.walk(top)
            if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load)}


def _module_level(body):
    """Statements at module level, through `if`, `try` and `with` blocks, not into functions."""
    import ast
    for stmt in body:
        yield stmt
        for field in ("body", "orelse", "finalbody", "handlers"):
            if isinstance(stmt, (ast.If, ast.Try, ast.With, ast.ExceptHandler)) or \
                    type(stmt).__name__ == "TryStar":
                yield from _module_level(getattr(stmt, field, []) or [])


# What a name means, as a tuple (kind, provider, extra, origin):
#   ("import", provider, None, origin) a provider's module or class, imported; `origin` is its
#       dotted name (`boto3`, `google.genai`, `openai.OpenAI`).
#   ("client", provider, (keys, defaults), None) a client made at module level: `keys` the
#       variables its making gave it, `defaults` the constructor default lists it falls back to.
# `keys` is a frozenset of names; `defaults` a frozenset of ordered tuples (first held wins).


def _chain(node):
    """(root name, [attributes]) of a call's target written straight from a name (`a(...)`,
    `a.b.c(...)`), or (None, []). A method on another call's result (`OpenAI(...).models.list()`)
    has no root here: that call is not a provider's, its inner `OpenAI(...)` is."""
    import ast
    attrs = []
    while isinstance(node, ast.Attribute):
        attrs.append(node.attr)
        node = node.value
    return (node.id, attrs[::-1]) if isinstance(node, ast.Name) else (None, [])


def _root(node):
    return _chain(node)[0]


def _plain(call) -> bool:
    """True when a construction visibly passes no key: every argument a literal, or a keyword
    known never to carry one. A `**`, a `*`, a variable or another keyword may be a key."""
    import ast
    for a in call.args:
        if not isinstance(a, ast.Constant):
            return False
    return all(k.arg is not None and k.arg in NO_KEY_KWARGS for k in call.keywords)


def _call_keys(call, m) -> tuple:
    """(keys, defaults) for a call on a provider's import `m`, shown by the code. A call that
    passes a key (a credential keyword, or a variable read in a positional argument) uses exactly
    what it passes; otherwise, only for a listed constructor that visibly passes no key, its one
    documented variable; otherwise nothing."""
    _, provider, _, origin = m
    passed = [k.value for k in call.keywords if k.arg in CREDENTIAL_KWARGS]
    positional_reads = _env_reads(list(call.args))
    if passed or positional_reads:
        return frozenset(_env_reads(passed) + positional_reads), frozenset()
    root, attrs = _chain(call.func)
    default = _DEFAULTS.get(".".join([origin] + attrs))
    if default and _plain(call):
        return frozenset(), frozenset([default])
    return frozenset(), frozenset()


def _uses(nodes, meaning) -> tuple:
    """(keys, defaults) the clients used in `nodes` were given. A name counts only where it is
    called or used as `name.x`; as an `except` type, an `isinstance` argument or an annotation it
    does not."""
    import ast
    keys, defaults = set(), set()
    overridden = set()   # `client.with_options(api_key=...)`: that use sends what it passes
    for top in nodes:
        for n in ast.walk(top):
            if isinstance(n, ast.Call):
                m = meaning.get(_root(n.func))
                if not m:
                    continue
                if m[0] == "client":
                    passed = [k.value for k in n.keywords if k.arg in CREDENTIAL_KWARGS]
                    if passed:
                        keys |= set(_env_reads(passed))
                        overridden.add(id(n.func))
                        continue
                    k, d = m[2]
                else:
                    k, d = _call_keys(n, m)
                keys |= k
                defaults |= d
    for top in nodes:
        for n in ast.walk(top):
            if isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name) \
                    and isinstance(n.ctx, ast.Load) and id(n) not in overridden:
                m = meaning.get(n.value.id)
                if m and m[0] == "client":
                    keys |= m[2][0]
                    defaults |= m[2][1]
    return frozenset(keys), frozenset(defaults)


def _outer_calls(value):
    """The calls a module-level value IS (`OpenAI(...)`, either side of `a if c else b`, the
    operands of `a or b`), never calls inside it (`boto3.client("ssm").get_parameter(...)` is a
    string read from AWS, not a client)."""
    import ast
    if isinstance(value, ast.Call):
        return [value]
    if isinstance(value, ast.IfExp):
        return _outer_calls(value.body) + _outer_calls(value.orelse)
    if isinstance(value, ast.BoolOp):
        return [c for v in value.values for c in _outer_calls(v)]
    if isinstance(value, ast.Await):
        return _outer_calls(value.value)
    return []


def _module_info(func) -> Dict[str, tuple]:
    import ast
    import sys
    name = getattr(func, "__module__", None) or ""
    if name not in _MODULES:
        mod = sys.modules.get(name)
        tree = _parse(_source(mod)) if mod is not None else None
        meaning: Dict[str, tuple] = {}
        if tree is not None:
            stmts = list(_module_level(tree.body))
            imported = _imports(stmts)
            for var, hit in imported.items():              # `import stripe`, `from openai import OpenAI`
                if hit:
                    meaning[var] = ("import", hit[0], None, hit[1])
            # Module-level clients. A name bound to a client in one place and to anything else
            # (another client, another value) in another means nothing; a constant (the `None` of
            # an optional import's fallback) is not a binding of a value. A `global` rebinding in
            # any function means the same.
            seen: Dict[str, set] = {}
            for stmt in stmts:                             # `client = OpenAI(api_key=...)`
                if not isinstance(stmt, (ast.Assign, ast.AnnAssign)) or stmt.value is None:
                    continue
                targets = stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]
                names = [t.id for t in targets if isinstance(t, ast.Name) and t.id not in imported]
                if not names or isinstance(stmt.value, ast.Constant):
                    continue
                makers = sorted({meaning[_root(c.func)][1] for c in _outer_calls(stmt.value)
                                 if _root(c.func) in meaning})
                result = (makers[0], _uses(_outer_calls(stmt.value), meaning)) if len(makers) == 1 else None
                for n in names:
                    seen.setdefault(n, set()).add(result)
            globals_ = {g for node in ast.walk(tree) if isinstance(node, ast.Global) for g in node.names}
            for n, results in seen.items():
                if len(results) == 1 and None not in results and n not in globals_:
                    provider, used = next(iter(results))
                    meaning[n] = ("client", provider, used, None)
        _MODULES[name] = meaning
    return _MODULES[name]


def tool_reads(func) -> Dict[str, list]:
    """What a tool's source says about the keys it uses: the variables its body reads ("env"), the
    variables the clients it uses were given ("client_env"), and the constructor defaults those
    clients fall back to ("client_default": lists in the library's order). Never the source text."""
    import ast
    import inspect
    none = {"env": [], "client_env": [], "client_default": []}
    target = inspect.unwrap(getattr(func, "func", func))   # a functools.partial wraps .func
    tree = _parse(_source(target))
    fn = tree.body[0] if tree is not None and tree.body else None
    if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return none
    # The body and the parameters' defaults; never the decorator list.
    nodes = list(fn.body) + list(fn.args.defaults) + [d for d in fn.args.kw_defaults if d is not None]
    # What each name means inside the tool: the module's names, minus any a function around the
    # tool binds (its free variables: not the module's), then the tool's own imports, then
    # anything else the tool binds, which shadows.
    meaning = dict(_module_info(target))
    for var in getattr(getattr(target, "__code__", None), "co_freevars", ()):
        meaning.pop(var, None)
    for var, hit in _imports([n for top in nodes for n in ast.walk(top)]).items():
        if not hit:
            meaning.pop(var, None)
        elif not (var in meaning and meaning[var][0] == "import" and meaning[var][3] == hit[1]):
            # A tool's own import of what the module already imported keeps the module's meaning
            # (and any key the module set on it); a new one starts with none set.
            meaning[var] = ("import", hit[0], None, hit[1])
    for var in _bound_names(nodes) | {a.arg for a in ast.walk(fn.args) if isinstance(a, ast.arg)}:
        meaning.pop(var, None)
    env = _env_reads(nodes)
    keys, defaults = _uses(nodes, meaning)
    return {"env": env, "client_env": sorted(keys - set(env)),
            "client_default": sorted(list(d) for d in defaults)}


def ref_of(d: Mapping[str, object]) -> str:
    """A held key's reference on the wire: its id, or `env:<variable>` when it has no id."""
    return str(d.get("id") or "env:%s" % d["source"])


def keys_used(reads: Mapping[str, List[str]], held_list: List[Mapping[str, object]]) -> List[Dict[str, str]]:
    """The held keys a tool's source links it to, each with how: "reads" or "client"."""
    out: Dict[str, str] = {}
    for d in held_list:
        if d["source"] in reads.get("env", ()):
            out[ref_of(d)] = "reads"
    for d in held_list:
        if d["source"] in reads.get("client_env", ()):
            out.setdefault(ref_of(d), "client")
    by_source = {}
    for d in held_list:
        by_source.setdefault(d["source"], d)
    for order in reads.get("client_default", ()):
        # The library reads these in order and uses the first that is set: link that one only.
        first = next((by_source[v] for v in order if v in by_source), None)
        if first is not None:
            out.setdefault(ref_of(first), "client")
    return [{"ref": r, "how": h} for r, h in sorted(out.items())]


_HELD: Optional[List[Dict[str, object]]] = None


def held() -> List[Dict[str, object]]:
    """This process's held credentials, read once and cached (the environment is read at most
    once per process; call ``forget()`` after changing it on purpose, as tests do)."""
    global _HELD
    if _HELD is None:
        _HELD = held_in(os.environ)
    return [dict(d) for d in _HELD]


def forget() -> None:
    global _HELD
    _HELD = None
    _SENT.clear()
    _NOTED.clear()


# The held list rides an agent's first call to the gateway, then at most once every
# RESEND_SECONDS, so a gateway that restarted learns it again without every call carrying it.
RESEND_SECONDS = 600
_SENT: Dict[str, float] = {}


def held_to_send(agent_id, now: Optional[float] = None) -> Optional[List[Dict[str, object]]]:
    """The held list when this agent's call should carry it, else None. Never raises. Due until
    a gateway has ANSWERED a call that carried it (`mark_sent`), so a first call that timed out
    does not leave the gateway without the list for RESEND_SECONDS."""
    import time
    try:
        now = time.monotonic() if now is None else now
        last = _SENT.get(str(agent_id))
        if last is not None and now - last < RESEND_SECONDS:
            return None
        return held() or None
    except Exception:
        return None


_NOTED: set = set()


def note_held(agent_id, environment, db_module) -> None:
    """Write this agent's held keys to the local ledger once per process (until a write lands,
    each call tries again: the ledger may not exist before the first call's own row). Never raises."""
    try:
        key = str(agent_id)
        if key in _NOTED:
            return
        if db_module.record_held_keys(key, held(), environment=environment):
            _NOTED.add(key)
    except Exception:
        pass


def mark_sent(agent_id, now: Optional[float] = None) -> None:
    """A gateway answered a call that carried this agent's held list."""
    import time
    _SENT[str(agent_id)] = time.monotonic() if now is None else now
