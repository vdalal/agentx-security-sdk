"""The SDK version is single-sourced in agentx_sdk/__init__.py; setup.py derives it
via a regex, and `agentx-mcp --version` reads it from there. These guard that the
three can't drift again (they did: `--version` shipped a stale 0.4.2 while the wheel
was 0.4.4) by catching a broken version line HERE, not in the founder's build."""
import os
import re

import agentx_sdk


def test_version_is_a_sane_string():
    v = agentx_sdk.__version__
    assert isinstance(v, str) and re.match(r"^\d+\.\d+", v), v


def test_setup_regex_resolves_the_same_version():
    """setup.py's _read_version() uses exactly this regex against __init__.py. If a
    reformat of the __version__ line breaks it, the wheel would build with the wrong
    version (or fail); catch it in the SDK suite instead."""
    init_py = os.path.join(os.path.dirname(agentx_sdk.__file__), "__init__.py")
    with open(init_py, encoding="utf-8") as f:
        match = re.search(r'^__version__\s*=\s*["\']([^"\']+)["\']', f.read(), re.M)
    assert match, "setup.py's version regex no longer matches __init__.py"
    assert match.group(1) == agentx_sdk.__version__
