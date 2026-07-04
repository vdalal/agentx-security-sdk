"""Regression guard for the Windows / piped-stream cold-start crash.

Before this fix, the SDK's first protected call printed a 🛡️ glyph to a
stream encoded with the legacy locale code page (cp1252 on default Windows,
or any piped/redirected run). That raised UnicodeEncodeError and aborted the
block *before* it returned — so a cold `pip install` demo died with a traceback
on Windows instead of blocking the DROP TABLE. `_ensure_utf8_console()` must
re-encode the stream to UTF-8 so protection never depends on the host code page.
"""

import io
import sys

import pytest

from agentx_sdk import decorators


def test_legacy_codepage_stream_is_reconfigured_to_utf8(monkeypatch):
    buf = io.BytesIO()
    legacy = io.TextIOWrapper(buf, encoding="cp1252")
    monkeypatch.setattr(sys, "stdout", legacy)

    # Precondition: the status glyph genuinely cannot be encoded as cp1252.
    with pytest.raises(UnicodeEncodeError):
        "🛡️".encode("cp1252")

    decorators._ensure_utf8_console()

    # Now the glyph must be writable without raising — the cold-path crash.
    sys.stdout.write("🛡️ AgentX intercepting")
    sys.stdout.flush()
    assert "utf" in (sys.stdout.encoding or "").lower()


def test_already_utf8_stream_is_left_untouched(monkeypatch):
    buf = io.BytesIO()
    utf8 = io.TextIOWrapper(buf, encoding="utf-8")
    monkeypatch.setattr(sys, "stdout", utf8)

    decorators._ensure_utf8_console()

    # No churn: still the same object, still UTF-8.
    assert sys.stdout is utf8
    assert "utf" in sys.stdout.encoding.lower()


def test_hardening_never_raises_on_odd_streams(monkeypatch):
    # A stream with no reconfigure(), and a missing stream, must both be safe.
    class _NoReconfigure:
        encoding = "cp1252"

    monkeypatch.setattr(sys, "stdout", _NoReconfigure())
    monkeypatch.setattr(sys, "stderr", None)

    decorators._ensure_utf8_console()  # must not raise
