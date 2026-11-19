"""Alert notification sinks for dbguard (Console and JSONL)."""

from __future__ import annotations

from datetime import datetime, timezone
import json
import logging
import os
from pathlib import Path
import sys
from typing import Protocol

from dbguard.detector import Verdict

MAX_REDACTED_BYTES = 2048
TRUNCATED_MARKER = "...[truncated]"


def _cap_redacted(text: str) -> str:
    """Cap redacted SQL string to 2048 bytes UTF-8 plus truncation marker."""
    encoded = text.encode("utf-8")
    if len(encoded) <= MAX_REDACTED_BYTES:
        return text

    # Cut to at most 2048 bytes at valid character boundary
    cut_bytes = encoded[:MAX_REDACTED_BYTES]
    cut_text = cut_bytes.decode("utf-8", errors="ignore")
    return cut_text + TRUNCATED_MARKER


class Notifier(Protocol):
    """Protocol for dbguard notification sinks."""

    def notify(self, v: Verdict) -> None:
        """Deliver alert notification for a verdict."""
        ...


class ConsoleNotifier:
    """Notifier that writes formatted alerts to console stream."""

    def __init__(self, stream=None) -> None:
        self.stream = stream if stream is not None else sys.stdout

    def notify(self, v: Verdict) -> None:
        """Format and print warning or destructive verdict."""
        if v.level not in ("warn", "destructive"):
            return

        capped_sql = _cap_redacted(v.stmt.redacted)
        reasons_str = ", ".join(v.reasons) if v.reasons else "none"
        msg = f"[{v.level.upper()}] score={v.score:.2f} reasons=({reasons_str}) sql: {capped_sql}\n"
        self.stream.write(msg)
        self.stream.flush()


class JsonlNotifier:
    """POSIX-hardened JSONL file notifier with 0600 permissions and O_NOFOLLOW."""

    def __init__(self, path: str | Path) -> None:
        if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "fchmod"):
            raise NotImplementedError("POSIX environment required (O_NOFOLLOW and fchmod)")

        self.path = str(path)
        # Verify or tighten permissions immediately
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
        try:
            st = os.fstat(fd)
            if (st.st_mode & 0o077) != 0:
                os.fchmod(fd, 0o600)
        finally:
            os.close(fd)

    def notify(self, v: Verdict) -> None:
        """Append one JSON line per alert to the file."""
        if v.level not in ("warn", "destructive"):
            return

        capped_sql = _cap_redacted(v.stmt.redacted)
        entry = {
            "level": v.level,
            "score": round(v.score, 4),
            "reasons": list(v.reasons),
            "redacted": capped_sql,
            "tables": list(v.stmt.tables),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        line = json.dumps(entry) + "\n"
        line_bytes = line.encode("utf-8")

        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
        try:
            st = os.fstat(fd)
            if (st.st_mode & 0o077) != 0:
                os.fchmod(fd, 0o600)
            os.write(fd, line_bytes)
        finally:
            os.close(fd)


def broadcast_notify(notifiers: list[Notifier], verdict: Verdict) -> None:
    """Deliver notification to all sinks; errors in one sink do not stop others."""
    for notifier in notifiers:
        try:
            notifier.notify(verdict)
        except Exception as e:
            logging.error("Notifier failed: %s", type(e).__name__)
