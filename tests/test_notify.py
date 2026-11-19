"""Tests covering Notifiers: Console and JSONL sinks, permissions, redaction safety, and truncation."""

import io
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

from dbguard.detector import Detector, Verdict
from dbguard.notify import ConsoleNotifier, JsonlNotifier, broadcast_notify
from dbguard.sqltok import parse


class TestNotify(unittest.TestCase):
    """Test suite for Notifiers (AC-11, AC-12, AC-18)."""

    def setUp(self) -> None:
        self.detector = Detector()
        self.tmpdir = tempfile.TemporaryDirectory()

    def tearDown(self) -> None:
        self.tmpdir.cleanup()

    def test_ac11_console_and_jsonl_output(self) -> None:
        """AC-11: Console and JSONL sinks output correct fields and exclude literals."""
        stream = io.StringIO()
        console = ConsoleNotifier(stream=stream)

        jsonl_path = Path(self.tmpdir.name) / "alerts.jsonl"
        jsonl = JsonlNotifier(jsonl_path)

        secret = "secret_password_123"
        sql = f"DROP TABLE users /* password is {secret} */"
        verdicts = self.detector.analyze(sql)
        self.assertEqual(len(verdicts), 1)
        v = verdicts[0]

        console.notify(v)
        jsonl.notify(v)

        console_out = stream.getvalue()
        # Ensure secret literal does NOT appear in console output
        self.assertNotIn(secret, console_out)
        self.assertIn("[DESTRUCTIVE]", console_out)

        # Ensure JSONL file created and formatted
        self.assertTrue(jsonl_path.exists())
        lines = jsonl_path.read_text(encoding="utf-8").strip().splitlines()
        self.assertEqual(len(lines), 1)
        entry = json.loads(lines[0])

        self.assertEqual(entry["level"], "destructive")
        self.assertIn("users", entry["tables"])
        self.assertNotIn(secret, entry["redacted"])
        self.assertNotIn(secret, json.dumps(entry))

    def test_ac11_file_permissions(self) -> None:
        """AC-11: New files have mode 0600; existing 0644 files are tightened to 0600."""
        # New file
        p1 = Path(self.tmpdir.name) / "new_alerts.jsonl"
        JsonlNotifier(p1)
        mode1 = stat.S_IMODE(os.stat(p1).st_mode)
        self.assertEqual(mode1, 0o600)

        # Existing 0644 file
        p2 = Path(self.tmpdir.name) / "existing_alerts.jsonl"
        p2.write_text("", encoding="utf-8")
        os.chmod(p2, 0o644)
        self.assertEqual(stat.S_IMODE(os.stat(p2).st_mode), 0o644)

        # Opening with JsonlNotifier should tighten mode to 0600
        JsonlNotifier(p2)
        mode2 = stat.S_IMODE(os.stat(p2).st_mode)
        self.assertEqual(mode2, 0o600)

        # Refusal of symlink targets
        target_file = Path(self.tmpdir.name) / "target.txt"
        target_file.write_text("target", encoding="utf-8")
        symlink_path = Path(self.tmpdir.name) / "symlink_alert.jsonl"
        os.symlink(target_file, symlink_path)

        with self.assertRaises(OSError):
            JsonlNotifier(symlink_path)

    def test_ac11_only_warn_and_destructive_notify(self) -> None:
        """AC-11: Safe statements do not produce console or JSONL output."""
        stream = io.StringIO()
        console = ConsoleNotifier(stream=stream)
        jsonl_path = Path(self.tmpdir.name) / "safe_test.jsonl"
        jsonl = JsonlNotifier(jsonl_path)

        safe_v = self.detector.analyze("SELECT * FROM users")[0]
        self.assertEqual(safe_v.level, "safe")

        console.notify(safe_v)
        jsonl.notify(safe_v)

        self.assertEqual(stream.getvalue(), "")
        self.assertEqual(jsonl_path.read_text(encoding="utf-8"), "")

    def test_ac11_r4_unterminated_placeholders_and_truncation(self) -> None:
        """AC-11 R4: Fixed placeholders for unterminated inputs, no secrets, 2 KiB truncation."""
        secret = "secret@x.com"
        cases = [
            (f"SELECT '{secret}", "SELECT <unparsed>"),
            (f"/* {secret}", "<unparsed>"),
            (f'"{secret}', "<unparsed>"),
        ]

        stream = io.StringIO()
        console = ConsoleNotifier(stream=stream)
        jsonl_path = Path(self.tmpdir.name) / "unterminated.jsonl"
        jsonl = JsonlNotifier(jsonl_path)

        for raw_sql, expected_placeholder in cases:
            st = parse(raw_sql)
            self.assertEqual(st.redacted, expected_placeholder)
            self.assertNotIn(secret, st.redacted)

            v = Verdict(stmt=st, score=0.4, level="warn", reasons=("unparsed",))
            console.notify(v)
            jsonl.notify(v)

        # Ensure secret never appeared anywhere in outputs
        self.assertNotIn(secret, stream.getvalue())
        self.assertNotIn(secret, jsonl_path.read_text(encoding="utf-8"))

        # Truncation: 10,000 char statement cut to <= 2048 bytes + ...[truncated]
        huge_stmt = parse("SELECT " + "col, " * 2000 + "1")
        v_huge = Verdict(stmt=huge_stmt, score=0.8, level="destructive", reasons=("policy:test",))

        stream_huge = io.StringIO()
        console_huge = ConsoleNotifier(stream=stream_huge)
        console_huge.notify(v_huge)
        out_huge = stream_huge.getvalue()
        self.assertIn("...[truncated]", out_huge)

        p_huge = Path(self.tmpdir.name) / "huge.jsonl"
        jsonl_huge = JsonlNotifier(p_huge)
        jsonl_huge.notify(v_huge)
        line = json.loads(p_huge.read_text(encoding="utf-8").strip())
        self.assertIn("...[truncated]", line["redacted"])
        # Check byte length before marker
        content_before_marker = line["redacted"].replace("...[truncated]", "")
        self.assertLessEqual(len(content_before_marker.encode("utf-8")), 2048)

    def test_ac12_notifier_isolation(self) -> None:
        """AC-12: Failing notifier does not crash broadcast or stop other notifiers."""
        class BrokenNotifier:
            def notify(self, v: Verdict) -> None:
                raise RuntimeError("Disk full simulation")

        stream = io.StringIO()
        working = ConsoleNotifier(stream=stream)
        broken = BrokenNotifier()

        v = self.detector.analyze("DROP TABLE users")[0]

        # Should not raise
        broadcast_notify([broken, working], v)
        self.assertIn("[DESTRUCTIVE]", stream.getvalue())

    def test_ac18_missing_posix_prerequisites(self) -> None:
        """AC-18: JsonlNotifier raises NotImplementedError if O_NOFOLLOW or fchmod missing."""
        with patch.object(os, "O_NOFOLLOW", create=False):
            if hasattr(os, "O_NOFOLLOW"):
                del os.O_NOFOLLOW
            with self.assertRaises(NotImplementedError):
                JsonlNotifier(Path(self.tmpdir.name) / "test_no_posix.jsonl")


if __name__ == "__main__":
    unittest.main()
