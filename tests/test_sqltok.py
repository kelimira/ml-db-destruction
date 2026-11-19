"""Tests covering sqltok: lexical analysis, dialect readings, statement splitting, and parsing."""

import itertools
import os
from pathlib import Path
import random
import time
import unittest

from dbguard.detector import Detector
from dbguard.sqltok import (
    SQLITE,
    InputTooLarge,
    Reading,
    parse,
    readings_for,
    split_statements,
)


class TestSqlTok(unittest.TestCase):
    """Test suite for sqltok (AC-1, AC-1b, AC-2, AC-3, AC-18, and ReDoS)."""

    def setUp(self) -> None:
        self.detector = Detector()

    def test_ac1_comments_and_literals(self) -> None:
        """AC-1: Comments and literals do not hide or fake statements."""
        # Benign statements containing keywords inside strings
        v_str = self.detector.analyze("SELECT 'DROP TABLE x'")
        self.assertEqual(len(v_str), 1)
        self.assertEqual(v_str[0].level, "safe")

        # Comment before DROP TABLE
        v_com = self.detector.analyze("/*x*/DROP TABLE t")
        self.assertTrue(any(v.level == "destructive" for v in v_com))

        # Executable comments
        v_mysql1 = self.detector.analyze("/*! DROP TABLE t */")
        self.assertTrue(any(v.level == "destructive" for v in v_mysql1))

        v_mysql2 = self.detector.analyze("/*M! DROP TABLE t */")
        self.assertTrue(any(v.level == "destructive" for v in v_mysql2))

    def test_ac1_six_evasion_inputs(self) -> None:
        """AC-1: All six R1/N1/B1 inputs are destructive through Detector.analyze."""
        evasions = [
            "/* /* */ DROP TABLE t; --*/",
            "SELECT 'a\\' ; DROP TABLE t; --'",
            "SELECT 1 # 2; DROP TABLE t",
            "/* /* */ */ DROP TABLE t",
            "SELECT 1 --; DROP TABLE t",
            "SELECT 1 AS $$; DROP TABLE t; SELECT 1 AS $$",
        ]

        for sql in evasions:
            verdicts = self.detector.analyze(sql)
            is_destr = any(v.level == "destructive" for v in verdicts)
            self.assertTrue(is_destr, f"Expected destructive verdict for evasion: {sql}")

        # Assert no single fixed reading finds all six
        all_32_readings = [
            Reading(nc, be, hc, ds, dq)
            for nc, be, hc, ds, dq in itertools.product((False, True), repeat=5)
        ]

        for single_r in all_32_readings:
            all_found = True
            for sql in evasions:
                pieces = split_statements(sql, single_r)
                found = False
                for p in pieces:
                    st = parse(p, single_r)
                    if st.verb == "DROP":
                        found = True
                        break
                if not found:
                    all_found = False
                    break
            self.assertFalse(all_found, f"Single reading {single_r} unexpectedly found all 6 evasions")

    def test_ac1_dashdash_and_dollar_ambiguity(self) -> None:
        """AC-1: Ordinary comments and benign dollar usages are not destructive."""
        # Space after -- is not ambiguous and not destructive
        v_dash = self.detector.analyze("SELECT 1 -- c; DROP TABLE t")
        self.assertTrue(all(v.level == "safe" for v in v_dash))

        # readings_for returns 1 reading for '-- ' and more for '--;'
        r_single = readings_for("SELECT 1 -- x")
        self.assertEqual(r_single, (SQLITE,))

        r_multi = readings_for("SELECT 1 --;x")
        self.assertGreater(len(r_multi), 1)

        # SELECT $1 returns 2 readings
        r_dollar = readings_for("SELECT $1")
        self.assertEqual(len(r_dollar), 2)

        # Benign dollar queries are safe
        v_dol1 = self.detector.analyze("SELECT $1")
        self.assertTrue(all(v.level == "safe" for v in v_dol1))

        v_dol2 = self.detector.analyze("SELECT a$b FROM t")
        self.assertTrue(all(v.level == "safe" for v in v_dol2))

        v_dol3 = self.detector.analyze("SELECT $$a;b$$")
        self.assertTrue(all(v.level == "safe" for v in v_dol3))

        # Benign backslash and hash
        v_bs = self.detector.analyze("SELECT 'a\\b'")
        self.assertTrue(all(v.level == "safe" for v in v_bs))

        v_h = self.detector.analyze("SELECT 1 # c")
        self.assertTrue(all(v.level == "safe" for v in v_h))

    def test_ac1b_pruned_equals_full(self) -> None:
        """AC-1b (P1): Pruned readings equal unpruned scan over all 32 readings on fuzz sample."""
        self.assertEqual(readings_for("SELECT 1"), (SQLITE,))

        all_32_readings = tuple(
            Reading(nc, be, hc, ds, dq)
            for nc, be, hc, ds, dq in itertools.product((False, True), repeat=5)
        )

        tokens_pool = [
            "SELECT", "DROP", "TABLE", "t", "1", ";",
            "\\", "#", "$", "--", "/*", "*/", "'", '"', "a", " "
        ]

        rng = random.Random(42)
        for _ in range(200):
            length = rng.randint(2, 10)
            sample = "".join(rng.choice(tokens_pool) for _ in range(length))

            pruned_r = readings_for(sample)
            self.assertIn(SQLITE, pruned_r)

            # Analyze with pruned
            verdicts_pruned = self.detector.analyze(sample)
            max_pruned_level = max(
                ({"safe": 0, "warn": 1, "destructive": 2}[v.level] for v in verdicts_pruned),
                default=0,
            )

            # Analyze manually with all 32
            max_all_level = 0
            for r in all_32_readings:
                try:
                    pieces = split_statements(sample, r)
                    for p in pieces:
                        st = parse(p, r)
                        v = self.detector._score_stmt(st)
                        lvl = {"safe": 0, "warn": 1, "destructive": 2}[v.level]
                        if lvl > max_all_level:
                            max_all_level = lvl
                except InputTooLarge:
                    pass

            self.assertEqual(
                max_pruned_level,
                max_all_level,
                f"Mismatch between pruned and all 32 on: {sample!r}",
            )

    def test_ac2_split_statements(self) -> None:
        """AC-2: Statement splitting, exposing reading pieces, and size limits."""
        # Exposing reading pieces start with DROP
        r_nested = Reading(nested_comments=False, backslash_escapes=False, hash_comment=False, dashdash_needs_space=False, dollar_quotes=False)
        p1 = split_statements("/* /* */ DROP TABLE t; --*/", r_nested)
        self.assertTrue(any(p.startswith("DROP") for p in p1))

        r_bs = Reading(nested_comments=False, backslash_escapes=False, hash_comment=False, dashdash_needs_space=False, dollar_quotes=False)
        p2 = split_statements("SELECT 'a\\' ; DROP TABLE t; --'", r_bs)
        self.assertTrue(any(p.startswith("DROP") for p in p2))

        r_h = Reading(nested_comments=False, backslash_escapes=False, hash_comment=False, dashdash_needs_space=False, dollar_quotes=False)
        p3 = split_statements("SELECT 1 # 2; DROP TABLE t", r_h)
        self.assertTrue(any(p.startswith("DROP") for p in p3))

        r_dash = Reading(nested_comments=False, backslash_escapes=False, hash_comment=False, dashdash_needs_space=True, dollar_quotes=False)
        p4 = split_statements("SELECT 1 --; DROP TABLE t", r_dash)
        self.assertTrue(any(p.startswith("DROP") for p in p4))

        r_dol = Reading(nested_comments=False, backslash_escapes=False, hash_comment=False, dashdash_needs_space=False, dollar_quotes=False)
        p5 = split_statements("SELECT 1 AS $$; DROP TABLE t; SELECT 1 AS $$", r_dol)
        self.assertTrue(any(p.startswith("DROP") for p in p5))

        # Size limits
        with self.assertRaises(InputTooLarge):
            split_statements("SELECT 1;" * 201)

        with self.assertRaises(InputTooLarge):
            split_statements("a" * (65 * 1024))

        # Token limit per statement (> 5000 tokens gives UNPARSED warn)
        huge_stmt = "SELECT " + " + 1" * 5001
        stmt = parse(huge_stmt)
        self.assertEqual(stmt.verb, "UNPARSED")
        v = self.detector._score_stmt(stmt)
        self.assertEqual(v.level, "warn")

    def test_ac3_parse_verbs_and_explain(self) -> None:
        """AC-3: Classification of SQL verbs and exhaustive EXPLAIN handling."""
        valid_kinds = {"DML", "DDL", "DQL", "DCL", "TCL", "OTHER"}

        cases = [
            ("SELECT * FROM t", "SELECT", "DQL", ("t",)),
            ("INSERT INTO t VALUES (1)", "INSERT", "DML", ("t",)),
            ("UPDATE t SET a=1 WHERE id=1", "UPDATE", "DML", ("t",)),
            ("DELETE FROM t WHERE id=1", "DELETE", "DML", ("t",)),
            ("DROP TABLE t", "DROP", "DDL", ("t",)),
            ("TRUNCATE TABLE t", "TRUNCATE", "DDL", ("t",)),
            ("ALTER TABLE t ADD COLUMN c INT", "ALTER", "DDL", ("t",)),
            ("CREATE TABLE t (id INT)", "CREATE", "DDL", ("t",)),
            ("GRANT SELECT ON t TO u", "GRANT", "DCL", ()),
            ("WITH cte AS (SELECT 1) SELECT * FROM cte", "SELECT", "DQL", ("cte",)),
            ("MERGE INTO t USING s ON t.id=s.id WHEN MATCHED THEN DELETE", "MERGE", "DML", ("t",)),
            ("REPLACE INTO t VALUES (1)", "REPLACE", "DML", ("t",)),
            ("PRAGMA foreign_keys = ON", "PRAGMA", "OTHER", ()),
            ("ATTACH DATABASE ':memory:' AS aux", "ATTACH", "OTHER", ()),
        ]

        for sql, exp_verb, exp_kind, exp_tables in cases:
            st = parse(sql)
            self.assertEqual(st.verb, exp_verb, f"Verb mismatch for {sql}")
            self.assertIn(st.kind, valid_kinds)
            self.assertEqual(st.kind, exp_kind, f"Kind mismatch for {sql}")
            for tbl in exp_tables:
                self.assertIn(tbl, st.tables, f"Table {tbl} not found in {st.tables} for {sql}")

        # EXPLAIN table tests per R6
        plain_explains = [
            "EXPLAIN DELETE FROM t",
            "EXPLAIN QUERY PLAN DELETE FROM t",
            "EXPLAIN (ANALYZE false) DELETE FROM t",
            "EXPLAIN (ANALYZE off, VERBOSE) DELETE FROM t",
        ]
        for sql in plain_explains:
            st = parse(sql)
            self.assertEqual(st.explain, "plain", f"Expected plain for {sql}")
            verdicts = self.detector.analyze(sql)
            self.assertTrue(all(v.level == "safe" for v in verdicts), f"Expected safe for {sql}")

        analyze_explains = [
            "EXPLAIN ANALYZE DELETE FROM t",
            "EXPLAIN (ANALYZE) DELETE FROM t",
            "EXPLAIN (ANALYZE true) DELETE FROM t",
            "EXPLAIN (ANALYZE false, ANALYZE true) DELETE FROM t",
            "EXPLAIN (FORMAT json) DELETE FROM t",
            "EXPLAIN (ANALYZE false DELETE FROM t",
        ]
        for sql in analyze_explains:
            st = parse(sql)
            self.assertEqual(st.explain, "analyze", f"Expected analyze for {sql}")
            verdicts = self.detector.analyze(sql)
            self.assertTrue(any(v.level == "destructive" for v in verdicts), f"Expected destructive for {sql}")

    def test_redos_performance(self) -> None:
        """AC-15: ReDoS test completing 64 KiB repetitive patterns under 1 second."""
        repeats = ["'", "/*", "\\", "#", "$a$"]
        for pattern in repeats:
            big_input = (pattern * 10000)[:65000]
            start_t = time.monotonic()
            split_statements(big_input, SQLITE)
            elapsed = time.monotonic() - start_t
            self.assertLess(elapsed, 1.0, f"ReDoS limit exceeded on pattern {pattern}: {elapsed:.3f}s")

    def test_ac18_package_standards(self) -> None:
        """AC-18: Verify no sqlparse.py, sqltok import works, and pyproject.toml matches."""
        # No sqlparse.py
        repo_root = Path(__file__).resolve().parent.parent
        self.assertFalse((repo_root / "sqlparse.py").exists())
        self.assertFalse((repo_root / "dbguard" / "sqlparse.py").exists())

        # sqltok import works
        import dbguard.sqltok
        self.assertTrue(hasattr(dbguard.sqltok, "parse"))

        # pyproject.toml has requires-python and POSIX
        pyproj = (repo_root / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn('requires-python = ">=3.11"', pyproj)
        self.assertIn("Operating System :: POSIX", pyproj)


if __name__ == "__main__":
    unittest.main()
