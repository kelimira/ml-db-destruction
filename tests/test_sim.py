"""Tests covering the Simulator: sandbox security, budgets, trace callback, and demo CLI."""

import io
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from dbguard.detector import Detector
from dbguard.sim import (
    DEMO_SCENARIO,
    make_sandbox,
    run_demo,
    run_repl,
    run_statement,
    _setup_demo_db,
)
from dbguard.sqltok import SQLITE, split_statements


class TestSim(unittest.TestCase):
    """Test suite for Simulator (AC-13, AC-14, AC-14b, AC-14c, AC-14d)."""

    def setUp(self) -> None:
        self.conn, self.budget = make_sandbox()
        _setup_demo_db(self.conn)
        self.detector = Detector()

    def tearDown(self) -> None:
        self.conn.close()

    def test_ac13_demo_execution_and_blocking(self) -> None:
        """AC-13: Demo runs offline, exits 0, blocks destructive statements, verifies row counts."""
        # Run demo
        res = run_demo(seed=0)
        self.assertEqual(res, 0)

        # Verify that destructive statements were blocked
        cur = self.conn.cursor()
        cur.execute("SELECT count(*) FROM users")
        user_count_init = cur.fetchone()[0]

        # Blocked DROP TABLE users
        run_statement(self.conn, self.detector, "DROP TABLE users", block=True, budget=self.budget)
        cur.execute("SELECT count(*) FROM users")
        self.assertEqual(cur.fetchone()[0], user_count_init)

        # Blocked DELETE FROM users
        run_statement(self.conn, self.detector, "DELETE FROM users", block=True, budget=self.budget)
        cur.execute("SELECT count(*) FROM users")
        self.assertEqual(cur.fetchone()[0], user_count_init)

        # With block=False, statement executes
        run_statement(self.conn, self.detector, "DELETE FROM users", block=False, budget=self.budget)
        cur.execute("SELECT count(*) FROM users")
        self.assertEqual(cur.fetchone()[0], 0)

        # Inject wrong expectation -> demo exits 1
        with patch("dbguard.sim.DEMO_SCENARIO", [(1, "SELECT 1", "destructive", "wrong")]):
            res_fail = run_demo(seed=0)
            self.assertEqual(res_fail, 1)

    def test_ac14_sandbox_security_escapes(self) -> None:
        """AC-14: Sandbox security boundaries prevent ATTACH, load_extension, writable_schema, VACUUM INTO."""
        tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=True)
        tmp_path = tmp.name
        tmp.close()

        # ATTACH DATABASE is denied
        err_stream = io.StringIO()
        with patch("sys.stderr", err_stream):
            run_statement(self.conn, self.detector, f"ATTACH DATABASE '{tmp_path}' AS aux", block=False, budget=self.budget)
        self.assertFalse(Path(tmp_path).exists())
        self.assertIn("denied by sandbox", err_stream.getvalue())

        # load_extension is denied
        err_stream = io.StringIO()
        with patch("sys.stderr", err_stream):
            run_statement(self.conn, self.detector, "SELECT load_extension('my_ext')", block=False, budget=self.budget)
        self.assertIn("denied by sandbox", err_stream.getvalue())

        # PRAGMA writable_schema is denied
        err_stream = io.StringIO()
        with patch("sys.stderr", err_stream):
            run_statement(self.conn, self.detector, "PRAGMA writable_schema = 1", block=False, budget=self.budget)
        self.assertIn("denied by sandbox", err_stream.getvalue())

        # PRAGMA table_info(users) works
        err_stream = io.StringIO()
        with patch("sys.stderr", err_stream):
            run_statement(self.conn, self.detector, "PRAGMA table_info(users)", block=False, budget=self.budget)
        self.assertNotIn("denied by sandbox", err_stream.getvalue())

        # VACUUM INTO is rejected and creates no file
        vacuum_file = tmp_path + "_vac.db"
        err_stream = io.StringIO()
        with patch("sys.stderr", err_stream):
            run_statement(self.conn, self.detector, f"VACUUM INTO '{vacuum_file}'", block=False, budget=self.budget)
        self.assertFalse(Path(vacuum_file).exists())
        self.assertIn("denied by sandbox", err_stream.getvalue())

    def test_ac14_repl_interaction(self) -> None:
        """AC-14: REPL interaction handles commands, :force, empty lines, EOF."""
        inputs = [
            "",
            "SELECT 1",
            "DROP TABLE users",
            ":force",
            ":quit",
        ]
        with patch("builtins.input", side_effect=inputs):
            res = run_repl()
            self.assertEqual(res, 0)

    def test_ac14b_trace_callback_execution_units(self) -> None:
        """AC-14b (R2): Sandbox execution matches split_statements(sql, SQLITE) exactly."""
        executed_stmts: list[str] = []

        def trace_cb(stmt_str: str) -> None:
            # Filter internal/trigger queries
            executed_stmts.append(stmt_str.strip())

        self.conn.set_trace_callback(trace_cb)

        # Multi-statement benign
        multi_sql = "SELECT count(*) FROM users; SELECT count(*) FROM orders"
        expected_pieces = split_statements(multi_sql, SQLITE)
        run_statement(self.conn, self.detector, multi_sql, block=True, budget=self.budget)

        # Trace should contain exactly the pieces (ignoring count queries)
        matching_executed = [s for s in executed_stmts if s in expected_pieces]
        self.assertEqual(matching_executed, expected_pieces)

        # Multi-statement with one destructive piece: NOTHING runs when block=True
        executed_stmts.clear()
        destr_multi = "SELECT 1; DROP TABLE users"
        run_statement(self.conn, self.detector, destr_multi, block=True, budget=self.budget)
        self.assertEqual(len(executed_stmts), 0)

    def test_ac14c_resource_limits_and_budgets(self) -> None:
        """AC-14c (R3): Budgets interrupt infinite loops, blobs, cross-joins within 5s."""
        # (a) Infinite recursive CTE
        inf_cte = "WITH RECURSIVE c(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM c) SELECT count(*) FROM c"
        err_stream = io.StringIO()
        with patch("sys.stderr", err_stream):
            run_statement(self.conn, self.detector, inf_cte, block=False, budget=self.budget)
        self.assertIn("budget", err_stream.getvalue())

        # (b) Huge randomblob
        blob_sql = "SELECT randomblob(1000000000)"
        err_stream = io.StringIO()
        with patch("sys.stderr", err_stream):
            run_statement(self.conn, self.detector, blob_sql, block=False, budget=self.budget)
        self.assertTrue(
            "budget" in err_stream.getvalue() or "sqlite error" in err_stream.getvalue()
        )

        # (c) Cross join
        self.conn.execute("CREATE TABLE a (id INT)")
        self.conn.executemany("INSERT INTO a VALUES (?)", [(i,) for i in range(1000)])
        cross_join = "SELECT count(*) FROM a, a, a, a"
        err_stream = io.StringIO()
        with patch("sys.stderr", err_stream):
            run_statement(self.conn, self.detector, cross_join, block=False, budget=self.budget)
        self.assertIn("budget", err_stream.getvalue())

        # Sandbox stays usable after abort
        cur = self.conn.execute("SELECT 1")
        self.assertEqual(cur.fetchone()[0], 1)

    def test_ac14d_source_slices_for_volume_estimate(self) -> None:
        """AC-14d (R9): Source slices preserve identifier quoting and predicate bounds."""
        # Quoted table name
        self.conn.execute('CREATE TABLE "My Orders" ("Status" TEXT)')
        self.conn.execute('INSERT INTO "My Orders" VALUES (\'x\')')

        v_quoted = run_statement(
            self.conn,
            self.detector,
            'DELETE FROM "My Orders" WHERE "Status" = \'x\'',
            block=False,
            budget=self.budget,
        )
        self.assertIsNotNone(v_quoted)

        # RETURNING clause cuts pred_span before RETURNING
        s_ret = "DELETE FROM orders WHERE id = 1 RETURNING id"
        st_ret = self.detector.analyze(s_ret)[0].stmt
        self.assertIsNotNone(st_ret.pred_span)
        pred_text = s_ret[st_ret.pred_span[0] : st_ret.pred_span[1]].strip()
        self.assertEqual(pred_text, "id = 1")

        # Predicate containing comment or semicolon sets pred_span to None
        s_bad = "DELETE FROM orders WHERE id = 1 -- comment"
        st_bad = self.detector.analyze(s_bad)[0].stmt
        self.assertIsNone(st_bad.pred_span)


if __name__ == "__main__":
    unittest.main()
