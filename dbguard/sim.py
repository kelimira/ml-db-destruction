"""Simulation interface and hardened SQLite sandbox for dbguard."""

from __future__ import annotations

import argparse
import logging
import re
import sqlite3
import sys
import time
from typing import Callable

from dbguard.detector import Detector, Verdict
from dbguard.model import LogisticModel, train
from dbguard.notify import ConsoleNotifier, JsonlNotifier, Notifier, broadcast_notify
from dbguard.sqltok import SQLITE, parse, split_statements

DEMO_SCENARIO: list[tuple[int, str, str, str]] = [
    (1, "SELECT count(*) FROM orders", "safe", "Standard query"),
    (2, "INSERT INTO orders (user_id, status) VALUES (1, 'new')", "safe", "Benign insert"),
    (3, "DELETE FROM orders WHERE id = 42", "safe", "Bounded delete"),
    (4, "UPDATE users SET email = 'x@example.com' WHERE id = 7", "safe", "Bounded update"),
    (5, "DELETE FROM orders WHERE status = 'shipped'", "warn", "Volume outlier (affects >= 100 rows)"),
    (6, "DELETE FROM orders", "destructive", "Unbounded delete"),
    (7, "UPDATE orders SET status = 'x'", "destructive", "Unbounded update"),
    (8, "ALTER TABLE users DROP COLUMN email", "destructive", "Drop column"),
    (9, "TRUNCATE TABLE orders", "destructive", "Truncate table"),
    (10, "DROP TABLE users", "destructive", "Drop table"),
    (11, "/* /* */ DROP TABLE users; --*/", "destructive", "R1 evasion: nested comment"),
    (12, "SELECT 1 # 2; DROP TABLE users", "destructive", "R1 evasion: hash comment"),
    (13, "SELECT 1 --; DROP TABLE users", "destructive", "N1 evasion: MySQL dashdash rule"),
    (14, "SELECT 1 AS $$; DROP TABLE users; SELECT 1 AS $$", "destructive", "B1 evasion: dollar quote"),
]


class SandboxBudget:
    """Tracks VM steps and elapsed wall time for sandbox execution."""

    def __init__(self, max_steps: int = 2_000_000, max_seconds: float = 2.0) -> None:
        self.max_steps = max_steps
        self.max_seconds = max_seconds
        self.step_count: int = 0
        self.start_time: float = time.monotonic()
        self.aborted: bool = False

    def reset(self) -> None:
        self.step_count = 0
        self.start_time = time.monotonic()
        self.aborted = False

    def progress_callback(self) -> int:
        self.step_count += 1000
        if self.step_count > self.max_steps or (time.monotonic() - self.start_time) > self.max_seconds:
            self.aborted = True
            return 1  # Non-zero interrupts execution
        return 0


def _authorizer_callback(
    read_only_mode: bool,
    action: int,
    arg1: str | None,
    arg2: str | None,
    db_name: str | None,
    trigger_or_view: str | None,
) -> int:
    """Enforce sandbox security restrictions via SQLite authorizer."""
    # Deny attach/detach
    if action in (getattr(sqlite3, "SQLITE_ATTACH", 24), getattr(sqlite3, "SQLITE_DETACH", 25)):
        return sqlite3.SQLITE_DENY

    # Deny unauthorized pragmas
    if action == getattr(sqlite3, "SQLITE_PRAGMA", 19):
        allowed_pragmas = {"table_info", "table_list", "foreign_keys", "index_list"}
        if arg1 and arg1.lower() not in allowed_pragmas:
            return sqlite3.SQLITE_DENY

    # Deny load_extension
    if action == getattr(sqlite3, "SQLITE_FUNCTION", 31):
        if arg2 and arg2.lower() == "load_extension":
            return sqlite3.SQLITE_DENY

    if read_only_mode:
        # In read-only mode, only allow SELECT, READ, and FUNCTION
        allowed_actions = {
            getattr(sqlite3, "SQLITE_SELECT", 21),
            getattr(sqlite3, "SQLITE_READ", 20),
            getattr(sqlite3, "SQLITE_FUNCTION", 31),
        }
        if action not in allowed_actions:
            return sqlite3.SQLITE_DENY

    return sqlite3.SQLITE_OK


class Sandbox:
    """Wrapper around SQLite connection with budgets and security controls."""

    def __init__(self, conn: sqlite3.Connection, budget: SandboxBudget) -> None:
        self.conn = conn
        self.budget = budget
        self.read_only_mode = False

    def set_read_only(self, read_only: bool) -> None:
        self.read_only_mode = read_only
        self.conn.set_authorizer(
            lambda action, arg1, arg2, db_name, trig: _authorizer_callback(
                self.read_only_mode, action, arg1, arg2, db_name, trig
            )
        )


def make_sandbox() -> tuple[sqlite3.Connection, SandboxBudget]:
    """Create and configure a hardened SQLite in-memory sandbox connection."""
    conn = sqlite3.connect(":memory:")

    if hasattr(conn, "enable_load_extension"):
        try:
            conn.enable_load_extension(False)
        except Exception:
            pass

    # Set resource limits before authorizer (§9.1)
    if hasattr(conn, "setlimit"):
        conn.setlimit(getattr(sqlite3, "SQLITE_LIMIT_LENGTH", 0), 1024 * 1024)
        conn.setlimit(getattr(sqlite3, "SQLITE_LIMIT_SQL_LENGTH", 1), 65536)
        conn.setlimit(getattr(sqlite3, "SQLITE_LIMIT_COLUMN", 2), 100)
        conn.setlimit(getattr(sqlite3, "SQLITE_LIMIT_EXPR_DEPTH", 3), 50)
        conn.setlimit(getattr(sqlite3, "SQLITE_LIMIT_COMPOUND_SELECT", 4), 20)
        conn.setlimit(getattr(sqlite3, "SQLITE_LIMIT_LIKE_PATTERN_LENGTH", 8), 1000)
        conn.setlimit(getattr(sqlite3, "SQLITE_LIMIT_TRIGGER_DEPTH", 10), 10)
        conn.setlimit(getattr(sqlite3, "SQLITE_LIMIT_ATTACHED", 7), 0)

    conn.execute("PRAGMA max_page_count = 2000")

    budget = SandboxBudget()
    conn.set_progress_handler(budget.progress_callback, 1000)

    # Set default authorizer
    conn.set_authorizer(
        lambda action, arg1, arg2, db_name, trig: _authorizer_callback(
            False, action, arg1, arg2, db_name, trig
        )
    )

    return conn, budget


def run_statement(
    conn: sqlite3.Connection,
    detector: Detector,
    sql: str,
    block: bool = True,
    notifiers: list[Notifier] | None = None,
    budget: SandboxBudget | None = None,
) -> list[Verdict]:
    """Execute SQL under detector analysis and sandbox constraints (§9.2, §9.3)."""
    # 1. Analyze input under all readings
    verdicts = detector.analyze(sql)

    # Deliver alerts if notifiers provided
    if notifiers:
        for v in verdicts:
            broadcast_notify(notifiers, v)

    # 2. Extract execution pieces using SQLITE reading
    pieces = split_statements(sql, SQLITE)

    # Filter out empty or comment-only pieces
    exec_pieces: list[tuple[str, any]] = []
    for piece in pieces:
        st = parse(piece, SQLITE)
        if st.verb != "UNPARSED" or st.redacted != "<unparsed>":
            exec_pieces.append((piece, st))

    # 4. If block and any verdict is destructive, block whole input
    is_destructive = any(v.level == "destructive" for v in verdicts)
    if block and is_destructive:
        return verdicts

    # 5. Volume estimate check (§9.3)
    # Runs only if no verdict was destructive, exactly one piece, single target DML with WHERE
    if not is_destructive and len(exec_pieces) == 1:
        piece_sql, stmt = exec_pieces[0]
        if (
            stmt.verb in ("DELETE", "UPDATE")
            and stmt.has_where
            and not stmt.tautology_where
            and len(stmt.tables) == 1
            and stmt.table_span is not None
            and stmt.pred_span is not None
        ):
            tbl_part = piece_sql[stmt.table_span[0] : stmt.table_span[1]]
            pred_part = piece_sql[stmt.pred_span[0] : stmt.pred_span[1]]
            count_query = f"SELECT count(*) FROM {tbl_part} WHERE {pred_part}"

            # Execute count query under read-only mode and progress budget
            if budget:
                budget.reset()

            # Temporarily enable read-only authorizer
            conn.set_authorizer(
                lambda act, a1, a2, db, tr: _authorizer_callback(True, act, a1, a2, db, tr)
            )
            estimated_rows: int | None = None
            try:
                cur = conn.execute(count_query)
                row = cur.fetchone()
                if row and row[0] is not None:
                    estimated_rows = int(row[0])
            except Exception:
                estimated_rows = None
            finally:
                conn.set_authorizer(
                    lambda act, a1, a2, db, tr: _authorizer_callback(False, act, a1, a2, db, tr)
                )

            # Re-analyze with estimated rows
            if estimated_rows is not None:
                verdicts = detector.analyze(sql, estimated_rows=estimated_rows)
                if notifiers:
                    for v in verdicts:
                        broadcast_notify(notifiers, v)
                if block and any(v.level == "destructive" for v in verdicts):
                    return verdicts

    # 6. Execute pieces in order
    for piece_sql, stmt in exec_pieces:
        # Check VACUUM INTO before execution
        upper_tokens = [t.upper() for t in stmt.tokens]
        if "VACUUM" in upper_tokens and "INTO" in upper_tokens:
            print("denied by sandbox", file=sys.stderr)
            break

        if budget:
            budget.reset()

        try:
            conn.execute(piece_sql)
        except sqlite3.Error as e:
            if budget and budget.aborted:
                print("denied by sandbox: budget", file=sys.stderr)
            elif "not authorized" in str(e).lower():
                print("denied by sandbox", file=sys.stderr)
            else:
                print(f"sqlite error: {e}", file=sys.stderr)
            break
        except Exception as e:
            print(f"sqlite error: {e}", file=sys.stderr)
            break

    return verdicts


def _setup_demo_db(conn: sqlite3.Connection) -> None:
    """Initialize demo database schema and data."""
    conn.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT)")
    conn.execute("CREATE TABLE orders (id INTEGER PRIMARY KEY, user_id INTEGER, status TEXT)")

    # Insert ~50 users
    user_rows = [(i, f"user{i}@example.com") for i in range(1, 51)]
    conn.executemany("INSERT INTO users (id, email) VALUES (?, ?)", user_rows)

    # Insert ~500 orders (at least 100 with status='shipped')
    order_rows = []
    for i in range(1, 501):
        uid = (i % 50) + 1
        status = "shipped" if i <= 150 else ("pending" if i <= 300 else "completed")
        order_rows.append((i, uid, status))
    conn.executemany("INSERT INTO orders (id, user_id, status) VALUES (?, ?, ?)", order_rows)


def run_demo(
    seed: int = 0, alerts_file: str | None = None, block: bool = True
) -> int:
    """Run demo scenario, training on benign activity and evaluating §9.5 scenario."""
    conn, budget = make_sandbox()
    _setup_demo_db(conn)

    model = train(seed=seed)
    detector = Detector(model=model)

    notifiers: list[Notifier] = [ConsoleNotifier()]
    if alerts_file:
        notifiers.append(JsonlNotifier(alerts_file))

    # Run ~200 benign statements and learn safe ones
    # At least 20 bounded DELETEs each affecting <= 1 row
    for i in range(1, 25):
        oid = 400 + i
        del_sql = f"DELETE FROM orders WHERE id = {oid}"
        run_statement(conn, detector, del_sql, block=block, budget=budget)
        detector.learn(del_sql, 1)

    # Additional benign selects, inserts, updates
    for i in range(1, 180):
        if i % 3 == 0:
            sel_sql = f"SELECT * FROM users WHERE id = {i % 50 + 1}"
            run_statement(conn, detector, sel_sql, block=block, budget=budget)
            detector.learn(sel_sql, 1)
        elif i % 3 == 1:
            ins_sql = f"INSERT INTO orders (user_id, status) VALUES ({i % 50 + 1}, 'pending')"
            run_statement(conn, detector, ins_sql, block=block, budget=budget)
            detector.learn(ins_sql, 1)
        else:
            upd_sql = f"UPDATE users SET email = 'test{i}@example.com' WHERE id = {i % 50 + 1}"
            run_statement(conn, detector, upd_sql, block=block, budget=budget)
            detector.learn(upd_sql, 1)

    print("\n--- Running dbguard Demo Scenario (§9.5) ---")
    print(f"{'#':<3} | {'Expected':<11} | {'Actual':<11} | {'Score':<5} | {'Reasons':<30} | {'Statement'}")
    print("-" * 90)

    all_passed = True

    for num, sql, expected_level, note in DEMO_SCENARIO:
        verdicts = run_statement(conn, detector, sql, block=block, notifiers=notifiers, budget=budget)

        # Overall level is maximum across verdicts
        if verdicts:
            max_v = max(verdicts, key=lambda v: ({"safe": 0, "warn": 1, "destructive": 2}[v.level], v.score))
            actual_level = max_v.level
            score = max_v.score
            reasons_str = ",".join(max_v.reasons) if max_v.reasons else "none"
            redacted = max_v.stmt.redacted
        else:
            actual_level = "safe"
            score = 0.0
            reasons_str = "none"
            redacted = sql

        passed = (actual_level == expected_level)
        if not passed:
            all_passed = False

        status_mark = "OK" if passed else "MISMATCH"
        print(f"{num:<3} | {expected_level:<11} | {actual_level:<11} | {score:<5.2f} | {reasons_str:<30} | {redacted} [{status_mark}]")

    conn.close()
    print("-" * 90)
    if all_passed:
        print("Demo completed: All statements produced expected levels.")
        return 0
    else:
        print("Demo failed: Some statements produced unexpected levels.", file=sys.stderr)
        return 1


def run_repl() -> int:
    """Run interactive REPL for testing statements against sandbox and detector."""
    conn, budget = make_sandbox()
    _setup_demo_db(conn)
    detector = Detector()
    notifiers = [ConsoleNotifier()]

    print("dbguard REPL (type SQL, :force to run last blocked, :quit to exit)")
    last_blocked: str | None = None

    while True:
        try:
            line = input("dbguard> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nExiting.")
            break

        if not line:
            continue
        if line == ":quit":
            break
        if line == ":force":
            if last_blocked:
                print(f"Forcing execution: {last_blocked}")
                run_statement(conn, detector, last_blocked, block=False, notifiers=notifiers, budget=budget)
                last_blocked = None
            else:
                print("No blocked statement to force.")
            continue

        verdicts = run_statement(conn, detector, line, block=True, notifiers=notifiers, budget=budget)
        is_destr = any(v.level == "destructive" for v in verdicts)
        if is_destr:
            print("[BLOCKED] Destructive operation prevented.")
            last_blocked = line
        else:
            last_blocked = None

    conn.close()
    return 0


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint for dbguard."""
    parser = argparse.ArgumentParser(prog="dbguard", description="Destructive database operation guard")
    subparsers = parser.add_subparsers(dest="command")

    # Demo
    demo_p = subparsers.add_parser("demo", help="Run scenario demonstration")
    demo_p.add_argument("--seed", type=int, default=0, help="Random seed for model and dataset")
    demo_p.add_argument("--alerts", type=str, default=None, help="JSONL file path for alerts")
    demo_p.add_argument("--no-block", action="store_true", help="Do not block destructive statements")

    # REPL
    subparsers.add_parser("repl", help="Interactive SQL evaluation shell")

    # Train
    train_p = subparsers.add_parser("train", help="Train model and save to JSON")
    train_p.add_argument("--out", type=str, default="model.json", help="Output model JSON path")
    train_p.add_argument("--seed", type=int, default=0, help="Random seed")

    args = parser.parse_args(argv)

    if args.command == "demo":
        return run_demo(seed=args.seed, alerts_file=args.alerts, block=not args.no_block)
    elif args.command == "repl":
        return run_repl()
    elif args.command == "train":
        m = train(seed=args.seed)
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(m.to_json())
        print(f"Model saved to {args.out}")
        return 0
    else:
        parser.print_help()
        return 0


if __name__ == "__main__":
    sys.exit(main())
