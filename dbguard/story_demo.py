"""Long-running story demo: dbguard learns, meets new workloads, catches anomalies, keeps learning.

Run: python3 -m dbguard.story_demo [--delay SECONDS] [--seed N]
A simulated ~6 weeks of one app's database traffic, replayed day by day.
"""

from __future__ import annotations

import argparse
import random
import time

from dbguard.detector import Detector
from dbguard.model import train
from dbguard.sim import make_sandbox, run_statement

ARCHIVE = "UPDATE orders SET status = 'archived' WHERE status = 'completed'"
CLEANUP = "DELETE FROM sessions WHERE expires_at <= 9999"
LEARNING_TARGET = 300


class Story:
    def __init__(self, seed: int, delay: float) -> None:
        self.rng = random.Random(seed)
        self.delay = delay
        self.conn, self.budget = make_sandbox()
        self.det = Detector(model=train(seed=seed), learning_target=LEARNING_TARGET)
        self.day = 0
        self.stmts = 0
        self.alerts = 0
        self.log: list[str] = []
        self.events: list[dict] = []  # for the HTML view
        self.days: list[dict] = []
        self.acts: list[dict] = []
        c = self.conn
        c.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT)")
        c.execute("CREATE TABLE orders (id INTEGER PRIMARY KEY, user_id INT, status TEXT)")
        c.execute("CREATE TABLE sessions (id INTEGER PRIMARY KEY, user_id INT, expires_at INT)")
        c.executemany("INSERT INTO users (email) VALUES (?)", [(f"u{i}@x.com",) for i in range(80)])
        c.executemany("INSERT INTO orders (user_id, status) VALUES (?, 'new')", [(i % 80 + 1,) for i in range(300)])
        c.executemany("INSERT INTO sessions (user_id, expires_at) VALUES (?, 1000)", [(i % 80,) for i in range(6000)])

    # -- helpers ------------------------------------------------------------
    def count(self, table: str) -> int:
        return self.conn.execute(f"SELECT count(*) FROM {table}").fetchone()[0]

    def say(self, msg: str, kind: str = "info", rows: int | None = None, score: float | None = None) -> None:
        print(f"      {msg}")
        self.log.append(f"day {self.day:>2}: {msg}")
        self.events.append(dict(day=self.day, kind=kind, text=msg, rows=rows, score=score))

    def act(self, title: str) -> None:
        print(("\n" if self.acts else "") + title)
        self.acts.append(dict(day=self.day + 1, title=title))

    def do(self, sql: str, show: bool = False, est: int | None = None) -> tuple[str, float, tuple[str, ...], int]:
        """Run through the guard. Safe statements are learned; warn/destructive raise an alert."""
        before = self.conn.total_changes
        vs = run_statement(self.conn, self.det, sql, block=True, budget=self.budget)
        worst = max(vs, key=lambda v: ({"safe": 0, "warn": 1, "destructive": 2}[v.level], v.score))
        rows = self.conn.total_changes - before
        self.stmts += 1
        if worst.level == "safe":
            self.det.learn(sql, rows)
        else:
            self.alerts += 1
        if show or worst.level != "safe":
            tag = {"safe": "ok  ", "warn": "WARN", "destructive": "BLOCKED"}[worst.level]
            why = ",".join(worst.reasons) or "model score"
            self.say(f"[{tag}] {worst.score:.2f} {why:<28} {sql[:60]}"
                     + (f"  (rows touched: {rows})" if worst.level != "destructive" else ""),
                     kind={"safe": "ok", "warn": "warn", "destructive": "blocked"}[worst.level],
                     rows=est if (worst.level == "destructive" and est) else rows, score=worst.score)
        return worst.level, worst.score, worst.reasons, rows

    def score(self, sql: str, rows: int) -> float:
        return max(v.score for v in self.det.analyze(sql, estimated_rows=rows))

    def normal_day(self) -> None:
        r = self.rng
        for _ in range(40):
            uid = r.randint(1, 80)
            self.do(r.choice([
                f"SELECT * FROM users WHERE id = {uid}",
                f"INSERT INTO orders (user_id, status) VALUES ({uid}, 'new')",
                f"UPDATE users SET email = 'e{r.randint(1, 999)}@x.com' WHERE id = {uid}",
            ]))
        if self.day % 4 == 0:  # a rare operation: few samples, so a new volume stands out quickly
            self.do(f"UPDATE orders SET status = 'shipped' WHERE id = {r.randint(1, 300)}")
        self.conn.executemany("INSERT INTO sessions (user_id, expires_at) VALUES (1, ?)",
                              [(self.day,)] * r.randint(25, 40))
        self.do(f"DELETE FROM sessions WHERE expires_at <= {self.day}")

    def header(self) -> None:
        st = self.det.profile._store
        band = {}
        for name, key in (("sessions", ("DELETE", "sessions")), ("orders", ("UPDATE", "orders"))):
            k = st.get(key)
            band[name] = [k.mean, k.mean + 3 * max(k.std, 1.0)] if k and k.row_count >= 5 else None
        self.days.append(dict(day=self.day, mode=self.det.mode, stmts=self.stmts, alerts=self.alerts,
                              cleanup=self.score(CLEANUP, 34), archive=self.score(ARCHIVE, 120), band=band))
        print(f"Day {self.day:>2}  mode={self.det.mode:<10} stmts={self.stmts:<4} alerts={self.alerts:<3} "
              f"| score of known 34-row cleanup: {self.score(CLEANUP, 34):.2f}"
              f" | 120-row weekly archive: {self.score(ARCHIVE, 120):.2f}")
        time.sleep(self.delay)

    # -- the story ----------------------------------------------------------
    def run(self) -> None:
        mode0 = self.det.mode
        self.act("Act 1 - LEARNING: normal traffic only. dbguard watches, builds its profile, ignores profile signals.")
        for self.day in range(1, 15):
            if self.day == 9:
                self.act("Act 2 - STEADY STATE: same traffic, now enforcing and still learning.")
            self.normal_day()
            self.header()
            if mode0 != self.det.mode:
                self.say(f"*** learning target reached: mode {mode0} -> {self.det.mode} ***", kind="mode")
                mode0 = self.det.mode

        self.act("Act 3 - SOMETHING NEW: a new feature ships. New (verb, table) pairs look novel, then become normal.")
        self.conn.execute("CREATE TABLE invoices (id INTEGER PRIMARY KEY, order_id INT, total INT)")
        for self.day in range(15, 21):
            self.normal_day()
            for i in range(3):
                self.do(f"INSERT INTO invoices (order_id, total) VALUES ({i + 1}, 10)")
            self.header()
            self.say(f"novelty of INSERT invoices is fading: score {self.score('INSERT INTO invoices (order_id, total) VALUES (1, 10)', 1):.2f}"
                     " (0.15 bump at first sight, 0 once seen 10x)")

        self.act("Act 4 - ANOMALIES: a bug and an attacker.")
        self.day = 21
        self.normal_day()
        self.header()
        self.say("a buggy deploy updates 80 user emails in one statement (a cold model rates this 'safe'):")
        self.do("UPDATE users SET email = 'oops@x.com' WHERE id > 0")
        self.day = 22
        self.normal_day()
        self.header()
        s0 = self.count("sessions"), self.count("users"), self.count("orders")
        self.say("someone tries to wipe data:")
        self.do("DELETE FROM sessions WHERE expires_at > 100", est=6000)
        self.do("DELETE FROM users")
        self.do("TRUNCATE TABLE orders")
        self.do("/* x */ DROP TABLE orders")
        s1 = self.count("sessions"), self.count("users"), self.count("orders")
        self.say(f"rows (sessions, users, orders) before {s0} / after {s1} -> {'ALL INTACT' if s0 == s1 else 'DATA LOST'}")

        self.act("Act 5 - A NEW LEGITIMATE JOB: weekly archive of ~120 orders. Unusual at first, an operator confirms it.")
        for self.day in range(23, 44):
            self.normal_day()
            if self.day in (28, 35, 42):
                self.conn.executemany("INSERT INTO orders (user_id, status) VALUES (1, 'completed')", [()] * 120)
                self.header()
                level, _, _, rows = self.do(ARCHIVE, show=True)
                if level == "warn" and self.det.approve(ARCHIVE, rows):
                    self.say(">>> operator reviews the alert and APPROVES it -> profile updated", kind="approve", rows=rows)
                elif level == "safe":
                    self.say(">>> no alert: the job is now part of normal behaviour")
            else:
                self.header()

        self.act("Act 6 - SAME SQL, DIFFERENT OUTCOME: the archive statement again, but 3000 rows are pending.")
        self.day = 44
        self.conn.executemany("INSERT INTO orders (user_id, status) VALUES (1, 'completed')", [()] * 3000)
        self.header()
        self.say("identical statement text as the approved weekly job:")
        self.do(ARCHIVE, show=True, est=3000)
        self.say(f"orders still 'completed' (untouched): {self.conn.execute("SELECT count(*) FROM orders WHERE status = 'completed'").fetchone()[0]}")

        self.act("Act 7 - HONEST LIMIT: slow, batched deletion. Each statement looks like the normal 34-row cleanup.")
        self.day = 45
        before = self.count("sessions")
        levels = [self.do(f"DELETE FROM sessions WHERE id BETWEEN {a} AND {a + 34}")[0]
                  for a in range(1, 35 * 40, 35)]
        lost = before - self.count("sessions")
        self.header()
        self.events.append(dict(day=45, kind="ok", text="[ok  ] each of 40 batched deletes: 35 rows, all judged safe", rows=35, score=0.05))
        self.say(f"40 batched deletes -> verdicts {sorted(set(levels))}, sessions lost: {lost}. "
                 "Not caught: no single statement is anomalous. Needs a rate/total-volume check.")

        print("\n=== Timeline of alerts ===")
        for line in self.log:
            if "[WARN]" in line or "[BLOCKED]" in line or ">>>" in line or "***" in line or "ALL INTACT" in line:
                print(line)
        print(f"\n{self.stmts} statements, {self.alerts} alerts, final mode: {self.det.mode}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--delay", type=float, default=0.3, help="seconds to pause per simulated day (0 = instant)")
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--html", metavar="PATH", help="also write a self-contained split-view HTML visualisation")
    a = ap.parse_args()
    s = Story(a.seed, a.delay)
    s.run()
    if a.html:
        from dbguard.story_html import write_html
        write_html(s, a.html)
        print(f"\nVisualisation written to {a.html} (open it in a browser)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
