"""Train-then-detect demo: shows the online profile learning "normal" and flagging anomalies.

Run: python3 -m dbguard.learn_demo [--days N] [--keep-profile PATH]
"""

from __future__ import annotations

import argparse
import os
import random
import tempfile

from dbguard.detector import Detector
from dbguard.model import train
from dbguard.profile import BehaviourProfile
from dbguard.sim import make_sandbox, run_statement

# (label, sql, count_sql giving the rows it would touch, or None)
PROBES = [
    ("normal nightly cleanup", "DELETE FROM sessions WHERE expires_at = 99",
     "SELECT count(*) FROM sessions WHERE expires_at = 99"),
    ("bounded delete by id", "DELETE FROM sessions WHERE id = 42", None),
    ("bulk update, 80 rows", "UPDATE users SET email = 'x@y.com' WHERE id > 0",
     "SELECT count(*) FROM users WHERE id > 0"),
    ("delete on never-seen table", "DELETE FROM users WHERE id = 5", None),
    ("mass delete WITH where", "DELETE FROM sessions WHERE expires_at > 100",
     "SELECT count(*) FROM sessions WHERE expires_at > 100"),
    ("delete with NO where", "DELETE FROM sessions", None),
    ("drop table", "DROP TABLE sessions", None),
]


def _setup(conn) -> None:
    conn.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT)")
    conn.execute("CREATE TABLE orders (id INTEGER PRIMARY KEY, user_id INT, status TEXT)")
    conn.execute("CREATE TABLE sessions (id INTEGER PRIMARY KEY, user_id INT, expires_at INT)")
    conn.executemany("INSERT INTO users (email) VALUES (?)", [(f"u{i}@x.com",) for i in range(80)])
    # 6000 live sessions (far-future expiry) = what a mass delete would wipe out
    conn.executemany("INSERT INTO sessions (user_id, expires_at) VALUES (?, 1000)", [(i % 50,) for i in range(6000)])
    # 30 expired sessions waiting for tonight's cleanup (expiry 99, which training never deletes)
    conn.executemany("INSERT INTO sessions (user_id, expires_at) VALUES (?, 99)", [(i % 50,) for i in range(30)])


def _probe(conn, det: Detector) -> list[tuple[str, str, float, str]]:
    out = []
    for label, sql, count_sql in PROBES:
        rows = conn.execute(count_sql).fetchone()[0] if count_sql else None
        vs = det.analyze(sql, estimated_rows=rows)
        v = max(vs, key=lambda v: v.score)
        out.append((label, v.level, v.score, ",".join(v.reasons) or "-"))
    return out


def _train(conn, det: Detector, budget, days: int, rng: random.Random) -> int:
    """Simulate `days` of normal app traffic; learn every statement the guard calls safe."""
    learned = 0

    def run(sql: str) -> None:
        nonlocal learned
        before = conn.total_changes
        vs = run_statement(conn, det, sql, block=True, budget=budget)
        if any(v.level == "destructive" for v in vs):
            return  # blocked: never executed, never learned
        if det.learn(sql, conn.total_changes - before):
            learned += 1

    for day in range(1, days + 1):
        for _ in range(40):  # daytime app traffic
            uid = rng.randint(1, 50)
            run(rng.choice([
                f"SELECT * FROM users WHERE id = {uid}",
                f"INSERT INTO orders (user_id, status) VALUES ({uid}, 'new')",
                f"UPDATE users SET email = 'e{rng.randint(1, 999)}@x.com' WHERE id = {uid}",
            ]))
        for _ in range(rng.randint(20, 40)):  # sessions that expire today
            conn.execute("INSERT INTO sessions (user_id, expires_at) VALUES (1, ?)", (day,))
        run(f"DELETE FROM sessions WHERE expires_at <= {day}")  # the nightly job
    return learned


def _print(title: str, rows) -> None:
    print(f"\n{title}\n{'-' * 86}")
    print(f"{'Scenario':<28} {'Level':<12} {'Score':<6} Reasons")
    for label, level, score, reasons in rows:
        print(f"{label:<28} {level:<12} {score:<6.2f} {reasons}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--days", type=int, default=14, help="length of simulated training period")
    ap.add_argument("--keep-profile", help="where to save the learned profile (default: temp dir)")
    ap.add_argument("--seed", type=int, default=0)
    args = ap.parse_args()

    conn, budget = make_sandbox()
    _setup(conn)
    model = train(seed=args.seed)

    before = _probe(conn, Detector(model=model))
    _print("BEFORE training (cold start: nothing learned yet)", before)

    # Training period: learning mode ignores profile signals until `learning_target` safe
    # statements were seen, then flips to enforcing by itself.
    det = Detector(model=model, learning_target=300)
    print(f"\nMode at start: {det.mode}")
    n = _train(conn, det, budget, args.days, random.Random(args.seed))
    print(f">>> Training period: {args.days} simulated days, {n} safe statements learned; mode now: {det.mode} <<<")
    path = args.keep_profile or os.path.join(tempfile.mkdtemp(), "profile.json")
    det.profile.save(path)
    det = Detector(model=model, profile=BehaviourProfile.load(path))  # as after a restart
    print(f"Profile saved to {path} and reloaded into a fresh detector (survives restarts).")
    for (verb, tbl), s in sorted(det.profile._store.items()):
        print(f"    learned {verb:<7} {tbl:<9} seen={s.count:<4} avg_rows={s.mean:<6.1f} std={s.std:.1f}")

    after = _probe(conn, det)
    _print("AFTER training", after)

    print("\nChange:")
    for (label, lv0, s0, _), (_, lv1, s1, r1) in zip(before, after):
        print(f"  {label:<28} {lv0:>11} {s0:.2f} -> {lv1:>11} {s1:.2f}")
    conn.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
