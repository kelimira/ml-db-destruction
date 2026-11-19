"""Synthetic corpus generator for training and evaluating dbguard."""

from __future__ import annotations

import random
from dbguard.features import extract
from dbguard.sqltok import parse

TABLES = ["users", "orders", "products", "accounts", "logs", "metrics", "sessions", "items"]
COLUMNS = ["id", "status", "created_at", "email", "amount", "name", "user_id", "data"]


def generate_corpus(seed: int = 0, n: int = 2000) -> list[tuple[str, int | None, float]]:
    """Generate n synthetic (sql, estimated_rows, label) tuples.

    label is 1.0 for destructive/warn operations, 0.0 for benign/safe operations.
    """
    rng = random.Random(seed)
    samples: list[tuple[str, int | None, float]] = []

    # Safe templates (label = 0.0)
    def gen_safe() -> tuple[str, int | None, float]:
        choice = rng.randint(0, 5)
        tbl = rng.choice(TABLES)
        col = rng.choice(COLUMNS)
        val = rng.randint(1, 100)

        if choice == 0:
            # Simple SELECT
            return (f"SELECT * FROM {tbl} WHERE {col} = {val}", None, 0.0)
        elif choice == 1:
            # Aggregate SELECT
            return (f"SELECT count(*) FROM {tbl}", None, 0.0)
        elif choice == 2:
            # INSERT
            return (f"INSERT INTO {tbl} ({col}) VALUES ({val})", None, 0.0)
        elif choice == 3:
            # Bounded UPDATE (small row count <= 10)
            rows = rng.randint(1, 5)
            return (f"UPDATE {tbl} SET {col} = {val} WHERE id = {val}", rows, 0.0)
        elif choice == 4:
            # Bounded DELETE (small row count <= 5)
            rows = rng.randint(1, 3)
            return (f"DELETE FROM {tbl} WHERE id = {val}", rows, 0.0)
        else:
            # DDL / TCL
            sub = rng.choice(["CREATE TABLE temp_t (id INT)", "BEGIN", "COMMIT"])
            return (sub, None, 0.0)

    # Destructive / Warn templates (label = 1.0)
    def gen_destructive() -> tuple[str, int | None, float]:
        choice = rng.randint(0, 9)
        tbl = rng.choice(TABLES)
        col = rng.choice(COLUMNS)

        if choice == 0:
            # DROP TABLE
            return (f"DROP TABLE {tbl}", None, 1.0)
        elif choice == 1:
            # TRUNCATE
            return (f"TRUNCATE TABLE {tbl}", None, 1.0)
        elif choice == 2:
            # DELETE without WHERE
            return (f"DELETE FROM {tbl}", rng.randint(100, 10000), 1.0)
        elif choice == 3:
            # UPDATE without WHERE
            return (f"UPDATE {tbl} SET {col} = 1", rng.randint(100, 10000), 1.0)
        elif choice == 4:
            # DELETE with tautology WHERE
            return (f"DELETE FROM {tbl} WHERE 1 = 1", rng.randint(100, 10000), 1.0)
        elif choice == 5:
            # UPDATE with tautology WHERE
            return (f"UPDATE {tbl} SET {col} = 1 WHERE 'a' = 'a'", rng.randint(100, 10000), 1.0)
        elif choice == 6:
            # ALTER DROP COLUMN
            return (f"ALTER TABLE {tbl} DROP COLUMN {col}", None, 1.0)
        elif choice == 7:
            # ALTER RENAME
            return (f"ALTER TABLE {tbl} RENAME TO old_{tbl}", None, 1.0)
        elif choice == 8:
            # High volume bounded DELETE (volume_outlier)
            return (f"DELETE FROM {tbl} WHERE status = 'old'", rng.randint(5000, 50000), 1.0)
        else:
            # REPLACE INTO
            return (f"REPLACE INTO {tbl} ({col}) VALUES (1)", None, 1.0)

    half = n // 2
    for _ in range(half):
        samples.append(gen_safe())
    for _ in range(n - half):
        samples.append(gen_destructive())

    rng.shuffle(samples)
    return samples


def generate_feature_dataset(seed: int = 0, n: int = 2000) -> list[tuple[list[float], float]]:
    """Generate (features, label) dataset from synthetic SQL corpus."""
    raw = generate_corpus(seed=seed, n=n)
    dataset: list[tuple[list[float], float]] = []
    for sql, est_rows, label in raw:
        stmt = parse(sql)
        feats = extract(stmt, est_rows)
        dataset.append((feats, label))
    return dataset
