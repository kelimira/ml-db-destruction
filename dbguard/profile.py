"""Online in-memory database behaviour profiling with Welford statistics and LRU eviction."""

from __future__ import annotations

from collections import OrderedDict
import json
import math
import os
from dbguard.sqltok import Stmt

MAX_PROFILE_SIZE = 8 * 1024 * 1024


class KeyStats:
    """Statistics for a single (verb, table) profile key."""

    def __init__(self) -> None:
        self.count: int = 0
        self.row_count: int = 0
        self.mean: float = 0.0
        self.m2: float = 0.0

    @property
    def std(self) -> float:
        if self.row_count < 2:
            return 0.0
        variance = self.m2 / (self.row_count - 1)
        return math.sqrt(variance)

    def update(self, rows_affected: int | None) -> None:
        self.count += 1
        if rows_affected is not None:
            self.row_count += 1
            x = float(rows_affected)
            delta = x - self.mean
            self.mean += delta / self.row_count
            delta2 = x - self.mean
            self.m2 += delta * delta2


class BehaviourProfile:
    """In-memory online profile learning (verb, table) frequencies and volume stats."""

    def __init__(self, max_keys: int = 10_000) -> None:
        self.max_keys = max_keys
        self._store: OrderedDict[tuple[str, str], KeyStats] = OrderedDict()

    def _keys_for(self, stmt: Stmt) -> list[tuple[str, str]]:
        if not stmt.tables:
            return [(stmt.verb, "*")]
        return [(stmt.verb, tbl) for tbl in stmt.tables]

    def observe(self, stmt: Stmt, rows_affected: int | None = None) -> None:
        """Observe executed safe statement and update frequency and volume statistics."""
        for key in self._keys_for(stmt):
            if key in self._store:
                stats = self._store[key]
                self._store.move_to_end(key)
            else:
                if len(self._store) >= self.max_keys:
                    self._store.popitem(last=False)
                stats = KeyStats()
                self._store[key] = stats

            stats.update(rows_affected)

    def novelty(self, stmt: Stmt) -> float:
        """Calculate novelty score in [0.0, 1.0]. 1.0 is completely unseen."""
        keys = self._keys_for(stmt)
        if not keys:
            return 1.0

        max_nov = 0.0
        for key in keys:
            if key in self._store:
                self._store.move_to_end(key)
                cnt = self._store[key].count
                nov = 1.0 - min(1.0, cnt / 10.0)
            else:
                nov = 1.0
            if nov > max_nov:
                max_nov = nov
        return max_nov

    def volume_outlier(self, stmt: Stmt, rows: int) -> bool:
        """Check if statement affected rows count is a volume outlier per §5."""
        keys = self._keys_for(stmt)
        for key in keys:
            if key not in self._store:
                continue
            self._store.move_to_end(key)
            stats = self._store[key]

            # 1. At least 5 samples with row counts
            if stats.row_count < 5:
                continue

            # 2. z-score > 3
            z = (rows - stats.mean) / max(stats.std, 1.0)
            if z <= 3.0:
                continue

            # 3. rows >= 50
            if rows < 50:
                continue

            # 4. rows >= 10 * mean
            if rows < 10.0 * stats.mean:
                continue

            return True

        return False

    @property
    def total_observed(self) -> int:
        return sum(s.count for s in self._store.values())

    def to_json(self) -> str:
        """Serialize learned state (LRU order preserved)."""
        keys = [[v, t, s.count, s.row_count, s.mean, s.m2] for (v, t), s in self._store.items()]
        return json.dumps({"version": 1, "max_keys": self.max_keys, "keys": keys})

    @classmethod
    def from_json(cls, text: str) -> "BehaviourProfile":
        """Load and validate a profile; raises ValueError on any malformed input."""
        if len(text.encode("utf-8")) > MAX_PROFILE_SIZE:
            raise ValueError("Profile file exceeds 8 MiB limit")
        try:
            data = json.loads(text)
            if data["version"] != 1 or set(data) != {"version", "max_keys", "keys"}:
                raise ValueError("bad version or keys")
            prof = cls(max_keys=int(data["max_keys"]))
            if len(data["keys"]) > prof.max_keys:
                raise ValueError("more keys than max_keys")
            for verb, tbl, count, row_count, mean, m2 in data["keys"]:
                nums = (count, row_count, mean, m2)
                if not (isinstance(verb, str) and isinstance(tbl, str)) or any(
                    isinstance(n, bool) or not isinstance(n, (int, float)) or not math.isfinite(n) for n in nums
                ):
                    raise ValueError("bad entry")
                if count < 0 or row_count < 0 or row_count > count or m2 < 0:
                    raise ValueError("inconsistent entry")
                s = KeyStats()
                s.count, s.row_count, s.mean, s.m2 = int(count), int(row_count), float(mean), float(m2)
                prof._store[(verb, tbl)] = s
        except (KeyError, TypeError, ValueError) as e:
            raise ValueError(f"Invalid profile: {e}") from e
        return prof

    def save(self, path: str) -> None:
        """Atomically write the profile (tmp file + rename) so a crash never leaves a torn file."""
        tmp = f"{path}.tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(self.to_json())
        os.replace(tmp, path)

    @classmethod
    def load(cls, path: str) -> "BehaviourProfile":
        with open(path, encoding="utf-8") as f:
            return cls.from_json(f.read(MAX_PROFILE_SIZE + 1))
