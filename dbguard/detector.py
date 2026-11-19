"""Core detector combining lexical analysis, policy rules, ML model, and behavior profile."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from dbguard.features import extract
from dbguard.model import LogisticModel, train
from dbguard.policy import policy_rules
from dbguard.profile import BehaviourProfile
from dbguard.sqltok import SQLITE, Reading, Stmt, parse, readings_for, split_statements

Level = Literal["safe", "warn", "destructive"]

LEVEL_ORDER = {"safe": 0, "warn": 1, "destructive": 2}


@dataclass(frozen=True)
class Verdict:
    """The classification verdict for a single parsed SQL statement."""

    stmt: Stmt
    score: float
    level: Level
    reasons: tuple[str, ...]


class Detector:
    """Multi-reading SQL detector for destructive operations."""

    def __init__(
        self,
        model: LogisticModel | None = None,
        profile: BehaviourProfile | None = None,
        warn_at: float = 0.4,
        destructive_at: float = 0.7,
    ) -> None:
        if not (0.0 <= warn_at <= destructive_at <= 1.0):
            raise ValueError(
                f"Thresholds must satisfy 0 <= warn_at <= destructive_at <= 1; got warn_at={warn_at}, destructive_at={destructive_at}"
            )
        self.warn_at = warn_at
        self.destructive_at = destructive_at
        self.model = model if model is not None else train(seed=0)
        self.profile = profile if profile is not None else BehaviourProfile()

    def _score_stmt(self, stmt: Stmt, estimated_rows: int | None = None) -> Verdict:
        """Score a single parsed statement per §4.1."""
        reasons: list[str] = []

        # 1. Deterministic policy rules
        rules = policy_rules(stmt)

        # 2-3. ML model prediction
        x = extract(stmt, estimated_rows)
        score = self.model.predict_proba(x)

        # 4. Novelty penalty for DML / DDL
        if stmt.kind in ("DML", "DDL"):
            score = score + 0.15 * self.profile.novelty(stmt)

        # 5. Volume outlier check
        if estimated_rows is not None and self.profile.volume_outlier(stmt, estimated_rows):
            score = max(score, self.warn_at)
            reasons.append("volume_outlier")

        # 6. Policy floor
        if rules:
            score = max(score, self.destructive_at)
            for r in rules:
                reasons.append(f"policy:{r}")

        # 7. Unparsed and admin statements
        if stmt.verb == "UNPARSED":
            score = max(score, self.warn_at)
            reasons.append("unparsed")
        elif stmt.kind == "OTHER" and "admin" in stmt.flags:
            score = max(score, self.warn_at)
            reasons.append("admin_stmt")

        # 8. Clamp score
        score = min(1.0, max(0.0, score))

        # 9. Initial level assignment
        if score >= self.destructive_at:
            level: Level = "destructive"
        elif score >= self.warn_at:
            level = "warn"
        else:
            level = "safe"

        # 10. Plain-EXPLAIN downgrade (§3.3), applied last
        if stmt.explain == "plain":
            level = "safe"
            reasons.append("explain_plain_not_executed")
        elif stmt.explain == "analyze":
            reasons.append("explain_analyze_executes")

        return Verdict(
            stmt=stmt,
            score=score,
            level=level,
            reasons=tuple(reasons),
        )

    def analyze(self, sql: str, estimated_rows: int | None = None) -> list[Verdict]:
        """Analyze SQL string across all relevant readings and return highest severity result."""
        readings = readings_for(sql)

        # Map each reading to list of verdicts and max level
        results: list[tuple[Reading, list[Verdict], float, int, int]] = []
        highest_levels: list[int] = []

        for reading in readings:
            pieces = split_statements(sql, reading)
            verdicts: list[Verdict] = []
            use_est = estimated_rows if len(pieces) == 1 else None

            for piece in pieces:
                stmt = parse(piece, reading)
                v = self._score_stmt(stmt, use_est)
                verdicts.append(v)

            if not verdicts:
                highest_levels.append(0)
                continue

            max_score = max(v.score for v in verdicts)
            non_safe_count = sum(1 for v in verdicts if v.level != "safe")
            reading_max_level = max(LEVEL_ORDER[v.level] for v in verdicts)
            highest_levels.append(reading_max_level)

            results.append((reading, verdicts, max_score, non_safe_count, reading_max_level))

        if not results:
            return []

        # Check if readings disagree on the highest level
        dialect_ambiguous = len(set(highest_levels)) > 1

        # Sort readings by severity:
        # 1. highest max score (descending)
        # 2. most non-safe verdicts (descending)
        # 3. prefer SQLITE reading (reading == SQLITE)
        results.sort(
            key=lambda item: (item[2], item[3], 1 if item[0] == SQLITE else 0),
            reverse=True,
        )

        best_reading, kept_verdicts, _, _, _ = results[0]

        # If dialect_ambiguous, add reason to every non-safe verdict
        final_verdicts: list[Verdict] = []
        for v in kept_verdicts:
            if dialect_ambiguous and v.level != "safe":
                new_reasons = v.reasons + ("dialect_ambiguous",)
                final_verdicts.append(
                    Verdict(
                        stmt=v.stmt,
                        score=v.score,
                        level=v.level,
                        reasons=new_reasons,
                    )
                )
            else:
                final_verdicts.append(v)

        return final_verdicts

    def learn(self, sql: str, rows_affected: int | None) -> bool:
        """Re-analyze SQL and learn behavior if and only if all statements are safe."""
        verdicts = self.analyze(sql, estimated_rows=rows_affected)
        if not verdicts:
            return False

        # Every verdict must be safe, explain must be empty, verb not UNPARSED
        for v in verdicts:
            if v.level != "safe" or v.stmt.explain != "" or v.stmt.verb == "UNPARSED":
                return False

        for v in verdicts:
            self.profile.observe(v.stmt, rows_affected)

        return True
