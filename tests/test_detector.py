"""Tests covering Detector: policy floor, calibration, adversarial set, volume outliers, and learning."""

import unittest

from dbguard.detector import Detector
from dbguard.features import FEATURE_NAMES
from dbguard.model import LogisticModel
from dbguard.profile import BehaviourProfile
from dbguard.sqltok import parse
try:
    from tests.adversarial import ADVERSARIAL_CASES
except ImportError:
    from adversarial import ADVERSARIAL_CASES



class TestDetector(unittest.TestCase):
    """Test suite for Detector (AC-4 zeroed model, AC-5b, AC-6, AC-9, AC-9b, AC-9c)."""

    def setUp(self) -> None:
        self.detector = Detector()

    def test_ac4_zeroed_model_floor(self) -> None:
        """AC-4: Zeroed model produces destructive verdicts for all policy rules."""
        zero_weights = [0.0] * len(FEATURE_NAMES)
        zero_model = LogisticModel(weights=zero_weights, bias=0.0)
        det = Detector(model=zero_model)

        policy_cases = [
            "DROP TABLE users",
            "DROP DATABASE prod",
            "DROP SCHEMA public",
            "DROP INDEX idx_name",
            "DROP VIEW v_users",
            "DROP USER alice",
            "DROP ROLE admin",
            "DROP TRIGGER trig_update",
            "DROP FUNCTION calc",
            "DROP PROCEDURE proc",
            "DROP SEQUENCE seq_id",
            "DROP TYPE my_type",
            "TRUNCATE orders",
            "TRUNCATE TABLE orders, items CASCADE",
            "DELETE FROM users",
            "DELETE FROM users WHERE 1=1",
            "UPDATE users SET email = 'hacked'",
            "UPDATE users SET email = 'hacked' WHERE 'a'='a'",
            "ALTER TABLE users DROP COLUMN email",
            "ALTER TABLE users DROP email",
            "GRANT ALL PRIVILEGES ON users TO public",
            "GRANT SELECT ON users TO app WITH GRANT OPTION",
            "MERGE INTO target t USING src s ON 1=1 WHEN MATCHED THEN DELETE",
            "REPLACE INTO users (id) VALUES (1)",
            "WITH cte AS (SELECT 1) DELETE FROM users",
            "WITH cte AS (SELECT 1) UPDATE users SET email = 'x'",
        ]

        for sql in policy_cases:
            verdicts = det.analyze(sql)
            self.assertTrue(
                any(v.level == "destructive" for v in verdicts),
                f"Zeroed model failed to flag policy rule as destructive: {sql}",
            )

    def test_ac5b_adversarial_suite(self) -> None:
        """AC-5b: Detector achieves >= 90% recall and precision on adversarial suite."""
        tp, fp, fn, tn = 0, 0, 0, 0

        for sql, expected_destr in ADVERSARIAL_CASES:
            verdicts = self.detector.analyze(sql)
            is_flagged = any(v.level in ("destructive", "warn") for v in verdicts)
            if expected_destr and is_flagged:
                tp += 1
            elif not expected_destr and is_flagged:
                fp += 1
            elif expected_destr and not is_flagged:
                fn += 1
            else:
                tn += 1

        recall = tp / (tp + fn) if (tp + fn) else 0.0
        precision = tp / (tp + fp) if (tp + fp) else 0.0

        print(f"\n[AC-5b Adversarial Results] Recall: {recall:.2%}, Precision: {precision:.2%}")
        self.assertGreaterEqual(recall, 0.90)
        self.assertGreaterEqual(precision, 0.90)

        # Assert no misses on R1, N1, B1 evasions
        evasions = [
            "/* /* */ DROP TABLE users; --*/",
            "SELECT 'a\\' ; DROP TABLE users; --'",
            "SELECT 1 # 2; DROP TABLE users",
            "/* /* */ */ DROP TABLE users",
            "SELECT 1 --; DROP TABLE users",
            "SELECT 1 AS $$; DROP TABLE users; SELECT 1 AS $$",
        ]
        for ev in evasions:
            v_list = self.detector.analyze(ev)
            self.assertTrue(
                any(v.level == "destructive" for v in v_list),
                f"Evasion was missed: {ev}",
            )

    def test_ac6_calibration_and_tautologies(self) -> None:
        """AC-6: Bounded DML safe on cold/warm profile; tautology classification."""
        # Cold profile
        cold_det = Detector()
        v_del_cold = cold_det.analyze("DELETE FROM t WHERE id = 1")
        self.assertEqual(v_del_cold[0].level, "safe")

        v_upd_cold = cold_det.analyze("UPDATE t SET a = 1 WHERE id = 2")
        self.assertEqual(v_upd_cold[0].level, "safe")

        # Warm profile
        warm_det = Detector()
        for _ in range(20):
            warm_det.learn("DELETE FROM t WHERE id = 1", 1)
            warm_det.learn("UPDATE t SET a = 1 WHERE id = 2", 1)

        v_del_warm = warm_det.analyze("DELETE FROM t WHERE id = 1")
        self.assertEqual(v_del_warm[0].level, "safe")

        v_upd_warm = warm_det.analyze("UPDATE t SET a = 1 WHERE id = 2")
        self.assertEqual(v_upd_warm[0].level, "safe")

        # Plain SELECT and INSERT
        self.assertEqual(cold_det.analyze("SELECT * FROM t")[0].level, "safe")
        self.assertEqual(cold_det.analyze("INSERT INTO t VALUES (1)")[0].level, "safe")

        # Subquery in SET without top-level WHERE
        v_sub = cold_det.analyze("UPDATE t SET a = (SELECT x FROM u WHERE u.id = 1)")
        self.assertEqual(v_sub[0].level, "destructive")

        # Tautology table test
        taut_sqls = [
            "DELETE FROM t WHERE id = 1 OR 1=1",
            "DELETE FROM t WHERE id = id",
            "DELETE FROM t WHERE 'a' = 'a'",
            "DELETE FROM t WHERE 1",
            "DELETE FROM t WHERE NOT 0",
            "DELETE FROM t WHERE 1 < 2",
        ]
        for sql in taut_sqls:
            st = parse(sql)
            self.assertTrue(st.tautology_where, f"Expected tautology_where for {sql}")

        non_taut_sqls = [
            "DELETE FROM t WHERE id = 1",
            "DELETE FROM t WHERE 1 = 0",
        ]
        for sql in non_taut_sqls:
            st = parse(sql)
            self.assertFalse(st.tautology_where, f"Expected NOT tautology_where for {sql}")

    def test_ac9_volume_outlier_detection(self) -> None:
        """AC-9: Volume outlier trigger conditions and detector scoring."""
        det = Detector()
        # Train profile with 20 observations of 1 row
        for _ in range(20):
            det.learn("DELETE FROM orders WHERE id = 1", 1)

        # 5 rows is not an outlier (z=4, but rows < 50)
        v5 = det.analyze("DELETE FROM orders WHERE status = 'old'", estimated_rows=5)
        self.assertNotIn("volume_outlier", v5[0].reasons)

        # 49 rows is not an outlier
        v49 = det.analyze("DELETE FROM orders WHERE status = 'old'", estimated_rows=49)
        self.assertNotIn("volume_outlier", v49[0].reasons)

        # 100,000 rows IS an outlier
        v100k = det.analyze("DELETE FROM orders WHERE status = 'old'", estimated_rows=100000)
        self.assertIn("volume_outlier", v100k[0].reasons)
        self.assertGreaterEqual(v100k[0].score, det.warn_at)

        # Without estimated_rows, no volume_outlier
        v_no_est = det.analyze("DELETE FROM orders WHERE status = 'old'")
        self.assertNotIn("volume_outlier", v_no_est[0].reasons)

        # History with mean 100 (std 10)
        prof2 = BehaviourProfile()
        st_base = parse("DELETE FROM users WHERE id = 1")
        # Feed 10 samples of 100
        for _ in range(10):
            prof2.observe(st_base, 100)

        # 500 rows: rows < 10 * mean (500 < 1000), not outlier
        st_test = parse("DELETE FROM users WHERE status = 'inactive'")
        self.assertFalse(prof2.volume_outlier(st_test, 500))

        # 1500 rows IS an outlier (1500 >= 1000 and >= 50 and z > 3)
        self.assertTrue(prof2.volume_outlier(st_test, 1500))

    def test_ac9b_threshold_validation(self) -> None:
        """AC-9b: Detector threshold validation."""
        # warn_at > destructive_at raises ValueError
        with self.assertRaises(ValueError):
            Detector(warn_at=0.8, destructive_at=0.5)

        # Out of bounds < 0 or > 1
        with self.assertRaises(ValueError):
            Detector(warn_at=-0.1, destructive_at=0.7)

        with self.assertRaises(ValueError):
            Detector(warn_at=0.4, destructive_at=1.1)

        # warn_at == destructive_at is allowed
        d_equal = Detector(warn_at=0.6, destructive_at=0.6)
        self.assertEqual(d_equal.warn_at, 0.6)
        self.assertEqual(d_equal.destructive_at, 0.6)

    def test_ac9c_learn_filter(self) -> None:
        """AC-9c (R5): learn ignores anything not safe; returns True only on safe."""
        det = Detector()

        # Destructive statement
        self.assertFalse(det.learn("DROP TABLE t", None))

        # Unbounded delete
        self.assertFalse(det.learn("DELETE FROM t", 3))

        # EXPLAIN statement (plain or analyze)
        self.assertFalse(det.learn("EXPLAIN DELETE FROM t WHERE id=1", 1))

        # Volume outlier statement
        for _ in range(10):
            det.learn("DELETE FROM orders WHERE id=1", 1)
        self.assertFalse(det.learn("DELETE FROM orders WHERE status='old'", 100000))

        # Unparsed input
        self.assertFalse(det.learn("SELECT 'unterminated", 1))

        # Multi-statement input where one is destructive
        self.assertFalse(det.learn("SELECT 1; DROP TABLE t", 1))

        # Safe statement learns and returns True
        init_keys = len(det.profile._store)
        res = det.learn("INSERT INTO new_table (id) VALUES (1)", 1)
        self.assertTrue(res)
        self.assertGreater(len(det.profile._store), init_keys)


if __name__ == "__main__":
    unittest.main()
