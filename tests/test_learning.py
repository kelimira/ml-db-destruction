"""Tests for profile persistence and learning mode."""

import os
import tempfile
import unittest

from dbguard.detector import Detector
from dbguard.profile import BehaviourProfile

UPD = "UPDATE users SET email = 'x' WHERE id > 0"


def _train(det: Detector, n: int = 20) -> None:
    for i in range(n):
        det.learn(f"UPDATE users SET email = 'x' WHERE id = {i}", 1)


class TestLearning(unittest.TestCase):
    def test_profile_roundtrip_and_rejects_garbage(self) -> None:
        det = Detector()
        _train(det)
        path = os.path.join(tempfile.mkdtemp(), "p.json")
        det.profile.save(path)
        loaded = BehaviourProfile.load(path)
        self.assertEqual(loaded.total_observed, 20)
        self.assertEqual(loaded.to_json(), det.profile.to_json())
        for bad in ("nope", '{"version":2,"max_keys":5,"keys":[]}',
                    '{"version":1,"max_keys":5,"keys":[["A","b",1,2,0,0]]}',
                    '{"version":1,"max_keys":5,"keys":[["A","b",1,1,NaN,0]]}'):
            with self.assertRaises(ValueError):
                BehaviourProfile.from_json(bad)

    def test_learning_mode_suppresses_then_enforces(self) -> None:
        det = Detector(learning_target=10)
        self.assertEqual(det.mode, "learning")
        _train(det, 9)
        self.assertEqual(det.mode, "learning")
        _train(det, 1)
        self.assertEqual(det.mode, "enforcing")

    def test_learned_volume_catches_what_model_alone_misses(self) -> None:
        cold = Detector().analyze(UPD, estimated_rows=80)[0]
        self.assertEqual(cold.level, "safe")
        det = Detector()
        _train(det)
        warm = det.analyze(UPD, estimated_rows=80)[0]
        self.assertEqual(warm.level, "warn")
        self.assertIn("volume_outlier", warm.reasons)

    def test_learning_mode_does_not_lower_policy_floor(self) -> None:
        v = Detector(learning_target=100).analyze("DROP TABLE users")[0]
        self.assertEqual(v.level, "destructive")

    def test_extreme_outlier_is_destructive(self) -> None:
        det = Detector()
        _train(det)
        self.assertEqual(det.analyze(UPD, estimated_rows=5000)[0].level, "destructive")


if __name__ == "__main__":
    unittest.main()


class TestApprove(unittest.TestCase):
    ARCHIVE = "UPDATE orders SET status = 'a' WHERE status = 'c'"

    def _det(self) -> Detector:
        det = Detector()
        for i in range(7):
            det.learn(f"UPDATE orders SET status = 's' WHERE id = {i}", 1)
        return det

    def test_approval_turns_warn_into_safe(self) -> None:
        det = self._det()
        self.assertEqual(det.analyze(self.ARCHIVE, 120)[0].level, "warn")
        self.assertFalse(det.learn(self.ARCHIVE, 120))  # warn is never auto-learned
        self.assertTrue(det.approve(self.ARCHIVE, 120))
        self.assertEqual(det.analyze(self.ARCHIVE, 120)[0].level, "safe")
        self.assertEqual(det.analyze(self.ARCHIVE, 5000)[0].level, "destructive")

    def test_destructive_cannot_be_approved(self) -> None:
        det = self._det()
        self.assertFalse(det.approve("DELETE FROM orders", None))
        self.assertFalse(det.approve("DROP TABLE orders", None))
