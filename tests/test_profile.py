"""Tests covering BehaviourProfile: frequency learning, Welford statistics, and LRU eviction."""

import unittest

from dbguard.profile import BehaviourProfile
from dbguard.sqltok import parse


class TestProfile(unittest.TestCase):
    """Test suite for BehaviourProfile (AC-8, AC-9)."""

    def test_ac8_novelty_and_lru_eviction(self) -> None:
        """AC-8: Novelty decreases with observations; LRU eviction maintains size cap."""
        profile = BehaviourProfile(max_keys=100)

        # Unseen key has novelty 1.0
        s1 = parse("SELECT * FROM users")
        self.assertEqual(profile.novelty(s1), 1.0)

        # After observations, novelty decreases
        for i in range(1, 11):
            profile.observe(s1, 1)
            nov = profile.novelty(s1)
            expected_nov = 1.0 - min(1.0, i / 10.0)
            self.assertAlmostEqual(nov, expected_nov, places=5)

        # No-table DDL uses (verb, "*")
        s_notable = parse("CREATE DATABASE analytics")
        self.assertEqual(profile.novelty(s_notable), 1.0)
        profile.observe(s_notable)
        self.assertIn(("CREATE", "*"), profile._store)
        self.assertLess(profile.novelty(s_notable), 1.0)

        # LRU eviction test with max_keys=100
        lru_profile = BehaviourProfile(max_keys=100)
        first_stmt = parse("SELECT * FROM table_0")
        lru_profile.observe(first_stmt)

        # Insert 100 more distinct keys (table_1 to table_100)
        for i in range(1, 101):
            st = parse(f"SELECT * FROM table_{i}")
            lru_profile.observe(st)

        # Store size must be capped at 100
        self.assertEqual(len(lru_profile._store), 100)

        # First key (table_0) should be evicted as least recently used
        self.assertNotIn(("SELECT", "table_0"), lru_profile._store)
        self.assertEqual(lru_profile.novelty(first_stmt), 1.0)

        # A recently touched key must stay
        recent_stmt = parse("SELECT * FROM table_100")
        self.assertIn(("SELECT", "table_100"), lru_profile._store)
        self.assertLess(lru_profile.novelty(recent_stmt), 1.0)

    def test_ac9_volume_outlier_conditions(self) -> None:
        """AC-9: Welford running variance and 4-way volume outlier conditions."""
        profile = BehaviourProfile()
        stmt = parse("DELETE FROM orders WHERE id = 1")

        # Fewer than 5 samples -> never an outlier
        for _ in range(4):
            profile.observe(stmt, 1)
        self.assertFalse(profile.volume_outlier(stmt, 100000))

        # 5th observation
        profile.observe(stmt, 1)

        # 20 observations of 1 row
        for _ in range(15):
            profile.observe(stmt, 1)

        # 5 rows is not an outlier (z=4, but rows < 50)
        self.assertFalse(profile.volume_outlier(stmt, 5))

        # 49 rows is not an outlier
        self.assertFalse(profile.volume_outlier(stmt, 49))

        # 100,000 rows IS an outlier
        self.assertTrue(profile.volume_outlier(stmt, 100000))

        # Custom history: mean 100, std ~10
        prof_custom = BehaviourProfile()
        st_users = parse("UPDATE users SET email = 'x' WHERE id = 1")
        # 10 samples around 100: [90, 110, 95, 105, 100, 100, 98, 102, 97, 103]
        samples = [90, 110, 95, 105, 100, 100, 98, 102, 97, 103]
        for s in samples:
            prof_custom.observe(st_users, s)

        # 500 rows: z > 3, rows >= 50, but rows >= 10*mean is false (500 >= 1000 is False)
        self.assertFalse(prof_custom.volume_outlier(st_users, 500))

        # 1500 rows IS an outlier (1500 >= 1000, 1500 >= 50, z > 3)
        self.assertTrue(prof_custom.volume_outlier(st_users, 1500))


if __name__ == "__main__":
    unittest.main()
