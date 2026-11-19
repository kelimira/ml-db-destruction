"""Performance tests verifying AC-15 throughput and time bounds."""

import os
import statistics
import time
import unittest

from dbguard.detector import Detector


class TestPerf(unittest.TestCase):
    """Test suite for performance requirements (AC-15)."""

    def setUp(self) -> None:
        self.detector = Detector()
        factor_str = os.environ.get("DBGUARD_PERF_FACTOR", "1.0")
        try:
            self.factor = float(factor_str)
        except ValueError:
            self.factor = 1.0

    def test_ac15_throughput_median(self) -> None:
        """AC-15: 2000 statements in under 2s (median of 3 runs)."""
        sql = "SELECT * FROM orders WHERE id = 42"
        runs: list[float] = []

        for _ in range(3):
            start = time.monotonic()
            for _ in range(2000):
                self.detector.analyze(sql)
            elapsed = time.monotonic() - start
            runs.append(elapsed)

        med = statistics.median(runs)
        max_allowed = 2.0 * self.factor
        print(f"\n[AC-15 Performance] 2000 analyze() calls median: {med:.4f}s (target < {max_allowed}s)")
        self.assertLess(med, max_allowed, f"Throughput target failed: median {med:.3f}s exceeds {max_allowed}s")

    def test_ac15_multi_reading_large_inputs(self) -> None:
        """AC-15: Multi-reading scans finish within spec time bounds."""
        # 4 readings (e.g. backslash and hash) under 4s
        inp4 = ("SELECT 'a\\' + # comment\n" * 1500)[:65000]
        start4 = time.monotonic()
        self.detector.analyze(inp4)
        elapsed4 = time.monotonic() - start4
        self.assertLess(elapsed4, 4.0 * self.factor)

        # 32 readings (all 5 triggers) under 32s
        inp32 = ("/* /* */ SELECT 'a\\' + # $1 --x\n" * 1500)[:65000]
        start32 = time.monotonic()
        self.detector.analyze(inp32)
        elapsed32 = time.monotonic() - start32
        self.assertLess(elapsed32, 32.0 * self.factor)


if __name__ == "__main__":
    unittest.main()
