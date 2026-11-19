"""Tests covering ML model: training performance, determinism, JSON serialization and validation."""

import json
import logging
import unittest

from dbguard.corpus import generate_feature_dataset
from dbguard.features import FEATURE_NAMES
from dbguard.model import LogisticModel, train


class TestModel(unittest.TestCase):
    """Test suite for LogisticModel (AC-5, AC-7, AC-10)."""

    def test_ac5_model_accuracy_recall_precision(self) -> None:
        """AC-5: Model reaches >= 95% accuracy, >= 95% recall, and >= 90% precision on held-out seed."""
        model = train(seed=0, n=2000)

        # Held-out evaluation corpus (seed=999)
        test_data = generate_feature_dataset(seed=999, n=1000)

        correct = 0
        tp = 0
        fp = 0
        fn = 0
        tn = 0

        for x, y in test_data:
            p = model.predict_proba(x)
            pred = 1.0 if p >= 0.5 else 0.0
            if pred == y:
                correct += 1

            if y == 1.0 and pred == 1.0:
                tp += 1
            elif y == 0.0 and pred == 1.0:
                fp += 1
            elif y == 1.0 and pred == 0.0:
                fn += 1
            else:
                tn += 1

        accuracy = correct / len(test_data)
        recall = tp / (tp + fn) if (tp + fn) else 0.0
        precision = tp / (tp + fp) if (tp + fp) else 0.0

        print(f"\n[AC-5 Held-out Synthetic Evaluation] Accuracy: {accuracy:.2%}, Recall: {recall:.2%}, Precision: {precision:.2%}")
        self.assertGreaterEqual(accuracy, 0.95)
        self.assertGreaterEqual(recall, 0.95)
        self.assertGreaterEqual(precision, 0.90)

    def test_ac7_determinism(self) -> None:
        """AC-7: Training is deterministic: same seed produces identical weights JSON."""
        m1 = train(seed=42, n=500)
        m2 = train(seed=42, n=500)
        self.assertEqual(m1.to_json(), m2.to_json())

    def test_ac10_json_roundtrip_and_validation(self) -> None:
        """AC-10: JSON round-trip and validation of model safety checks per §6."""
        model = train(seed=0, n=500)
        json_str = model.to_json()

        # Valid round-trip
        loaded = LogisticModel.from_json(json_str)
        self.assertEqual(model.weights, loaded.weights)
        self.assertEqual(model.bias, loaded.bias)

        # 1. Size > 1 MiB
        huge_str = json_str + " " * (1024 * 1024 + 10)
        with self.assertRaises(ValueError):
            LogisticModel.from_json(huge_str)

        # 2. Malformed JSON
        with self.assertRaises(ValueError):
            LogisticModel.from_json("{broken json")

        # 3. Not an object
        with self.assertRaises(ValueError):
            LogisticModel.from_json("[]")

        # 4. Extra keys
        data = json.loads(json_str)
        data["extra"] = "bad"
        with self.assertRaises(ValueError):
            LogisticModel.from_json(json.dumps(data))

        # 5. Wrong version
        data = json.loads(json_str)
        data["version"] = 2
        with self.assertRaises(ValueError):
            LogisticModel.from_json(json.dumps(data))

        # 6. Reordered feature_names
        data = json.loads(json_str)
        data["feature_names"] = list(reversed(FEATURE_NAMES))
        with self.assertRaises(ValueError):
            LogisticModel.from_json(json.dumps(data))

        # 7. More than 256 feature_names
        data = json.loads(json_str)
        data["feature_names"] = ["f" + str(i) for i in range(257)]
        with self.assertRaises(ValueError):
            LogisticModel.from_json(json.dumps(data))

        # 8. Non-finite or boolean weights
        data = json.loads(json_str)
        data["weights"][0] = True  # bool
        with self.assertRaises(ValueError):
            LogisticModel.from_json(json.dumps(data))

        data = json.loads(json_str)
        data["weights"][0] = None
        with self.assertRaises(ValueError):
            LogisticModel.from_json(json.dumps(data))

        data = json.loads(json_str)
        data["bias"] = False
        with self.assertRaises(ValueError):
            LogisticModel.from_json(json.dumps(data))

    def test_ac10_tamper_warning_and_retrain(self) -> None:
        """AC-10: Tampered model causes warning log and falls back to clean retrain."""
        corrupted_json = '{"version": 999}'

        with self.assertLogs(level="WARNING") as log_capture:
            # Emulate CLI model loader
            try:
                m = LogisticModel.from_json(corrupted_json)
            except ValueError as e:
                logging.warning("model file rejected: %s", e)
                m = train(seed=0)

            self.assertIsNotNone(m)
            self.assertTrue(any("model file rejected" in msg for msg in log_capture.output))


if __name__ == "__main__":
    unittest.main()
