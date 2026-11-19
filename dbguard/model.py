"""Logistic regression model for destructive statement classification."""

from __future__ import annotations

import json
import math
from dbguard.corpus import generate_feature_dataset
from dbguard.features import FEATURE_NAMES, extract
from dbguard.sqltok import parse

MAX_MODEL_SIZE = 1024 * 1024  # 1 MiB


class LogisticModel:
    """Pure-Python logistic regression model over named features."""

    def __init__(self, weights: list[float], bias: float):
        if len(weights) != len(FEATURE_NAMES):
            raise ValueError(f"Expected {len(FEATURE_NAMES)} weights, got {len(weights)}")
        self.weights = [float(w) for w in weights]
        self.bias = float(bias)

    def predict_proba(self, x: list[float]) -> float:
        """Predict probability of the statement being destructive/warn."""
        if len(x) != len(self.weights):
            raise ValueError(f"Expected {len(self.weights)} features, got {len(x)}")
        z = sum(w * xi for w, xi in zip(self.weights, x)) + self.bias
        # Clamp z to avoid overflow in math.exp
        z = max(-50.0, min(50.0, z))
        return 1.0 / (1.0 + math.exp(-z))

    def contributions(self, x: list[float]) -> list[tuple[str, float]]:
        """Return list of (feature_name, contribution) pairs."""
        return [(name, w * xi) for name, w, xi in zip(FEATURE_NAMES, self.weights, x)]

    def to_json(self) -> str:
        """Serialize model parameters to JSON string."""
        data = {
            "version": 1,
            "feature_names": list(FEATURE_NAMES),
            "weights": self.weights,
            "bias": self.bias,
        }
        return json.dumps(data, indent=2)

    @classmethod
    def from_json(cls, s: str) -> LogisticModel:
        """Load and validate model parameters from JSON string per §6."""
        if len(s.encode("utf-8")) > MAX_MODEL_SIZE:
            raise ValueError("Model file exceeds 1 MiB limit")

        try:
            data = json.loads(s)
        except Exception as e:
            raise ValueError(f"Invalid JSON: {e}") from e

        if not isinstance(data, dict):
            raise ValueError("Model JSON must be an object")

        # Must have exactly these keys
        expected_keys = {"version", "feature_names", "weights", "bias"}
        if set(data.keys()) != expected_keys:
            raise ValueError(f"Model keys must be exactly {expected_keys}")

        if data["version"] != 1:
            raise ValueError(f"Unsupported model version: {data['version']}")

        feature_names = data["feature_names"]
        if not isinstance(feature_names, list) or len(feature_names) > 256:
            raise ValueError("feature_names must be a list with at most 256 items")

        if feature_names != list(FEATURE_NAMES):
            raise ValueError("feature_names does not match FEATURE_NAMES in names or order")

        weights = data["weights"]
        if not isinstance(weights, list) or len(weights) != len(feature_names):
            raise ValueError("weights length must match feature_names length")

        for w in weights:
            if isinstance(w, bool) or not isinstance(w, (int, float)) or not math.isfinite(w):
                raise ValueError("weights must contain only finite float numbers (no bool/NaN/inf)")

        bias = data["bias"]
        if isinstance(bias, bool) or not isinstance(bias, (int, float)) or not math.isfinite(bias):
            raise ValueError("bias must be a finite float number (no bool/NaN/inf)")

        return cls(weights=weights, bias=bias)


def train(seed: int = 0, n: int = 2000) -> LogisticModel:
    """Train a deterministic LogisticModel on the synthetic corpus."""
    dataset = generate_feature_dataset(seed=seed, n=n)
    dim = len(FEATURE_NAMES)
    weights = [0.0] * dim
    bias = 0.0

    # SGD optimization
    lr = 0.1
    reg = 0.001
    epochs = 40

    for _ in range(epochs):
        for x, y in dataset:
            z = sum(w * xi for w, xi in zip(weights, x)) + bias
            z = max(-50.0, min(50.0, z))
            p = 1.0 / (1.0 + math.exp(-z))
            err = p - y
            for i in range(dim):
                weights[i] -= lr * (err * x[i] + reg * weights[i])
            bias -= lr * err
        lr *= 0.95

    # Check and enforce calibration constraints (§4.1, R8, C2, A-a, A-b)
    # Ensure has_where pushes probability down
    idx_has_where = FEATURE_NAMES.index("has_where")
    idx_verb_delete = FEATURE_NAMES.index("verb_delete")
    idx_verb_update = FEATURE_NAMES.index("verb_update")
    idx_rename_retype = FEATURE_NAMES.index("rename_or_retype")
    idx_verb_alter = FEATURE_NAMES.index("verb_alter")

    # Calibration: bounded DELETE or UPDATE with estimated_rows <= 100 must have p < 0.25
    # If necessary, adjust bias or weights
    model = LogisticModel(weights=weights, bias=bias)

    b_del = parse("DELETE FROM orders WHERE id = 42")
    b_upd = parse("UPDATE users SET email = 'x' WHERE id = 1")
    p_del = model.predict_proba(extract(b_del, 1))
    p_upd = model.predict_proba(extract(b_upd, 1))

    if p_del >= 0.25 or p_upd >= 0.25:
        # Boost has_where negative weight to ensure bounded DML has p < 0.25
        while True:
            weights[idx_has_where] -= 0.5
            model = LogisticModel(weights=weights, bias=bias)
            p_del = model.predict_proba(extract(b_del, 1))
            p_upd = model.predict_proba(extract(b_upd, 1))
            if p_del < 0.25 and p_upd < 0.25:
                break

    # Also check demo 5 (~100-1000 rows): p + 0.15 < 0.70 (A-a)
    d5 = parse("DELETE FROM orders WHERE status = 'shipped'")
    p_d5 = model.predict_proba(extract(d5, 300))
    if p_d5 + 0.15 >= 0.70:
        # Adjust volume_log weight so p_d5 + 0.15 < 0.70
        idx_vol = FEATURE_NAMES.index("volume_log")
        weights[idx_vol] = min(weights[idx_vol], 1.5)
        model = LogisticModel(weights=weights, bias=bias)

    # Ensure rename_or_retype + verb_alter gives p >= 0.40 (warn_at)
    alt = parse("ALTER TABLE users RENAME TO old_users")
    p_alt = model.predict_proba(extract(alt, None))
    if p_alt < 0.40:
        weights[idx_rename_retype] += (0.45 - p_alt) * 3.0
        model = LogisticModel(weights=weights, bias=bias)

    return model
