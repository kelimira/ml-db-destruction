# dbguard

`dbguard` is a machine learning database guard. It detects destructive DML and DDL statements, produces alerts, and provides an offline simulation interface.

## Architecture

`dbguard` combines three evaluation layers:
1. **Deterministic Policy Rules**: Enforces strict floors for destructive DDL and unbounded DML. Machine learning cannot lower these floors.
2. **Logistic Regression Model**: Evaluates 22 structural and lexical features to score fuzzy cases (renames, column retypes, volume blast radius, unknown shapes).
3. **Online Behaviour Profile**: Learns `(verb, table)` execution frequencies and Welford running volume statistics in memory.

Dependencies flow one way: `sqltok -> features/policy -> model -> profile -> detector -> notify -> sim`.

## Requirements
- Python 3.11 or later.
- POSIX-compliant operating system (uses `O_NOFOLLOW` and `fchmod`).
- Zero third-party runtime dependencies (pure Python standard library).

## Installation
Install from source using `pip`:
```bash
pip install .
```

## CLI Usage

### Demo Mode
Runs database setup, trains on safe baseline traffic, and executes the 14-statement benchmark scenario:
```bash
python -m dbguard demo
```

Run with alert logging to a secure JSONL file:
```bash
python -m dbguard demo --alerts alerts.jsonl
```

Run without blocking destructive statements:
```bash
python -m dbguard demo --no-block
```

### REPL Mode
Interactive shell to evaluate statements against the detector and sandbox:
```bash
python -m dbguard repl
```
Commands:
- Type any SQL query to analyze and execute.
- `:force` forces execution of the last blocked destructive statement.
- `:quit` exits the REPL.

### Train Mode
Train a new model checkpoint and export weights to JSON:
```bash
python -m dbguard train --out model.json --seed 0
```

## Python API Example

```python
from dbguard.detector import Detector

detector = Detector()

# Analyze a statement
verdicts = detector.analyze("DELETE FROM orders WHERE id = 42")
for v in verdicts:
    print(f"Level: {v.level}, Score: {v.score:.2f}, Reasons: {v.reasons}")

# Observe and learn safe behavior
detector.learn("DELETE FROM orders WHERE id = 42", rows_affected=1)
```

## Security & Operational Boundaries

1. **Dialect Ambiguity Defense**:
   Evaluates input across pruned dialect readings (nested comments, backslash escapes, hash comments, MySQL dash-dash spacing, and dollar quotes). Keeps the highest severity reading. Adds `dialect_ambiguous` reason when readings disagree.
2. **Sandbox Host Protection**:
   The sandbox isolates execution to an in-memory SQLite database (`:memory:`). It enforces resource limits (page count, VM step budgets, recursion depths) and blocks attach, load extension, and unauthorized pragmas. The sandbox protects the host system, not data integrity inside the sandbox.
3. **Redaction & Privacy**:
   Alert logs replace string and numeric literals with `?`. Identifiers (table and column names) are retained for operator action. Unterminated inputs use fixed keyword placeholders. Logs cap statement output to 2 048 bytes.
4. **JSONL File Security**:
   `JsonlNotifier` opens files with `O_NOFOLLOW` and mode `0600`. Existing files are tightened to `0600`. The parent directory must be trusted.
5. **Trust Assumptions & Profile Poisoning**:
   `Detector.learn` accepts only statements classified as `safe`. It ignores statements with `EXPLAIN` or volume outliers. Direct calls to `BehaviourProfile.observe` bypass this check.
6. **LRU Eviction**:
   Profiles retain up to 10 000 keys. Adding new keys beyond the limit evicts the least recently used keys. Eviction resets novelty to 1.0. Calibration ensures bounded DML remains `safe` regardless of novelty.
7. **Best-Effort Tautology**:
   Tautology detection identifies common constant and identical operand patterns (`1=1`, `'a'='a'`, `id=id`). Complex arithmetic tautologies (`id = id + 0`) are not evaluated.
8. **Concurrency**:
   `Detector` and `BehaviourProfile` are not thread-safe. Use one instance per thread or synchronize with locks.
9. **Console Sinks**:
   Console notification streams do not enforce rate limiting. Use dedicated log aggregation sinks in production.
