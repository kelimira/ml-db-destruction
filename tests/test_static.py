"""Static analysis tests verifying zero runtime dependencies and banned calls per AC-16."""

import ast
from pathlib import Path
import unittest

BANNED_IMPORTS = {
    "urllib",
    "http",
    "requests",
    "socket",
    "pickle",
    "subprocess",
    "asyncio",
}

BANNED_FUNCTIONS = {
    "eval",
    "exec",
    "os.system",
}


class TestStatic(unittest.TestCase):
    """Test suite for static source verification (AC-16)."""

    def setUp(self) -> None:
        self.pkg_dir = Path(__file__).resolve().parent.parent / "dbguard"

    def test_ac16_no_banned_modules_or_functions(self) -> None:
        """AC-16: Grep/AST check finds no network, eval, exec, pickle, shell=True, os.system in dbguard/."""
        py_files = list(self.pkg_dir.glob("*.py"))
        self.assertGreater(len(py_files), 0)

        for py_path in py_files:
            content = py_path.read_text(encoding="utf-8")
            self.assertNotIn("shell=True", content, f"shell=True found in {py_path.name}")

            tree = ast.parse(content, filename=str(py_path))
            for node in ast.walk(tree):
                # Check banned imports
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        mod = alias.name.split(".")[0]
                        self.assertNotIn(
                            mod,
                            BANNED_IMPORTS,
                            f"Banned import {mod} found in {py_path.name}",
                        )
                elif isinstance(node, ast.ImportFrom):
                    if node.module:
                        mod = node.module.split(".")[0]
                        self.assertNotIn(
                            mod,
                            BANNED_IMPORTS,
                            f"Banned import from {mod} found in {py_path.name}",
                        )

                # Check banned function calls (eval, exec)
                if isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Name):
                        self.assertNotIn(
                            node.func.id,
                            {"eval", "exec"},
                            f"Banned call {node.func.id}() found in {py_path.name}",
                        )
                    elif isinstance(node.func, ast.Attribute):
                        if (
                            isinstance(node.func.value, ast.Name)
                            and node.func.value.id == "os"
                            and node.func.attr == "system"
                        ):
                            self.fail(f"Banned call os.system() found in {py_path.name}")

    def test_ac16_sqlite3_isolated_to_sim(self) -> None:
        """AC-16: sqlite3 is only imported in sim.py; other modules do not import it."""
        py_files = list(self.pkg_dir.glob("*.py"))
        for py_path in py_files:
            if py_path.name == "sim.py":
                continue
            content = py_path.read_text(encoding="utf-8")
            tree = ast.parse(content, filename=str(py_path))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        self.assertNotEqual(
                            alias.name,
                            "sqlite3",
                            f"sqlite3 imported outside sim.py in {py_path.name}",
                        )
                elif isinstance(node, ast.ImportFrom):
                    self.assertNotEqual(
                        node.module,
                        "sqlite3",
                        f"sqlite3 imported outside sim.py in {py_path.name}",
                    )


if __name__ == "__main__":
    unittest.main()
