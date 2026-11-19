"""Tests covering deterministic policy rules (AC-4, no model)."""

import unittest

from dbguard.policy import policy_rules
from dbguard.sqltok import parse


class TestPolicyRules(unittest.TestCase):
    """Test deterministic policy rules in isolation (AC-4)."""

    def test_drop_object_rule(self) -> None:
        """Test drop_object rule matches all specified object types."""
        targets = [
            "TABLE",
            "DATABASE",
            "SCHEMA",
            "INDEX",
            "VIEW",
            "USER",
            "ROLE",
            "TRIGGER",
            "FUNCTION",
            "PROCEDURE",
            "SEQUENCE",
            "TYPE",
        ]
        for tgt in targets:
            stmt = parse(f"DROP {tgt} my_obj")
            rules = policy_rules(stmt)
            self.assertIn("drop_object", rules, f"Expected drop_object for DROP {tgt}")

            # With IF EXISTS
            stmt_if = parse(f"DROP {tgt} IF EXISTS my_obj")
            rules_if = policy_rules(stmt_if)
            self.assertIn("drop_object", rules_if, f"Expected drop_object for DROP {tgt} IF EXISTS")

    def test_truncate_variants(self) -> None:
        """Test truncate rule across multiple syntax forms."""
        variants = [
            "TRUNCATE t",
            "TRUNCATE TABLE t",
            "TRUNCATE t CASCADE",
            "TRUNCATE t RESTART IDENTITY",
            "TRUNCATE t1, t2",
            "TRUNCATE TABLE t1, t2 CASCADE",
        ]
        for sql in variants:
            stmt = parse(sql)
            rules = policy_rules(stmt)
            self.assertIn("truncate", rules, f"Expected truncate for {sql}")

    def test_delete_update_no_where(self) -> None:
        """Test delete_no_where and update_no_where rules."""
        # DELETE without WHERE
        s1 = parse("DELETE FROM users")
        self.assertIn("delete_no_where", policy_rules(s1))

        # DELETE with tautology WHERE
        s2 = parse("DELETE FROM users WHERE 1 = 1")
        self.assertIn("delete_no_where", policy_rules(s2))

        # UPDATE without WHERE
        s3 = parse("UPDATE users SET email = 'pwned'")
        self.assertIn("update_no_where", policy_rules(s3))

        # UPDATE with tautology WHERE
        s4 = parse("UPDATE users SET email = 'pwned' WHERE 'a' = 'a'")
        self.assertIn("update_no_where", policy_rules(s4))

        # Bounded DELETE / UPDATE should NOT trigger rule
        s5 = parse("DELETE FROM users WHERE id = 42")
        self.assertNotIn("delete_no_where", policy_rules(s5))

        s6 = parse("UPDATE users SET email = 'ok' WHERE id = 42")
        self.assertNotIn("update_no_where", policy_rules(s6))

    def test_drop_column(self) -> None:
        """Test drop_column rule with and without COLUMN keyword."""
        s1 = parse("ALTER TABLE users DROP COLUMN email")
        self.assertIn("drop_column", policy_rules(s1))

        s2 = parse("ALTER TABLE users DROP email")
        self.assertIn("drop_column", policy_rules(s2))

        # Other ALTER operations should not trigger drop_column
        s3 = parse("ALTER TABLE users ADD COLUMN age INT")
        self.assertNotIn("drop_column", policy_rules(s3))

    def test_grant_all_and_grant_option(self) -> None:
        """Test grant_all rule on ALL privileges and WITH GRANT OPTION."""
        s1 = parse("GRANT ALL PRIVILEGES ON users TO public")
        self.assertIn("grant_all", policy_rules(s1))

        s2 = parse("GRANT ALL ON users TO public")
        self.assertIn("grant_all", policy_rules(s2))

        s3 = parse("REVOKE ALL ON users FROM public")
        self.assertIn("grant_all", policy_rules(s3))

        s4 = parse("GRANT SELECT ON users TO app WITH GRANT OPTION")
        self.assertIn("grant_all", policy_rules(s4))

        # Normal grant should not trigger grant_all
        s5 = parse("GRANT SELECT ON users TO app")
        self.assertNotIn("grant_all", policy_rules(s5))

    def test_merge_delete_and_replace_into(self) -> None:
        """Test merge_delete and replace_into rules."""
        s1 = parse("MERGE INTO target t USING src s ON t.id = s.id WHEN MATCHED THEN DELETE")
        self.assertIn("merge_delete", policy_rules(s1))

        s2 = parse("MERGE INTO target t USING src s ON 1 = 1 WHEN MATCHED THEN DELETE")
        self.assertIn("merge_delete", policy_rules(s2))

        # MERGE with UPDATE only should not trigger merge_delete
        s3 = parse("MERGE INTO target t USING src s ON t.id = s.id WHEN MATCHED THEN UPDATE SET a=1")
        self.assertNotIn("merge_delete", policy_rules(s3))

        # REPLACE INTO
        s4 = parse("REPLACE INTO users (id, name) VALUES (1, 'alice')")
        self.assertIn("replace_into", policy_rules(s4))


if __name__ == "__main__":
    unittest.main()
