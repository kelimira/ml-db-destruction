"""Deterministic policy rules for dbguard."""

from __future__ import annotations

from dbguard.sqltok import Stmt

DROP_TARGET_OBJECTS: frozenset[str] = frozenset(
    {
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
    }
)


def policy_rules(stmt: Stmt) -> tuple[str, ...]:
    """Evaluate deterministic policy rules on a parsed Stmt.

    Returns a tuple of triggered rule names, or empty tuple if no floor applies.
    """
    rules: list[str] = []
    verb = stmt.verb
    tokens = stmt.tokens

    # 1. drop_object
    if verb == "DROP":
        # Check if any target object follows DROP (skipping IF EXISTS)
        idx = 1
        while idx < len(tokens) and tokens[idx] in ("IF", "EXISTS"):
            idx += 1
        if idx < len(tokens) and tokens[idx] in DROP_TARGET_OBJECTS:
            rules.append("drop_object")
        elif not tokens or idx >= len(tokens):
            # Bare DROP or unknown object
            rules.append("drop_object")

    # 2. truncate
    if verb == "TRUNCATE":
        rules.append("truncate")

    # 3. delete_no_where
    if verb == "DELETE":
        if (not stmt.has_where) or stmt.tautology_where:
            rules.append("delete_no_where")

    # 4. update_no_where
    if verb == "UPDATE":
        if (not stmt.has_where) or stmt.tautology_where:
            rules.append("update_no_where")

    # 5. drop_column
    if verb == "ALTER" and "drop_column" in stmt.flags:
        rules.append("drop_column")

    # 6. grant_all
    if verb in ("GRANT", "REVOKE"):
        is_grant_all = False
        if "ALL" in tokens:
            is_grant_all = True
        # Check WITH GRANT OPTION
        for i in range(len(tokens) - 2):
            if tokens[i] == "WITH" and tokens[i + 1] == "GRANT" and tokens[i + 2] == "OPTION":
                is_grant_all = True
                break
        if is_grant_all:
            rules.append("grant_all")

    # 7. merge_delete
    if verb == "MERGE" and "merge_delete" in stmt.flags:
        rules.append("merge_delete")

    # 8. replace_into
    if verb == "REPLACE" and "replace_into" in stmt.flags:
        rules.append("replace_into")

    return tuple(rules)
