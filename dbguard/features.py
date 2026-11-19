"""Model feature extraction for dbguard."""

from __future__ import annotations

import math
from dbguard.sqltok import Stmt

FEATURE_NAMES: tuple[str, ...] = (
    "verb_select",
    "verb_insert",
    "verb_update",
    "verb_delete",
    "verb_drop",
    "verb_truncate",
    "verb_alter",
    "verb_create",
    "verb_merge_replace",
    "verb_dcl",
    "kind_other",
    "has_where",
    "tautology_where",
    "n_tables",
    "drop_object",
    "drop_column",
    "cascade",
    "if_exists",
    "cte_target",
    "merge_delete",
    "rename_or_retype",
    "volume_log",
)


def extract(stmt: Stmt, estimated_rows: int | None = None) -> list[float]:
    """Extract 22 feature values from Stmt and estimated_rows."""
    verb = stmt.verb
    kind = stmt.kind
    flags = stmt.flags

    v_select = 1.0 if verb in ("SELECT", "VALUES", "SHOW", "DESCRIBE") else 0.0
    v_insert = 1.0 if verb == "INSERT" else 0.0
    v_update = 1.0 if verb == "UPDATE" else 0.0
    v_delete = 1.0 if verb == "DELETE" else 0.0
    v_drop = 1.0 if verb == "DROP" else 0.0
    v_truncate = 1.0 if verb == "TRUNCATE" else 0.0
    v_alter = 1.0 if verb in ("ALTER", "RENAME") else 0.0
    v_create = 1.0 if verb == "CREATE" else 0.0
    v_merge_replace = 1.0 if verb in ("MERGE", "REPLACE") else 0.0
    v_dcl = 1.0 if verb in ("GRANT", "REVOKE") else 0.0
    k_other = 1.0 if kind == "OTHER" else 0.0
    h_where = 1.0 if stmt.has_where else 0.0
    t_where = 1.0 if stmt.tautology_where else 0.0
    n_tbl = min(len(stmt.tables), 5) / 5.0

    # drop_object: DROP target is TABLE, DATABASE or SCHEMA (binary)
    d_obj = 0.0
    if verb == "DROP":
        # Check tokens for target object
        target_tokens = [tok.upper() for tok in stmt.tokens[:5]]
        if any(t in target_tokens for t in ("TABLE", "DATABASE", "SCHEMA")):
            d_obj = 1.0

    d_col = 1.0 if "drop_column" in flags else 0.0
    casc = 1.0 if "cascade" in flags else 0.0
    if_ex = 1.0 if "if_exists" in flags else 0.0
    cte_t = 1.0 if "cte_target" in flags else 0.0
    m_del = 1.0 if "merge_delete" in flags else 0.0
    ren_ret = 1.0 if "rename_or_retype" in flags else 0.0

    vol_log = 0.0
    if estimated_rows is not None and estimated_rows > 0:
        vol_log = min(1.0, max(0.0, math.log10(1.0 + estimated_rows) / 6.0))

    return [
        v_select,
        v_insert,
        v_update,
        v_delete,
        v_drop,
        v_truncate,
        v_alter,
        v_create,
        v_merge_replace,
        v_dcl,
        k_other,
        h_where,
        t_where,
        n_tbl,
        d_obj,
        d_col,
        casc,
        if_ex,
        cte_t,
        m_del,
        ren_ret,
        vol_log,
    ]
