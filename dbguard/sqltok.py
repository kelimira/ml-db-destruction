"""Tokenizer, dialect readings, statement splitting, parsing, and redaction for dbguard."""

from __future__ import annotations

from dataclasses import dataclass, field
import itertools
import re
from typing import Literal

Kind = Literal["DML", "DDL", "DQL", "DCL", "TCL", "OTHER"]

MAX_INPUT_BYTES = 64 * 1024  # 64 KiB
MAX_STATEMENTS = 200
MAX_TOKENS_PER_STMT = 5000


class InputTooLarge(ValueError):
    """Raised when input exceeds size or statement count limits."""


@dataclass(frozen=True)
class Reading:
    """One lexical interpretation of the SQL input across dialect variations."""

    nested_comments: bool
    backslash_escapes: bool
    hash_comment: bool
    dashdash_needs_space: bool
    dollar_quotes: bool


SQLITE = Reading(
    nested_comments=False,
    backslash_escapes=False,
    hash_comment=False,
    dashdash_needs_space=False,
    dollar_quotes=False,
)


def _is_ws_or_ctrl(c: str) -> bool:
    if c in " \t\r\n\f\v":
        return True
    code = ord(c)
    return code < 0x20 or code == 0x7F


def readings_for(sql: str) -> tuple[Reading, ...]:
    """Return the pruned set of readings relevant to the input."""
    # Check trigger conditions
    rel_nested = sql.count("/*") >= 2
    rel_backslash = "\\" in sql
    rel_hash = "#" in sql
    rel_dollar = "$" in sql

    # dashdash_needs_space: a -- followed by a char that is not ws, not ctrl, and not EOF
    rel_dashdash = False
    idx = 0
    while True:
        pos = sql.find("--", idx)
        if pos == -1:
            break
        after_pos = pos + 2
        if after_pos < len(sql):
            ch = sql[after_pos]
            if not _is_ws_or_ctrl(ch):
                rel_dashdash = True
                break
        idx = pos + 2

    flag_options = [
        (True, False) if rel_nested else (False,),
        (True, False) if rel_backslash else (False,),
        (True, False) if rel_hash else (False,),
        (True, False) if rel_dashdash else (False,),
        (True, False) if rel_dollar else (False,),
    ]

    all_readings: list[Reading] = []
    for n_c, b_e, h_c, d_s, d_q in itertools.product(*flag_options):
        all_readings.append(
            Reading(
                nested_comments=n_c,
                backslash_escapes=b_e,
                hash_comment=h_c,
                dashdash_needs_space=d_s,
                dollar_quotes=d_q,
            )
        )

    # Ensure SQLITE is present
    if SQLITE not in all_readings:
        all_readings.insert(0, SQLITE)
    else:
        # Move SQLITE to first position for deterministic tie-breaking
        all_readings.remove(SQLITE)
        all_readings.insert(0, SQLITE)

    return tuple(all_readings)


@dataclass(frozen=True)
class RawToken:
    kind: str  # "WORD", "NUMBER", "STRING", "DOLLAR_STRING", "OP", "PUNCT", "COMMENT", "UNTERMINATED"
    value: str
    raw: str
    start: int
    end: int


@dataclass(frozen=True)
class Stmt:
    verb: str
    kind: Kind
    tables: tuple[str, ...]
    has_where: bool
    tautology_where: bool
    explain: Literal["", "plain", "analyze"]
    flags: frozenset[str]
    redacted: str
    tokens: tuple[str, ...] = field(default=(), repr=False, compare=False)
    table_span: tuple[int, int] | None = None
    pred_span: tuple[int, int] | None = None


def _lex_tokens(sql: str, reading: Reading) -> tuple[list[RawToken], bool]:
    """Tokenize the input into RawTokens. Returns (tokens, has_unterminated)."""
    n = len(sql)
    i = 0
    tokens: list[RawToken] = []
    has_unterminated = False
    exec_comment_depth = 0

    while i < n:
        c = sql[i]

        # Whitespace
        if c in " \t\r\n\f\v":
            i += 1
            continue

        # Closing of executable comments /*! ... */ or /*M! ... */
        if exec_comment_depth > 0 and sql.startswith("*/", i):
            exec_comment_depth -= 1
            i += 2
            continue

        # Comments
        # -- line comment
        if sql.startswith("--", i):
            is_comment = True
            if reading.dashdash_needs_space:
                if i + 2 < n:
                    ch = sql[i + 2]
                    if not _is_ws_or_ctrl(ch):
                        is_comment = False
            if is_comment:
                start = i
                nl = sql.find("\n", i + 2)
                if nl == -1:
                    i = n
                else:
                    i = nl + 1
                tokens.append(RawToken("COMMENT", sql[start:i], sql[start:i], start, i))
                continue
            else:
                # Treated as operator --
                tokens.append(RawToken("OP", "--", "--", i, i + 2))
                i += 2
                continue

        # # line comment
        if c == "#":
            if reading.hash_comment:
                start = i
                nl = sql.find("\n", i + 1)
                if nl == -1:
                    i = n
                else:
                    i = nl + 1
                tokens.append(RawToken("COMMENT", sql[start:i], sql[start:i], start, i))
                continue
            else:
                tokens.append(RawToken("OP", "#", "#", i, i + 1))
                i += 1
                continue

        # Block comment /* ... */
        if sql.startswith("/*", i):
            # Executable comments: /*! ... */ or /*M! ... */
            if sql.startswith("/*!", i) or sql.startswith("/*M!", i):
                start = i
                # Skip opening marker and any MySQL version digits
                j = i + (4 if sql.startswith("/*M!", i) else 3)
                while j < n and sql[j].isdigit():
                    j += 1
                exec_comment_depth += 1
                i = j
                continue

            # Hint /*+ ... */: dropped as comment
            if sql.startswith("/*+", i):
                start = i
                end_pos = sql.find("*/", i + 3)
                if end_pos == -1:
                    tokens.append(RawToken("UNTERMINATED", sql[start:], sql[start:], start, n))
                    has_unterminated = True
                    i = n
                else:
                    i = end_pos + 2
                    tokens.append(RawToken("COMMENT", sql[start:i], sql[start:i], start, i))
                continue

            # Standard block comment
            start = i
            if reading.nested_comments:
                depth = 1
                j = i + 2
                while j < n and depth > 0:
                    if sql.startswith("/*", j):
                        depth += 1
                        j += 2
                    elif sql.startswith("*/", j):
                        depth -= 1
                        j += 2
                    else:
                        j += 1
                if depth > 0:
                    tokens.append(RawToken("UNTERMINATED", sql[start:], sql[start:], start, n))
                    has_unterminated = True
                    i = n
                else:
                    i = j
                    tokens.append(RawToken("COMMENT", sql[start:i], sql[start:i], start, i))
                continue
            else:
                end_pos = sql.find("*/", i + 2)
                if end_pos == -1:
                    tokens.append(RawToken("UNTERMINATED", sql[start:], sql[start:], start, n))
                    has_unterminated = True
                    i = n
                else:
                    i = end_pos + 2
                    tokens.append(RawToken("COMMENT", sql[start:i], sql[start:i], start, i))
                continue

        # Dollar quoted string (PostgreSQL only: $tag$...$tag$)
        if reading.dollar_quotes and c == "$":
            # Match $tag$
            m = re.match(r"\$([A-Za-z0-9_]*)\$", sql[i:])
            if m:
                tag = m.group(0)
                tag_len = len(tag)
                start = i
                end_pos = sql.find(tag, i + tag_len)
                if end_pos == -1:
                    tokens.append(RawToken("UNTERMINATED", sql[start:], sql[start:], start, n))
                    has_unterminated = True
                    i = n
                else:
                    end_idx = end_pos + tag_len
                    tokens.append(
                        RawToken("DOLLAR_STRING", sql[start + tag_len : end_pos], sql[start:end_idx], start, end_idx)
                    )
                    i = end_idx
                continue

        # String literals: '...' or E'...'
        is_e_str = (c in "Ee") and (i + 1 < n) and (sql[i + 1] == "'")
        if c == "'" or is_e_str:
            start = i
            if is_e_str:
                i += 2
            else:
                i += 1
            str_closed = False
            use_backslash = is_e_str or reading.backslash_escapes
            val_chars: list[str] = []
            while i < n:
                ch = sql[i]
                if use_backslash and ch == "\\":
                    if i + 1 < n:
                        val_chars.append(sql[i + 1])
                        i += 2
                    else:
                        i += 1
                elif ch == "'":
                    if i + 1 < n and sql[i + 1] == "'":
                        val_chars.append("'")
                        i += 2
                    else:
                        i += 1
                        str_closed = True
                        break
                else:
                    val_chars.append(ch)
                    i += 1
            if not str_closed:
                tokens.append(RawToken("UNTERMINATED", sql[start:], sql[start:], start, n))
                has_unterminated = True
            else:
                tokens.append(RawToken("STRING", "".join(val_chars), sql[start:i], start, i))
            continue

        # Quoted identifiers: "...", `...`, [...]
        if c in ('"', '`', '['):
            start = i
            close_char = ']' if c == '[' else c
            i += 1
            closed = False
            ident_chars: list[str] = []
            use_backslash = (c == '"' and reading.backslash_escapes)
            while i < n:
                ch = sql[i]
                if use_backslash and ch == "\\":
                    if i + 1 < n:
                        ident_chars.append(sql[i + 1])
                        i += 2
                    else:
                        i += 1
                elif ch == close_char:
                    if close_char != ']' and i + 1 < n and sql[i + 1] == close_char:
                        ident_chars.append(close_char)
                        i += 2
                    else:
                        i += 1
                        closed = True
                        break
                else:
                    ident_chars.append(ch)
                    i += 1
            if not closed:
                tokens.append(RawToken("UNTERMINATED", sql[start:], sql[start:], start, n))
                has_unterminated = True
            else:
                # Quoted identifier
                tokens.append(RawToken("WORD", "".join(ident_chars), sql[start:i], start, i))
            continue

        # Numbers
        if c.isdigit() or (c == "." and i + 1 < n and sql[i + 1].isdigit()):
            start = i
            if sql.startswith(("0x", "0X"), i):
                i += 2
                while i < n and (sql[i].isalnum() or sql[i] in "_"):
                    i += 1
            else:
                while i < n and (sql[i].isdigit() or sql[i] in "._eE+-"):
                    # Don't absorb consecutive operators into numbers
                    if sql[i] in "+-" and sql[i - 1] not in "eE":
                        break
                    i += 1
            tokens.append(RawToken("NUMBER", sql[start:i], sql[start:i], start, i))
            continue

        # Identifiers and keywords
        # When not dollar_quotes, '$' can be identifier char
        ident_start = c.isalpha() or c == "_" or (not reading.dollar_quotes and c == "$")
        if ident_start:
            start = i
            while i < n and (
                sql[i].isalnum()
                or sql[i] == "_"
                or (not reading.dollar_quotes and sql[i] == "$")
            ):
                i += 1
            tokens.append(RawToken("WORD", sql[start:i], sql[start:i], start, i))
            continue

        # Semicolon
        if c == ";":
            tokens.append(RawToken("PUNCT", ";", ";", i, i + 1))
            i += 1
            continue

        # Multi-char operators
        two = sql[i : i + 2]
        if two in ("<=", ">=", "<>", "!=", "||", "::"):
            tokens.append(RawToken("OP", two, two, i, i + 2))
            i += 2
            continue

        # Single-char punctuation / operator
        if c in "(),.":
            tokens.append(RawToken("PUNCT", c, c, i, i + 1))
        else:
            tokens.append(RawToken("OP", c, c, i, i + 1))
        i += 1

    return tokens, has_unterminated


def split_statements(sql: str, reading: Reading = SQLITE) -> list[str]:
    """Split SQL into statement strings using the given reading.

    Raises InputTooLarge if input > 64 KiB or statement count > 200.
    """
    raw_bytes = sql.encode("utf-8")
    if len(raw_bytes) > MAX_INPUT_BYTES:
        raise InputTooLarge("Input exceeds 64 KiB")

    raw_tokens, _ = _lex_tokens(sql, reading)

    # Split by semicolon at paren depth 0
    pieces: list[str] = []
    current_tokens: list[RawToken] = []
    paren_depth = 0

    for tok in raw_tokens:
        if tok.kind == "PUNCT" and tok.value == "(":
            paren_depth += 1
        elif tok.kind == "PUNCT" and tok.value == ")":
            if paren_depth > 0:
                paren_depth -= 1

        if tok.kind == "PUNCT" and tok.value == ";" and paren_depth == 0:
            if current_tokens:
                piece_text = _extract_statement_piece(sql, current_tokens)
                if piece_text:
                    pieces.append(piece_text)
                current_tokens = []
        else:
            current_tokens.append(tok)

    if current_tokens:
        piece_text = _extract_statement_piece(sql, current_tokens)
        if piece_text:
            pieces.append(piece_text)

    if len(pieces) > MAX_STATEMENTS:
        raise InputTooLarge("Statement count exceeds 200")

    return pieces


def _extract_statement_piece(full_sql: str, tokens: list[RawToken]) -> str:
    """Extract trimmed statement text, stripping leading comments and outer whitespace."""
    # Find first non-comment token
    first_code_idx = -1
    last_code_idx = -1
    for idx, tok in enumerate(tokens):
        if tok.kind != "COMMENT":
            if first_code_idx == -1:
                first_code_idx = idx
            last_code_idx = idx

    if first_code_idx == -1:
        # All comments
        return ""

    start_char = tokens[first_code_idx].start
    end_char = tokens[-1].end
    return full_sql[start_char:end_char].strip()


def _unparsed_stmt(raw_sql: str, reading: Reading = SQLITE) -> Stmt:
    # First keyword is leading run of 1 to 16 ASCII letters
    m = re.match(r"^\s*([A-Za-z]{1,16})", raw_sql)
    if m:
        kw = m.group(1).upper()
        redacted = f"{kw} <unparsed>"
    else:
        redacted = "<unparsed>"

    return Stmt(
        verb="UNPARSED",
        kind="OTHER",
        tables=(),
        has_where=False,
        tautology_where=False,
        explain="",
        flags=frozenset({"unparsed"}),
        redacted=redacted,
        tokens=(),
        table_span=None,
        pred_span=None,
    )


def redact(stmt_sql: str, reading: Reading = SQLITE) -> str:
    """Produce redacted statement string: literals -> '?', comments removed."""
    tokens, has_unterm = _lex_tokens(stmt_sql, reading)
    if has_unterm:
        return _unparsed_stmt(stmt_sql, reading).redacted

    parts: list[str] = []
    for tok in tokens:
        if tok.kind == "COMMENT":
            continue
        elif tok.kind in ("STRING", "DOLLAR_STRING", "NUMBER"):
            parts.append("?")
        else:
            parts.append(tok.raw)

    res = " ".join(parts).strip()
    # Normalize spaces around punctuation
    res = re.sub(r"\s+([,;.()])", r"\1", res)
    res = re.sub(r"([(])\s+", r"\1", res)
    return res


def parse(stmt_sql: str, reading: Reading = SQLITE) -> Stmt:
    """Parse a single SQL statement into a Stmt structure. Never raises on bad SQL."""
    if not stmt_sql or not stmt_sql.strip():
        return _unparsed_stmt(stmt_sql, reading)

    raw_tokens, has_unterm = _lex_tokens(stmt_sql, reading)
    if has_unterm:
        return _unparsed_stmt(stmt_sql, reading)

    code_tokens = [tok for tok in raw_tokens if tok.kind != "COMMENT"]
    if not code_tokens:
        return _unparsed_stmt(stmt_sql, reading)

    if len(code_tokens) > MAX_TOKENS_PER_STMT:
        return _unparsed_stmt(stmt_sql, reading)

    norm_tokens = tuple(tok.value.upper() if tok.kind in ("WORD", "OP", "PUNCT") else tok.raw for tok in code_tokens)

    # EXPLAIN handling (§3.3)
    explain_type: Literal["", "plain", "analyze"] = ""
    target_tokens = code_tokens
    target_norm = norm_tokens

    if norm_tokens and norm_tokens[0] == "EXPLAIN":
        explain_res, inner_code_tokens, inner_norm = _handle_explain(code_tokens, norm_tokens)
        explain_type = explain_res
        target_tokens = inner_code_tokens
        target_norm = inner_norm

    if not target_norm:
        return _unparsed_stmt(stmt_sql, reading)

    # CTE handling (§3.2)
    flags: set[str] = set()
    first_norm = target_norm[0]

    if first_norm == "WITH":
        inner_res = _handle_cte(target_tokens, target_norm)
        if inner_res is None:
            return _unparsed_stmt(stmt_sql, reading)
        target_tokens, target_norm, is_cte_target = inner_res
        if is_cte_target:
            flags.add("cte_target")
        first_norm = target_norm[0]

    # Classify verb and kind
    verb = first_norm
    kind: Kind = "OTHER"

    if verb in ("SELECT", "VALUES", "SHOW", "DESCRIBE"):
        kind = "DQL"
    elif verb == "INSERT":
        kind = "DML"
    elif verb in ("UPDATE", "DELETE"):
        kind = "DML"
    elif verb == "REPLACE":
        kind = "DML"
        flags.add("replace_into")
    elif verb == "MERGE":
        kind = "DML"
        # Check for WHEN MATCHED ... THEN DELETE
        if _has_merge_delete(target_norm):
            flags.add("merge_delete")
    elif verb in ("CREATE", "ALTER", "DROP", "TRUNCATE", "RENAME"):
        kind = "DDL"
    elif verb in ("GRANT", "REVOKE"):
        kind = "DCL"
    elif verb in ("BEGIN", "COMMIT", "ROLLBACK", "SAVEPOINT"):
        kind = "TCL"
    elif verb in ("PRAGMA", "ATTACH", "DETACH", "VACUUM", "LOAD", "COPY", "SET", "CALL", "DELIMITER"):
        kind = "OTHER"
        flags.add("admin")
    else:
        # Unknown verb
        kind = "OTHER"

    # Specific flag checks
    if "CASCADE" in target_norm:
        flags.add("cascade")
    if "IF" in target_norm and "EXISTS" in target_norm:
        flags.add("if_exists")

    # Drop column or rename/retype flags for ALTER
    if verb == "ALTER":
        if _is_alter_drop_column(target_norm):
            flags.add("drop_column")
        if _is_alter_rename_or_retype(target_norm):
            flags.add("rename_or_retype")
    elif verb == "RENAME":
        flags.add("rename_or_retype")

    # Table extraction
    tables = _extract_tables(target_tokens, target_norm, verb)

    # WHERE clause and tautology analysis
    has_where, tautology_where, pred_span = _analyze_where(stmt_sql, target_tokens, target_norm)

    # Table span extraction for DML (single target)
    table_span = _extract_table_span(stmt_sql, target_tokens, target_norm, verb, tables)

    # Clean up spans if they contain invalid characters
    if pred_span is not None:
        p_text = stmt_sql[pred_span[0] : pred_span[1]]
        if any(bad in p_text for bad in ("--", "/*", "#", ";", "?", "$")):
            pred_span = None

    # Produce redacted string
    redacted_text = redact(stmt_sql, reading)

    return Stmt(
        verb=verb,
        kind=kind,
        tables=tuple(tables),
        has_where=has_where,
        tautology_where=tautology_where,
        explain=explain_type,
        flags=frozenset(flags),
        redacted=redacted_text,
        tokens=norm_tokens,
        table_span=table_span,
        pred_span=pred_span,
    )


def _handle_explain(
    tokens: list[RawToken], norm: tuple[str, ...]
) -> tuple[Literal["plain", "analyze"], list[RawToken], tuple[str, ...]]:
    """Determine explain type and extract inner statement per §3.3."""
    # Find where the inner statement starts
    # Tokens after EXPLAIN up to the first DML/DDL/DQL verb
    prefix_tokens: list[str] = []
    idx = 1
    paren_depth = 0
    in_paren = False

    while idx < len(norm):
        w = norm[idx]
        if w == "(":
            in_paren = True
            paren_depth += 1
            idx += 1
            continue
        elif w == ")":
            paren_depth -= 1
            if paren_depth <= 0:
                in_paren = False
                paren_depth = 0
            idx += 1
            continue

        # Check if w is an SQL statement verb
        if w in (
            "SELECT",
            "INSERT",
            "UPDATE",
            "DELETE",
            "DROP",
            "TRUNCATE",
            "ALTER",
            "CREATE",
            "REPLACE",
            "MERGE",
            "WITH",
        ):
            # If we encountered a statement verb, whether parens closed or not, this is the inner statement
            break
        idx += 1

    prefix_code = tokens[1:idx]
    inner_tokens = tokens[idx:]
    inner_norm = norm[idx:]

    # If paren_depth > 0, option list was unterminated -> analyze
    if paren_depth > 0 or in_paren:
        return "analyze", inner_tokens, inner_norm

    # Analyze prefix: rule 1, 2, 3
    # Plain if:
    # 1. empty
    # 2. only QUERY, PLAN, VERBOSE
    # 3. parenthesized option list meeting rule 2
    is_plain = False
    prefix_words = [t.value.upper() for t in prefix_code if t.kind in ("WORD", "PUNCT")]

    if not prefix_words:
        is_plain = True
    elif all(pw in ("QUERY", "PLAN", "VERBOSE") for pw in prefix_words):
        is_plain = True
    else:
        # Check parenthesized list
        # Look for '(' ... ')'
        if "(" in prefix_words:
            p_start = prefix_words.index("(")
            if ")" in prefix_words:
                p_end = len(prefix_words) - 1 - list(reversed(prefix_words)).index(")")
                # Outside parens can only be QUERY, PLAN, VERBOSE
                outer_words = prefix_words[:p_start] + prefix_words[p_end + 1 :]
                if all(ow in ("QUERY", "PLAN", "VERBOSE") for ow in outer_words):
                    # Inspect options inside parens
                    opt_tokens = prefix_words[p_start + 1 : p_end]
                    # Parse comma-separated options: NAME or NAME value
                    opts = _parse_explain_options(opt_tokens)
                    if opts is not None:
                        allowed_plain_keys = {"ANALYZE", "VERBOSE", "QUERY", "PLAN"}
                        if all(k in allowed_plain_keys for k, v in opts):
                            analyze_opts = [v for k, v in opts if k == "ANALYZE"]
                            if len(analyze_opts) == 0:
                                is_plain = True
                            elif len(analyze_opts) == 1:
                                val = analyze_opts[0]
                                if val in ("FALSE", "OFF", "0"):
                                    is_plain = True

    return ("plain" if is_plain else "analyze"), inner_tokens, inner_norm


def _parse_explain_options(opt_tokens: list[str]) -> list[tuple[str, str | None]] | None:
    """Parse comma-separated NAME or NAME value options. Returns list or None on error."""
    res: list[tuple[str, str | None]] = []
    # Split by comma
    chunks: list[list[str]] = []
    curr: list[str] = []
    for tok in opt_tokens:
        if tok == ",":
            if curr:
                chunks.append(curr)
                curr = []
        else:
            curr.append(tok)
    if curr:
        chunks.append(curr)

    for chunk in chunks:
        if len(chunk) == 1:
            res.append((chunk[0], None))
        elif len(chunk) == 2:
            res.append((chunk[0], chunk[1]))
        else:
            return None
    return res


def _handle_cte(
    tokens: list[RawToken], norm: tuple[str, ...]
) -> tuple[list[RawToken], tuple[str, ...], bool] | None:
    """Handle WITH CTE statement. Return (main_tokens, main_norm, is_cte_target)."""
    # Scan past WITH (and optional RECURSIVE) and CTE definitions
    # CTE definition: name AS (...)
    idx = 1
    if idx < len(norm) and norm[idx] == "RECURSIVE":
        idx += 1

    paren_depth = 0
    main_start = -1

    while idx < len(norm):
        w = norm[idx]
        if w == "(":
            paren_depth += 1
        elif w == ")":
            if paren_depth > 0:
                paren_depth -= 1
        elif paren_depth == 0:
            if w in ("SELECT", "UPDATE", "DELETE", "INSERT", "MERGE", "REPLACE"):
                main_start = idx
                break
        idx += 1

    if main_start == -1:
        return None

    main_tokens = tokens[main_start:]
    main_norm = norm[main_start:]
    is_cte_target = main_norm[0] in ("UPDATE", "DELETE", "INSERT")
    return main_tokens, main_norm, is_cte_target


def _has_merge_delete(norm: tuple[str, ...]) -> bool:
    """Check if MERGE has a WHEN MATCHED ... THEN DELETE branch."""
    for i in range(len(norm) - 1):
        if norm[i] == "WHEN" and norm[i + 1] == "MATCHED":
            for j in range(i + 2, len(norm) - 1):
                if norm[j] == "WHEN":
                    break
                if norm[j] == "THEN" and norm[j + 1] == "DELETE":
                    return True
    return False


def _is_alter_drop_column(norm: tuple[str, ...]) -> bool:
    """Check if ALTER TABLE drops a column."""
    for i in range(len(norm) - 1):
        if norm[i] == "DROP":
            # DROP COLUMN <name> or DROP <name>
            # But not DROP CONSTRAINT / DROP INDEX / DROP PARTITION
            next_w = norm[i + 1]
            if next_w == "COLUMN":
                return True
            if next_w not in ("TABLE", "DATABASE", "SCHEMA", "INDEX", "VIEW", "USER", "ROLE", "TRIGGER", "FUNCTION", "PROCEDURE", "SEQUENCE", "TYPE", "CONSTRAINT"):
                return True
    return False


def _is_alter_rename_or_retype(norm: tuple[str, ...]) -> bool:
    """Check for ALTER TABLE ... RENAME or ALTER COLUMN ... TYPE."""
    if "RENAME" in norm:
        return True
    for i in range(len(norm) - 2):
        if norm[i] == "COLUMN" and norm[i + 2] == "TYPE":
            return True
        if norm[i] == "ALTER" and norm[i + 1] == "COLUMN":
            # ALTER COLUMN col TYPE ...
            if "TYPE" in norm[i + 2 :]:
                return True
    return False


def _extract_tables(tokens: list[RawToken], norm: tuple[str, ...], verb: str) -> list[str]:
    """Extract normalised, lower-case table names from statement tokens."""
    tables: list[str] = []

    def normalize_name(raw_name: str) -> str:
        # Strip quotes and brackets, keep schema e.g. "db"."t" -> db.t
        parts = raw_name.split(".")
        clean_parts = [re.sub(r'^[\["`\']|[\]"`\']$', "", p).lower() for p in parts]
        return ".".join(clean_parts)

    n = len(norm)

    if verb == "SELECT":
        paren_depth = 0
        for i in range(n):
            if norm[i] == "(":
                paren_depth += 1
            elif norm[i] == ")":
                if paren_depth > 0:
                    paren_depth -= 1
            elif paren_depth == 0 and norm[i] in ("FROM", "JOIN"):
                if i + 1 < n and tokens[i + 1].kind in ("WORD", "PUNCT"):
                    tbl = _build_dotted_name(tokens, i + 1)
                    if tbl and tbl.upper() not in ("SELECT", "LATERAL", "UNNEST"):
                        tables.append(normalize_name(tbl))

    elif verb in ("INSERT", "REPLACE"):
        for i in range(n):
            if norm[i] == "INTO" and i + 1 < n:
                tbl = _build_dotted_name(tokens, i + 1)
                if tbl:
                    tables.append(normalize_name(tbl))
                break

    elif verb == "UPDATE":
        for i in range(n):
            if norm[i] == "UPDATE" and i + 1 < n:
                tbl = _build_dotted_name(tokens, i + 1)
                if tbl:
                    tables.append(normalize_name(tbl))
                break

    elif verb == "DELETE":
        for i in range(n):
            if norm[i] == "FROM" and i + 1 < n:
                tbl = _build_dotted_name(tokens, i + 1)
                if tbl:
                    tables.append(normalize_name(tbl))
                break
            elif norm[i] == "DELETE" and i + 1 < n and norm[i + 1] != "FROM":
                # DELETE target FROM ...
                tbl = _build_dotted_name(tokens, i + 1)
                if tbl:
                    tables.append(normalize_name(tbl))
                break

    elif verb in ("DROP", "TRUNCATE"):
        # DROP TABLE [IF EXISTS] t1, t2... or TRUNCATE [TABLE] t1, t2...
        i = 1
        while i < n and norm[i] in ("TABLE", "IF", "EXISTS", "ONLY"):
            i += 1
        while i < n:
            tbl = _build_dotted_name(tokens, i)
            if tbl:
                tables.append(normalize_name(tbl))
                # Advance past name tokens
                while i < n and norm[i] not in (",", "CASCADE", "RESTRICT"):
                    i += 1
                if i < n and norm[i] == ",":
                    i += 1
                    continue
            break

    elif verb == "ALTER":
        for i in range(n):
            if norm[i] == "TABLE" and i + 1 < n:
                tbl = _build_dotted_name(tokens, i + 1)
                if tbl:
                    tables.append(normalize_name(tbl))
                break

    elif verb == "CREATE":
        for i in range(n):
            if norm[i] == "TABLE" and i + 1 < n:
                j = i + 1
                if j < n and norm[j] in ("IF", "NOT", "EXISTS"):
                    while j < n and norm[j] in ("IF", "NOT", "EXISTS"):
                        j += 1
                if j < n:
                    tbl = _build_dotted_name(tokens, j)
                    if tbl:
                        tables.append(normalize_name(tbl))
                break

    elif verb == "MERGE":
        for i in range(n):
            if norm[i] == "INTO" and i + 1 < n:
                tbl = _build_dotted_name(tokens, i + 1)
                if tbl:
                    tables.append(normalize_name(tbl))
                break

    return tables


def _build_dotted_name(tokens: list[RawToken], start_idx: int) -> str | None:
    """Build dotted name e.g. db.tbl or tbl starting from token index."""
    if start_idx >= len(tokens):
        return None
    tok = tokens[start_idx]
    if tok.kind != "WORD":
        return None
    res = tok.raw
    idx = start_idx + 1
    while idx + 1 < len(tokens):
        if tokens[idx].raw == "." and tokens[idx + 1].kind == "WORD":
            res += "." + tokens[idx + 1].raw
            idx += 2
        else:
            break
    return res


def _analyze_where(
    full_sql: str, tokens: list[RawToken], norm: tuple[str, ...]
) -> tuple[bool, bool, tuple[int, int] | None]:
    """Check where presence, tautology, and pred_span at paren depth 0."""
    paren_depth = 0
    where_tok_idx = -1

    for idx, tok in enumerate(tokens):
        if tok.raw == "(":
            paren_depth += 1
        elif tok.raw == ")":
            if paren_depth > 0:
                paren_depth -= 1
        elif paren_depth == 0 and norm[idx] == "WHERE":
            where_tok_idx = idx
            break

    if where_tok_idx == -1:
        return False, False, None

    # Find the end of the top-level WHERE predicate
    # Predicate ends at top-level RETURNING, ORDER, LIMIT, or end of statement
    pred_end_idx = -1
    paren_depth = 0
    for idx in range(where_tok_idx + 1, len(tokens)):
        if tokens[idx].raw == "(":
            paren_depth += 1
        elif tokens[idx].raw == ")":
            if paren_depth > 0:
                paren_depth -= 1
        elif paren_depth == 0:
            if norm[idx] in ("RETURNING", "ORDER", "LIMIT", "GROUP", "HAVING", "WINDOW"):
                pred_end_idx = idx
                break

    if pred_end_idx != -1:
        pred_tokens = tokens[where_tok_idx + 1 : pred_end_idx]
        pred_norm = norm[where_tok_idx + 1 : pred_end_idx]
        pred_end_char = tokens[pred_end_idx].start
    else:
        pred_tokens = tokens[where_tok_idx + 1 :]
        pred_norm = norm[where_tok_idx + 1 :]
        pred_end_char = len(full_sql)

    if not pred_tokens:
        return True, True, None

    pred_start_char = pred_tokens[0].start

    # Check if raw text between pred_start_char and pred_end_char contains comments, ';', '?', or '$'
    raw_span_text = full_sql[pred_start_char:pred_end_char]
    if any(bad in raw_span_text for bad in ("--", "/*", "#", ";", "?", "$")):
        pred_span = None
    else:
        # Trim trailing whitespace from pred_end_char
        trimmed = raw_span_text.rstrip()
        pred_span = (pred_start_char, pred_start_char + len(trimmed))

    # Check tautology
    is_taut = _check_tautology(pred_tokens, pred_norm)

    return True, is_taut, pred_span


def _check_tautology(pred_tokens: list[RawToken], pred_norm: tuple[str, ...]) -> bool:
    """Check if predicate is a tautology (§3.4)."""
    # 1. Top-level OR followed by constant tautology
    paren_depth = 0
    for idx, w in enumerate(pred_norm):
        if w == "(":
            paren_depth += 1
        elif w == ")":
            if paren_depth > 0:
                paren_depth -= 1
        elif paren_depth == 0 and w == "OR":
            sub_norm = pred_norm[idx + 1 :]
            sub_tokens = pred_tokens[idx + 1 :]
            if _is_constant_tautology(sub_tokens, sub_norm):
                return True

    # Check if the entire predicate is a constant tautology
    if _is_constant_tautology(pred_tokens, pred_norm):
        return True

    # 3. Predicate is x = x with identical operands
    if len(pred_norm) == 3 and pred_norm[1] == "=":
        if pred_norm[0] == pred_norm[2]:
            return True

    # 4. Predicate is NOT 0, NOT FALSE, or TRUE
    if pred_norm in (("NOT", "0"), ("NOT", "FALSE"), ("TRUE",)):
        return True

    # 2. Holds only literals and operators, not constant-false
    has_ident = any(t.kind == "WORD" and t.value.upper() not in ("NOT", "AND", "OR", "TRUE", "FALSE", "NULL", "IS") for t in pred_tokens)
    if not has_ident:
        # Check if constant false
        if pred_norm in (("0",), ("FALSE",), ("1", "=", "0"), ("NULL",)):
            return False
        # Evaluated as tautology
        return True

    return False


def _is_constant_tautology(tokens: list[RawToken], norm: tuple[str, ...]) -> bool:
    """Check if tokens represent a constant tautology."""
    if norm in (("1", "=", "1"), ("TRUE",), ("NOT", "0"), ("NOT", "FALSE")):
        return True
    if len(norm) == 3 and norm[1] == "=" and norm[0] == norm[2]:
        return True
    if len(norm) == 1 and tokens[0].kind == "NUMBER":
        try:
            val = float(norm[0])
            if val != 0:
                return True
        except ValueError:
            pass
    # <num> < <num> that evaluates true
    if len(norm) == 3 and norm[1] in ("<", "<=", ">", ">="):
        try:
            v1 = float(norm[0])
            v2 = float(norm[2])
            op = norm[1]
            if op == "<" and v1 < v2:
                return True
            if op == "<=" and v1 <= v2:
                return True
            if op == ">" and v1 > v2:
                return True
            if op == ">=" and v1 >= v2:
                return True
        except ValueError:
            pass
    return False


def _extract_table_span(
    stmt_sql: str,
    tokens: list[RawToken],
    norm: tuple[str, ...],
    verb: str,
    tables: list[str],
) -> tuple[int, int] | None:
    """Extract table span for single-target DML."""
    if verb not in ("UPDATE", "DELETE") or len(tables) != 1:
        return None

    n = len(norm)
    if verb == "UPDATE":
        for i in range(n):
            if norm[i] == "UPDATE" and i + 1 < n:
                tbl_name = _build_dotted_name(tokens, i + 1)
                if tbl_name:
                    start = tokens[i + 1].start
                    end = start + len(tbl_name)
                    # verify
                    if stmt_sql[start:end] == tbl_name:
                        return (start, end)
                break
    elif verb == "DELETE":
        for i in range(n):
            if norm[i] == "FROM" and i + 1 < n:
                tbl_name = _build_dotted_name(tokens, i + 1)
                if tbl_name:
                    start = tokens[i + 1].start
                    end = start + len(tbl_name)
                    if stmt_sql[start:end] == tbl_name:
                        return (start, end)
                break
    return None
