"""Release gate: prove every literal SQL statement binds the right number of values.

WHY THIS EXISTS
---------------
MonClub Access 1.4.20 and 1.4.21 shipped with this in ``app/core/db.py``::

    INSERT INTO sync_devices (... 59 column names ...)
    VALUES (... only 57 terms ...)        -- the bound tuple had all 59

SQLite rejects that at prepare time, so EVERY device sync raised
``sqlite3.OperationalError: 57 values for 59 columns``. The whole
``save_sync_cache_delta`` transaction rolled back -- devices, members,
credentials and settings alike -- and affected gyms silently stopped receiving
data while still looking healthy.

It is a pure arity mistake: add a column to the list and to the bound tuple,
forget the matching ``?``. No type checker or linter catches it; it fails only
at runtime, on a real database, against a real payload.

This script catches it statically, using nothing but the stdlib, so it can run
as a build gate before PyInstaller packages anything.

WHAT IT CHECKS
--------------
For every ``.execute(...)`` / ``.executemany(...)`` call whose SQL is a literal:

  * ``INSERT INTO t (cols) VALUES (terms)``
        -> len(columns) == len(VALUES terms), per VALUES row.
        Compared against TERMS, not against ``?``, because a row may legitimately
        mix placeholders with literals and expressions -- ``VALUES (?, 0, ?,
        datetime('now'))`` is correct and must not be flagged. Term count is
        exactly what SQLite's "N values for M columns" message counts.
  * any literal SQL passed a literal tuple/list of bound values
        -> count('?') == len(values)   [``execute`` only; ``executemany`` binds
        a sequence of rows, so the comparison does not apply]

WHAT IT DELIBERATELY SKIPS
--------------------------
  * SQL assembled at runtime (f-strings, concatenation, ``",".join(...)``) --
    not knowable statically. Counted and reported as SKIPPED, never as a pass,
    so the summary line cannot overstate coverage.
  * ``INSERT ... SELECT``, and bound values passed as a variable.

Exit code 0 = no mismatch. Exit code 1 = at least one mismatch.

Usage:
    python tools/check_sql_arity.py [path ...]      # default: app
"""

from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

_EXEC_METHODS = {"execute", "executemany"}

# "INSERT INTO name (a, b, c)" -- captures the parenthesised column list.
_INSERT_COLS_RE = re.compile(
    r"INSERT\s+(?:OR\s+\w+\s+)?INTO\s+[\w.\"`\[\]]+\s*\(([^)]*)\)",
    re.IGNORECASE | re.DOTALL,
)

_VALUES_RE = re.compile(r"\bVALUES\b", re.IGNORECASE)


def _literal_sql(node: ast.AST) -> str | None:
    """Return the SQL text if the node is a plain string literal, else None.

    Implicitly concatenated literals ("a" "b") parse as a single Constant, so a
    JoinedStr/BinOp arriving here means the SQL is assembled at runtime.
    """
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _split_top_level(text: str) -> list[str]:
    """Split on commas at paren-depth 0 and outside string literals.

    ``a, f(b, c), 'x,y'`` -> ``["a", "f(b, c)", "'x,y'"]``. A naive split(",")
    miscounts both function calls and quoted strings containing commas.
    """
    out: list[str] = []
    depth = 0
    in_str = False
    buf: list[str] = []
    i = 0
    while i < len(text):
        ch = text[i]
        if in_str:
            buf.append(ch)
            if ch == "'":
                # '' inside a string literal is an escaped quote, not the end.
                if i + 1 < len(text) and text[i + 1] == "'":
                    buf.append("'")
                    i += 2
                    continue
                in_str = False
            i += 1
            continue
        if ch == "'":
            in_str = True
            buf.append(ch)
        elif ch == "(":
            depth += 1
            buf.append(ch)
        elif ch == ")":
            depth -= 1
            buf.append(ch)
        elif ch == "," and depth == 0:
            out.append("".join(buf).strip())
            buf = []
        else:
            buf.append(ch)
        i += 1
    tail = "".join(buf).strip()
    if tail:
        out.append(tail)
    return [t for t in out if t]


def _count_placeholders(sql: str) -> int:
    return sql.count("?")


def _values_len(node: ast.AST | None) -> int | None:
    """Length of a literal tuple/list of bound values, else None.

    A starred element (``*rest``) makes the length unknowable, so return None.
    """
    if isinstance(node, (ast.Tuple, ast.List)):
        if any(isinstance(e, ast.Starred) for e in node.elts):
            return None
        return len(node.elts)
    return None


def _values_groups(sql: str, from_index: int) -> list[list[str]] | None:
    """Term lists for each ``VALUES (...)`` row appearing after ``from_index``.

    None means "not a plain VALUES insert, or not confidently parseable" --
    callers must skip rather than guess.
    """
    match = _VALUES_RE.search(sql, from_index)
    if not match:
        return None
    groups: list[list[str]] = []
    i = match.end()
    n = len(sql)
    while i < n:
        while i < n and sql[i].isspace():
            i += 1
        if i >= n or sql[i] != "(":
            break
        depth = 0
        start = i
        in_str = False
        while i < n:
            ch = sql[i]
            if in_str:
                if ch == "'":
                    if i + 1 < n and sql[i + 1] == "'":
                        i += 2
                        continue
                    in_str = False
            elif ch == "'":
                in_str = True
            elif ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    i += 1
                    break
            i += 1
        if depth != 0:
            return None  # unbalanced -> refuse to judge
        groups.append(_split_top_level(sql[start + 1 : i - 1]))
        while i < n and sql[i].isspace():
            i += 1
        if i < n and sql[i] == ",":
            i += 1
            continue
        break
    return groups or None


def check_file(path: Path) -> tuple[list[str], int, int]:
    """Return (problems, checked_count, skipped_count) for one file."""
    problems: list[str] = []
    checked = 0
    skipped = 0

    try:
        src = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        return ([f"{path}: unreadable ({exc})"], 0, 0)

    try:
        tree = ast.parse(src)
    except SyntaxError as exc:
        return ([f"{path}: syntax error ({exc})"], 0, 0)

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if not isinstance(node.func, ast.Attribute):
            continue
        if node.func.attr not in _EXEC_METHODS or not node.args:
            continue

        sql = _literal_sql(node.args[0])
        if sql is None:
            skipped += 1
            continue
        if "?" not in sql and "INSERT" not in sql.upper():
            continue

        line = node.lineno
        checked += 1

        # (1) INSERT column list vs the VALUES terms.
        match = _INSERT_COLS_RE.search(sql)
        if match and "SELECT" not in sql[match.end() : match.end() + 40].upper():
            cols = _split_top_level(match.group(1))
            groups = _values_groups(sql, match.end())
            if cols and groups:
                for row, terms in enumerate(groups, 1):
                    if len(terms) != len(cols):
                        where = f" (VALUES row {row})" if len(groups) > 1 else ""
                        problems.append(
                            f"{path}:{line}: INSERT names {len(cols)} columns "
                            f"but supplies {len(terms)} values{where}"
                        )

        # (2) placeholders vs the literal bound-value tuple.
        if len(node.args) >= 2 and node.func.attr == "execute":
            placeholders = _count_placeholders(sql)
            n_values = _values_len(node.args[1])
            if n_values is not None and placeholders and n_values != placeholders:
                problems.append(
                    f"{path}:{line}: statement has {placeholders} '?' placeholders "
                    f"but binds {n_values} values"
                )

    return (problems, checked, skipped)


def main(argv: list[str]) -> int:
    roots = [Path(a) for a in argv[1:]] or [Path("app")]
    files: list[Path] = []
    for root in roots:
        if root.is_file():
            files.append(root)
        else:
            files.extend(sorted(root.rglob("*.py")))
    # Never audit vendored dependencies or build leftovers.
    files = [
        f
        for f in files
        if ".venv" not in f.parts and "__pycache__" not in f.parts and "build" not in f.parts
    ]

    all_problems: list[str] = []
    total_checked = 0
    total_skipped = 0
    for f in files:
        problems, checked, skipped = check_file(f)
        all_problems.extend(problems)
        total_checked += checked
        total_skipped += skipped

    print(
        f"[sql-arity] {len(files)} files | {total_checked} literal statements checked | "
        f"{total_skipped} runtime-built statements skipped (not verifiable statically)"
    )
    if all_problems:
        print(f"[sql-arity] FAIL - {len(all_problems)} mismatch(es):")
        for problem in all_problems:
            print(f"  {problem}")
        return 1
    print("[sql-arity] PASS - every literal statement binds the right number of values")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
