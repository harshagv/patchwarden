"""Breaking changes between PHP versions, as rules the breakage scanner runs over masked code.

`since` is the PHP line where the change lands. A rule applies to a migration
when from_line < since <= to_line. Severity "error" means the code stops working
(a fatal error); "warning" means a deprecation notice or a changed result that needs a look.
Sources: the PHP migration guides for 7.x -> 8.4 (php.net/manual/en/appendices.php).
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass

from .lexer import Source

# (start, end, replacement) on the raw source text
Edit = tuple[int, int, str]


@dataclass(frozen=True)
class Hit:
    start: int
    end: int
    name: str  # the function/construct found, for the message
    edit: Edit | None = None  # a safe mechanical fix, if there is one


@dataclass(frozen=True)
class Rule:
    id: str
    since: tuple[int, int]
    severity: str  # "error" or "warning"
    kind: str  # "removed", "behaviour" or "deprecated"
    title: str
    fix: str
    find: Callable[[Source], list[Hit]]

    @property
    def since_label(self) -> str:
        return f"{self.since[0]}.{self.since[1]}"


def _calls(names: list[str], *, replacement: Callable[[re.Match, Source], Edit | None] | None = None):
    """Calls to global functions, not methods (->x), static calls (::x), variables ($x) or namespaced x."""
    pattern = re.compile(r"(?<![\w$>:\\])\\?\b(" + "|".join(map(re.escape, names)) + r")\s*\(", re.IGNORECASE)
    definition = re.compile(r"function\s+&?\s*$", re.IGNORECASE)

    def find(src: Source) -> list[Hit]:
        hits = []
        for m in pattern.finditer(src.masked):
            if definition.search(src.masked[max(0, m.start() - 30):m.start()]):
                continue  # a definition (polyfill), not a call
            hits.append(Hit(m.start(1), m.end(), m.group(1).lower(), replacement(m, src) if replacement else None))
        return hits

    find.is_call = True  # type: ignore[attr-defined]  # a site-defined polyfill of the same name makes it safe
    return find


def _regex(pattern: str, name: str, replacement: Callable[[re.Match, Source], Edit | None] | None = None,
           flags: int = 0, where: str = "code"):
    rx = re.compile(pattern, flags)

    def find(src: Source) -> list[Hit]:
        if where == "strings":
            out = []
            for start, end in src.interpolated:
                for m in rx.finditer(src.text, start, end):
                    out.append(Hit(m.start(), m.end(), name, replacement(m, src) if replacement else None))
            return out
        return [Hit(m.start(), m.end(), name, replacement(m, src) if replacement else None)
                for m in rx.finditer(src.masked)]

    return find


# --- auto-fixes (only where the rewrite is exact) ---------------------------------

def _empty_call_to_false(m: re.Match, src: Source) -> Edit | None:
    close = src.masked.find(")", m.end())
    if close != -1 and src.masked[m.end():close].strip() == "":
        return (m.start(), close + 1, "false")
    return None


def _curly_offset(m: re.Match, src: Source) -> Edit | None:
    depth, i = 0, m.end() - 1  # at "{"
    while i < len(src.masked):
        ch = src.masked[i]
        depth += ch == "{"
        depth -= ch == "}"
        if depth == 0:
            inner = src.text[m.end():i]
            return (m.end() - 1, i + 1, "[" + inner + "]")
        i += 1
    return None


def _cast(new: str):
    return lambda m, src: (m.start(), m.end(), new)


def _unset_cast(m: re.Match, src: Source) -> Edit:
    return (m.start(), m.end(), "null")


def _nullable(m: re.Match, src: Source) -> Edit | None:
    type_start = m.start("type")
    return (type_start, type_start, "?")


def _interp(m: re.Match, src: Source) -> Edit:
    return (m.start(), m.end(), "{$" + m.group(1) + "}")


# Implicitly nullable parameter: "Type $x = null" in a parameter list, without "?Type" or a union.
_NULLABLE = (r"(?:\(|,)\s*(?:(?:public|private|protected|readonly)\s+)*"
             r"(?P<type>(?!mixed\b|null\b)(?:\\?[A-Za-z_][\w\\]*))\s+&?\s*(?:\.\.\.)?\$\w+\s*=\s*null\b")


RULES: list[Rule] = [
    # PHP 7.0
    Rule("mysql_ext", (7, 0), "error", "removed", "The old mysql_* functions were removed",
         "Use mysqli or PDO instead.",
         _calls(["mysql_connect", "mysql_query", "mysql_fetch_array", "mysql_fetch_assoc", "mysql_real_escape_string",
                 "mysql_select_db", "mysql_close", "mysql_num_rows", "mysql_error", "mysql_insert_id"])),
    Rule("ereg", (7, 0), "error", "removed", "The ereg* regular expression functions were removed",
         "Use preg_match / preg_replace with a /.../ pattern.",
         _calls(["ereg", "eregi", "ereg_replace", "eregi_replace", "split", "spliti", "sql_regcase"])),
    Rule("raw_post_data", (7, 0), "error", "removed", "$HTTP_RAW_POST_DATA was removed",
         "Read the request body with file_get_contents('php://input').",
         _regex(r"\$HTTP_RAW_POST_DATA\b", "$HTTP_RAW_POST_DATA")),
    # PHP 8.0: functions deprecated in 7.x and removed
    Rule("create_function", (8, 0), "error", "removed", "create_function() was removed",
         "Rewrite as an anonymous function: function ($a) { ... }.", _calls(["create_function"])),
    Rule("each", (8, 0), "error", "removed", "each() was removed",
         "Rewrite the loop with foreach ($array as $key => $value).", _calls(["each"])),
    Rule("magic_quotes", (8, 0), "error", "removed", "get_magic_quotes_gpc() / get_magic_quotes_runtime() were removed",
         "They always returned false since PHP 5.4: replace the call with false.",
         _calls(["get_magic_quotes_gpc", "get_magic_quotes_runtime"], replacement=_empty_call_to_false)),
    Rule("money_format", (8, 0), "error", "removed", "money_format() was removed",
         "Use NumberFormatter::formatCurrency() from the intl extension.", _calls(["money_format"])),
    Rule("autoload_fn", (8, 0), "error", "removed", "__autoload() is no longer called",
         "Register the autoloader with spl_autoload_register().",
         _regex(r"function\s+__autoload\s*\(", "__autoload", flags=re.IGNORECASE)),
    Rule("removed_80_misc", (8, 0), "error", "removed", "A function removed in PHP 8.0",
         "Replace it; see the PHP 8.0 migration guide for the replacement.",
         _calls(["fgetss", "hebrevc", "convert_cyr_string", "ezmlm_hash", "restore_include_path", "read_exif_data",
                 "gmp_random", "image2wbmp", "png2wbmp", "jpeg2wbmp", "ldap_sort", "mbereg", "mberegi",
                 "mbereg_replace", "mbsplit"])),
    Rule("curly_offset", (8, 0), "error", "removed", "Curly-brace string/array offsets ($s{0}) were removed",
         "Use square brackets: $s[0].", _regex(r"\$\w+\s*\{", "${…} offset", replacement=_curly_offset)),
    Rule("real_cast", (8, 0), "error", "removed", "The (real) cast was removed", "Use (float).",
         _regex(r"\(\s*real\s*\)", "(real)", replacement=_cast("(float)"), flags=re.IGNORECASE)),
    Rule("unset_cast", (8, 0), "error", "removed", "The (unset) cast was removed", "Use null.",
         _regex(r"\(\s*unset\s*\)\s*\$\w+", "(unset)", replacement=_unset_cast, flags=re.IGNORECASE)),
    Rule("php_errormsg", (8, 0), "error", "removed", "$php_errormsg was removed", "Use error_get_last().",
         _regex(r"\$php_errormsg\b", "$php_errormsg")),
    Rule("define_ci", (8, 0), "warning", "removed", "Case-insensitive constants (define(..., true)) are gone",
         "Drop the third argument and use the constant's exact case.",
         _regex(r"\bdefine\s*\([^;()]*,[^;()]*,\s*true\s*\)", "define(…, true)", flags=re.IGNORECASE)),
    Rule("match_keyword", (8, 0), "error", "removed", "match is now a reserved keyword",
         "Rename the function or class called match.",
         _regex(r"\b(?:function|class)\s+match\b", "match", flags=re.IGNORECASE)),
    # PHP 8.1
    Rule("deprecated_81", (8, 1), "warning", "deprecated", "A function deprecated in PHP 8.1",
         "strftime(): use IntlDateFormatter or date(). mhash*(): use hash(). date_sunrise/sunset(): use date_sun_info().",
         _calls(["strftime", "gmstrftime", "mhash", "mhash_count", "mhash_get_block_size", "mhash_get_hash_name",
                 "mhash_keygen_s2k", "date_sunrise", "date_sunset"])),
    Rule("filter_sanitize_string", (8, 1), "warning", "deprecated", "FILTER_SANITIZE_STRING is deprecated",
         "Use htmlspecialchars() for output, or FILTER_UNSAFE_RAW with your own checks.",
         _regex(r"\bFILTER_SANITIZE_(?:STRING|STRIPPED)\b", "FILTER_SANITIZE_STRING")),
    # PHP 8.2
    Rule("utf8_encode", (8, 2), "warning", "deprecated", "utf8_encode() / utf8_decode() are deprecated",
         "Use mb_convert_encoding($s, 'UTF-8', 'ISO-8859-1') (or the reverse).",
         _calls(["utf8_encode", "utf8_decode"])),
    Rule("dollar_brace_interp", (8, 2), "warning", "deprecated", '"${var}" string interpolation is deprecated',
         'Write "{$var}" instead.', _regex(r"\$\{(\w+)\}", "${var}", replacement=_interp, where="strings")),
    # PHP 8.3
    Rule("get_class_noargs", (8, 3), "warning", "deprecated", "get_class() / get_parent_class() without arguments are deprecated",
         "Use self::class / static::class, or pass $this.",
         _regex(r"(?<![\w$>:])\b(?:get_class|get_parent_class)\s*\(\s*\)", "get_class()", flags=re.IGNORECASE)),
    # PHP 8.4
    Rule("implicit_nullable", (8, 4), "warning", "deprecated", "Implicitly nullable parameter types are deprecated",
         "Write ?Type $x = null instead of Type $x = null.", _regex(_NULLABLE, "Type $x = null", replacement=_nullable)),
    Rule("imap_unbundled", (8, 4), "error", "removed", "The IMAP extension is no longer bundled with PHP",
         "Install the imap extension from PECL on the new server, or move to a mail library.",
         _regex(r"(?<![\w$>:\\])\bimap_\w+\s*\(", "imap_*", flags=re.IGNORECASE)),
    Rule("e_strict", (8, 4), "warning", "deprecated", "The E_STRICT constant is deprecated", "Remove it from error_reporting().",
         _regex(r"\bE_STRICT\b", "E_STRICT")),
    Rule("trigger_user_error", (8, 4), "warning", "deprecated", "trigger_error() with E_USER_ERROR is deprecated",
         "Throw an exception or call exit() instead.",
         _regex(r"\btrigger_error\s*\([^;]*E_USER_ERROR", "trigger_error(E_USER_ERROR)", flags=re.IGNORECASE)),
]

RULES_BY_ID = {r.id: r for r in RULES}
