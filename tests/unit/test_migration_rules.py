"""Breakage scanner: lexer, rules, version windows, auto-fixes."""

from __future__ import annotations

import pytest

from patchwarden.migration.lexer import lex
from patchwarden.migration.scanner import apply_auto_fixes, build_plan, rules_between, scan_files

THEME = "wp-content/themes/t/functions.php"


def found(code: str, frm="7.4.33", to="8.4.27", path=THEME) -> list[tuple[str, int]]:
    return [(h["rule"], h["line"]) for h in scan_files({path: code}, frm, to)["hits"]]


def test_lexer_masks_comments_strings_and_html_but_keeps_lines():
    src = lex("x.php", "<b>each(</b><?php\n// each($a)\n$s = 'each($a)'; /* each() */\n?>each(\n<?= each($b) ?>")
    assert src.masked.count("\n") == src.text.count("\n") and len(src.masked) == len(src.text)
    assert "each" not in src.masked.replace("each($b)", "")
    assert "each($b)" in src.masked


def test_heredoc_and_nowdoc():
    code = "<?php\n$a = <<<EOT\neach($x) ${y}\nEOT;\n$b = <<<'N'\n${z}\nN;\neach($real);\n"
    src = lex("x.php", code)
    assert "each($x)" not in src.masked and "each($real)" in src.masked
    assert [r for r, _ in found(code)] == ["each", "dollar_brace_interp"]  # ${z} is in a nowdoc: not interpolated


@pytest.mark.parametrize("code,rule", [
    ("<?php create_function('$a', 'return 1;');", "create_function"),
    ("<?php while (list($k) = each($a)) {}", "each"),
    ("<?php if (get_magic_quotes_gpc()) {}", "magic_quotes"),
    ("<?php echo money_format('%i', 1);", "money_format"),
    ("<?php function __autoload($c) {}", "autoload_fn"),
    ("<?php fgetss($fh);", "removed_80_misc"),
    ("<?php $c = $s{0};", "curly_offset"),
    ("<?php $f = (real) $x;", "real_cast"),
    ("<?php $f = (unset) $x;", "unset_cast"),
    ("<?php echo $php_errormsg;", "php_errormsg"),
    ("<?php define('X', 1, true);", "define_ci"),
    ("<?php function match($a) {}", "match_keyword"),
    ("<?php echo strftime('%Y');", "deprecated_81"),
    ("<?php filter_var($x, FILTER_SANITIZE_STRING);", "filter_sanitize_string"),
    ("<?php utf8_encode($s);", "utf8_encode"),
    ('<?php echo "hi ${name}";', "dollar_brace_interp"),
    ("<?php class A { function f() { return get_class(); } }", "get_class_noargs"),
    ("<?php function f(Foo $x = null) {}", "implicit_nullable"),
    ("<?php imap_open($a, $b, $c);", "imap_unbundled"),
    ("<?php error_reporting(E_ALL & ~E_STRICT);", "e_strict"),
    ("<?php trigger_error('x', E_USER_ERROR);", "trigger_user_error"),
])
def test_each_rule_finds_its_case(code, rule):
    assert rule in [r for r, _ in found(code)]


@pytest.mark.parametrize("code", [
    "<?php $obj->each(); Foo::each(); foreach ($a as $b) {}",
    "<?php str_split($s); preg_split('/x/', $s); My\\Lib\\each($a);",
    "<?php function f(?Foo $x = null, mixed $m = null, int|null $n = null) {}",
    "<?php $c = $s[0]; if ($x) { }",
    "<?php echo \"{$name}\"; echo '${literal}';",
    "<?php echo get_class($this);",
])
def test_no_false_positives(code):
    assert found(code) == []


def test_site_polyfill_is_not_reported():
    code = "<?php if (!function_exists('each')) { function each(&$a) { return false; } }\neach($items);"
    assert found(code) == []


def test_polyfill_definitions_are_never_rewritten():
    code = ("<?php\nif (!function_exists('get_magic_quotes_gpc')) {\n"
            "    function get_magic_quotes_gpc() { return false; }\n}\n")
    assert apply_auto_fixes({THEME: code}, "7.4.33", "8.4.27") == ({}, [])


def test_rules_follow_the_version_window():
    assert {r.id for r in rules_between("8.1.31", "8.3.36")} >= {"utf8_encode", "get_class_noargs"}
    assert "create_function" not in {r.id for r in rules_between("8.1.31", "8.3.36")}  # already gone in 8.1
    assert "implicit_nullable" not in {r.id for r in rules_between("7.4.33", "8.3.36")}  # 8.4 only
    assert found("<?php function f(Foo $x = null) {}", to="8.3.36") == []


def test_wordpress_core_is_skipped_but_custom_index_php_is_not():
    wp = scan_files({"wp-includes/a.php": "<?php each($a);", THEME: "<?php each($b);"}, "7.4.33", "8.4.27")
    assert [h["file"] for h in wp["hits"]] == [THEME] and wp["skipped_wordpress_core"] == 1
    custom = scan_files({"index.php": "<?php each($a);"}, "7.4.33", "8.4.27")
    assert [h["file"] for h in custom["hits"]] == ["index.php"]


def test_report_snippets_never_show_string_literals():
    r = scan_files({"wp-config.php": "<?php define('DB_PASSWORD', 'S3cr3t-literal', true);"}, "7.4.33", "8.4.27")
    assert r["hits"][0]["code"] == "define('…', '…', true);"
    assert "S3cr3t" not in str(r)


def test_auto_fixes_are_exact_and_leave_the_rest():
    code = ("<?php\nif (get_magic_quotes_gpc()) {}\n$c = $s{$i + 1};\n$f = (real) $x;\n$u = (unset) $y;\n"
            "function f(Foo $a = null, ?Bar $b = null) {}\necho \"x ${v}\";\neach($z);\n")
    changed, applied = apply_auto_fixes({THEME: code, "wp-config.php": "<?php $c = $s{0};"}, "7.4.33", "8.4.27")
    assert set(changed) == {THEME}  # config files are never edited
    assert changed[THEME] == ("<?php\nif (false) {}\n$c = $s[$i + 1];\n$f = (float) $x;\n$u = null;\n"
                              "function f(?Foo $a = null, ?Bar $b = null) {}\necho \"x {$v}\";\neach($z);\n")
    assert {a["rule"] for a in applied} == {"magic_quotes", "curly_offset", "real_cast", "unset_cast",
                                            "implicit_nullable", "dollar_brace_interp"}
    # Running again finds nothing more to fix automatically; each() stays for a developer.
    assert apply_auto_fixes(changed, "7.4.33", "8.4.27")[0] == {}
    assert [r for r, _ in found(changed[THEME])] == ["each"]


def test_plan_orders_breaking_fixes_first_and_sizes_effort():
    code = "<?php\necho strftime('%Y');\neach($a);\n$c = $s{0};\n"
    breakage = scan_files({THEME: code}, "7.4.33", "8.4.27")
    plan = build_plan(breakage)
    assert [f["rule"] for f in plan["fixes"]] == ["curly_offset", "each", "deprecated_81"]
    assert [f["automatic"] for f in plan["fixes"]] == [True, False, False]
    assert plan["effort"] == "small" and plan["target_version"] == "8.4.27"
    big = scan_files({f"wp-content/plugins/p{i}/a.php": "<?php each($a); create_function('', '');"
                      for i in range(10)}, "7.4.33", "8.4.27")
    assert build_plan(big)["effort"] == "large"
