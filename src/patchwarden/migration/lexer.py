"""A small PHP lexer: masks comments, string contents and inline HTML so rules only see code.

The masked text has the same length and the same line breaks as the source,
so a match offset maps straight back to a file line and column. String
contents become spaces (the quotes stay). That keeps literals, such as a
database password in a define(), out of every report snippet.
"""

from __future__ import annotations

import bisect
import re
from dataclasses import dataclass, field

_OPEN_TAG = re.compile(r"<\?(?:php\b|=)", re.IGNORECASE)
_HEREDOC = re.compile(r"<<<[ \t]*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\1\r?\n")


@dataclass
class Source:
    path: str
    text: str
    masked: str
    # (start, end) of the contents of double-quoted strings and heredocs, where "${var}" lives
    interpolated: list[tuple[int, int]] = field(default_factory=list)
    _lines: list[int] = field(default_factory=list, repr=False)

    def position(self, offset: int) -> tuple[int, int]:
        if not self._lines:
            self._lines = [0] + [m.end() for m in re.finditer(r"\n", self.text)]
        line = bisect.bisect_right(self._lines, offset)
        return line, offset - self._lines[line - 1] + 1

    def snippet(self, line: int) -> str:
        """The masked line: code is shown, string contents are blanked out."""
        lines = self.masked.split("\n")
        raw = lines[line - 1] if 0 < line <= len(lines) else ""
        shown = re.sub(r"(['\"])\s+\1", r"\1…\1", raw.strip())[:200]
        return shown or "(inside a multi-line string)"


def _blank(chars: list[str], start: int, end: int) -> None:
    for i in range(start, end):
        if chars[i] != "\n":
            chars[i] = " "


def lex(path: str, text: str) -> Source:
    chars = list(text)
    interpolated: list[tuple[int, int]] = []
    n = len(text)
    i = 0
    in_php = False
    while i < n:
        if not in_php:
            m = _OPEN_TAG.search(text, i)
            end = m.start() if m else n
            _blank(chars, i, end)  # inline HTML is not PHP
            if not m:
                break
            _blank(chars, m.start(), m.end())  # the <?php tag itself
            i, in_php = m.end(), True
            continue

        c = text[i]
        two = text[i:i + 2]
        if two == "?>":
            _blank(chars, i, i + 2)
            in_php = False
            i += 2
        elif two == "//" or (c == "#" and text[i + 1:i + 2] != "["):
            j = i
            while j < n and text[j] != "\n" and text[j:j + 2] != "?>":
                j += 1
            _blank(chars, i, j)
            i = j
        elif two == "/*":
            j = text.find("*/", i + 2)
            j = n if j == -1 else j + 2
            _blank(chars, i, j)
            i = j
        elif c in "'\"`":
            j = i + 1
            while j < n and text[j] != c:
                j += 2 if text[j] == "\\" else 1
            j = min(j, n)
            if c == '"':
                interpolated.append((i + 1, j))
            _blank(chars, i + 1, j)
            i = j + 1
        elif text.startswith("<<<", i) and (m := _HEREDOC.match(text, i)):
            quote, label = m.group(1), m.group(2)
            close = re.compile(r"^[ \t]*" + re.escape(label) + r"\b", re.MULTILINE)
            mc = close.search(text, m.end())
            body_end = mc.start() if mc else n
            if quote != "'":
                interpolated.append((m.end(), body_end))
            _blank(chars, m.end(), body_end)
            i = mc.end() if mc else n
        else:
            i += 1
    return Source(path=path, text=text, masked="".join(chars), interpolated=interpolated)
