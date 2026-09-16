r"""BibTeX / BibLaTeX databases (.bib).

This is a field scrubber, not a comment scrubber, and it shares no code with the
LaTeX dialects on purpose: in BibTeX a ``%`` is an ordinary character, not a
comment, and text outside an entry is already ignored. Running the LaTeX rules
over a ``.bib`` would truncate at the first percent in a URL.

What is private here is not the bibliography. Author names and titles are
citations -- public record, and the point of the file. What leaks is the
plumbing reference managers add: ``file`` and ``bdsk-file-*`` hold absolute
paths into the user's home directory, and ``owner`` names the account that added
the entry.
"""

from __future__ import annotations

import re

from ..base import Policy, Removal, ScrubResult
from .scanner import Edit, apply_edits

#: Removed by default. Local paths and account names, never citation data.
DROP_FIELDS = frozenset({b"file", b"local-url", b"owner", b"pdf"})
DROP_PREFIXES = (b"bdsk-file",)

#: Removed only under --strip-dates: when the entry was filed, not when the work
#: was published.
DATE_FIELDS = frozenset({b"timestamp", b"date-added", b"date-modified"})

_ENTRY = re.compile(rb"@[A-Za-z]+[ \t]*[{(]")
_QUOTE, _COMMA, _EQUALS = 0x22, 0x2C, 0x3D
_LBRACE, _RBRACE, _LPAREN, _RPAREN = 0x7B, 0x7D, 0x28, 0x29
_BACKSLASH = 0x5C


def _entry_body(data: bytes, open_index: int) -> int | None:
    """Index just past the delimiter closing the entry opened at ``open_index``."""
    opener = data[open_index]
    closer = _RBRACE if opener == _LBRACE else _RPAREN
    depth, cursor, in_quotes = 0, open_index, False
    while cursor < len(data):
        byte = data[cursor]
        if byte == _BACKSLASH:
            cursor += 2
            continue
        if byte == _QUOTE and depth <= 1:
            in_quotes = not in_quotes
        elif not in_quotes:
            if byte == opener:
                depth += 1
            elif byte == closer:
                depth -= 1
                if depth == 0:
                    return cursor + 1
        cursor += 1
    return None


def _iter_fields(data: bytes, start: int, end: int):
    """Yield ``(name, field_start, field_end)`` for each field in an entry body.

    ``field_end`` includes the trailing comma so removing the span leaves the
    entry well-formed. The citation key -- the first comma-separated chunk, which
    has no ``=`` -- is skipped.
    """
    cursor = start
    while cursor < end:
        while cursor < end and data[cursor] in (0x20, 0x09, 0x0A, 0x0D, _COMMA):
            cursor += 1
        if cursor >= end:
            return
        field_start = cursor
        depth, in_quotes = 0, False
        while cursor < end:
            byte = data[cursor]
            if byte == _BACKSLASH:
                cursor += 2
                continue
            if byte == _QUOTE and depth == 0:
                in_quotes = not in_quotes
            elif not in_quotes:
                if byte in (_LBRACE, _LPAREN):
                    depth += 1
                elif byte in (_RBRACE, _RPAREN):
                    depth -= 1
                elif byte == _COMMA and depth == 0:
                    break
            cursor += 1
        field_end = cursor
        if cursor < end and data[cursor] == _COMMA:
            field_end = cursor + 1

        equals = data.find(b"=", field_start, cursor)
        if equals != -1:
            yield data[field_start:equals].strip().lower(), field_start, field_end
        cursor = field_end


class BibScrubber:
    fmt = "bibtex"

    def sniff(self, data: bytes) -> bool:
        from . import looks_like_bib
        return looks_like_bib(data)

    def scrub(self, data: bytes, policy: Policy) -> ScrubResult:
        removals: list[Removal] = []
        edits: list[Edit] = []
        dropped: dict[str, int] = {}

        for match in _ENTRY.finditer(data):
            open_index = match.end() - 1
            close = _entry_body(data, open_index)
            if close is None:
                continue
            for name, start, end in _iter_fields(data, open_index + 1, close - 1):
                if not self._drops(name, policy):
                    continue
                edits.append(Edit(start, end, b""))
                key = name.decode("ascii", "replace")
                dropped[key] = dropped.get(key, 0) + 1

        for name, count in sorted(dropped.items()):
            removals.append(Removal("BibTeX entry", name, f"{count} occurrence(s)"))

        return ScrubResult(apply_edits(data, edits), removals, [])

    def _drops(self, name: bytes, policy: Policy) -> bool:
        if name in DROP_FIELDS or name.startswith(DROP_PREFIXES):
            return True
        return policy.strip_dates and name in DATE_FIELDS
