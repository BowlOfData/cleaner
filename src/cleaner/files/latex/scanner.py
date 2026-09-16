"""A byte-level scanner for LaTeX source.

It locates spans; it never rebuilds the document. Everything the scrubber
changes is expressed as an :class:`Edit` over the original bytes, so any byte
not covered by an edit is copied verbatim by construction -- the same guarantee
``png.py`` and ``jpeg.py`` give, and the reason a scrubbed ``.tex`` still
compiles to the same document.

Operating on ``bytes`` rather than ``str`` is deliberate. Every LaTeX syntax
character (``\\ % { } [ ]``) is ASCII, and no UTF-8 continuation byte is ever
below 0x80, so the same scanner is correct for UTF-8 and for the Latin-1 sources
``\\usepackage[latin1]{inputenc}`` still produces. Nothing here has to guess an
encoding, and nothing round-trips through one.

The precedence order below is the whole correctness argument. A regex over
``%.*$`` finds every comment in a test file and also destroys ``\\%``, every
``lstlisting`` block, and every ``\\url`` holding a percent-encoded byte.

  1. A backslash escapes the byte after it, so ``\\%`` is a literal percent and
     never introduces a comment.
  2. Verbatim-like regions are opaque: inside them ``%`` and ``\\`` are ordinary
     characters. They are only ever copied, never edited, so being conservative
     about what counts as opaque is always safe -- ``lstlisting``'s
     ``escapechar`` and similar re-entry tricks need no special handling.
  3. Only then does ``%`` start a comment, running to just before the line
     terminator, which it never consumes.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass

#: Environments whose bodies are copied untouched. ``comment`` and
#: ``filecontents`` are here for parsing, not because they are harmless -- the
#: scrubber reports them separately as content hidden from the rendered document.
OPAQUE_ENVIRONMENTS = frozenset({
    b"verbatim", b"verbatim*", b"Verbatim", b"Verbatim*", b"BVerbatim", b"LVerbatim",
    b"lstlisting", b"minted", b"alltt", b"comment", b"filecontents", b"filecontents*",
})

#: Inline verbatim macros: a delimiter byte follows, and the region ends at its
#: next occurrence on the same line.
INLINE_VERBATIM = frozenset({b"verb", b"verb*", b"lstinline", b"mintinline"})

#: Macros whose brace argument is verbatim. ``url.sty`` gives ``%`` a harmless
#: catcode inside these, so ``\url{http://x/a%20b}`` is a whole URL and not a
#: comment -- reading it as one and truncating there would silently corrupt every
#: percent-encoded link in the document. ``\href`` takes two arguments and only
#: the first is verbatim, which falls out of resuming the scan after it.
VERBATIM_ARG_MACROS = frozenset({b"url", b"nolinkurl", b"path", b"href"})

_LF, _CR = 0x0A, 0x0D
_BACKSLASH, _PERCENT = 0x5C, 0x25
_LBRACE, _RBRACE = 0x7B, 0x7D
_LBRACKET, _RBRACKET = 0x5B, 0x5D
_STAR = 0x2A


def _is_letter(byte: int) -> bool:
    return 0x41 <= byte <= 0x5A or 0x61 <= byte <= 0x7A


class Kind(enum.Enum):
    COMMENT = "comment"
    OPAQUE = "opaque"
    CONTROL = "control"


@dataclass(frozen=True)
class Span:
    kind: Kind
    start: int
    end: int          # exclusive
    line: int         # 1-based, of ``start``
    name: bytes = b""  # control word, or environment name for an opaque span

    @property
    def column(self) -> int | None:
        return None


@dataclass(frozen=True)
class Edit:
    """Replace ``data[start:end]`` with ``replacement``."""

    start: int
    end: int
    replacement: bytes


def apply_edits(data: bytes, edits: list[Edit]) -> bytes:
    """Splice non-overlapping edits into ``data``.

    Overlap is a programming error rather than a malformed-input case, so it
    raises instead of silently picking a winner.
    """
    ordered = sorted(edits, key=lambda edit: (edit.start, edit.end))
    out = bytearray()
    cursor = 0
    for edit in ordered:
        if edit.start < cursor:
            raise ValueError(f"overlapping edit at {edit.start} (cursor {cursor})")
        out += data[cursor:edit.start]
        out += edit.replacement
        cursor = edit.end
    out += data[cursor:]
    return bytes(out)


def line_of(data: bytes, index: int) -> int:
    return data.count(b"\n", 0, index) + 1


def _scan_delimited(data: bytes, pos: int) -> int:
    """End of an inline verbatim region whose delimiter sits at ``pos``.

    Returns the index just past the closing delimiter, or ``pos`` if the region
    is malformed (unclosed, or running past the end of its line).
    """
    if pos >= len(data):
        return pos
    delimiter = data[pos]
    if delimiter in (_LF, _CR) or _is_letter(delimiter) or delimiter == _STAR:
        return pos
    closing = _RBRACE if delimiter == _LBRACE else delimiter
    cursor = pos + 1
    while cursor < len(data):
        if data[cursor] in (_LF, _CR):
            return pos        # \verb cannot span a line
        if data[cursor] == closing:
            return cursor + 1
        cursor += 1
    return pos


def _raw_brace_group(data: bytes, pos: int) -> tuple[int, int] | None:
    r"""Brace group at ``pos`` matched without honouring escapes or comments.

    That is what makes it right for a verbatim argument: inside ``\url`` a
    backslash and a percent are ordinary bytes.
    """
    length = len(data)
    cursor = pos
    while cursor < length and data[cursor] in (0x20, 0x09):
        cursor += 1
    if cursor >= length or data[cursor] != _LBRACE:
        return None
    opening, depth = cursor, 0
    while cursor < length:
        if data[cursor] == _LBRACE:
            depth += 1
        elif data[cursor] == _RBRACE:
            depth -= 1
            if depth == 0:
                return opening, cursor + 1
        cursor += 1
    return None


def _environment_name(data: bytes, pos: int) -> tuple[bytes, int] | None:
    """Read ``{name}`` at ``pos``, allowing leading blanks. Returns (name, end)."""
    cursor = pos
    while cursor < len(data) and data[cursor] in (0x20, 0x09):
        cursor += 1
    if cursor >= len(data) or data[cursor] != _LBRACE:
        return None
    close = data.find(b"}", cursor)
    if close == -1:
        return None
    return data[cursor + 1:close], close + 1


def scan(data: bytes):
    """Yield the comment, opaque and control spans of ``data``, in order."""
    index = 0
    line = 1
    length = len(data)

    while index < length:
        byte = data[index]

        if byte == _BACKSLASH:
            following = index + 1
            if following < length and _is_letter(data[following]):
                cursor = following
                while cursor < length and _is_letter(data[cursor]):
                    cursor += 1
                if cursor < length and data[cursor] == _STAR:
                    cursor += 1
                name = data[following:cursor]

                if name in INLINE_VERBATIM:
                    body = cursor
                    # \lstinline may carry [options] before its delimiter.
                    if body < length and data[body] == _LBRACKET:
                        depth, probe = 1, body + 1
                        while probe < length and depth:
                            if data[probe] == _LBRACKET:
                                depth += 1
                            elif data[probe] == _RBRACKET:
                                depth -= 1
                            probe += 1
                        if depth == 0:
                            body = probe
                    end = _scan_delimited(data, body)
                    if end > body:
                        yield Span(Kind.OPAQUE, index, end, line, name)
                        line += data.count(b"\n", index, end)
                        index = end
                        continue

                if name in VERBATIM_ARG_MACROS:
                    group = _raw_brace_group(data, cursor)
                    if group is not None:
                        end = group[1]
                        yield Span(Kind.OPAQUE, index, end, line, name)
                        line += data.count(b"\n", index, end)
                        index = end
                        continue

                if name == b"begin":
                    read = _environment_name(data, cursor)
                    if read is not None and read[0] in OPAQUE_ENVIRONMENTS:
                        env, after = read
                        closer = b"\\end{" + env + b"}"
                        stop = data.find(closer, after)
                        end = len(data) if stop == -1 else stop + len(closer)
                        yield Span(Kind.OPAQUE, index, end, line, env)
                        line += data.count(b"\n", index, end)
                        index = end
                        continue

                yield Span(Kind.CONTROL, index, cursor, line, name)
                index = cursor
                continue

            # A backslash escapes exactly one byte, whatever it is.
            if following < length and data[following] == _LF:
                line += 1
            index = following + 1
            continue

        if byte == _PERCENT:
            cursor = index
            while cursor < length and data[cursor] not in (_LF, _CR):
                cursor += 1
            yield Span(Kind.COMMENT, index, cursor, line)
            index = cursor
            continue

        if byte == _LF:
            line += 1
        index += 1


def balanced_arg(data: bytes, pos: int) -> tuple[int, int] | None:
    """Locate the brace group at or after ``pos``.

    Returns ``(open_index, close_index)`` with ``close_index`` exclusive, or
    ``None`` if no well-formed group follows. Honours escapes, nesting, and
    comments, so ``\\author{a % }\\n b}`` is read as one argument.
    """
    length = len(data)
    cursor = pos
    while cursor < length and data[cursor] in (0x20, 0x09, _LF, _CR):
        cursor += 1
    if cursor >= length or data[cursor] != _LBRACE:
        return None

    opening = cursor
    depth = 0
    while cursor < length:
        byte = data[cursor]
        if byte == _BACKSLASH:
            cursor += 2
            continue
        if byte == _PERCENT:
            while cursor < length and data[cursor] not in (_LF, _CR):
                cursor += 1
            continue
        if byte == _LBRACE:
            depth += 1
        elif byte == _RBRACE:
            depth -= 1
            if depth == 0:
                return opening, cursor + 1
        cursor += 1
    return None
