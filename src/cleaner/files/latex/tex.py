r"""Metadata scrubbing for LaTeX document sources (.tex, .ltx).

Two rules shape everything here.

**Comment bodies are truncated, never deleted.** A comment becomes a bare ``%``.
That is not cosmetic: a trailing ``%`` suppresses the following newline, so

    \newcommand{\x}{y}%  reviewer 2 is wrong
       baz

loses a space before ``baz`` if the comment is removed outright. Truncating
keeps the newline-eating semantics, the line numbering that compiler errors
refer to, and every byte offset on every other line.

**Macros are emptied, never removed.** ``\author{Jane Doe}`` becomes
``\author{}``. Deleting the macro is worse than useless for ``\date``: a
document with no ``\date`` at all prints *today's* date, so removing it would
leak the scrub date in place of the original.

Values are never echoed into the report. The report names the macro that held
identifying data, not what it said -- printing it would move the secret from a
file the user is cleaning to a terminal they may paste elsewhere.
"""

from __future__ import annotations

import posixpath

from ..base import Policy, Removal, ScrubResult
from .scanner import Edit, Kind, apply_edits, balanced_arg, scan

#: Emptied by default. These name a person or an organisation.
IDENTITY_MACROS = frozenset({
    b"author", b"thanks", b"email", b"affiliation", b"institute", b"address",
    b"authorrunning", b"institution", b"orcid", b"correspondingauthor",
})

#: Emptied only under --strip-dates.
DATE_MACROS = frozenset({b"date"})

#: Read by the TeX engine, so their paths cannot be rewritten without breaking
#: the build. Reported when absolute; never altered.
PATH_MACROS = frozenset({
    b"includegraphics", b"input", b"include", b"bibliography", b"addbibresource",
    b"graphicspath", b"lstinputlisting", b"verbatiminput",
})

#: changes / todonotes markup. The author id lives in the optional argument.
REVISION_MACROS = frozenset({b"added", b"deleted", b"replaced", b"todo", b"annote"})
REVISION_KEYS = (b"id", b"author", b"caption")

#: The only \hypersetup and \pdfinfo keys removed. Everything else is copied
#: through untouched -- an unrecognised key could be the sole link to the
#: document's provenance, exactly as for an XMP packet.
IDENTITY_PDF_KEYS = frozenset({
    b"pdfauthor", b"pdfcreator", b"pdfproducer", b"pdfsubject", b"pdfkeywords",
})
PDFINFO_KEYS = frozenset({b"/Author", b"/Creator", b"/Producer", b"/Subject", b"/Keywords"})

MAX_REPORTED_LINES = 5


def _is_absolute(value: bytes) -> bool:
    text = value.strip()
    if text.startswith(b"/") or text.startswith(b"~"):
        return True
    return len(text) > 2 and text[1:3] in (b":\\", b":/")


def _basename(value: bytes) -> bytes:
    return posixpath.basename(value.strip().replace(b"\\", b"/")) or value.strip()


class TexScrubber:
    fmt = "latex"

    def __init__(self, dialect: str = "tex") -> None:
        self.dialect = dialect

    def sniff(self, data: bytes) -> bool:
        from . import looks_like_latex
        return looks_like_latex(data, strong=True)

    # -- dialect hooks ---------------------------------------------------
    def _prepare(self, data: bytes) -> None:
        """Called once per file, before scanning."""

    def _keeps_comment(self, data: bytes, span, body: bytes) -> tuple[bool, str]:
        """Whether this comment is content rather than commentary.

        Returns ``(keep, why)``; ``why`` is surfaced as a preserved entry so a
        reader can see what was deliberately left alone. Dialects differ sharply
        here: in ``.dtx`` a ``%`` in column 0 introduces the document itself.
        """
        return False, ""

    # -- main ------------------------------------------------------------
    def scrub(self, data: bytes, policy: Policy) -> ScrubResult:
        removals: list[Removal] = []
        preserved: list[str] = []
        edits: list[Edit] = []

        self._prepare(data)

        if self._catcode_hazard(data):
            removals.append(Removal(
                "LaTeX source", "\\catcode applied to a syntax character",
                "reported only; the scanner's assumptions no longer hold",
                applied=False))
            return ScrubResult(data, removals, preserved)

        comment_lines: list[int] = []
        included: list[str] = []
        covered_until = 0

        for span in scan(data):
            if span.start < covered_until:
                continue

            if span.kind is Kind.OPAQUE:
                preserved.append(f"verbatim {span.name.decode('ascii', 'replace')} "
                                 f"at line {span.line}")
                if span.name in (b"comment", b"filecontents", b"filecontents*"):
                    removals.append(Removal(
                        f"line {span.line}", f"{span.name.decode()} environment",
                        f"{span.end - span.start} bytes hidden from the rendered "
                        f"document", applied=False))
                continue

            if span.kind is Kind.COMMENT:
                covered_until = self._comment(data, span, edits, removals,
                                              comment_lines, preserved)
                continue

            covered_until = self._control(data, span, policy, edits, removals,
                                          included)

        if included:
            # A scrubbed main.tex that still \inputs an unscrubbed authors.tex is
            # not a clean result, and a single-file run must not look like one.
            shown = ", ".join(included[:MAX_REPORTED_LINES])
            more = "" if len(included) <= MAX_REPORTED_LINES else ", ..."
            removals.append(Removal(
                "LaTeX source", f"references {len(included)} other source file(s)",
                f"{shown}{more}; scrub the project directory to cover them",
                applied=False))

        if comment_lines:
            shown = ", ".join(str(n) for n in comment_lines[:MAX_REPORTED_LINES])
            more = "" if len(comment_lines) <= MAX_REPORTED_LINES else ", ..."
            removals.append(Removal(
                "LaTeX comments", f"{len(comment_lines)} comment body(s) truncated",
                f"lines {shown}{more}"))

        return ScrubResult(apply_edits(data, edits), removals, preserved)

    def _catcode_hazard(self, data: bytes) -> bool:
        r"""True if the file redefines the category code of a syntax character.

        ``\catcode`\%=12`` makes a percent an ordinary byte, at which point every
        assumption this scanner makes about comments is wrong. Refuse to rewrite
        rather than corrupt: the file is still reported on.
        """
        index = data.find(b"\\catcode")
        while index != -1:
            window = data[index:index + 32]
            for char in (b"\\%", b"`%", b"\\\\", b"`{", b"`}", b"\\{", b"\\}"):
                if char in window:
                    return True
            index = data.find(b"\\catcode", index + 1)
        return False

    def _comment(self, data, span, edits, removals, comment_lines, preserved) -> int:
        body = data[span.start + 1:span.end]
        keep, why = self._keeps_comment(data, span, body)
        if keep:
            if why:
                preserved.append(f"{why} at line {span.line}")
            return span.end
        stripped = body.lstrip(b" \t")

        if stripped[:4].lower() == b"!tex":
            self._magic_comment(data, span, body, edits, removals)
            return span.end

        if not body:                       # already truncated: stay idempotent
            return span.end

        edits.append(Edit(span.start + 1, span.end, b""))
        comment_lines.append(span.line)
        return span.end

    def _magic_comment(self, data, span, body, edits, removals) -> None:
        r"""``% !TeX root = /Users/x/main.tex`` -> ``% !TeX root = main.tex``.

        These are read by editors and never by the TeX engine, so rewriting the
        path cannot affect compilation -- and leaving a home directory in place
        while stripping every other comment for privacy made no sense.
        """
        equals = body.find(b"=")
        if equals == -1:
            return
        value = body[equals + 1:]
        if not _is_absolute(value):
            return
        leading = len(value) - len(value.lstrip(b" \t"))
        start = span.start + 1 + equals + 1 + leading
        edits.append(Edit(start, span.end, _basename(value)))
        removals.append(Removal(f"line {span.line}", "% !TeX directive path",
                                "reduced to its basename"))

    def _control(self, data, span, policy, edits, removals, included) -> int:
        name = span.name

        if name in IDENTITY_MACROS or (name in DATE_MACROS and policy.strip_dates):
            return self._empty_argument(data, span, edits, removals)

        if name == b"hypersetup":
            return self._keyvals(data, span, edits, removals)

        if name == b"pdfinfo":
            return self._pdfinfo(data, span, edits, removals)

        if name in PATH_MACROS:
            return self._report_path(data, span, removals, included)

        if name in REVISION_MACROS:
            return self._revision(data, span, policy, edits, removals)

        if name == b"endinput":
            trailing = len(data) - span.end
            if trailing > 1:
                removals.append(Removal(
                    f"line {span.line}", "content after \\endinput",
                    f"{trailing} bytes hidden from the rendered document",
                    applied=False))
            return span.end

        if name == b"iffalse":
            closing = data.find(b"\\fi", span.end)
            if closing != -1:
                removals.append(Removal(
                    f"line {span.line}", "\\iffalse block",
                    f"{closing - span.end} bytes hidden from the rendered document",
                    applied=False))
            return span.end

        return span.end

    def _empty_argument(self, data, span, edits, removals) -> int:
        group = balanced_arg(data, span.end)
        if group is None:
            return span.end
        opening, closing = group
        if closing - opening > 2:          # not already empty
            edits.append(Edit(opening + 1, closing - 1, b""))
            removals.append(Removal(f"\\{span.name.decode()}", "value",
                                    f"line {span.line}"))
        return closing

    def _keyvals(self, data, span, edits, removals) -> int:
        group = balanced_arg(data, span.end)
        if group is None:
            return span.end
        opening, closing = group
        for key, key_start, pair_end in _split_pairs(data, opening + 1, closing - 1):
            if key.lower() in IDENTITY_PDF_KEYS:
                edits.append(Edit(key_start, pair_end, b""))
                removals.append(Removal("\\hypersetup", key.decode(),
                                        f"line {span.line}"))
        return closing

    def _pdfinfo(self, data, span, edits, removals) -> int:
        group = balanced_arg(data, span.end)
        if group is None:
            return span.end
        opening, closing = group
        cursor = opening + 1
        while cursor < closing - 1:
            if data[cursor] != 0x2F:                      # '/'
                cursor += 1
                continue
            end = cursor + 1
            while end < closing and (chr(data[end]).isalnum()):
                end += 1
            key = data[cursor:end]
            paren = data.find(b"(", end)
            if paren == -1 or paren >= closing:
                break
            depth, probe = 1, paren + 1
            while probe < closing and depth:
                if data[probe] == 0x5C:
                    probe += 2
                    continue
                if data[probe] == 0x28:
                    depth += 1
                elif data[probe] == 0x29:
                    depth -= 1
                probe += 1
            if key in PDFINFO_KEYS:
                edits.append(Edit(cursor, probe, b""))
                removals.append(Removal("\\pdfinfo", key.decode(),
                                        f"line {span.line}"))
            cursor = probe
        return closing

    #: Macros that pull in another TeX source, as opposed to an asset.
    SOURCE_MACROS = frozenset({b"input", b"include"})

    def _report_path(self, data, span, removals, included) -> int:
        group = balanced_arg(data, span.end)
        if group is None:
            return span.end
        opening, closing = group
        value = data[opening + 1:closing - 1]
        if _is_absolute(value.lstrip(b"{")):
            removals.append(Removal(
                f"\\{span.name.decode()}", "absolute path",
                f"line {span.line}; reported only, rewriting it would break the "
                f"build", applied=False))
        if span.name in self.SOURCE_MACROS and value.strip():
            included.append(value.strip().decode("ascii", "replace"))
        return closing

    def _revision(self, data, span, policy, edits, removals) -> int:
        options = _optional_arg(data, span.end)
        if options is None:
            return span.end
        opening, closing = options
        if not policy.strip_revisions:
            removals.append(Removal(
                f"\\{span.name.decode()}", "revision author",
                f"line {span.line}; reported only, use --strip-revisions",
                applied=False))
            return closing
        changed = False
        for key, key_start, pair_end in _split_pairs(data, opening + 1, closing - 1):
            if key.lower() in REVISION_KEYS:
                equals = data.find(b"=", key_start, pair_end)
                if equals != -1:
                    value_end = pair_end
                    while value_end > equals and data[value_end - 1] in (0x2C, 0x20):
                        value_end -= 1
                    edits.append(Edit(equals + 1, value_end, b"Author"))
                    changed = True
        if changed:
            removals.append(Removal(f"\\{span.name.decode()}", "revision author",
                                    f"line {span.line}; anonymised"))
        return closing


def _optional_arg(data: bytes, pos: int) -> tuple[int, int] | None:
    """Locate a ``[...]`` group at ``pos``, returning (open, close-exclusive)."""
    length = len(data)
    cursor = pos
    while cursor < length and data[cursor] in (0x20, 0x09):
        cursor += 1
    if cursor >= length or data[cursor] != 0x5B:
        return None
    opening, depth = cursor, 0
    while cursor < length:
        if data[cursor] == 0x5C:
            cursor += 2
            continue
        if data[cursor] == 0x5B:
            depth += 1
        elif data[cursor] == 0x5D:
            depth -= 1
            if depth == 0:
                return opening, cursor + 1
        cursor += 1
    return None


def _split_pairs(data: bytes, start: int, end: int):
    """Yield ``(key, key_start, pair_end)`` for comma-separated key=value pairs.

    ``pair_end`` includes the trailing comma when there is one, so removing the
    span leaves the rest of the list well-formed.
    """
    cursor = start
    while cursor < end:
        while cursor < end and data[cursor] in (0x20, 0x09, 0x0A, 0x0D, 0x2C):
            cursor += 1
        if cursor >= end:
            return
        key_start = cursor
        depth = 0
        while cursor < end:
            byte = data[cursor]
            if byte == 0x5C:
                cursor += 2
                continue
            if byte in (0x7B, 0x5B):
                depth += 1
            elif byte in (0x7D, 0x5D):
                depth -= 1
            elif byte == 0x2C and depth == 0:
                break
            cursor += 1
        pair_end = cursor
        key_end = key_start
        while key_end < pair_end and data[key_end] not in (0x3D, 0x20, 0x09):
            key_end += 1
        if cursor < end and data[cursor] == 0x2C:
            pair_end = cursor + 1
        yield data[key_start:key_end], key_start, pair_end
        cursor = pair_end
