r"""Literate TeX sources (.dtx) and their installers (.ins).

The comment rule inverts here, which is the whole reason this is a separate
dialect. ``docstrip`` splits a ``.dtx`` by column: a line beginning with ``%``
is *documentation* -- the actual prose of the document -- and a line that does
not is code. Applying the ``.tex`` rule would truncate every documentation line
in the file and destroy it.

``%<*driver>`` and friends are guards, read by docstrip to decide which lines go
into which generated file. They are executable directives, not commentary.

Only a mid-line ``%`` on a code line is an ordinary comment, and only those are
truncated. If the file does not carry the docstrip shape at all, this degrades
to report-only rather than guessing which convention applies.
"""

from __future__ import annotations

from ..base import Policy, Removal, ScrubResult
from .tex import TexScrubber


class DtxScrubber(TexScrubber):
    fmt = "latex-docstrip"

    def __init__(self) -> None:
        super().__init__(dialect="dtx")
        self._is_docstrip = True

    def _prepare(self, data: bytes) -> None:
        from . import looks_like_docstrip
        self._is_docstrip = looks_like_docstrip(data)

    def scrub(self, data: bytes, policy: Policy) -> ScrubResult:
        self._prepare(data)
        if not self._is_docstrip:
            # Without the guards we cannot tell documentation from commentary,
            # and guessing wrong deletes the document rather than leaking it.
            return ScrubResult(data, [Removal(
                "docstrip source", "no %<...> guards found",
                "reported only; cannot distinguish documentation from comments",
                applied=False)], [])
        return super().scrub(data, policy)

    def _keeps_comment(self, data: bytes, span, body: bytes) -> tuple[bool, str]:
        at_line_start = span.start == 0 or data[span.start - 1] in (0x0A, 0x0D)
        if at_line_start:
            if body[:1] == b"<":
                return True, "docstrip guard"
            return True, "docstrip documentation"
        return False, ""
