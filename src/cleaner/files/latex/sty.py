r"""Package and class sources (.sty, .cls).

Identity macros are scrubbed as in a document, but comments are not all
commentary here. A package's leading comment block is its licence, and the LPPL
requires that notice to travel with the file. Stripping it to protect the
author's privacy would strip the author's rights along with it, so the header
block and any comment carrying a licence marker are preserved and reported.
"""

from __future__ import annotations

from .scanner import Kind, scan
from .tex import TexScrubber

#: Markers that make a comment part of the licence rather than an aside.
LICENCE_MARKERS = (
    b"copyright", b"(c)", b"lppl", b"latex project public license",
    b"license", b"licence", b"all rights reserved", b"gnu general public",
    b"mit license", b"permission is hereby granted", b"this work may be distributed",
)


class StyScrubber(TexScrubber):
    fmt = "latex-package"

    def __init__(self) -> None:
        super().__init__(dialect="sty")
        self._header_end = 0

    def _prepare(self, data: bytes) -> None:
        """Find the contiguous run of comment lines opening the file.

        Anything inside it is the header notice, whether or not the particular
        line names a licence -- a copyright block's continuation lines usually
        do not.
        """
        self._header_end = 0
        for span in scan(data):
            if span.kind is not Kind.COMMENT:
                break
            if data[:span.start].strip():
                break
            self._header_end = span.end

    def _keeps_comment(self, data: bytes, span, body: bytes) -> tuple[bool, str]:
        if span.end <= self._header_end:
            return True, "licence header"
        lowered = body.lower()
        if any(marker in lowered for marker in LICENCE_MARKERS):
            return True, "licence header"
        return False, ""
