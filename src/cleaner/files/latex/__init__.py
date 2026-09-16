r"""TeX-family source scrubbing.

Unlike every other format here, TeX sources have no magic bytes -- a ``.tex``
file is just text. Detection is therefore a content heuristic plus the suffix,
and it must stay conservative in both directions: claiming a plain ``.txt`` that
happens to mention ``\usepackage`` would rewrite a file the user never meant to
hand us, and the family sniff runs *after* the four binary sniffs so a JPEG
saved as ``.tex`` is still treated as a JPEG.

The suffix matters beyond convenience. ``.tex`` and ``.dtx`` are not reliably
separable by content, and they disagree about what a ``%`` at the start of a
line means -- documentation in one, a comment in the other. Guessing wrong on a
``.dtx`` deletes the document.
"""

from __future__ import annotations

import re
from pathlib import Path

from .bib import BibScrubber
from .dtx import DtxScrubber
from .sty import StyScrubber
from .tex import TexScrubber

TEX_SUFFIXES = frozenset({".tex", ".ltx"})
STY_SUFFIXES = frozenset({".sty", ".cls"})
BIB_SUFFIXES = frozenset({".bib"})
DTX_SUFFIXES = frozenset({".dtx", ".ins"})

#: Markers that only a TeX file realistically carries. Required before claiming
#: a file whose suffix does not already say TeX, so a prose .txt quoting
#: \usepackage in a code sample is left alone.
_STRONG_MARKERS = (
    rb"\documentclass", rb"\documentstyle", rb"\begin{document}",
    rb"\ProvidesPackage", rb"\ProvidesClass", rb"\NeedsTeXFormat",
)

#: Weaker corroboration, trusted only when the suffix already says TeX.
_WEAK_MARKERS = _STRONG_MARKERS + (
    rb"\usepackage", rb"\RequirePackage", rb"\newcommand", rb"\renewcommand",
    rb"\begin{",
)

_BIB_ENTRY = re.compile(rb"@[A-Za-z]+\s*[{(]")


def _is_binary(data: bytes) -> bool:
    """UTF-16 and true binary are out of scope: the scanner assumes an
    ASCII-compatible encoding, which is what makes it safe on bytes."""
    if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return True
    return b"\x00" in data[:8192]


def looks_like_latex(data: bytes, *, strong: bool = False) -> bool:
    if _is_binary(data):
        return False
    window = data[:65536]
    markers = _STRONG_MARKERS if strong else _WEAK_MARKERS
    return any(marker in window for marker in markers)


def looks_like_bib(data: bytes) -> bool:
    return not _is_binary(data) and _BIB_ENTRY.search(data[:65536]) is not None


def looks_like_docstrip(data: bytes) -> bool:
    """``%<*driver>`` guards are the giveaway, and they are executable."""
    return not _is_binary(data) and re.search(rb"(?m)^%<[*/+-]", data[:65536]) is not None


def sniff_family(data: bytes, path: Path | None = None):
    """Return a scrubber for this TeX-family source, or None.

    Suffix decides the dialect when it is known. A file named outright with an
    unrecognised suffix falls back to content, which is why the docstrip check
    comes first: mistaking a ``.dtx`` for a ``.tex`` is the one error here that
    destroys content instead of leaking it.
    """
    suffix = path.suffix.lower() if path is not None else ""
    if _is_binary(data):
        return None

    if suffix in TEX_SUFFIXES:
        return TexScrubber()
    if suffix in STY_SUFFIXES:
        return StyScrubber()
    if suffix in BIB_SUFFIXES:
        return BibScrubber()
    if suffix in DTX_SUFFIXES:
        return DtxScrubber()

    if suffix not in _KNOWN_SUFFIXES:
        if looks_like_docstrip(data):
            return DtxScrubber()
        if looks_like_bib(data) and not looks_like_latex(data, strong=True):
            return BibScrubber()
        if looks_like_latex(data, strong=True):
            return TexScrubber()
    return None


_KNOWN_SUFFIXES = TEX_SUFFIXES | STY_SUFFIXES | BIB_SUFFIXES | DTX_SUFFIXES

SUFFIXES = frozenset(_KNOWN_SUFFIXES)

__all__ = ["TexScrubber", "StyScrubber", "BibScrubber", "DtxScrubber",
           "sniff_family", "looks_like_latex", "looks_like_bib",
           "looks_like_docstrip", "SUFFIXES"]
