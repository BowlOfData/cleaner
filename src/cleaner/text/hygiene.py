"""Deterministic Unicode hygiene for text.

Every transformation is a fixed operation on codepoints. There is no statistical,
semantic, or model-driven rewriting here, by design: the goal is text that
survives CSV parsers, string equality, URL slugs and diffs, not text that reads
differently.

The hard part is that several "invisible" characters are load-bearing:

* **U+200D ZWJ** joins emoji into single glyphs (families, professions), forces
  connected letterforms in Arabic and Persian, and builds conjuncts in
  Devanagari, Bengali and Tamil.
* **U+200C ZWNJ** does the inverse in the same scripts.
* **U+E0020-E007E tag characters** are not junk. After U+1F3F4 and closed by
  U+E007F they encode subdivision flags -- the England, Scotland and Wales flags
  are exactly this sequence.

A blanket regex over "invisible" codepoints corrupts all of the above, so those
three are decided by context rather than by class.
"""

from __future__ import annotations

import unicodedata
from bisect import bisect_right
from dataclasses import dataclass, field

from .tables import EXTENDED_PICTOGRAPHIC_RANGES, JOINING_SCRIPT_RANGES

ZWJ = "‍"
ZWNJ = "‌"
BOM = "﻿"
WAVING_BLACK_FLAG = "\U0001f3f4"
TAG_START, TAG_END = 0xE0020, 0xE007E
TAG_TERM = 0xE007F
CANCEL_TAG = "\U000e007f"

#: Tier 1 -- no legitimate role in prose.
INVISIBLES = {
    "​": "ZERO WIDTH SPACE",
    "⁠": "WORD JOINER",
    "­": "SOFT HYPHEN",
    "᠎": "MONGOLIAN VOWEL SEPARATOR",
    "؜": "ARABIC LETTER MARK",
    "‎": "LEFT-TO-RIGHT MARK",
    "‏": "RIGHT-TO-LEFT MARK",
}

#: Tier 2 -- the Trojan Source (CVE-2021-42574) character set.
BIDI_CONTROLS = {
    "‪": "LEFT-TO-RIGHT EMBEDDING",
    "‫": "RIGHT-TO-LEFT EMBEDDING",
    "‬": "POP DIRECTIONAL FORMATTING",
    "‭": "LEFT-TO-RIGHT OVERRIDE",
    "‮": "RIGHT-TO-LEFT OVERRIDE",
    "⁦": "LEFT-TO-RIGHT ISOLATE",
    "⁧": "RIGHT-TO-LEFT ISOLATE",
    "⁨": "FIRST STRONG ISOLATE",
    "⁩": "POP DIRECTIONAL ISOLATE",
}

#: Tier 4 -- legitimate typography, normalized only on request.
TYPOGRAPHY = {
    "“": '"', "”": '"', "„": '"', "‟": '"',
    "‘": "'", "’": "'", "‚": "'", "‛": "'",
    "—": "--", "–": "-", "―": "--",
    "…": "...",
    " ": " ", " ": " ", " ": " ", " ": " ", " ": " ",
    " ": " ", " ": " ", " ": " ", " ": " ", " ": " ",
}

_JOIN_STARTS = [lo for lo, _ in JOINING_SCRIPT_RANGES]
_PICTO_STARTS = [lo for lo, _ in EXTENDED_PICTOGRAPHIC_RANGES]


def _in_ranges(cp: int, ranges, starts) -> bool:
    idx = bisect_right(starts, cp) - 1
    return idx >= 0 and ranges[idx][0] <= cp <= ranges[idx][1]


def is_joining_script(ch: str) -> bool:
    return _in_ranges(ord(ch), JOINING_SCRIPT_RANGES, _JOIN_STARTS)


def is_pictographic(ch: str) -> bool:
    return _in_ranges(ord(ch), EXTENDED_PICTOGRAPHIC_RANGES, _PICTO_STARTS)


@dataclass(frozen=True)
class Finding:
    codepoint: int
    name: str
    line: int
    column: int
    action: str      # "removed" | "replaced" | "kept"
    reason: str = ""

    def __str__(self) -> str:
        base = f"U+{self.codepoint:04X} {self.name} — line {self.line}, col {self.column}: {self.action}"
        return f"{base} ({self.reason})" if self.reason else base


@dataclass(frozen=True)
class Options:
    keep_bidi: bool = False
    ascii_punct: bool = False
    normalize: str | None = None      # None | "nfc" | "nfd" | "nfkc" | "nfkd"
    strip_bom: bool = False


@dataclass
class TextResult:
    text: str
    findings: list[Finding] = field(default_factory=list)

    @property
    def changed(self) -> bool:
        return any(f.action != "kept" for f in self.findings)

    @property
    def removed(self) -> list[Finding]:
        return [f for f in self.findings if f.action != "kept"]


def _char_name(ch: str) -> str:
    try:
        return unicodedata.name(ch)
    except ValueError:
        return f"U+{ord(ch):04X}"


def _tag_sequence_end(text: str, index: int) -> int | None:
    """If a well-formed emoji tag sequence starts at ``index``, return the index
    just past its terminator. U+1F3F4 + one or more tag characters + U+E007F."""
    if text[index] != WAVING_BLACK_FLAG:
        return None
    pos = index + 1
    seen = 0
    while pos < len(text) and TAG_START <= ord(text[pos]) <= TAG_END:
        pos += 1
        seen += 1
    if seen and pos < len(text) and ord(text[pos]) == TAG_TERM:
        return pos + 1
    return None


def _neighbours(text: str, index: int) -> tuple[str | None, str | None]:
    prev = text[index - 1] if index > 0 else None
    nxt = text[index + 1] if index + 1 < len(text) else None
    return prev, nxt


def _joiner_is_meaningful(text: str, index: int) -> bool:
    prev, nxt = _neighbours(text, index)
    for neighbour in (prev, nxt):
        if neighbour is None:
            continue
        if is_pictographic(neighbour) or is_joining_script(neighbour):
            return True
    return False


def scrub_text(text: str, options: Options = Options()) -> TextResult:
    findings: list[Finding] = []
    out: list[str] = []
    line, column = 1, 1
    index = 0
    length = len(text)

    while index < length:
        ch = text[index]
        cp = ord(ch)

        if ch == "\n":
            out.append(ch)
            index += 1
            line += 1
            column = 1
            continue

        # Well-formed emoji tag sequences are copied whole, so their tag
        # characters are never examined individually.
        end = _tag_sequence_end(text, index)
        if end is not None:
            out.append(text[index:end])
            column += end - index
            index = end
            continue

        if TAG_START <= cp <= TAG_END or cp == TAG_TERM:
            findings.append(Finding(cp, f"TAG U+{cp:04X}", line, column, "removed",
                                    "outside an emoji tag sequence"))
            index += 1
            continue

        if ch in (ZWJ, ZWNJ):
            if _joiner_is_meaningful(text, index):
                findings.append(Finding(cp, _char_name(ch), line, column, "kept",
                                        "joins adjacent script or emoji"))
                out.append(ch)
            else:
                findings.append(Finding(cp, _char_name(ch), line, column, "removed",
                                        "isolated between non-joining characters"))
            index += 1
            column += 1
            continue

        if ch == BOM:
            at_start = index == 0
            if at_start and not options.strip_bom:
                out.append(ch)
            else:
                findings.append(
                    Finding(cp, "ZERO WIDTH NO-BREAK SPACE", line, column, "removed",
                            "byte order mark" if at_start else "mid-text")
                )
            index += 1
            column += 1
            continue

        if ch in INVISIBLES:
            findings.append(Finding(cp, INVISIBLES[ch], line, column, "removed"))
            index += 1
            column += 1
            continue

        if ch in BIDI_CONTROLS:
            if options.keep_bidi:
                out.append(ch)
                findings.append(Finding(cp, BIDI_CONTROLS[ch], line, column, "kept",
                                        "--keep-bidi"))
            else:
                findings.append(Finding(cp, BIDI_CONTROLS[ch], line, column, "removed",
                                        "bidi control"))
            index += 1
            column += 1
            continue

        if options.ascii_punct and ch in TYPOGRAPHY:
            out.append(TYPOGRAPHY[ch])
            findings.append(Finding(cp, _char_name(ch), line, column, "replaced",
                                    f"-> {TYPOGRAPHY[ch]!r}"))
            index += 1
            column += 1
            continue

        out.append(ch)
        index += 1
        column += 1

    result = "".join(out)
    if options.normalize:
        result = unicodedata.normalize(options.normalize.upper(), result)
    return TextResult(result, findings)
