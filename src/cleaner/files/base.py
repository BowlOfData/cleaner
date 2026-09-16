"""Shared types for format scrubbers."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol


@dataclass
class Removal:
    """One finding, for the report.

    ``applied`` distinguishes something actually taken out from something merely
    reported -- tracked-change authors, absolute paths, content hidden from the
    rendered document. Both are findings, but only an applied one means the file
    was rewritten, and conflating them made a byte-identical copy get written and
    described as scrubbed.
    """

    where: str          # e.g. "chunk tEXt", "EXIF GPS IFD", "docProps/core.xml"
    what: str           # e.g. "Author", "GPSLatitude"
    detail: str = ""
    applied: bool = True

    def __str__(self) -> str:
        base = f"{self.where}: {self.what}"
        return f"{base} ({self.detail})" if self.detail else base


@dataclass
class ScrubResult:
    data: bytes
    removals: list[Removal] = field(default_factory=list)
    preserved: list[str] = field(default_factory=list)

    @property
    def changed(self) -> bool:
        """True only if something was actually rewritten.

        Report-only findings must not count: they leave ``data`` byte-identical
        to the input, and treating them as a change writes a pointless copy and
        labels it as scrubbed.
        """
        return any(removal.applied for removal in self.removals)


@dataclass(frozen=True)
class Policy:
    strip_dates: bool = False
    strip_revisions: bool = False


class Scrubber(Protocol):
    fmt: str

    def sniff(self, data: bytes) -> bool: ...

    def scrub(self, data: bytes, policy: Policy) -> ScrubResult: ...
