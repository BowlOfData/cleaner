"""Rendering for inspect/scrub results."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from .files.base import Removal
from .provenance.classify import Disposition, Provenance

REFUSALS = {
    Disposition.REFUSE,
    Disposition.REFUSE_UNRECOGNIZED,
    Disposition.REFUSE_NEEDS_CERT,
    Disposition.REFUSE_IS_MANIFEST,
}

#: DOCX reports every copied zip entry as preserved, which would drown the
#: report, so only entries matching one of these markers are surfaced.
NOTABLE_PRESERVED = ("C2PA", "/AF", "EmbeddedFiles", "verbatim", "licence header",
                     "docstrip guard", "hidden")

_EXPLAIN = {
    Disposition.REFUSE:
        "carries Content Credentials; scrubbing would invalidate them",
    Disposition.REFUSE_UNRECOGNIZED:
        "C2PA state could not be established; refusing rather than guessing",
    Disposition.REFUSE_NEEDS_CERT:
        "resealing requires a signing identity",
    Disposition.REFUSE_IS_MANIFEST:
        "this file is a detached C2PA manifest, not an asset with metadata in it",
}

#: Shown once, under a refused file that turned out to hold private data. The
#: honest remedy is upstream: C2PA's hard binding covers the asset bytes, so
#: there is no edit to this file that removes the tag and keeps the credentials.
NO_SAFE_EDIT = ("nothing above was removed -- to drop it, re-export from the "
                "original and sign the result, rather than editing this file")


@dataclass
class FileOutcome:
    path: Path
    disposition: Disposition
    provenance: Provenance
    removals: list[Removal] = field(default_factory=list)
    preserved: list[str] = field(default_factory=list)
    written: Path | None = None
    error: str | None = None

    @property
    def refused(self) -> bool:
        return self.disposition in REFUSALS or self.error is not None

    def reason(self) -> str:
        if self.error:
            return self.error
        return _EXPLAIN.get(self.disposition, "")


@dataclass
class Report:
    outcomes: list[FileOutcome] = field(default_factory=list)

    @property
    def refused(self) -> list[FileOutcome]:
        return [o for o in self.outcomes if o.refused]

    def to_text(self, verbose: bool = True) -> str:
        lines: list[str] = []
        for outcome in self.outcomes:
            if outcome.refused:
                lines.append(f"REFUSED  {outcome.path}")
                lines.append(f"         {outcome.reason()}")
                if outcome.provenance.attribution:
                    lines.append(f"         mark: {outcome.provenance.attribution}")
                if outcome.provenance.present:
                    lines.append(f"         found: {outcome.provenance.describe()}")
                # A refused file is still analysed, so the owner learns what is
                # in the file they cannot scrub. These are findings, never
                # removals: the bytes on disk are untouched.
                if outcome.removals:
                    if verbose:
                        for removal in outcome.removals:
                            lines.append(f"         found: {removal}")
                    else:
                        lines.append(f"         found {len(outcome.removals)} item(s) "
                                     f"that would be removed if it were scrubbable")
                    lines.append(f"         {NO_SAFE_EDIT}")
                continue

            verb = "would remove" if outcome.written is None else "removed"
            applied = [r for r in outcome.removals if r.applied]
            found = [r for r in outcome.removals if not r.applied]
            lines.append(f"OK       {outcome.path}"
                         + (f" -> {outcome.written}" if outcome.written else ""))
            if not outcome.removals:
                lines.append("         nothing to remove")
            elif verbose:
                # Reported findings are rendered as "found", never as removed:
                # nothing was taken out, and saying otherwise would misdescribe
                # a file that is byte-identical to its input.
                for removal in applied:
                    lines.append(f"         {verb}: {removal}")
                for removal in found:
                    lines.append(f"         found: {removal}")
            else:
                if applied:
                    lines.append(f"         {verb} {len(applied)} item(s)")
                if found:
                    lines.append(f"         found {len(found)} item(s)")
            for kept in outcome.preserved:
                if any(marker in kept for marker in NOTABLE_PRESERVED):
                    lines.append(f"         preserved: {kept}")

        total = len(self.outcomes)
        refused = len(self.refused)
        lines.append("")
        lines.append(f"{total} file(s), {refused} refused, {total - refused} processed")
        return "\n".join(lines)

    def to_json(self) -> str:
        return json.dumps(
            [
                {
                    "path": str(o.path),
                    "disposition": o.disposition.value,
                    "refused": o.refused,
                    "reason": o.reason(),
                    "provenance": o.provenance.describe(),
                    "attribution": o.provenance.attribution,
                    "signer": (
                        {
                            "issuer": o.provenance.signer.issuer,
                            "common_name": o.provenance.signer.common_name,
                            "alg": o.provenance.signer.alg,
                            "cert_serial": o.provenance.signer.cert_serial,
                            "claim_generator": o.provenance.signer.claim_generator,
                            "title": o.provenance.signer.title,
                            "validation_state": o.provenance.signer.validation_state,
                        }
                        if o.provenance.signer else None
                    ),
                    "sidecars": [str(s) for s in o.provenance.sidecars],
                    "removals": [str(r) for r in o.removals if r.applied],
                    "found": [str(r) for r in o.removals if not r.applied],
                    "preserved": o.preserved,
                    "written": str(o.written) if o.written else None,
                }
                for o in self.outcomes
            ],
            indent=2,
        )
