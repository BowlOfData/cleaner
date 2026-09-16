"""File dispatch, disposition gating, and atomic writes."""

from __future__ import annotations

import os
import shutil
import tempfile
from dataclasses import replace
from pathlib import Path

from .files.base import Policy, Removal, Scrubber
from .files.docx import DocxScrubber
from .files.jpeg import JpegScrubber
from .files.pdf import PdfScrubber
from .files.latex import SUFFIXES as LATEX_SUFFIXES, sniff_family
from .files.png import PngScrubber
from .provenance.classify import (SIDECAR_SUFFIX, Disposition, Provenance, classify,
                                  offline_context)
from .report import FileOutcome, Report

SCRUBBERS: list[Scrubber] = [JpegScrubber(), PngScrubber(), PdfScrubber(), DocxScrubber()]

#: Detached manifests are included so a directory scan reports them. They are
#: never scrubbed -- classify() refuses a .c2pa outright -- but leaving them out
#: made the one file that is *entirely* credentials the only file the tool would
#: not mention, including when it is orphaned from the asset it describes.
SUFFIXES = ({".jpg", ".jpeg", ".png", ".pdf", ".docx", SIDECAR_SUFFIX}
            | set(LATEX_SUFFIXES))


def pick_scrubber(data: bytes, path: Path | None = None) -> Scrubber | None:
    """Content decides the format; the path only picks a TeX dialect.

    The binary sniffs run first and unconditionally, so a JPEG saved as .tex is
    still scrubbed as a JPEG. TeX sources have no magic bytes, so they are
    matched last and on a deliberately conservative heuristic.
    """
    for scrubber in SCRUBBERS:
        if scrubber.sniff(data):
            return scrubber
    return sniff_family(data, path)


def atomic_write(destination: Path, data: bytes, mode_from: Path | None = None) -> None:
    """Write via a temp file in the destination directory, then rename.

    The temp file must share a filesystem with the destination or os.replace is
    not atomic, which is why it is not placed in the system temp directory.
    """
    destination.parent.mkdir(parents=True, exist_ok=True)
    handle, temp_name = tempfile.mkstemp(dir=destination.parent,
                                         prefix=f".{destination.name}.", suffix=".tmp")
    temp_path = Path(temp_name)
    try:
        with os.fdopen(handle, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        if mode_from is not None and mode_from.exists():
            shutil.copymode(mode_from, temp_path)
        os.replace(temp_path, destination)
    except BaseException:
        temp_path.unlink(missing_ok=True)
        raise


def resolve_destination(source: Path, in_place: bool, output_dir: Path | None,
                        base: Path | None = None) -> Path:
    if in_place:
        # Follow symlinks so the target is rewritten rather than the link replaced.
        return source.resolve()
    if output_dir is not None:
        # Mirror the source tree rather than flattening it. Returning
        # output_dir / source.name meant two files sharing a basename in
        # different subdirectories resolved to one destination, and the second
        # silently overwrote the first -- near-certain for a LaTeX project, where
        # every chapter directory holds its own intro.tex and fig.png.
        if base is not None:
            try:
                return output_dir / source.relative_to(base)
            except ValueError:
                pass
        return output_dir / source.name
    return source.with_name(f"{source.stem}.cleaned{source.suffix}")


def analyse_only(path: Path, policy: Policy) -> list[Removal]:
    """What a refused file contains, reported without removing any of it.

    A refusal used to end the report at "carries Content Credentials", which
    tells the owner nothing about *what* is in the file. Their real question is
    whether the photo they cannot scrub is the one with their home in its GPS
    tag -- and answering it needs no write, only the analysis the scrubber
    already does.

    Every finding is forced to ``applied=False``. The scrubbed bytes are
    discarded here and the caller never reaches a write for a refused
    disposition, so the flag is belt-and-braces: it also keeps the finding from
    being rendered, or serialised, as something that was taken out.
    """
    try:
        data = path.read_bytes()
        scrubber = pick_scrubber(data, path)
        if scrubber is None:
            return []
        result = scrubber.scrub(data, policy)
    except Exception:
        # Analysis is a courtesy. A scrubber that cannot parse the file must not
        # turn a clean refusal into an error.
        return []
    return [replace(removal, applied=False) for removal in result.removals]


def process(path: Path, policy: Policy, *, dry_run: bool, in_place: bool = False,
            output_dir: Path | None = None, reseal: bool = False,
            context=None, base: Path | None = None,
            destination: Path | None = None) -> FileOutcome:
    """``destination``, if given, is written to as-is instead of a destination
    computed from ``in_place``/``output_dir`` -- the GUI's Save-As flow needs an
    exact, user-chosen name that ``resolve_destination`` has no way to produce.
    """
    ctx = context or offline_context()
    disposition, provenance = classify(path, reseal=reseal, signer_configured=False,
                                       context=ctx)

    if disposition is not Disposition.SCRUB_FREELY:
        return FileOutcome(path, disposition, provenance,
                           removals=analyse_only(path, policy))

    data = path.read_bytes()
    scrubber = pick_scrubber(data, path)
    if scrubber is None:
        return FileOutcome(path, disposition, provenance,
                           error=f"unsupported file type: {path.suffix or 'unknown'}")

    try:
        result = scrubber.scrub(data, policy)
    except Exception as exc:
        return FileOutcome(path, disposition, provenance,
                           error=f"{type(exc).__name__}: {exc}")

    outcome = FileOutcome(path, disposition, provenance,
                          removals=result.removals, preserved=result.preserved)
    if dry_run:
        return outcome
    if not result.changed and destination is None:
        # Bulk paths (-o/--in-place) skip an unchanged file rather than write a
        # pointless byte-identical copy. An explicit destination is a Save-As,
        # though: the caller named an exact file it expects to exist afterwards,
        # so it is still written even when there was nothing to remove.
        return outcome

    if destination is None:
        destination = resolve_destination(path, in_place, output_dir, base)
    atomic_write(destination, result.data, mode_from=path)
    outcome.written = destination
    return outcome


def iter_rooted_targets(paths: list[Path], recursive: bool):
    """Files are always taken as given. A directory is scanned for supported
    types -- its immediate children, or the whole tree under --recursive.

    Directories used to be skipped silently unless --recursive was passed, so
    pointing the tool at a folder reported "0 file(s)" and exited 0, which reads
    as "nothing to clean" rather than "I did not look".

    Each file is paired with the root it was found under, so ``-o`` can mirror
    the source tree instead of flattening it.
    """
    for path in paths:
        if path.is_dir():
            walk = path.rglob("*") if recursive else path.iterdir()
            for child in sorted(walk):
                if child.is_file() and child.suffix.lower() in SUFFIXES:
                    yield path, child
        elif path.is_file():
            yield path.parent, path


def iter_targets(paths: list[Path], recursive: bool):
    """The files ``iter_rooted_targets`` would visit, without their roots."""
    for _, target in iter_rooted_targets(paths, recursive):
        yield target


def run(paths: list[Path], policy: Policy, *, dry_run: bool, recursive: bool = False,
        in_place: bool = False, output_dir: Path | None = None,
        reseal: bool = False) -> Report:
    ctx = offline_context()
    report = Report()
    claimed: dict[Path, Path] = {}

    for base, target in iter_rooted_targets(paths, recursive):
        if not dry_run:
            # Refuse a collision rather than overwrite. Mirroring the tree under
            # -o removes the common cause, but duplicate arguments and symlinks
            # resolving to one file can still collide, and losing a file to a
            # silent clobber is the worst failure this tool has.
            destination = resolve_destination(target, in_place, output_dir, base)
            first = claimed.get(destination)
            if first is not None:
                report.outcomes.append(FileOutcome(
                    target, Disposition.SCRUB_FREELY, Provenance(),
                    error=f"destination {destination} is already claimed by {first}"))
                continue
            claimed[destination] = target

        report.outcomes.append(
            process(target, policy, dry_run=dry_run, in_place=in_place,
                    output_dir=output_dir, reseal=reseal, context=ctx, base=base)
        )
    return report
