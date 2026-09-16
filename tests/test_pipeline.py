"""Pipeline gating, atomic writes, and the CLI surface."""
import os
import shutil
import stat
from pathlib import Path

import pytest

from cleaner.cli import main
from cleaner.files.base import Policy
from cleaner.pipeline import atomic_write, process, resolve_destination, run


def test_refused_file_produces_no_output(corpus, tmp_path):
    """The central safety property: a refusal must not leave a scrubbed file
    behind, in any location."""
    staged = tmp_path / "signed.jpg"
    shutil.copy(corpus / "signed.jpg", staged)
    before = set(tmp_path.iterdir())

    outcome = process(staged, Policy(), dry_run=False)
    assert outcome.refused
    assert outcome.written is None
    assert set(tmp_path.iterdir()) == before


def test_sidecar_file_is_refused_without_being_consumed(corpus, tmp_path):
    """Scrubbing to foo.cleaned.jpg would orphan an adjacent foo.c2pa. Refusal
    prevents it; this pins the behaviour."""
    shutil.copy(corpus / "sidecar.jpg", tmp_path / "sidecar.jpg")
    shutil.copy(corpus / "sidecar.c2pa", tmp_path / "sidecar.c2pa")

    outcome = process(tmp_path / "sidecar.jpg", Policy(), dry_run=False)
    assert outcome.refused
    assert (tmp_path / "sidecar.c2pa").exists()
    assert not (tmp_path / "sidecar.cleaned.jpg").exists()


def test_dry_run_writes_nothing(corpus, tmp_path):
    staged = tmp_path / "phone.jpg"
    shutil.copy(corpus / "phone.jpg", staged)
    outcome = process(staged, Policy(), dry_run=True)
    assert outcome.removals and outcome.written is None
    assert list(tmp_path.iterdir()) == [staged]


def test_scrub_writes_beside_source_by_default(corpus, tmp_path):
    staged = tmp_path / "phone.jpg"
    shutil.copy(corpus / "phone.jpg", staged)
    outcome = process(staged, Policy(), dry_run=False)
    assert outcome.written == tmp_path / "phone.cleaned.jpg"
    assert staged.read_bytes() == (corpus / "phone.jpg").read_bytes()


def test_in_place_follows_symlinks(corpus, tmp_path):
    """os.replace on a symlink path would swap the link for a regular file,
    silently detaching it from its target."""
    real = tmp_path / "real.jpg"
    shutil.copy(corpus / "phone.jpg", real)
    link = tmp_path / "link.jpg"
    link.symlink_to(real)

    destination = resolve_destination(link, in_place=True, output_dir=None)
    assert destination == real.resolve()

    process(link, Policy(), dry_run=False, in_place=True)
    assert link.is_symlink()
    assert b"Marco Parrillo" not in real.read_bytes()


def test_atomic_write_preserves_mode(tmp_path):
    source = tmp_path / "src.bin"
    source.write_bytes(b"x")
    source.chmod(0o640)
    destination = tmp_path / "dst.bin"

    atomic_write(destination, b"payload", mode_from=source)
    assert destination.read_bytes() == b"payload"
    assert stat.S_IMODE(destination.stat().st_mode) == 0o640


def test_atomic_write_leaves_no_temp_on_failure(tmp_path, monkeypatch):
    destination = tmp_path / "out.bin"
    monkeypatch.setattr(os, "replace", lambda *a: (_ for _ in ()).throw(OSError("boom")))
    with pytest.raises(OSError):
        atomic_write(destination, b"data")
    assert list(tmp_path.iterdir()) == []


def test_cli_exit_codes(corpus, tmp_path, capsys):
    out = tmp_path / "out"
    assert main(["scrub", str(corpus / "phone.jpg"), "-o", str(out)]) == 0
    assert main(["scrub", str(corpus / "signed.jpg"), "-o", str(out)]) == 1
    assert main(["scrub", str(corpus / "signed.jpg"), "--reseal", "-o", str(out)]) == 2
    assert not (out / "signed.jpg").exists()


def test_cli_inspect_writes_nothing(corpus, tmp_path, capsys):
    staged = tmp_path / "phone.jpg"
    shutil.copy(corpus / "phone.jpg", staged)
    assert main(["inspect", str(staged)]) == 0
    assert list(tmp_path.iterdir()) == [staged]
    assert "would remove" in capsys.readouterr().out


def test_cli_text_rejects_bad_encoding(tmp_path, capsys):
    bad = tmp_path / "latin.txt"
    bad.write_bytes(b"caf\xe9")
    assert main(["text", str(bad)]) == 1
    assert "not valid utf-8" in capsys.readouterr().err

    # --in-place, so the non-UTF-8 output round-trips to disk instead of into
    # pytest's captured stdout, which decodes as UTF-8 and would break every
    # subsequent test in the session.
    assert main(["text", str(bad), "--encoding", "latin-1", "--in-place"]) == 0
    assert bad.read_bytes() == b"caf\xe9"


def test_directory_argument_is_scanned_without_recursive(corpus, tmp_path):
    """A directory used to be skipped unless --recursive was passed, so pointing
    the tool at a folder printed "0 file(s)" and exited 0 -- indistinguishable
    from "nothing to clean"."""
    import shutil

    from cleaner.pipeline import iter_targets

    shutil.copy(corpus / "phone.jpg", tmp_path / "phone.jpg")
    nested = tmp_path / "sub"
    nested.mkdir()
    shutil.copy(corpus / "doc.pdf", nested / "doc.pdf")

    shallow = list(iter_targets([tmp_path], recursive=False))
    assert shallow == [tmp_path / "phone.jpg"]

    deep = list(iter_targets([tmp_path], recursive=True))
    assert set(deep) == {tmp_path / "phone.jpg", nested / "doc.pdf"}


def test_unsupported_suffixes_are_skipped_when_scanning_a_directory(tmp_path):
    from cleaner.pipeline import iter_targets

    (tmp_path / "notes.txt").write_text("hello")
    (tmp_path / "photo.jpg").write_bytes(b"\xff\xd8\xff\xd9")
    assert list(iter_targets([tmp_path], recursive=False)) == [tmp_path / "photo.jpg"]


def test_explicit_file_is_processed_regardless_of_suffix(tmp_path, corpus):
    """Suffix filtering applies to directory scanning, not to files named
    outright -- otherwise a JPEG saved as .dat could never be scrubbed."""
    from cleaner.pipeline import iter_targets

    odd = tmp_path / "photo.dat"
    odd.write_bytes((corpus / "phone.jpg").read_bytes())
    assert list(iter_targets([odd], recursive=False)) == [odd]

    outcome = process(odd, Policy(), dry_run=True)
    assert any("GPS" in str(r) for r in outcome.removals)


def test_output_dir_mirrors_the_source_tree(corpus, tmp_path):
    """-o resolved to output_dir / source.name, so two files sharing a basename
    in different subdirectories landed on one destination and the second
    silently overwrote the first -- near-certain for a document project, where
    every chapter directory holds its own figure."""
    source = tmp_path / "src"
    for sub in ("sections", "appendix"):
        (source / sub).mkdir(parents=True)
        shutil.copy(corpus / "phone.jpg", source / sub / "figure.jpg")
    out = tmp_path / "out"

    report = run([source], Policy(), dry_run=False, recursive=True, output_dir=out)

    assert report.refused == []
    assert (out / "sections" / "figure.jpg").exists()
    assert (out / "appendix" / "figure.jpg").exists()
    for written in (out / "sections" / "figure.jpg", out / "appendix" / "figure.jpg"):
        assert b"Marco Parrillo" not in written.read_bytes()


def test_colliding_destinations_are_refused_not_overwritten(corpus, tmp_path):
    """Mirroring removes the common cause, but duplicate arguments still collide.
    Losing a file to a silent clobber is the worst failure this tool has."""
    staged = tmp_path / "phone.jpg"
    shutil.copy(corpus / "phone.jpg", staged)
    out = tmp_path / "out"

    report = run([staged, staged], Policy(), dry_run=False, output_dir=out)

    assert len(report.outcomes) == 2
    assert not report.outcomes[0].refused
    assert report.outcomes[1].refused
    assert "already claimed" in report.outcomes[1].reason()


def test_resolve_destination_falls_back_when_base_is_unrelated(tmp_path):
    """A base the source does not live under must not raise; flatten instead."""
    source = tmp_path / "a" / "photo.jpg"
    out = tmp_path / "out"
    assert resolve_destination(source, False, out, tmp_path / "a") == out / "photo.jpg"
    assert resolve_destination(source, False, out, Path("/nowhere")) == out / "photo.jpg"


def test_file_with_only_report_only_findings_is_not_written(corpus, tmp_path):
    """The pipeline consequence of the same thing: nothing was removed, so
    there is nothing to write."""
    staged = tmp_path / "clean.docx"
    from cleaner.files.docx import DocxScrubber

    scrubbed = DocxScrubber().scrub((corpus / "doc.docx").read_bytes(), Policy())
    staged.write_bytes(scrubbed.data)
    before = set(tmp_path.iterdir())

    outcome = process(staged, Policy(), dry_run=False)

    assert outcome.removals, "the tracked-change authors should still be reported"
    assert all(not r.applied for r in outcome.removals)
    assert outcome.written is None
    assert set(tmp_path.iterdir()) == before


def test_tex_with_a_sidecar_manifest_is_refused(corpus, tmp_path):
    """A .tex cannot embed a manifest, but it can have one beside it. The
    provenance gate must reach text formats exactly as it does binary ones."""
    shutil.copy(corpus / "paper.tex", tmp_path / "paper.tex")
    shutil.copy(corpus / "sidecar.c2pa", tmp_path / "paper.c2pa")
    before = set(tmp_path.iterdir())

    outcome = process(tmp_path / "paper.tex", Policy(), dry_run=False)

    assert outcome.refused
    assert outcome.written is None
    assert set(tmp_path.iterdir()) == before


def test_tex_without_provenance_is_scrubbed(corpus, tmp_path):
    staged = tmp_path / "paper.tex"
    shutil.copy(corpus / "paper.tex", staged)

    outcome = process(staged, Policy(), dry_run=False)

    assert not outcome.refused
    assert outcome.written == tmp_path / "paper.cleaned.tex"
    assert b"Marco Parrillo" not in outcome.written.read_bytes()


def test_refused_file_is_analysed_not_just_refused(corpus, tmp_path):
    """A refusal used to end at "carries Content Credentials", telling the owner
    nothing about what is in the file they cannot scrub. The scrubber's analysis
    runs anyway -- reported, never applied, and never written."""
    staged = tmp_path / "signed-phone.jpg"
    shutil.copy(corpus / "signed-phone.jpg", staged)
    before = staged.read_bytes()

    outcome = process(staged, Policy(), dry_run=False)

    assert outcome.refused
    assert outcome.written is None
    assert outcome.removals, "the GPS/serial findings should still be reported"
    assert all(not r.applied for r in outcome.removals)
    assert any("GPS" in str(r) for r in outcome.removals)
    assert staged.read_bytes() == before


def test_analysis_of_a_refused_file_never_writes(corpus, tmp_path):
    staged = tmp_path / "signed-phone.jpg"
    shutil.copy(corpus / "signed-phone.jpg", staged)
    only = set(tmp_path.iterdir())

    process(staged, Policy(), dry_run=False)

    assert set(tmp_path.iterdir()) == only


def test_analysis_failure_does_not_turn_refusal_into_error(corpus, tmp_path, monkeypatch):
    """Analysis is a courtesy. A scrubber that raises must leave a clean refusal
    a clean refusal, not an error."""
    import cleaner.pipeline as mod

    staged = tmp_path / "signed.jpg"
    shutil.copy(corpus / "signed.jpg", staged)

    def boom(*a, **k):
        raise RuntimeError("scrubber blew up")

    monkeypatch.setattr(mod, "pick_scrubber", boom)
    outcome = process(staged, Policy(), dry_run=False)

    assert outcome.refused
    assert outcome.error is None
    assert outcome.removals == []


def test_detached_manifest_argument_is_refused_and_analysed(corpus, tmp_path):
    shutil.copy(corpus / "sidecar.c2pa", tmp_path / "photo.c2pa")

    outcome = process(tmp_path / "photo.c2pa", Policy(), dry_run=False)

    assert outcome.refused
    assert outcome.written is None
    assert outcome.provenance.is_manifest


def test_directory_scan_surfaces_a_detached_manifest(corpus, tmp_path):
    """A lone .c2pa in a scanned folder was the one file the tool would not even
    mention. It is now listed (and refused), so an orphaned manifest is visible."""
    from cleaner.pipeline import iter_targets

    shutil.copy(corpus / "sidecar.c2pa", tmp_path / "orphan.c2pa")
    assert list(iter_targets([tmp_path], recursive=False)) == [tmp_path / "orphan.c2pa"]
