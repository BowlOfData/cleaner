"""LaTeX source scrubbing.

The tests that matter here are the structural ones. "The secret is gone" is easy
to satisfy while destroying the document, so most of these assert what must
*not* have changed.
"""
import re
import shutil
import subprocess

import pytest

from cleaner.files.base import Policy
from cleaner.files.latex import looks_like_latex, sniff_family
from cleaner.files.latex.scanner import Kind, apply_edits, Edit, scan
from cleaner.files.latex.tex import TexScrubber


@pytest.fixture(scope="module")
def paper(corpus):
    return (corpus / "paper.tex").read_bytes()


def unescaped(data: bytes, char: bytes) -> int:
    """Count occurrences of ``char`` not preceded by a backslash."""
    return len(re.findall(rb"(?<!\\)" + re.escape(char), data))


# -- what must not change ------------------------------------------------

def test_line_count_is_preserved(paper):
    """Comments are truncated to a bare %, never deleted, so line numbering --
    which every compiler error message refers to -- survives."""
    result = TexScrubber().scrub(paper, Policy())
    assert result.data.count(b"\n") == paper.count(b"\n")


def test_every_comment_percent_survives(paper):
    """A trailing % suppresses the following newline. Removing the whole comment
    would introduce a space and change the typeset output."""
    result = TexScrubber().scrub(paper, Policy())
    assert unescaped(result.data, b"%") == unescaped(paper, b"%")
    assert b"\\newcommand{\\joined}{tight}%\n" in result.data


def test_braces_stay_balanced(paper):
    """Emptying \\author{Jane\\thanks{ACME}} removes matched pairs, so the raw
    counts fall -- but they must fall together. Balance is the invariant; an
    unchanged count is not, and asserting one would forbid the scrub."""
    result = TexScrubber().scrub(paper, Policy())
    assert unescaped(paper, b"{") == unescaped(paper, b"}")
    assert unescaped(result.data, b"{") == unescaped(result.data, b"}")
    assert unescaped(result.data, b"{") < unescaped(paper, b"{")


def test_verbatim_regions_are_byte_identical(paper):
    """Nothing inside a listing, \\verb, \\url or \\href is ever rewritten."""
    result = TexScrubber().scrub(paper, Policy())
    for region in (
        b"# 50% of the time it works every time",
        b'print("\\verb is inert here")',
        b"\\verb|100%|",
        b"\\lstinline{a % b}",
        b"\\url{https://example.invalid/a%20b/c}",
        b"\\href{https://x.invalid/%41}",
    ):
        assert region in result.data, region


def test_escaped_percent_is_not_a_comment(paper):
    result = TexScrubber().scrub(paper, Policy())
    assert b"Margin rose 100\\% year on year." in result.data


def test_only_the_reported_spans_differ(paper):
    """The invariant the whole design rests on: every byte outside an edit is
    copied verbatim, so the document cannot drift."""
    result = TexScrubber().scrub(paper, Policy())
    original = paper.split(b"\n")
    scrubbed = result.data.split(b"\n")
    differing = {i + 1 for i, (a, b) in enumerate(zip(original, scrubbed)) if a != b}
    assert differing == {1, 8, 10, 13, 14, 15, 29}


def test_scrubbing_is_idempotent(paper):
    once = TexScrubber().scrub(paper, Policy())
    twice = TexScrubber().scrub(once.data, Policy())
    assert not twice.changed
    assert twice.data == once.data


def test_latin1_source_survives(corpus):
    """Byte-level scanning means no encoding is ever guessed or round-tripped."""
    data = (corpus / "latin1.tex").read_bytes()
    result = TexScrubber().scrub(data, Policy())
    result.data.decode("latin-1")
    assert result.data == b"\\documentclass{article}\n%\n\\author{}\n"


def test_crlf_line_endings_are_preserved(corpus):
    data = (corpus / "crlf.tex").read_bytes()
    result = TexScrubber().scrub(data, Policy())
    assert result.data.count(b"\r\n") == data.count(b"\r\n")


# -- what must change ----------------------------------------------------

def test_identity_macros_are_emptied_not_deleted(paper):
    result = TexScrubber().scrub(paper, Policy())
    assert b"Marco Parrillo" not in result.data
    assert b"Initech Holdings" not in result.data      # nested \thanks
    assert b"marco@example.invalid" not in result.data
    assert b"\\author{}" in result.data
    assert b"\\email{}" in result.data


def test_date_is_kept_unless_asked_and_never_deleted(paper):
    """A document with no \\date prints today's date, so removing the macro
    would leak the scrub date instead of hiding the original."""
    kept = TexScrubber().scrub(paper, Policy())
    assert b"\\date{2024-03-11}" in kept.data

    stripped = TexScrubber().scrub(paper, Policy(strip_dates=True))
    assert b"2024-03-11" not in stripped.data
    assert b"\\date{}" in stripped.data


def test_hypersetup_removes_identity_keys_only(paper):
    """Unknown keys are copied through: one of them could be the only link to
    the document's provenance, exactly as for an XMP packet."""
    result = TexScrubber().scrub(paper, Policy())
    assert b"pdfauthor" not in result.data
    assert b"pdfcreator" not in result.data
    assert b"pdfsubject" not in result.data
    assert b"pdftitle={Quarterly numbers}" in result.data
    assert b"colorlinks=true" in result.data
    assert b"dcterms:provenance={https://example.invalid/manifest.c2pa}" in result.data


def test_magic_comment_path_is_reduced_to_a_basename(paper):
    """% !TeX directives are read by editors, never by the engine, so scrubbing
    the path cannot break the build -- and leaving a home directory in place
    while stripping every other comment would be incoherent."""
    result = TexScrubber().scrub(paper, Policy())
    assert b"% !TeX root = paper.tex" in result.data
    assert b"/Users/marco" not in result.data.split(b"\n")[0]
    assert b"% !TeX program = pdflatex" in result.data


# -- reported, not altered ----------------------------------------------

def test_absolute_include_paths_are_reported_not_rewritten(paper):
    """These are read by the engine; a basename would break the build."""
    result = TexScrubber().scrub(paper, Policy())
    assert b"\\includegraphics{/Users/marco/Desktop/figure.png}" in result.data
    finding = [r for r in result.removals if "includegraphics" in r.where]
    assert finding and not finding[0].applied


def test_hidden_content_is_reported(paper):
    """Invisible in the PDF, fully present in the file -- the leak class this
    feature exists for."""
    result = TexScrubber().scrub(paper, Policy())
    reported = " ".join(str(r) for r in result.removals if not r.applied)
    assert "comment environment" in reported
    assert "content after \\endinput" in reported
    assert b"Reviewer 2 is wrong" in result.data
    assert b"the Initech deal closes in April" in result.data


def test_revision_authors_follow_strip_revisions(paper):
    kept = TexScrubber().scrub(paper, Policy())
    assert b"\\added[id=MP]" in kept.data
    assert all(not r.applied for r in kept.removals if r.where == "\\added")

    stripped = TexScrubber().scrub(paper, Policy(strip_revisions=True))
    assert b"id=MP" not in stripped.data
    assert b"author=MP" not in stripped.data
    assert b"\\added[id=Author]" in stripped.data


def test_catcode_hazard_degrades_to_report_only(corpus):
    """Redefining the category code of % makes every assumption here wrong.
    Refuse to rewrite rather than corrupt."""
    data = (corpus / "catcode.tex").read_bytes()
    result = TexScrubber().scrub(data, Policy())
    assert result.data == data
    assert not result.changed
    assert any("catcode" in str(r) for r in result.removals)


# -- the control ---------------------------------------------------------

def test_naive_comment_regex_would_have_broken_it(paper):
    """The counterpart to test_naive_reencode_would_have_destroyed_it: proof the
    scanner does work a regex cannot. If this ever stops failing, the fixture
    has lost the constructs that justify the scanner."""
    naive = re.sub(rb"(?m)%.*$", b"%", paper)

    assert b"Margin rose 100\\% year on year." not in naive, "escaped percent"
    assert b"# 50% of the time it works every time" not in naive, "listing body"
    assert b"\\url{https://example.invalid/a%20b/c}" not in naive, "percent-encoded URL"
    assert b"\\verb|100%|" not in naive, "inline verbatim"

    good = TexScrubber().scrub(paper, Policy()).data
    assert b"Margin rose 100\\% year on year." in good
    assert b"# 50% of the time it works every time" in good
    assert b"\\url{https://example.invalid/a%20b/c}" in good
    assert b"\\verb|100%|" in good


# -- scanner units -------------------------------------------------------

def test_apply_edits_rejects_overlap():
    with pytest.raises(ValueError, match="overlapping"):
        apply_edits(b"abcdef", [Edit(0, 3, b""), Edit(2, 5, b"")])


def test_verb_does_not_span_a_line():
    """An unclosed \\verb must not swallow the rest of the file."""
    spans = list(scan(b"\\verb|unclosed\n% a real comment\n"))
    assert any(s.kind is Kind.COMMENT for s in spans)


@pytest.mark.parametrize("suffix,data,claimed", [
    (".tex", rb"\documentclass{article}", True),
    (".txt", rb"prose quoting \usepackage in a sample", False),
    (".txt", rb"\documentclass{article}", True),
    (".dat", rb"\documentclass{article}", True),
    (".tex", b"\xff\xd8\xff\x00", False),
])
def test_sniffing_is_conservative(tmp_path, suffix, data, claimed):
    path = tmp_path / f"f{suffix}"
    assert (sniff_family(data, path) is not None) is claimed


# -- opt-in: the real thing ----------------------------------------------

@pytest.mark.skipif(shutil.which("pdflatex") is None,
                    reason="no TeX distribution available")
def test_scrubbed_document_still_compiles(corpus, tmp_path):
    def compile_to_pdf(source: bytes, name: str) -> bytes:
        work = tmp_path / name
        work.mkdir()
        (work / "paper.tex").write_bytes(source)
        subprocess.run(["pdflatex", "-interaction=nonstopmode", "paper.tex"],
                       cwd=work, capture_output=True, check=True)
        return (work / "paper.pdf").read_bytes()

    original = (corpus / "paper.tex").read_bytes()
    scrubbed = TexScrubber().scrub(original, Policy()).data
    assert compile_to_pdf(original, "before")
    assert compile_to_pdf(scrubbed, "after")


def test_included_sources_are_reported(tmp_path):
    """A scrubbed main.tex that still \\inputs an unscrubbed authors.tex is not a
    clean result, and a single-file run must not look like one."""
    source = (rb"\documentclass{article}" b"\n"
              rb"\input{authors}" b"\n"
              rb"\include{sections/intro}" b"\n")
    result = TexScrubber().scrub(source, Policy())
    finding = [r for r in result.removals if "references" in r.what]
    assert finding and not finding[0].applied
    assert "authors" in finding[0].detail
    assert "sections/intro" in finding[0].detail


# -- dialects ------------------------------------------------------------

def test_sty_preserves_the_licence_header(corpus):
    """The LPPL requires the notice to travel with the file. Stripping it to
    protect the author's privacy would strip the author's rights with it, so it
    is preserved -- and reported, so the author's name still being there is not
    a surprise."""
    from cleaner.files.latex.sty import StyScrubber

    data = (corpus / "mypkg.sty").read_bytes()
    result = StyScrubber().scrub(data, Policy())

    assert b"Copyright 2024 Marco Parrillo" in result.data
    assert b"LaTeX Project Public License" in result.data
    assert any("licence header" in entry for entry in result.preserved)
    # ...but an ordinary comment further down is still commentary.
    assert b"Marco to rewrite before release" not in result.data
    assert b"\\author{}" in result.data


def test_dtx_never_touches_column_zero_comments(corpus):
    """In docstrip a leading % introduces the document itself. Applying the .tex
    rule here would truncate every documentation line in the file."""
    from cleaner.files.latex.dtx import DtxScrubber

    data = (corpus / "doc.dtx").read_bytes()
    result = DtxScrubber().scrub(data, Policy())

    assert b"% This prose is the document itself." in result.data
    assert b"100% literal percent lives here." in result.data
    assert b"%<*driver>" in result.data
    assert b"%</driver>" in result.data
    # Only the mid-line comment on a code line is commentary.
    assert b"a real code comment" not in result.data
    assert b"\\def\\tag{x}   %\n" in result.data


def test_dtx_without_guards_degrades_to_report_only():
    """Without the guards there is no way to tell documentation from commentary,
    and guessing wrong deletes the document rather than leaking it."""
    from cleaner.files.latex.dtx import DtxScrubber

    data = b"% just a comment\n\\author{Marco}\n"
    result = DtxScrubber().scrub(data, Policy())
    assert result.data == data
    assert not result.changed


def test_bib_drops_manager_plumbing_and_keeps_citations(corpus):
    """Author names and titles here are citations -- public record, and the point
    of the file. What leaks is the plumbing reference managers add."""
    from cleaner.files.latex.bib import BibScrubber

    data = (corpus / "refs.bib").read_bytes()
    result = BibScrubber().scrub(data, Policy())

    assert b"/Users/marco/Zotero" not in result.data
    assert b"bdsk-file-1" not in result.data
    assert b"owner" not in result.data
    assert b"Smith, Jane and Doe, John" in result.data
    assert b"A Study of 50% Efficiency" in result.data
    assert b"https://example.invalid/a%20b" in result.data
    assert b'{Quoted, with a comma "inside"}' in result.data


def test_bib_timestamp_follows_strip_dates(corpus):
    from cleaner.files.latex.bib import BibScrubber

    data = (corpus / "refs.bib").read_bytes()
    assert b"timestamp" in BibScrubber().scrub(data, Policy()).data
    assert b"timestamp" not in BibScrubber().scrub(data, Policy(strip_dates=True)).data


@pytest.mark.parametrize("name,expected", [
    ("a.tex", "TexScrubber"), ("a.ltx", "TexScrubber"),
    ("a.sty", "StyScrubber"), ("a.cls", "StyScrubber"),
    ("a.bib", "BibScrubber"),
    ("a.dtx", "DtxScrubber"), ("a.ins", "DtxScrubber"),
])
def test_suffix_picks_the_dialect(tmp_path, name, expected):
    """.tex and .dtx are not separable by content and disagree about what a
    leading % means, so the suffix decides."""
    path = tmp_path / name
    assert type(sniff_family(rb"\documentclass{article}", path)).__name__ == expected
