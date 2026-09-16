"""PDF and DOCX scrubbing."""
import io
import zipfile

import pikepdf
import pytest

from cleaner.files.base import Policy
from cleaner.files.docx import DocxScrubber
from cleaner.files.pdf import PdfScrubber


def entries_containing(blob: bytes, needle: bytes) -> list[str]:
    """Search decompressed entries. Scanning the raw zip bytes finds nothing,
    because the parts are deflated -- an easy way to write a test that passes
    while the data is still there."""
    with zipfile.ZipFile(io.BytesIO(blob)) as archive:
        return [n for n in archive.namelist() if needle in archive.read(n)]


def test_pdf_identity_removed_and_document_still_opens(corpus):
    data = (corpus / "doc.pdf").read_bytes()
    result = PdfScrubber().scrub(data, Policy())
    for secret in (b"Marco Parrillo", b"ACME Writer", b"ACME PDF Engine"):
        assert secret not in result.data
    with pikepdf.Pdf.open(io.BytesIO(result.data)) as pdf:
        assert len(pdf.pages) == 1
        assert "/Author" not in pdf.docinfo


def test_pdf_title_is_kept(corpus):
    """Only identifying metadata goes. A title is content, not a fingerprint."""
    data = (corpus / "doc.pdf").read_bytes()
    result = PdfScrubber().scrub(data, Policy())
    with pikepdf.Pdf.open(io.BytesIO(result.data)) as pdf:
        assert str(pdf.docinfo["/Title"]) == "Quarterly numbers"


def test_pdf_dates_follow_policy(corpus):
    data = (corpus / "doc.pdf").read_bytes()
    with pikepdf.Pdf.open(io.BytesIO(PdfScrubber().scrub(data, Policy()).data)) as pdf:
        assert "/CreationDate" in pdf.docinfo
    stripped = PdfScrubber().scrub(data, Policy(strip_dates=True)).data
    with pikepdf.Pdf.open(io.BytesIO(stripped)) as pdf:
        assert "/CreationDate" not in pdf.docinfo


def test_docx_metadata_removed_body_preserved(corpus):
    data = (corpus / "doc.docx").read_bytes()
    result = DocxScrubber().scrub(data, Policy())
    assert entries_containing(result.data, b"Marco Parrillo") == []
    assert entries_containing(result.data, b"Initech Holdings") == []
    assert entries_containing(result.data, b"00AB12CD") == []
    assert entries_containing(result.data, b"Revenue was flat.") == ["word/document.xml"]


def test_docx_tracked_change_authors_reported_not_removed_by_default(corpus):
    """Anonymising tracked changes edits the document's content, so it is opt-in
    and merely reported otherwise."""
    data = (corpus / "doc.docx").read_bytes()
    result = DocxScrubber().scrub(data, Policy())
    assert entries_containing(result.data, b"Dana Whitfield") == ["word/document.xml"]
    assert any("tracked-change authors" in str(r) for r in result.removals)

    stripped = DocxScrubber().scrub(data, Policy(strip_revisions=True))
    assert entries_containing(stripped.data, b"Dana Whitfield") == []


def test_docx_preserves_unknown_entries(corpus, tmp_path):
    """The mechanism that keeps a C2PA entry alive without knowing its path."""
    data = (corpus / "doc.docx").read_bytes()
    staged = tmp_path / "with_extra.docx"
    staged.write_bytes(data)
    with zipfile.ZipFile(staged, "a") as archive:
        archive.writestr("custom/vendor.bin", b"\xde\xad\xbe\xef")

    result = DocxScrubber().scrub(staged.read_bytes(), Policy())
    with zipfile.ZipFile(io.BytesIO(result.data)) as archive:
        assert archive.read("custom/vendor.bin") == b"\xde\xad\xbe\xef"


def test_docx_output_is_a_readable_archive(corpus):
    data = (corpus / "doc.docx").read_bytes()
    result = DocxScrubber().scrub(data, Policy())
    with zipfile.ZipFile(io.BytesIO(result.data)) as archive:
        assert archive.testzip() is None
        assert "[Content_Types].xml" in archive.namelist()


def test_report_only_findings_do_not_count_as_a_change(corpus):
    """A second pass finds nothing left to remove but still reports the
    tracked-change authors. ScrubResult.changed was bool(removals), so that
    report alone marked the file changed -- which for a byte-surgical format
    means writing a copy identical to its input and calling it scrubbed."""
    once = DocxScrubber().scrub((corpus / "doc.docx").read_bytes(), Policy())
    assert once.changed

    twice = DocxScrubber().scrub(once.data, Policy())
    assert [r for r in twice.removals if r.applied] == []
    assert any("tracked-change authors" in str(r) for r in twice.removals)
    assert not twice.changed
