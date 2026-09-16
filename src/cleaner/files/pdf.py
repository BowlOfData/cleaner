"""PDF metadata scrubbing via pikepdf.

Embedded files are never removed wholesale: a C2PA manifest attaches to a PDF as
an associated file (``/AF``), so blanket-clearing attachments would strip
provenance along with the metadata.

Note that ``--reseal`` cannot cover PDF: c2pa-python 0.37.7's Reader supports
``application/pdf`` but its Builder does not, so a scrubbed PDF cannot be
re-signed. PDFs carrying credentials are therefore always refused.
"""

from __future__ import annotations

import io

import pikepdf

from .base import Policy, Removal, ScrubResult

DOCINFO_IDENTITY = ["/Author", "/Creator", "/Producer", "/Keywords", "/Subject", "/Company"]
DOCINFO_DATES = ["/CreationDate", "/ModDate"]

XMP_IDENTITY = [
    "dc:creator", "xmp:CreatorTool", "xmpMM:DocumentID",
    "xmpMM:InstanceID", "xmpMM:OriginalDocumentID", "pdf:Producer",
]
XMP_DATES = ["xmp:CreateDate", "xmp:ModifyDate", "xmp:MetadataDate"]


class PdfScrubber:
    fmt = "pdf"

    def sniff(self, data: bytes) -> bool:
        return data[:5] == b"%PDF-"

    def scrub(self, data: bytes, policy: Policy) -> ScrubResult:
        removals: list[Removal] = []
        preserved: list[str] = []

        with pikepdf.Pdf.open(io.BytesIO(data)) as pdf:
            if "/Names" in pdf.Root and "/EmbeddedFiles" in pdf.Root.Names:
                preserved.append("/EmbeddedFiles (may hold a C2PA manifest)")
            if "/AF" in pdf.Root:
                preserved.append("/AF associated files")

            fields = list(DOCINFO_IDENTITY)
            if policy.strip_dates:
                fields += DOCINFO_DATES
            for key in fields:
                if key in pdf.docinfo:
                    removals.append(Removal("PDF DocInfo", key.lstrip("/")))
                    del pdf.docinfo[key]

            try:
                # update_docinfo=False is essential: pikepdf otherwise regenerates DocInfo
                # from the XMP packet on exit, silently discarding DocInfo keys that
                # have no XMP counterpart -- including dates we were asked to keep.
                with pdf.open_metadata(set_pikepdf_as_editor=False,
                                       update_docinfo=False) as meta:
                    targets = list(XMP_IDENTITY)
                    if policy.strip_dates:
                        targets += XMP_DATES
                    for key in targets:
                        if key in meta:
                            removals.append(Removal("PDF XMP", key))
                            del meta[key]
            except Exception as exc:                       # malformed XMP
                removals.append(Removal("PDF XMP", "packet", f"unparseable: {exc}"))

            out = io.BytesIO()
            pdf.save(out, linearize=False)

        return ScrubResult(out.getvalue(), removals, preserved)
