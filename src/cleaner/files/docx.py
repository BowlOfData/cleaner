"""OOXML (.docx) metadata scrubbing.

Every zip entry is copied verbatim except the specific parts rewritten below.
That is deliberate and load-bearing: c2pa-python 0.37.7 cannot parse OOXML at
all, so we do not know with certainty where a C2PA manifest entry would live --
but copying everything we are not explicitly editing preserves it regardless of
its name.

Tracked changes and comments carry author names, but removing them alters the
document's content rather than its metadata, so they are reported by default and
removed only under ``--strip-revisions``.
"""

from __future__ import annotations

import io
import re
import zipfile

from defusedxml import ElementTree as DefusedET
from xml.etree import ElementTree as ET

from .base import Policy, Removal, ScrubResult

CORE = "docProps/core.xml"
APP = "docProps/app.xml"
SETTINGS = "word/settings.xml"

NS = {
    "cp": "http://schemas.openxmlformats.org/package/2006/metadata/core-properties",
    "dc": "http://purl.org/dc/elements/1.1/",
    "dcterms": "http://purl.org/dc/terms/",
    "ep": "http://schemas.openxmlformats.org/officeDocument/2006/extended-properties",
    "w": "http://schemas.openxmlformats.org/wordprocessingml/2006/main",
}

CORE_IDENTITY = [f"{{{NS['dc']}}}creator", f"{{{NS['cp']}}}lastModifiedBy",
                 f"{{{NS['cp']}}}revision", f"{{{NS['cp']}}}category",
                 f"{{{NS['cp']}}}contentStatus"]
CORE_DATES = [f"{{{NS['dcterms']}}}created", f"{{{NS['dcterms']}}}modified"]
APP_IDENTITY = [f"{{{NS['ep']}}}Company", f"{{{NS['ep']}}}Manager",
                f"{{{NS['ep']}}}TotalTime", f"{{{NS['ep']}}}LastPrinted"]

_AUTHOR_ATTR = f"{{{NS['w']}}}author"
_RSID_RE = re.compile(r"\{.*\}rsid")


class DocxScrubber:
    fmt = "docx"

    def sniff(self, data: bytes) -> bool:
        return data[:2] == b"PK" and b"[Content_Types].xml" in data[:4096]

    def scrub(self, data: bytes, policy: Policy) -> ScrubResult:
        removals: list[Removal] = []
        preserved: list[str] = []
        buffer = io.BytesIO()

        for prefix, uri in NS.items():
            ET.register_namespace(prefix, uri)

        with zipfile.ZipFile(io.BytesIO(data)) as src:
            with zipfile.ZipFile(buffer, "w") as dst:
                for info in src.infolist():
                    payload = src.read(info.filename)
                    handler = {
                        CORE: self._core, APP: self._app, SETTINGS: self._settings,
                    }.get(info.filename)

                    if handler is not None:
                        payload = handler(payload, policy, removals)
                    elif info.filename.endswith(".xml"):
                        payload = self._revisions(info.filename, payload, policy, removals)
                    else:
                        preserved.append(info.filename)

                    # Preserve the original entry metadata and compression type.
                    new_info = zipfile.ZipInfo(info.filename, date_time=info.date_time)
                    new_info.compress_type = info.compress_type
                    new_info.external_attr = info.external_attr
                    new_info.internal_attr = info.internal_attr
                    new_info.create_system = info.create_system
                    dst.writestr(new_info, payload)

        return ScrubResult(buffer.getvalue(), removals, preserved)

    def _strip(self, payload: bytes, tags: list[str], where: str,
               removals: list[Removal]) -> bytes:
        try:
            root = DefusedET.fromstring(payload)
        except Exception:
            return payload
        changed = False
        for parent in root.iter():
            for child in list(parent):
                if child.tag in tags:
                    parent.remove(child)
                    removals.append(Removal(where, child.tag.split("}")[-1]))
                    changed = True
        if not changed:
            return payload
        return ET.tostring(root, encoding="UTF-8", xml_declaration=True)

    def _core(self, payload, policy, removals):
        tags = list(CORE_IDENTITY) + (CORE_DATES if policy.strip_dates else [])
        return self._strip(payload, tags, CORE, removals)

    def _app(self, payload, policy, removals):
        return self._strip(payload, APP_IDENTITY, APP, removals)

    def _settings(self, payload, policy, removals):
        try:
            root = DefusedET.fromstring(payload)
        except Exception:
            return payload
        changed = False
        for parent in root.iter():
            for child in list(parent):
                if _RSID_RE.match(child.tag):
                    parent.remove(child)
                    changed = True
        if changed:
            removals.append(Removal(SETTINGS, "w:rsid revision-session identifiers"))
            return ET.tostring(root, encoding="UTF-8", xml_declaration=True)
        return payload

    def _revisions(self, name, payload, policy, removals):
        """Tracked-change and comment authorship."""
        if b"w:author" not in payload and _AUTHOR_ATTR.encode() not in payload:
            return payload
        if not policy.strip_revisions:
            removals.append(Removal(name, "tracked-change authors",
                                    "reported only; use --strip-revisions to anonymise",
                                    applied=False))
            return payload
        try:
            root = DefusedET.fromstring(payload)
        except Exception:
            return payload
        count = 0
        for element in root.iter():
            if _AUTHOR_ATTR in element.attrib:
                element.set(_AUTHOR_ATTR, "Author")
                count += 1
        if count:
            removals.append(Removal(name, f"{count} tracked-change author name(s)",
                                    "anonymised"))
            return ET.tostring(root, encoding="UTF-8", xml_declaration=True)
        return payload
