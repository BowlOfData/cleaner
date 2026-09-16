"""Selective XMP rewriting.

XMP is never dropped wholesale. It can carry ``dcterms:provenance``, the URL of a
remotely-stored C2PA manifest -- confirmed against c2pa-python 0.37.7, which
writes exactly that property for a remote-manifest asset. Deleting the packet
would sever an asset from its credentials while leaving no trace that it ever
had any.
"""

from __future__ import annotations

import re

from defusedxml import ElementTree as DefusedET
from xml.etree import ElementTree as ET

from .base import Removal

NS = {
    "x": "adobe:ns:meta/",
    "rdf": "http://www.w3.org/1999/02/22-rdf-syntax-ns#",
    "dc": "http://purl.org/dc/elements/1.1/",
    "dcterms": "http://purl.org/dc/terms/",
    "xmp": "http://ns.adobe.com/xap/1.0/",
    "xmpMM": "http://ns.adobe.com/xap/1.0/mm/",
    "photoshop": "http://ns.adobe.com/photoshop/1.0/",
    "exif": "http://ns.adobe.com/exif/1.0/",
    "tiff": "http://ns.adobe.com/tiff/1.0/",
    "Iptc4xmpCore": "http://iptc.org/std/Iptc4xmpCore/1.0/xmlns/",
}

#: Never removed: the link from an asset to its remote C2PA manifest.
PROVENANCE_PROPERTY = f"{{{NS['dcterms']}}}provenance"

#: Identity, authorship, tooling and tracking identifiers.
REMOVE = {
    f"{{{NS['dc']}}}creator": "dc:creator",
    f"{{{NS['xmp']}}}CreatorTool": "xmp:CreatorTool",
    f"{{{NS['xmpMM']}}}History": "xmpMM:History",
    f"{{{NS['xmpMM']}}}DocumentID": "xmpMM:DocumentID",
    f"{{{NS['xmpMM']}}}InstanceID": "xmpMM:InstanceID",
    f"{{{NS['xmpMM']}}}OriginalDocumentID": "xmpMM:OriginalDocumentID",
    f"{{{NS['photoshop']}}}AuthorsPosition": "photoshop:AuthorsPosition",
    f"{{{NS['tiff']}}}Make": "tiff:Make",
    f"{{{NS['tiff']}}}Model": "tiff:Model",
    f"{{{NS['Iptc4xmpCore']}}}CreatorContactInfo": "Iptc4xmpCore:CreatorContactInfo",
}

_DATE_PROPS = {
    f"{{{NS['xmp']}}}CreateDate": "xmp:CreateDate",
    f"{{{NS['xmp']}}}ModifyDate": "xmp:ModifyDate",
    f"{{{NS['xmp']}}}MetadataDate": "xmp:MetadataDate",
}

_GPS_RE = re.compile(r"^\{" + re.escape(NS["exif"]) + r"\}GPS")

_PACKET_RE = re.compile(rb"<\?xpacket begin=.*?\?>", re.DOTALL)
_PACKET_END_RE = re.compile(rb"<\?xpacket end=.*?\?>", re.DOTALL)


def _targets(strip_dates: bool) -> dict[str, str]:
    targets = dict(REMOVE)
    if strip_dates:
        targets.update(_DATE_PROPS)
    return targets


def scrub_xmp(raw: bytes, strip_dates: bool = False) -> tuple[bytes, list[Removal]]:
    """Return rewritten XMP and what was removed. On any parse failure the input
    is returned unchanged -- a packet we cannot understand is left alone rather
    than mangled."""
    head = _PACKET_RE.search(raw)
    tail = _PACKET_END_RE.search(raw)
    body_start = head.end() if head else 0
    body_end = tail.start() if tail else len(raw)
    body = raw[body_start:body_end]

    for prefix, uri in NS.items():
        ET.register_namespace(prefix, uri)

    try:
        root = DefusedET.fromstring(body)
    except Exception:
        return raw, []

    targets = _targets(strip_dates)
    removals: list[Removal] = []

    for element in root.iter():
        for attr in list(element.attrib):
            if attr == PROVENANCE_PROPERTY:
                continue
            if attr in targets:
                del element.attrib[attr]
                removals.append(Removal("XMP", targets[attr]))
            elif _GPS_RE.match(attr):
                del element.attrib[attr]
                removals.append(Removal("XMP", attr.split("}")[-1], "location"))

    for parent in root.iter():
        for child in list(parent):
            if child.tag == PROVENANCE_PROPERTY:
                continue
            if child.tag in targets:
                parent.remove(child)
                removals.append(Removal("XMP", targets[child.tag]))
            elif _GPS_RE.match(child.tag):
                parent.remove(child)
                removals.append(Removal("XMP", child.tag.split("}")[-1], "location"))

    if not removals:
        return raw, []

    rebuilt = ET.tostring(root, encoding="utf-8", xml_declaration=False)
    prefix = raw[:body_start]
    suffix = raw[body_end:]
    return prefix + rebuilt + suffix, removals
