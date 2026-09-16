"""JPEG metadata scrubbing by marker-segment surgery.

Entropy-coded image data is copied byte for byte and never decoded, which both
avoids a silent recompression and keeps the APP11 segments holding a C2PA
manifest store intact.
"""

from __future__ import annotations

from .base import Policy, Removal, ScrubResult
from .exif import EXIF_PREFIX, scrub_exif_block
from .xmp import scrub_xmp

SOI = 0xD8
EOI = 0xD9
SOS = 0xDA
APP1 = 0xE1
APP2 = 0xE2
APP11 = 0xEB
APP13 = 0xED
COM = 0xFE

XMP_PREFIX = b"http://ns.adobe.com/xap/1.0/\x00"
XMP_EXT_PREFIX = b"http://ns.adobe.com/xmp/extension/\x00"
PHOTOSHOP_PREFIX = b"Photoshop 3.0\x00"
ICC_PREFIX = b"ICC_PROFILE\x00"

#: Markers that stand alone, carrying no length field.
STANDALONE = {0x01, EOI, SOI} | set(range(0xD0, 0xD8))


class MalformedJPEG(ValueError):
    pass


class JpegScrubber:
    fmt = "jpeg"

    def sniff(self, data: bytes) -> bool:
        return data[:2] == b"\xff\xd8"

    def scrub(self, data: bytes, policy: Policy) -> ScrubResult:
        if not self.sniff(data):
            raise MalformedJPEG("missing SOI")

        out = bytearray(b"\xff\xd8")
        removals: list[Removal] = []
        preserved: list[str] = []
        pos = 2
        end = len(data)

        while pos < end:
            if data[pos] != 0xFF:
                raise MalformedJPEG(f"expected marker at {pos}")
            marker = data[pos + 1]
            if marker == 0xFF:            # fill byte
                pos += 1
                continue
            if marker in STANDALONE:
                out += data[pos:pos + 2]
                pos += 2
                continue

            if pos + 4 > end:
                raise MalformedJPEG(f"truncated segment header at {pos}")
            length = int.from_bytes(data[pos + 2:pos + 4], "big")
            seg_start = pos + 4
            seg_end = pos + 2 + length
            if seg_end > end:
                raise MalformedJPEG(f"segment {marker:#x} overruns file")
            payload = data[seg_start:seg_end]

            if marker == SOS:
                # Everything from SOS onward is entropy-coded data: copy verbatim.
                out += data[pos:]
                pos = end
                break

            replacement = self._handle(marker, payload, policy, removals, preserved)
            if replacement is not None:
                seg = bytes([0xFF, marker]) + (len(replacement) + 2).to_bytes(2, "big") + replacement
                out += seg
            pos = seg_end

        return ScrubResult(bytes(out), removals, preserved)

    def _handle(self, marker, payload, policy, removals, preserved) -> bytes | None:
        if marker == APP11:
            preserved.append("APP11 (C2PA manifest store)")
            return payload

        if marker == APP2 and payload.startswith(ICC_PREFIX):
            preserved.append("APP2 (ICC colour profile)")
            return payload

        if marker == APP1 and payload.startswith(EXIF_PREFIX):
            tiff = payload[len(EXIF_PREFIX):]
            new_tiff, hits = scrub_exif_block(tiff, policy)
            removals.extend(hits)
            if not new_tiff:
                return None
            return EXIF_PREFIX + new_tiff

        if marker == APP1 and payload.startswith(XMP_PREFIX):
            raw = payload[len(XMP_PREFIX):]
            new_raw, hits = scrub_xmp(raw, policy.strip_dates)
            removals.extend(hits)
            return XMP_PREFIX + new_raw

        if marker == APP1 and payload.startswith(XMP_EXT_PREFIX):
            removals.append(Removal("APP1", "extended XMP packet"))
            return None

        if marker == APP13 and payload.startswith(PHOTOSHOP_PREFIX):
            removals.append(Removal("APP13", "Photoshop/IPTC resource block"))
            return None

        if marker == COM:
            removals.append(Removal("COM", "comment segment"))
            return None

        return payload
