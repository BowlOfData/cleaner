"""PNG metadata scrubbing by chunk surgery.

The image data is never decoded. Beyond avoiding a silent recompression, this is
what keeps the C2PA ``caBX`` chunk alive: it is flagged *not safe to copy*, so
any decode/re-encode round trip -- including Pillow's ``open().save()`` -- drops
it, along with the JPEG APP11 equivalent.
"""

from __future__ import annotations

import struct
import zlib
from dataclasses import dataclass

from .base import Policy, Removal, ScrubResult

SIGNATURE = b"\x89PNG\r\n\x1a\n"

#: Chunk carrying the C2PA manifest store. Never touched.
C2PA_CHUNK = b"caBX"

#: PNG stores XMP in an iTXt chunk under this keyword. XMP may carry the remote
#: manifest reference, so this chunk is rewritten selectively, never dropped.
XMP_KEYWORD = b"XML:com.adobe.xmp"

#: Text-chunk keywords removed wholesale: identity and tooling provenance.
TEXT_KEYWORD_DENYLIST = {
    b"Author", b"Comment", b"Source", b"Software", b"Disclaimer",
    b"Warning", b"Copyright Owner", b"Contact", b"Email", b"URL",
}

TEXT_CHUNKS = {b"tEXt", b"iTXt", b"zTXt"}

#: Rendering-critical or structural; preserved unconditionally.
PRESERVE = {
    b"IHDR", b"PLTE", b"IDAT", b"IEND", b"iCCP", b"sRGB",
    b"gAMA", b"cHRM", b"tRNS", b"sBIT", b"bKGD", b"pHYs", C2PA_CHUNK,
}


@dataclass
class Chunk:
    type: bytes
    data: bytes

    def to_bytes(self) -> bytes:
        crc = zlib.crc32(self.type + self.data) & 0xFFFFFFFF
        return struct.pack(">I", len(self.data)) + self.type + self.data + struct.pack(">I", crc)


class MalformedPNG(ValueError):
    pass


def iter_chunks(data: bytes):
    if not data.startswith(SIGNATURE):
        raise MalformedPNG("missing PNG signature")
    offset = len(SIGNATURE)
    end = len(data)
    while offset < end:
        if offset + 8 > end:
            raise MalformedPNG(f"truncated chunk header at {offset}")
        (length,) = struct.unpack(">I", data[offset:offset + 4])
        ctype = data[offset + 4:offset + 8]
        start = offset + 8
        stop = start + length
        if stop + 4 > end:
            raise MalformedPNG(f"truncated chunk {ctype!r} at {offset}")
        yield Chunk(ctype, data[start:stop])
        offset = stop + 4
        if ctype == b"IEND":
            break


def _keyword_of(chunk: Chunk) -> bytes:
    """Leading NUL-terminated keyword, shared by tEXt/zTXt/iTXt."""
    idx = chunk.data.find(b"\x00")
    return chunk.data[:idx] if idx != -1 else b""


class PngScrubber:
    fmt = "png"

    def sniff(self, data: bytes) -> bool:
        return data.startswith(SIGNATURE)

    def scrub(self, data: bytes, policy: Policy) -> ScrubResult:
        from .exif import scrub_exif_block
        from .xmp import scrub_xmp

        out = bytearray(SIGNATURE)
        removals: list[Removal] = []
        preserved: list[str] = []

        for chunk in iter_chunks(data):
            ctype = chunk.type

            if ctype == C2PA_CHUNK:
                preserved.append("caBX (C2PA manifest store)")
                out += chunk.to_bytes()
                continue

            if ctype in TEXT_CHUNKS:
                keyword = _keyword_of(chunk)
                if keyword == XMP_KEYWORD:
                    new_data, hits = _scrub_itxt_xmp(chunk.data, scrub_xmp)
                    removals.extend(hits)
                    out += Chunk(ctype, new_data).to_bytes()
                    continue
                if keyword in TEXT_KEYWORD_DENYLIST:
                    removals.append(Removal(f"chunk {ctype.decode()}", keyword.decode()))
                    continue
                out += chunk.to_bytes()
                continue

            if ctype == b"eXIf":
                new_data, hits = scrub_exif_block(chunk.data, policy)
                removals.extend(hits)
                if new_data:
                    out += Chunk(ctype, new_data).to_bytes()
                continue

            if ctype == b"tIME" and policy.strip_dates:
                removals.append(Removal("chunk tIME", "last-modified timestamp"))
                continue

            if ctype in PRESERVE:
                out += chunk.to_bytes()
                continue

            out += chunk.to_bytes()

        return ScrubResult(bytes(out), removals, preserved)


def _scrub_itxt_xmp(chunk_data: bytes, scrub_xmp) -> tuple[bytes, list[Removal]]:
    """Rewrite the XMP packet inside an iTXt chunk, preserving its framing.

    iTXt layout: keyword \0 compression_flag compression_method
                 language_tag \0 translated_keyword \0 text
    """
    kw_end = chunk_data.find(b"\x00")
    if kw_end == -1 or len(chunk_data) < kw_end + 3:
        return chunk_data, []
    comp_flag = chunk_data[kw_end + 1]
    comp_method = chunk_data[kw_end + 2]
    rest = chunk_data[kw_end + 3:]
    lang_end = rest.find(b"\x00")
    if lang_end == -1:
        return chunk_data, []
    trans_end = rest.find(b"\x00", lang_end + 1)
    if trans_end == -1:
        return chunk_data, []
    header = rest[:trans_end + 1]
    payload = rest[trans_end + 1:]

    if comp_flag:
        try:
            raw = zlib.decompress(payload)
        except zlib.error:
            return chunk_data, []
    else:
        raw = payload

    new_raw, removals = scrub_xmp(raw)
    if not removals:
        return chunk_data, []

    new_payload = zlib.compress(new_raw, 9) if comp_flag else new_raw
    prefix = chunk_data[:kw_end + 1] + bytes([comp_flag, comp_method])
    return prefix + header + new_payload, removals
