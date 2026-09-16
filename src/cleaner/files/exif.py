"""Selective EXIF rewriting.

EXIF is a TIFF structure whose values live at absolute offsets, so removing tags
means rebuilding the block and recomputing every offset. The alternative --
dropping EXIF wholesale -- would take Orientation with it and leave photos
rendering rotated.

Deliberate removals beyond the obvious identifiers:

* The **entire GPS IFD**, not merely the coordinate tags.
* **MakerNote**, a vendor blob that carries serial numbers and often a second
  full-resolution preview. It uses offsets relative to the TIFF header, so it is
  delete-only: it can never be retained across a rebuild.
* **IFD1, the thumbnail.** Thumbnails are frequently stale copies of the image
  from before it was cropped or redacted, which makes them a genuine leak rather
  than a nicety.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from .base import Policy, Removal

EXIF_PREFIX = b"Exif\x00\x00"

TAG_ORIENTATION = 0x0112
TAG_EXIF_IFD = 0x8769
TAG_GPS_IFD = 0x8825
TAG_INTEROP_IFD = 0xA005

# Tag -> human name. Removed from whichever IFD they appear in.
IDENTITY_TAGS = {
    0x013B: "Artist",
    0x9C9D: "XPAuthor",
    0x9C9C: "XPComment",
    0x9C9E: "XPKeywords",
    0x927C: "MakerNote",
    0xA430: "CameraOwnerName",
    0xA431: "BodySerialNumber",
    0xA435: "LensSerialNumber",
    0xA433: "LensMake",
    0xC62F: "CameraSerialNumber",
    0x00FE: "NewSubfileType",
    0x010F: "Make",
    0x0110: "Model",
    0x0131: "Software",
    0x001C: "HostComputer",
    0x013C: "HostComputer",
}

DATE_TAGS = {
    0x0132: "DateTime",
    0x9003: "DateTimeOriginal",
    0x9004: "DateTimeDigitized",
    0x9010: "OffsetTime",
    0x9011: "OffsetTimeOriginal",
    0x9012: "OffsetTimeDigitized",
}

TYPE_SIZES = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 6: 1, 7: 1, 8: 2, 9: 4, 10: 8, 11: 4, 12: 8}


class MalformedExif(ValueError):
    pass


@dataclass
class Entry:
    tag: int
    type: int
    count: int
    value: bytes          # raw value bytes, already dereferenced

    @property
    def byte_len(self) -> int:
        return TYPE_SIZES.get(self.type, 1) * self.count


def _unpack(endian: str, fmt: str, data: bytes, offset: int):
    size = struct.calcsize(endian + fmt)
    if offset + size > len(data):
        raise MalformedExif(f"read past end at {offset}")
    return struct.unpack_from(endian + fmt, data, offset)


def _read_ifd(tiff: bytes, endian: str, offset: int) -> tuple[list[Entry], int]:
    (count,) = _unpack(endian, "H", tiff, offset)
    entries: list[Entry] = []
    pos = offset + 2
    for _ in range(count):
        tag, typ, cnt = _unpack(endian, "HHI", tiff, pos)
        raw = tiff[pos + 8:pos + 12]
        size = TYPE_SIZES.get(typ, 1) * cnt
        if size > 4:
            (voff,) = _unpack(endian, "I", tiff, pos + 8)
            if voff + size > len(tiff):
                raise MalformedExif(f"value for tag {tag:#x} out of range")
            value = tiff[voff:voff + size]
        else:
            value = raw[:size]
        entries.append(Entry(tag, typ, cnt, value))
        pos += 12
    (next_off,) = _unpack(endian, "I", tiff, pos)
    return entries, next_off


def _serialize(endian: str, ifd0: list[Entry], exif_ifd: list[Entry],
               interop_ifd: list[Entry] | None) -> bytes:
    """Rebuild a TIFF block. Offsets are assigned in a fixed layout:
    header, IFD0, ExifIFD, InteropIFD, then all overflow values."""
    header_len = 8

    def ifd_len(entries: list[Entry]) -> int:
        return 2 + 12 * len(entries) + 4

    ifd0_off = header_len
    exif_off = ifd0_off + ifd_len(ifd0) if exif_ifd else 0
    interop_off = (exif_off + ifd_len(exif_ifd)) if (exif_ifd and interop_ifd) else 0

    cursor = ifd0_off + ifd_len(ifd0)
    if exif_ifd:
        cursor += ifd_len(exif_ifd)
    if interop_ifd:
        cursor += ifd_len(interop_ifd)
    value_area_start = cursor

    # Patch the sub-IFD pointers to their new homes before emitting.
    def set_pointer(entries: list[Entry], tag: int, target: int) -> None:
        for e in entries:
            if e.tag == tag:
                e.value = struct.pack(endian + "I", target)
                e.type, e.count = 4, 1

    if exif_ifd:
        set_pointer(ifd0, TAG_EXIF_IFD, exif_off)
    if interop_ifd:
        set_pointer(exif_ifd, TAG_INTEROP_IFD, interop_off)

    values = bytearray()

    def emit_ifd(entries: list[Entry], next_ifd: int) -> bytes:
        nonlocal values
        buf = bytearray(struct.pack(endian + "H", len(entries)))
        for e in sorted(entries, key=lambda x: x.tag):
            payload = e.value
            if len(payload) > 4:
                voff = value_area_start + len(values)
                values += payload
                if len(values) % 2:
                    values += b"\x00"
                tail = struct.pack(endian + "I", voff)
            else:
                tail = payload.ljust(4, b"\x00")
            buf += struct.pack(endian + "HHI", e.tag, e.type, e.count) + tail
        buf += struct.pack(endian + "I", next_ifd)
        return bytes(buf)

    body = emit_ifd(ifd0, 0)          # next IFD = 0: IFD1 (thumbnail) is dropped
    if exif_ifd:
        body += emit_ifd(exif_ifd, 0)
    if interop_ifd:
        body += emit_ifd(interop_ifd, 0)

    magic = struct.pack(endian + "HI", 42, ifd0_off)
    byte_order = b"II" if endian == "<" else b"MM"
    return byte_order + magic + body + bytes(values)


def scrub_exif_block(tiff: bytes, policy: Policy) -> tuple[bytes, list[Removal]]:
    """Scrub a bare TIFF block (no ``Exif\\0\\0`` prefix).

    Returns rewritten bytes and removals. On malformed input the block is
    dropped entirely and reported -- for a privacy tool, discarding metadata we
    cannot parse is the safe direction to fail.
    """
    removals: list[Removal] = []
    try:
        if len(tiff) < 8:
            raise MalformedExif("too short")
        order = tiff[:2]
        if order == b"II":
            endian = "<"
        elif order == b"MM":
            endian = ">"
        else:
            raise MalformedExif(f"bad byte order {order!r}")
        magic, ifd0_off = _unpack(endian, "HI", tiff, 2)
        if magic != 42:
            raise MalformedExif(f"bad magic {magic}")

        ifd0, next_off = _read_ifd(tiff, endian, ifd0_off)
        if next_off:
            removals.append(Removal("EXIF", "IFD1 thumbnail",
                                    "may predate cropping or redaction"))

        exif_entries: list[Entry] = []
        interop_entries: list[Entry] | None = None
        for e in ifd0:
            if e.tag == TAG_EXIF_IFD:
                (sub,) = struct.unpack(endian + "I", e.value.ljust(4, b"\x00")[:4])
                exif_entries, _ = _read_ifd(tiff, endian, sub)
            elif e.tag == TAG_GPS_IFD:
                removals.append(Removal("EXIF", "GPS IFD", "entire location record"))

        for e in list(exif_entries):
            if e.tag == TAG_INTEROP_IFD:
                (sub,) = struct.unpack(endian + "I", e.value.ljust(4, b"\x00")[:4])
                try:
                    interop_entries, _ = _read_ifd(tiff, endian, sub)
                except MalformedExif:
                    exif_entries.remove(e)
                    interop_entries = None

        drop = dict(IDENTITY_TAGS)
        if policy.strip_dates:
            drop.update(DATE_TAGS)

        def filter_ifd(entries: list[Entry], where: str) -> list[Entry]:
            kept = []
            for e in entries:
                if e.tag == TAG_GPS_IFD:
                    continue
                if e.tag in drop:
                    removals.append(Removal(where, drop[e.tag]))
                    continue
                kept.append(e)
            return kept

        ifd0 = filter_ifd(ifd0, "EXIF IFD0")
        exif_entries = filter_ifd(exif_entries, "EXIF SubIFD")

        if not removals:
            return tiff, []

        rebuilt = _serialize(endian, ifd0, exif_entries, interop_entries)
        return rebuilt, removals

    except (MalformedExif, struct.error) as exc:
        removals.append(Removal("EXIF", "entire block", f"unparseable: {exc}"))
        return b"", removals
