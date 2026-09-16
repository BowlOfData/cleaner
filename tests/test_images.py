"""Image scrubbers: byte-surgical, provenance-preserving, pixel-exact."""
import io

import pytest
from PIL import Image

from cleaner.files.base import Policy
from cleaner.files.jpeg import JpegScrubber
from cleaner.files.png import C2PA_CHUNK, PngScrubber, iter_chunks

SECRETS = [b"Marco Parrillo", b"SN-ABC-123456", b"LENS-99887", b"ACMEPRIVATE", b"ACME Camera"]


def test_gps_and_identifiers_are_gone_from_raw_bytes(corpus):
    """Asserted against raw bytes, not the parser's view: a tag can survive as
    orphaned value data even when the IFD no longer points at it."""
    data = (corpus / "phone.jpg").read_bytes()
    result = JpegScrubber().scrub(data, Policy())
    for secret in SECRETS:
        assert secret not in result.data, f"{secret!r} survived scrubbing"
    assert any("GPS IFD" in str(r) for r in result.removals)


def test_pixels_are_bit_identical(corpus):
    """Proves no decode/re-encode happened. A recompression would also silently
    drop the C2PA segments."""
    data = (corpus / "phone.jpg").read_bytes()
    result = JpegScrubber().scrub(data, Policy())
    before = Image.open(io.BytesIO(data))
    after = Image.open(io.BytesIO(result.data))
    assert before.size == after.size
    assert before.tobytes() == after.tobytes()


def test_orientation_is_preserved(corpus):
    """Dropping EXIF wholesale would take Orientation with it and render the
    photo rotated -- the most visible way a scrubber can damage an image."""
    import piexif

    data = (corpus / "phone.jpg").read_bytes()
    result = JpegScrubber().scrub(data, Policy())
    tags = piexif.load(result.data)["0th"]
    assert tags[piexif.ImageIFD.Orientation] == 6


def test_thumbnail_is_dropped(corpus):
    import piexif

    data = (corpus / "phone.jpg").read_bytes()
    result = JpegScrubber().scrub(data, Policy())
    assert not piexif.load(result.data)["thumbnail"]


def test_dates_survive_by_default_and_go_under_policy(corpus):
    import piexif

    data = (corpus / "phone.jpg").read_bytes()
    kept = piexif.load(JpegScrubber().scrub(data, Policy()).data)
    assert piexif.ExifIFD.DateTimeOriginal in kept["Exif"]

    stripped = piexif.load(JpegScrubber().scrub(data, Policy(strip_dates=True)).data)
    assert piexif.ExifIFD.DateTimeOriginal not in stripped["Exif"]


@pytest.mark.parametrize("name,scrubber", [("signed.jpg", JpegScrubber()), ("signed.png", PngScrubber())])
def test_scrubbing_preserves_the_manifest_store(corpus, tmp_path, name, scrubber):
    import c2pa
    from cleaner.provenance.classify import offline_context

    data = (corpus / name).read_bytes()
    result = scrubber.scrub(data, Policy())
    assert result.preserved, "scrubber did not report preserving the manifest"

    out = tmp_path / name
    out.write_bytes(result.data)
    with c2pa.Reader(str(out), context=offline_context()) as reader:
        assert reader.is_embedded()


def test_png_cabx_chunk_survives(corpus):
    data = (corpus / "signed.png").read_bytes()
    result = PngScrubber().scrub(data, Policy())
    assert C2PA_CHUNK in [c.type for c in iter_chunks(result.data)]


def test_naive_reencode_would_have_destroyed_it(corpus, tmp_path):
    """Control for the test above. The C2PA PNG chunk is flagged not-safe-to-copy,
    so a decode/re-encode round trip drops it. This is why the scrubbers are
    byte-surgical rather than Pillow-based."""
    data = (corpus / "signed.png").read_bytes()
    assert C2PA_CHUNK in [c.type for c in iter_chunks(data)]

    out = tmp_path / "reencoded.png"
    Image.open(io.BytesIO(data)).save(out)
    assert C2PA_CHUNK not in [c.type for c in iter_chunks(out.read_bytes())], (
        "Pillow preserved caBX; the byte-surgical justification needs revisiting"
    )
