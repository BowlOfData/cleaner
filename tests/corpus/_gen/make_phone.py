"""Generate an unsigned, phone-camera-like JPEG: GPS, serials, MakerNote, thumbnail."""
import io, pathlib
import piexif
from PIL import Image

GEN = pathlib.Path(__file__).parent
OUT = GEN.parent

def main():
    img = Image.new("RGB", (64, 48), (90, 120, 200))
    thumb = img.copy(); thumb.thumbnail((32, 24))
    tb = io.BytesIO(); thumb.save(tb, "JPEG")

    zeroth = {
        piexif.ImageIFD.Make: b"ACME",
        piexif.ImageIFD.Model: b"Phone X200",
        piexif.ImageIFD.Software: b"ACME Camera 4.2",
        piexif.ImageIFD.Artist: b"Marco Parrillo",
        piexif.ImageIFD.Orientation: 6,
        piexif.ImageIFD.DateTime: b"2026:08:22 12:00:00",
        piexif.ImageIFD.XResolution: (72, 1),
        piexif.ImageIFD.YResolution: (72, 1),
    }
    exif = {
        piexif.ExifIFD.DateTimeOriginal: b"2026:08:22 12:00:00",
        piexif.ExifIFD.BodySerialNumber: b"SN-ABC-123456",
        piexif.ExifIFD.CameraOwnerName: b"Marco Parrillo",
        piexif.ExifIFD.LensSerialNumber: b"LENS-99887",
        piexif.ExifIFD.MakerNote: b"\x00ACMEPRIVATE\x00serial=SN-ABC-123456\x00",
        piexif.ExifIFD.ExifVersion: b"0231",
        piexif.ExifIFD.ColorSpace: 1,
    }
    gps = {
        piexif.GPSIFD.GPSLatitudeRef: b"N",
        piexif.GPSIFD.GPSLatitude: ((45, 1), (27, 1), (3600, 100)),
        piexif.GPSIFD.GPSLongitudeRef: b"E",
        piexif.GPSIFD.GPSLongitude: ((9, 1), (11, 1), (2400, 100)),
        piexif.GPSIFD.GPSAltitude: (250, 1),
    }
    data = piexif.dump({"0th": zeroth, "Exif": exif, "GPS": gps,
                        "1st": {}, "thumbnail": tb.getvalue()})
    img.save(OUT / "phone.jpg", exif=data, quality=92)
    print("wrote phone.jpg")

if __name__ == "__main__":
    main()
