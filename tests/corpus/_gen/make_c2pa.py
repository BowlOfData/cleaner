"""Regenerate the C2PA fixtures. Run: uv run python tests/corpus/_gen/make_c2pa.py"""
import json, pathlib, shutil
import c2pa
from PIL import Image

GEN = pathlib.Path(__file__).parent
OUT = GEN.parent

def signer():
    info = c2pa.C2paSignerInfo(
        alg=b"es256",
        sign_cert=(GEN / "cert.pem").read_bytes(),
        private_key=(GEN / "key.pem").read_bytes(),
        ta_url=None,
    )
    return c2pa.Signer.from_info(info)

MANIFEST = {
    "claim_generator_info": [{"name": "cleaner-test-fixture", "version": "0.1.0"}],
    "title": "fixture",
    "assertions": [
        {"label": "c2pa.actions", "data": {"actions": [{"action": "c2pa.created"}]}}
    ],
}

def base_image(path, color):
    Image.new("RGB", (32, 32), color).save(path)

def main():
    src = GEN / "_base.jpg"
    base_image(src, (180, 40, 40))
    srcpng = GEN / "_base.png"
    base_image(srcpng, (40, 180, 40))

    b = c2pa.Builder(json.dumps(MANIFEST))
    sg = signer()
    b.sign_file(str(src), str(OUT / "signed.jpg"), sg)
    print("wrote signed.jpg")

    b = c2pa.Builder(json.dumps(MANIFEST))
    sg = signer()
    b.sign_file(str(srcpng), str(OUT / "signed.png"), sg)
    print("wrote signed.png")

    b = c2pa.Builder(json.dumps(MANIFEST))
    b.set_no_embed()
    shutil.copy(src, OUT / "sidecar.jpg")
    with open(src, "rb") as fin, open(GEN / "_sidecar_out.jpg", "wb") as fout:
        sg = signer()
        manifest_bytes = b.sign(sg, "image/jpeg", fin, fout)
    (OUT / "sidecar.c2pa").write_bytes(bytes(manifest_bytes))
    print("wrote sidecar.jpg + sidecar.c2pa")

    b = c2pa.Builder(json.dumps(MANIFEST))
    b.set_no_embed()
    b.set_remote_url("https://example.invalid/cleaner-fixture.c2pa")
    with open(src, "rb") as fin, open(OUT / "remote-ref.jpg", "wb") as fout:
        sg = signer()
        b.sign(sg, "image/jpeg", fin, fout)
    print("wrote remote-ref.jpg")

    # A signed asset that also carries private EXIF. The other signed fixtures
    # are blank squares with nothing to find, so they cannot show that a refused
    # file is still analysed. Depends on phone.jpg: run make_phone.py first.
    phone = OUT / "phone.jpg"
    if phone.is_file():
        b = c2pa.Builder(json.dumps(MANIFEST))
        b.sign_file(str(phone), str(OUT / "signed-phone.jpg"), signer())
        print("wrote signed-phone.jpg")
    else:
        print("skipped signed-phone.jpg: run make_phone.py first")

    # Self-declared generator name only. Nothing here is an Anthropic signature
    # -- it is signed by the same throwaway CA as every other fixture. It exists
    # so the attribution table has something to match, and to pin that
    # attribution reads the claim generator rather than the certificate.
    manifest = json.loads(json.dumps(MANIFEST))
    manifest["claim_generator_info"] = [{"name": "Claude", "version": "0.0.0-fixture"}]
    b = c2pa.Builder(json.dumps(manifest))
    b.sign_file(str(src), str(OUT / "generator-claude.jpg"), signer())
    print("wrote generator-claude.jpg")

if __name__ == "__main__":
    main()
