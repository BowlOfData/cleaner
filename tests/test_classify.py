"""The classification spine. Two prior design bugs lived here, so it is tested hardest."""
import socket
import pytest

from cleaner.provenance.classify import Disposition, classify, detect, structural_scan

REFUSING = [
    ("signed.jpg", "embedded"),
    ("signed.png", "embedded"),
    ("sidecar.jpg", "sidecar"),
    ("remote-ref.jpg", "remote"),
]


@pytest.mark.parametrize("name,kind", REFUSING)
def test_provenance_bearing_files_are_refused(corpus, name, kind):
    """All three discovery paths must be caught, not just the embedded one.

    remote-ref.jpg is the important case: it has no embedded manifest, so any
    structural scan reports a clean file, and scrubbing its XMP would sever the
    only link to its credentials.
    """
    disposition, prov = classify(corpus / name)
    assert disposition is Disposition.REFUSE
    assert prov.present
    if kind == "embedded":
        assert prov.embedded
    elif kind == "sidecar":
        assert prov.sidecar is not None and prov.sidecar.name == "sidecar.c2pa"
    elif kind == "remote":
        assert prov.remote_url and prov.remote_url.startswith("https://")


def test_unsigned_file_is_scrubbable(unsigned_jpg):
    disposition, prov = classify(unsigned_jpg)
    assert disposition is Disposition.SCRUB_FREELY
    assert not prov.present


def test_sidecar_detected_independently_of_reader(corpus):
    """c2pa-python 0.37.7's Reader does not do sidecar discovery, despite the
    documented discovery order. If a future version starts doing so this test
    still passes; if we ever drop our own check, it fails."""
    prov = detect(corpus / "sidecar.jpg")
    assert prov.sidecar is not None
    assert not prov.embedded


def test_untrusted_signature_still_counts_as_provenance(corpus):
    """The fixtures are signed by a test CA that is in no trust list, so their
    validation state is Invalid. Presence, not validity, must gate scrubbing --
    otherwise every self-signed or expired asset becomes fair game."""
    import c2pa
    from cleaner.provenance.classify import offline_context

    with c2pa.Reader(str(corpus / "signed.jpg"), context=offline_context()) as r:
        assert str(r.get_validation_state()) != "Valid"
    assert classify(corpus / "signed.jpg")[0] is Disposition.REFUSE


def test_classification_never_touches_the_network(tmp_path, corpus):
    """A file names the URL its manifest lives at. Dereferencing it would announce
    every scanned file to a third party and let untrusted input steer an outbound
    request.

    This binds a real listener and points a fixture at it, because the fetch
    happens inside the Rust core -- monkeypatching Python's socket module does
    not observe it, and a test built that way passes even with the protection
    removed.
    """
    import json, threading
    import c2pa
    from cleaner.provenance.classify import offline_context

    hits: list[str] = []
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 0))
    server.listen(4)
    port = server.getsockname()[1]

    def accept_loop():
        while True:
            try:
                conn, _ = server.accept()
            except OSError:
                return
            hits.append("connected")
            conn.close()

    thread = threading.Thread(target=accept_loop, daemon=True)
    thread.start()

    gen = corpus / "_gen"
    url = f"http://127.0.0.1:{port}/manifest.c2pa"
    info = c2pa.C2paSignerInfo(
        alg=b"es256",
        sign_cert=(gen / "cert.pem").read_bytes(),
        private_key=(gen / "key.pem").read_bytes(),
        ta_url=None,
    )
    signer = c2pa.Signer.from_info(info)
    builder = c2pa.Builder(json.dumps({
        "claim_generator_info": [{"name": "cleaner-test", "version": "0.1.0"}],
        "assertions": [{"label": "c2pa.actions",
                        "data": {"actions": [{"action": "c2pa.created"}]}}],
    }))
    builder.set_no_embed()
    builder.set_remote_url(url)
    target = tmp_path / "localref.jpg"
    with open(gen / "_base.jpg", "rb") as fin, open(target, "wb") as fout:
        builder.sign(signer, "image/jpeg", fin, fout)

    try:
        # Control: without the offline context the SDK really does dial out.
        try:
            c2pa.Reader(str(target))
        except Exception:
            pass
        assert hits, "control failed: SDK did not fetch, so this test proves nothing"
        hits.clear()

        # The real assertion.
        disposition, prov = classify(target, context=offline_context())
        assert disposition is Disposition.REFUSE
        assert prov.remote_url == url
        assert not hits, "classification dialed out to the URL named by the file"
    finally:
        server.close()


def test_unrecognized_c2pa_error_fails_closed(corpus, monkeypatch):
    """An SDK error we do not understand must never downgrade to SCRUB_FREELY."""
    import c2pa
    import cleaner.provenance.classify as mod

    def boom(*args, **kwargs):
        raise c2pa.C2paError("Something entirely new went wrong")

    monkeypatch.setattr(mod.c2pa, "Reader", boom)
    disposition, prov = classify(corpus / "signed.jpg")
    assert disposition is Disposition.REFUSE_UNRECOGNIZED
    assert prov.present


# -- structural_scan -----------------------------------------------------
#
# The fallback for containers the SDK cannot parse at all. It had no direct
# tests, which is why the false positive below survived: it only became
# reachable when text formats were added, and every .tex now goes through it.

def jumbf_box(payload: bytes = b"c2pa_manifest") -> bytes:
    """A minimal JUMBF superbox: 4-byte big-endian length, then 'jumb'."""
    body = b"jumb" + payload
    return (len(body) + 4).to_bytes(4, "big") + body


def test_structural_scan_finds_a_jumbf_box(tmp_path):
    path = tmp_path / "blob.bin"
    path.write_bytes(b"\x00" * 32 + jumbf_box() + b"\x00" * 32)
    assert structural_scan(path) is True


def test_structural_scan_finds_a_c2pa_named_zip_entry(tmp_path):
    import zipfile

    path = tmp_path / "doc.docx"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("[Content_Types].xml", "<Types/>")
        archive.writestr("manifest.c2pa", b"whatever")
    assert structural_scan(path) is True


def test_structural_scan_finds_a_jumbf_box_inside_a_zip_entry(tmp_path):
    import zipfile

    path = tmp_path / "doc.docx"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("[Content_Types].xml", "<Types/>")
        archive.writestr("custom/vendor.bin", b"\x00" * 8 + jumbf_box())
    assert structural_scan(path) is True


def test_structural_scan_ignores_prose_about_c2pa(tmp_path):
    """A paper *about* Content Credentials is not a file carrying them.

    Matching the bare label meant any text mentioning a JUMBF superbox near the
    string c2pa was refused -- which is this repository's own subject matter, and
    became reachable for every .tex when text formats were added. A real box
    carries a length before its type; prose does not.
    """
    path = tmp_path / "about_c2pa.tex"
    path.write_bytes(rb"""\documentclass{article}
\begin{document}
The JUMBF superbox (\texttt{jumb}) carries a \texttt{c2pa} label.
\end{document}
""")
    assert structural_scan(path) is False


def test_structural_scan_fails_closed_on_an_unreadable_file(tmp_path):
    missing = tmp_path / "gone.bin"
    assert structural_scan(missing) is True


def test_signed_fixtures_are_still_detected_structurally(corpus):
    """The tightening must not weaken detection on a file that really carries a
    manifest, even though the SDK reaches these by a different route."""
    for name in ("signed.jpg", "signed.png"):
        assert structural_scan(corpus / name) is True, name


# -- signer reporting ----------------------------------------------------
#
# Reporting only. Nothing below may change a disposition: a file with
# credentials is protected regardless of who issued them.

def test_embedded_manifest_reports_its_signer(corpus):
    prov = detect(corpus / "signed.jpg")
    assert prov.signer is not None
    assert prov.signer.issuer == "cleaner-tests"
    assert prov.signer.common_name == "cleaner test signer"
    assert prov.signer.claim_generator.startswith("cleaner-test-fixture")
    assert prov.signer.validation_state == "Invalid"
    assert prov.signer.describe() in prov.describe()


def test_sidecar_manifest_reports_its_signer(corpus):
    """The sidecar path returns before the Reader is ever opened on the asset,
    so the signer has to be read out of the detached manifest instead."""
    prov = detect(corpus / "sidecar.jpg")
    assert prov.embedded is False
    assert prov.signer is not None and prov.signer.issuer == "cleaner-tests"


def test_remote_manifest_names_no_signer(corpus):
    """Naming the signer of a remote manifest would mean fetching it, which is
    exactly what offline_context() exists to prevent. Silence here is correct."""
    prov = detect(corpus / "remote-ref.jpg")
    assert prov.remote_url
    assert prov.signer is None


def test_attribution_matches_the_claim_generator(corpus):
    """The fixture declares a generator name and is signed by the same throwaway
    CA as every other fixture -- attribution reads self-declared identity, which
    is all a manifest actually carries."""
    prov = detect(corpus / "generator-claude.jpg")
    assert prov.attribution == "Anthropic (Claude)"
    assert prov.signer.claim_generator.startswith("Claude")


def test_attribution_is_absent_for_an_unrelated_signer(corpus):
    assert detect(corpus / "signed.jpg").attribution is None


def test_a_person_named_claude_is_not_attributed_to_anthropic():
    """A certificate's common name is often a person, and Claude is an ordinary
    given name. Product names are matched against the claim generator only."""
    from cleaner.provenance.classify import SignerInfo

    person = SignerInfo(issuer="Some CA", common_name="Claude Dupont")
    assert person.attribution is None
    assert SignerInfo(claim_generator="Claude 1.0").attribution == "Anthropic (Claude)"
    assert SignerInfo(issuer="Anthropic PBC").attribution == "Anthropic"


def test_signer_reporting_never_gates_the_disposition(corpus, monkeypatch):
    """If the manifest JSON cannot be parsed the file is still refused. Losing
    the report must never cost the protection."""
    import cleaner.provenance.classify as mod

    monkeypatch.setattr(mod, "_signer_from_reader", lambda reader: None)
    disposition, prov = classify(corpus / "signed.jpg")
    assert disposition is Disposition.REFUSE
    assert prov.signer is None and prov.embedded


# -- sidecar handling ----------------------------------------------------

def test_both_sidecar_spellings_are_found(corpus, tmp_path):
    """The spec form replaces the extension; some tools append instead. Missing
    a sidecar means scrubbing an asset whose credentials sit beside it, so both
    are checked."""
    from cleaner.provenance.classify import find_sidecars
    import shutil

    asset = tmp_path / "photo.jpg"
    shutil.copy(corpus / "phone.jpg", asset)
    assert find_sidecars(asset) == ()

    appended = tmp_path / "photo.jpg.c2pa"
    shutil.copy(corpus / "sidecar.c2pa", appended)
    assert find_sidecars(asset) == (appended,)
    assert classify(asset)[0] is Disposition.REFUSE

    replaced = tmp_path / "photo.c2pa"
    shutil.copy(corpus / "sidecar.c2pa", replaced)
    assert set(find_sidecars(asset)) == {replaced, appended}


def test_a_manifest_is_not_its_own_sidecar(corpus):
    """with_suffix('.c2pa') on a .c2pa path returns the path itself, which would
    make every detached manifest report a sidecar of itself."""
    from cleaner.provenance.classify import find_sidecars

    assert find_sidecars(corpus / "sidecar.c2pa") == ()


def test_detached_manifest_is_recognised_not_called_unsupported(corpus):
    """A .c2pa handed to the tool used to fall through to "unsupported file
    type" -- the least informative thing it can say about the one file whose
    entire content is credentials."""
    disposition, prov = classify(corpus / "sidecar.c2pa")
    assert disposition is Disposition.REFUSE_IS_MANIFEST
    assert prov.is_manifest and prov.present
    assert [p.name for p in prov.manifest_assets] == ["sidecar.jpg"]
    assert prov.signer is not None and prov.signer.issuer == "cleaner-tests"


def test_orphaned_manifest_is_reported_as_orphaned(corpus, tmp_path):
    """A manifest whose asset was moved, renamed, or scrubbed by something that
    did not know it was there. It is still credentials, and still refused."""
    import shutil

    lone = tmp_path / "photo.c2pa"
    shutil.copy(corpus / "sidecar.c2pa", lone)

    disposition, prov = classify(lone)
    assert disposition is Disposition.REFUSE_IS_MANIFEST
    assert prov.manifest_assets == ()
    assert "orphaned" in prov.describe()


def test_appended_manifest_finds_its_asset(corpus, tmp_path):
    import shutil

    shutil.copy(corpus / "phone.jpg", tmp_path / "photo.jpg")
    shutil.copy(corpus / "sidecar.c2pa", tmp_path / "photo.jpg.c2pa")

    prov = detect(tmp_path / "photo.jpg.c2pa")
    assert [p.name for p in prov.manifest_assets] == ["photo.jpg"]


def test_unparseable_sidecar_is_still_refused(corpus, tmp_path):
    """Failing to read a sidecar must fail closed. A file we cannot parse is not
    a file we may scrub."""
    import shutil

    asset = tmp_path / "photo.jpg"
    shutil.copy(corpus / "phone.jpg", asset)
    (tmp_path / "photo.c2pa").write_bytes(b"not a manifest at all")

    disposition, prov = classify(asset)
    assert disposition is Disposition.REFUSE
    assert prov.sidecar is not None
    assert prov.signer is None
