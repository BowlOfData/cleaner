"""Report rendering: what inspect/scrub actually shows for a refused file."""
import json

from cleaner.cli import main


def test_refused_report_names_findings_and_the_honest_remedy(corpus, capsys):
    """The report for a signed-but-private file must list what is in it, mark
    every item as a finding (not a removal), and say the only real fix is
    upstream -- there is no edit that drops the tag and keeps the credentials."""
    assert main(["inspect", str(corpus / "signed-phone.jpg")]) == 1
    out = capsys.readouterr().out
    assert "REFUSED" in out
    assert "found: EXIF: GPS IFD" in out
    # No finding is labelled as removed: the bytes are untouched. (The remedy
    # line legitimately contains the word, so this checks the finding lines.)
    assert not any("removed:" in line or "would remove" in line
                   for line in out.splitlines())
    assert "re-export from the original and sign the result" in out


def test_attribution_is_surfaced_as_a_mark_line(corpus, capsys):
    assert main(["inspect", str(corpus / "generator-claude.jpg")]) == 1
    assert "mark: Anthropic (Claude)" in capsys.readouterr().out


def test_json_report_exposes_signer_and_sidecars(corpus, capsys):
    assert main(["inspect", str(corpus / "sidecar.jpg"), "--json"]) == 1
    record = json.loads(capsys.readouterr().out)[0]
    assert record["refused"] is True
    assert record["signer"]["issuer"] == "cleaner-tests"
    assert any(s.endswith("sidecar.c2pa") for s in record["sidecars"])
    # A refused file's findings are reported, never listed as removed.
    assert record["removals"] == []


def test_detached_manifest_report_is_specific(corpus, capsys):
    assert main(["inspect", str(corpus / "sidecar.c2pa")]) == 1
    out = capsys.readouterr().out
    assert "detached C2PA manifest" in out
    assert "sidecar.jpg" in out
