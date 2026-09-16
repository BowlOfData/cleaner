"""Text hygiene. The identity cases matter most: a naive regex over "invisible"
codepoints passes the removal tests and silently corrupts these."""
import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from cleaner.text.hygiene import Options, scrub_text

FAMILY = "\U0001F468‍\U0001F469‍\U0001F467‍\U0001F466"
SCOTLAND = "\U0001F3F4\U000E0067\U000E0062\U000E0073\U000E0063\U000E0074\U000E007F"
ENGLAND = "\U0001F3F4\U000E0067\U000E0062\U000E0065\U000E006E\U000E0067\U000E007F"
PERSIAN = "می‌خواهم"
DEVANAGARI = "क्‍ष"
TAMIL = "க்‍"


@pytest.mark.parametrize("label,text", [
    ("family emoji ZWJ sequence", FAMILY),
    ("Scotland tag-sequence flag", SCOTLAND),
    ("England tag-sequence flag", ENGLAND),
    ("Persian ZWNJ", PERSIAN),
    ("Devanagari conjunct", DEVANAGARI),
    ("Tamil conjunct", TAMIL),
])
def test_meaningful_sequences_are_left_alone(label, text):
    assert scrub_text(text).text == text, f"{label} was corrupted"


@pytest.mark.parametrize("raw,expected", [
    ("he​llo", "hello"),                 # ZWSP
    ("soft­hyphen", "softhyphen"),       # soft hyphen
    ("mid﻿text", "midtext"),             # BOM mid-string
    ("word⁠joiner", "wordjoiner"),
    ("ab‍cd", "abcd"),                   # ZWJ between plain Latin
    ("hi\U000E0041there", "hithere"),         # tag char outside a sequence
])
def test_noise_is_removed(raw, expected):
    assert scrub_text(raw).text == expected


def test_bom_at_offset_zero_is_kept_by_default():
    assert scrub_text("﻿hello").text == "﻿hello"
    assert scrub_text("﻿hello", Options(strip_bom=True)).text == "hello"


def test_bidi_controls_removed_by_default():
    """Trojan Source: a right-to-left override can make source code read
    differently from how it compiles."""
    raw = 'x = "‮evil‬"'
    assert "‮" not in scrub_text(raw).text
    assert "‮" in scrub_text(raw, Options(keep_bidi=True)).text


def test_typography_is_off_by_default():
    raw = "it’s “fine” — really…"
    assert scrub_text(raw).text == raw
    converted = scrub_text(raw, Options(ascii_punct=True)).text
    assert converted == "it's \"fine\" -- really..."


def test_findings_report_position_and_reason():
    result = scrub_text("ok\nbad​here")
    hit = next(f for f in result.findings if f.codepoint == 0x200B)
    assert hit.line == 2 and hit.column == 4
    assert hit.action == "removed"


@given(st.text())
@settings(max_examples=400)
def test_idempotent(text):
    once = scrub_text(text).text
    assert scrub_text(once).text == once


@given(st.text())
@settings(max_examples=400)
def test_never_lengthens_under_defaults(text):
    """Holds only for the default profile. --ascii-punct legitimately grows text
    (U+2026 becomes three dots), so it is excluded rather than special-cased."""
    assert len(scrub_text(text).text) <= len(text)


@given(st.text(alphabet=st.characters(codec="utf-8")))
@settings(max_examples=200)
def test_output_is_always_valid_text(text):
    scrub_text(text).text.encode("utf-8")
