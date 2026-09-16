# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
uv sync                                          # install (deps + dev group)
uv run pytest                                    # full suite (108 tests, <1s)
uv run pytest tests/test_classify.py -q          # one file
uv run pytest -k test_orientation_is_preserved   # one test
uv run cleaner inspect <paths>                   # read-only run of the tool

uv run python tools/gen_tables.py                # regenerate Unicode tables from the UCD (network)
uv run python tests/corpus/_gen/make_c2pa.py     # regenerate signed fixtures
uv run python tests/corpus/_gen/make_phone.py    # regenerate GPS-tagged JPEG fixture
uv run python tests/corpus/_gen/make_docs.py     # regenerate PDF/DOCX fixtures
uv run python tests/corpus/_gen/make_latex.py    # regenerate LaTeX/.sty/.bib/.dtx fixtures
```

There is no linter or formatter configured.

## What this project is

A privacy metadata scrubber (JPEG/PNG/PDF/DOCX) plus deterministic Unicode text
hygiene. It exists as the legitimate half of a request to build a C2PA/provenance
stripper; that framing is load-bearing, not incidental. Two invariants follow from
it and should not be relaxed without a deliberate decision:

- **It must never remove C2PA Content Credentials.** Files carrying them are
  refused, never scrubbed.
- **Pixels and glyphs are never modified.** Nothing decodes and re-encodes an
  image, so invisible watermarks and perceptual fingerprints survive by
  construction.

`text` applies a fixed table of codepoint operations. Do not add statistical,
semantic, or model-driven rewriting — that would turn it into a text-watermark
defeat tool.

## Architecture

`Removal.applied` separates what was taken out from what was merely reported, and
`ScrubResult.changed` counts only the former. Report-only findings leave the bytes
identical, and treating them as a change wrote a byte-identical copy and labelled
it scrubbed.

`-o DIR` mirrors the source tree via `iter_rooted_targets`; it used to return
`output_dir / source.name`, so two files sharing a basename in different
subdirectories silently overwrote each other. `run()` refuses on any remaining
destination collision.

**`provenance/classify.py` is the spine.** Nothing writes to disk without a
`Disposition` from it, and `pipeline.process()` returns early on anything that is
not `SCRUB_FREELY`. Two design bugs have already lived here, so it carries the
heaviest tests.

Why scrubbing a signed file is refused rather than done carefully: C2PA's hard
binding hashes the *asset* bytes, and the spec directs generators to include EXIF
and XMP in that hash. Removing a GPS tag invalidates the claim even when the
manifest bytes are preserved byte-for-byte. Checking that a manifest survived is
therefore checking the wrong thing.

`detect()` now also reports *who* signed, read straight out of the manifest's
own `signature_info` and `claim_generator_info` (`SignerInfo`). It is reporting
only: no `Disposition` branches on it, so a manifest whose JSON will not parse is
still refused — `test_signer_reporting_never_gates_the_disposition` pins that.
`SignerInfo.attribution` matches a small table of known generator names; a
product name like "Claude" is matched against the claim generator only, never a
certificate common name, because that field is often a *person* and Claude is an
ordinary given name.

A refused file is still *analysed*: `pipeline.analyse_only` runs the format
scrubber and reports its findings with `applied=False`, so the owner of a signed
photo can still learn it carries their GPS tag even though the tool will not
remove it. The honest remedy — re-export from the original and re-sign — is
printed, because C2PA's hard binding covers the asset bytes and there is no edit
that drops the tag while keeping the credentials.

A detached `.c2pa` handed in directly (or swept up in a directory scan) is
classified `REFUSE_IS_MANIFEST` rather than "unsupported file type", and its
asset(s) are located by both sidecar spellings so an orphaned manifest is called
out as orphaned. Both spellings — extension-replaced (`foo.c2pa`) and appended
(`foo.jpg.c2pa`) — are checked in `find_sidecars`; missing one means scrubbing an
asset whose credentials sit right beside it.

Credentials arrive by **three** routes, all of which must be detected:
embedded manifest, sidecar `foo.c2pa`, and a remote manifest named by
`dcterms:provenance` in the asset's XMP. The remote case is the dangerous one — no
embedded manifest exists, so a structural scan sees a clean file and scrubbing its
XMP severs the only link to its credentials. This is why XMP is rewritten
selectively everywhere and never dropped wholesale.

**Format scrubbers are byte-surgical.** `png.py` and `jpeg.py` walk chunks and
marker segments, rewriting only what is being scrubbed and copying every other byte
verbatim. This is not a performance choice: PNG's C2PA `caBX` chunk is flagged
*not-safe-to-copy*, so `Image.open(p).save(p)` destroys it (and JPEG APP11), plus
recompresses the image. Pillow is a **test-only** dependency — keep it out of
`src/`. `test_naive_reencode_would_have_destroyed_it` is the control that pins this.

**`files/latex/` locates spans and never rebuilds the document.** `scanner.py`
walks bytes and yields comment, opaque and control spans; every change is an
`Edit` over the original, spliced by `apply_edits`, so any byte not covered by an
edit is copied by construction. It works on `bytes` deliberately: LaTeX syntax is
all ASCII and no UTF-8 continuation byte is < 0x80, so the same scanner is correct
for UTF-8 and Latin-1 without guessing an encoding.

The precedence order in `scan()` is the correctness argument, not a detail. A
backslash escapes the next byte (`\%` is not a comment); verbatim-like regions are
opaque; **and `\url`/`\href`/`\path` arguments are opaque too** — `url.sty` gives
`%` a harmless catcode there, so reading `\url{http://x/a%20b}` as a comment
truncates the link. That last case was a live bug during development and is pinned
by `test_naive_comment_regex_would_have_broken_it`.

Two rules make the output still compile. **Comment bodies are truncated to a bare
`%`, never deleted** — a trailing `%` eats the following newline, so removing the
whole comment inserts a space and changes the typeset output. **Macros are emptied,
never removed** — a document with no `\date` prints *today's* date, so deleting it
leaks the scrub date. `\hypersetup` is filtered against a key allowlist for the
same reason XMP is: an unrecognised key could be the only provenance link.

The four dialects are separate classes because the languages genuinely differ:
in `.dtx` a column-0 `%` is *documentation* (truncating it destroys the file), in
`.sty` the header block is the licence the LPPL requires be kept, and in `.bib`
`%` is not a comment at all. `.tex` and `.dtx` are not separable by content, so
`sniff_family` takes the path; the family sniff runs *after* the binary sniffs and
demands a strong marker for unknown suffixes, so a prose `.txt` quoting
`\usepackage` is not claimed.

`docx.py` copies every zip entry verbatim except the specific parts it rewrites.
That is deliberate: the SDK cannot parse OOXML, so we do not know where a C2PA
entry would live — copying everything unedited preserves it regardless of name.

**`text/hygiene.py` decides three character classes by context, not by class.**
U+200D/U+200C are kept next to emoji or joining scripts (Arabic, Devanagari, Tamil…);
tag characters U+E0020–E007E are kept inside well-formed emoji tag sequences (the
England/Scotland/Wales flags). A blanket regex over "invisible" codepoints passes
the removal tests and silently corrupts all of these. Ranges are vendored in
`text/tables.py`, generated — do not hand-edit.

## c2pa-python 0.37.7 behaviours (established empirically)

- **`Reader` dereferences the remote-manifest URL by default** — a live HTTP request
  to a location named by untrusted input. Always construct readers via
  `classify.offline_context()` (`verify.remote_manifest_fetch: false`), which also
  turns the failure into a better signal: it reports the URL instead of a network error.
- **`Reader` does not do sidecar discovery**, despite the documented order. We check
  for `foo.c2pa` ourselves.
- The blocked-fetch case raises an **untyped `C2paError`**, not
  `C2paError.RemoteManifest`, so it is matched on message text. Any unrecognized
  error must fail closed to `REFUSE_UNRECOGNIZED`.
- **OOXML is unsupported by both Reader and Builder**; PDF is Reader-only. A raised
  `NotSupported` falls back to `classify.structural_scan()` rather than refusing the
  whole format.
- **An actions assertion must open with `c2pa.created` (which requires
  `digitalSourceType`) or `c2pa.opened`.** Without it every manifest fails
  `assertion.action.malformed` — including the test fixtures, by design.
- **`--reseal` is disabled** and exits 2. See the long comment in
  `provenance/reseal.py`: the only validating shape asserts `c2pa.created`, which
  would falsely claim this tool created the asset, while the truthful
  `c2pa.opened` + `c2pa.edited` needs an ingredient hash that does not exist until
  signing. The chaining code is kept and tested behind `allow_invalid=True`.

## Traps when writing tests here

- **Scan decompressed zip entries, not raw bytes.** DOCX parts are deflated, so
  `secret in blob` finds nothing while the data is still present. Use
  `entries_containing()` in `tests/test_documents.py`.
- **Python `socket` cannot observe the SDK's fetch** — it happens in Rust. The
  no-network test binds a real listener and carries a control assertion that fails
  if the SDK ever stops fetching, so it cannot silently become vacuous.
- **Assert LaTeX invariants, not just absence.** "the secret is gone" passes while
  the document is destroyed. `tests/test_latex.py` pins line count, brace
  *balance* (not brace count — emptying an argument removes matched pairs, so the
  counts legitimately fall), byte-identical verbatim regions, the exact set of
  differing lines, and idempotence.
- **Do not write non-UTF-8 bytes to captured stdout.** It poisons pytest's capture
  buffer for every later test in the session; use `--in-place` instead.
- **Fixtures are signed by a throwaway CA and validate as `Invalid`.** That is
  intentional — presence of credentials, not validity, gates scrubbing.
- `pikepdf.open_metadata()` regenerates DocInfo from XMP on exit; pass
  `update_docinfo=False` or it silently drops keys with no XMP counterpart.

## Defaults worth preserving

Timestamps survive unless `--strip-dates`. Tracked-change authors are reported but
not altered unless `--strip-revisions`, since that edits document content rather
than metadata. Typography (smart quotes, em dashes) is kept unless `--ascii-punct`.
In LaTeX, absolute paths in `\includegraphics`/`\input` are reported but never
rewritten (a basename breaks the build), while `% !TeX` directive paths *are*
reduced to a basename — those are read by editors, never by the engine, so
scrubbing them cannot affect compilation. Content hidden from the reader
(`\endinput` tails, `\iffalse`, `comment` environments) is reported, not removed.
A `\catcode` applied to a syntax character degrades the file to report-only.
EXIF `Orientation` is always kept — dropping it renders photos rotated.
