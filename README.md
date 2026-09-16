# cleaner

![Python](https://img.shields.io/badge/python-3.12%2B-blue)
![Tests](https://img.shields.io/badge/tests-130%20passing-brightgreen)
![Runs locally](https://img.shields.io/badge/network-none-informational)
![C2PA](https://img.shields.io/badge/C2PA-preserved%2C%20never%20stripped-8A2BE2)

Remove privacy-identifying metadata from your own files, and normalise invisible
characters out of text.

> [!NOTE]
> **Runs entirely on your machine.** `inspect`, `scrub` and `text` make no
> network calls. C2PA reading is forced through an offline context, so the
> manifest URL named *inside* a scanned file is never dereferenced — scanning a
> file cannot announce it to a third party. The only online step in the repo is
> the dev-time table/fixture regeneration under `tools/` and `tests/corpus/_gen/`.

> [!IMPORTANT]
> **This is a provenance-*preserving* tool, not a provenance stripper.** Files
> carrying C2PA Content Credentials are refused, never scrubbed, and pixels and
> glyphs are never rewritten. See [What it does not do](#what-it-does-not-do).

```bash
uv sync
uv run cleaner inspect ~/Pictures            # report only, writes nothing
uv run cleaner scrub photo.jpg -o ./clean
uv run cleaner scrub ~/Pictures -r --in-place
uv run cleaner scrub paper/ -r -o ./clean        # sources and figures together
uv run cleaner text notes.md --report
```

A directory argument is scanned for supported types — its immediate children, or
the whole tree with `-r`. Files named outright are processed whatever their
extension: format is detected by content, so a JPEG saved as `.dat` still works.

Exit codes: `0` success, `1` one or more files refused, `2` unavailable option.

## GUI

```bash
uv run cleaner gui         # or: uv run cleaner-gui
```

Two buttons — **Import** and **Clean** — plus a listbox that also accepts files
dropped onto it. Import queues files via the native file picker; Clean asks for
an export folder and runs the same `scrub` pipeline as the CLI, with default
settings (no `--strip-dates`/`--strip-revisions`). It is built on tkinter (part
of the Python standard library) plus `tkinterdnd2` for drag-and-drop, both of
which ship prebuilt for macOS, Windows and Linux, so the same code runs
everywhere with no platform-specific branch. If `tkinterdnd2` is ever
unavailable at runtime the window still opens, just via Import only. The `cli`
module itself never imports tkinter, so `inspect`, `scrub` and `text` run
without touching the GUI stack at all.

## What it does

**`scrub`** removes GPS coordinates, device and lens serial numbers, camera owner
and author names, MakerNote blobs, embedded thumbnails, editing history and
tracked-session identifiers from JPEG, PNG, PDF and DOCX — and author macros,
PDF-metadata directives and comment bodies from LaTeX sources.

How much of the original survives depends on the container:

| Format | Treatment |
|---|---|
| JPEG, PNG | Byte-surgical. Only the segments or chunks being scrubbed are rewritten; everything else, image data included, is copied verbatim. Decoded pixels are bit-identical before and after. |
| DOCX | Rebuilt as an archive, but every entry not being edited is byte-identical — including `word/document.xml`. |
| PDF | Page content streams are preserved, but the file is re-saved through pikepdf, so object numbering and the xref table are rebuilt. Not byte-identical. |
| LaTeX (`.tex` `.ltx` `.sty` `.cls` `.bib` `.dtx` `.ins`) | Byte-surgical. Only the spans being scrubbed are rewritten. Line count, brace balance and every verbatim region are unchanged, so the document still compiles to the same output. |

### LaTeX sources

A `.tex` file leaks in ways the compiled PDF does not. `\author`, `\thanks` and
`\email` are emptied — the macro is kept, because a document with no `\date` at
all prints *today's* date. `\hypersetup` and `\pdfinfo` lose their identity keys
and nothing else. Comment bodies are truncated to a bare `%`, which matters: a
trailing `%` suppresses the following newline, so deleting the comment outright
would change the typeset output.

What is *reported* rather than altered: absolute paths in `\includegraphics` and
friends (rewriting them breaks the build), `changes`/`todonotes` author ids
(`--strip-revisions` anonymises them), and content hidden from the reader —
text after `\endinput`, `\iffalse` blocks and `comment` environments. A run over
one file also reports the sources it `\input`s, so a single-file scrub cannot
look like a clean project.

The dialects differ where the languages do. In `.sty`/`.cls` the leading comment
block is the licence, so it is preserved and reported — the LPPL requires the
notice to travel with the file, even when it names the author. In `.dtx` a `%` in
column 0 introduces *documentation*, not a comment, so those lines are never
touched. In `.bib` a `%` is not a comment at all; only reference-manager plumbing
(`file`, `bdsk-file-*`, `owner`) is dropped, since author names and titles there
are citations.

`scrub` handles metadata; `text` handles Unicode. Neither does the other's job —
running `text` over a `.tex` is content-agnostic and will happily reach inside a
`verbatim` block.

**`text`** removes zero-width spaces, soft hyphens, word joiners, stray tag
characters and bidirectional controls, so text survives CSV parsers, string
comparison, URL slugs and diffs. Bidi controls are removed by default because they
enable [Trojan Source](https://trojansource.codes/) attacks (CVE-2021-42574).

## What it does not do

**It does not remove C2PA Content Credentials.** Files carrying them are refused,
not scrubbed, and `cleaner` exits non-zero:

```
REFUSED  photo.jpg
         carries Content Credentials; scrubbing would invalidate them
         found: embedded manifest, generator Adobe Firefly 1.0, issuer DigiCert
         found: EXIF: GPS IFD (entire location record)
         found: EXIF SubIFD: BodySerialNumber
         nothing above was removed -- to drop it, re-export from the original and sign the result, rather than editing this file
```

This is not a policy bolted on top — it falls out of how C2PA works. The manifest's
hard binding hashes the asset bytes, and the specification directs claim generators
to include EXIF and XMP in that hash, so removing a GPS tag invalidates the
credentials even when the manifest itself is untouched. A tool that scrubbed anyway
would hand back a file whose credentials no longer verify, which is worse than
either leaving it alone or removing them outright.

A refused file is still **analysed**, not just rejected: the same scrubber runs to
list what the file contains — GPS coordinates, serial numbers, author names — so
you can see what a signed photo is exposing even though the tool will not touch it.
Every such line is a *finding*, never a removal; the bytes on disk are unchanged.
The honest remedy is printed with it: re-export from the original and re-sign,
because there is no edit to the signed file that drops the tag and keeps the
credentials.

Detection covers all three ways an asset can carry credentials — an embedded
manifest, a sidecar `foo.c2pa`, or a remote manifest named by `dcterms:provenance`
in the file's XMP. The third matters most: such a file has no embedded manifest at
all, so a structural scan sees nothing, and scrubbing its XMP would sever the only
link to its credentials. When the C2PA state cannot be established at all, the file
is refused rather than guessed at.

Where the manifest can be read offline, the report also names **who signed** —
issuer, signer common name, algorithm and claim generator — and flags a known
generator (for example Anthropic/Claude) as a `mark:` line. This is read straight
from the manifest's self-declared identity; it is a reporting aid, and nothing the
tool *does* branches on it. A product name is matched only against the claim
generator, never a certificate's common name, so a person named Claude is not
mistaken for the model. The remote-manifest case names no signer on purpose —
reading it would mean fetching it.

A detached `foo.c2pa` handed in directly, or found while scanning a directory, is
recognised as a manifest rather than dismissed as an unsupported file type. Its
asset is located by both spellings the ecosystem uses — extension-replaced
(`photo.c2pa`) and appended (`photo.jpg.c2pa`) — and a manifest whose asset is
missing is reported as orphaned:

```
REFUSED  orphan.c2pa
         this file is a detached C2PA manifest, not an asset with metadata in it
         found: detached C2PA manifest, orphaned (no asset of that name beside it), issuer DigiCert
```

**Pixels and glyphs are never modified.** Nothing here decodes and re-encodes an
image, so invisible watermarks and perceptual fingerprints survive by construction.
The tool cannot remove them even if asked.

**No statistical or model-driven rewriting.** `text` applies a fixed table of
codepoint operations. It will not paraphrase, and it is not a way to defeat text
provenance.

## Notes

- Detection never touches the network. The SDK will otherwise dereference the
  remote-manifest URL *named by the file being inspected*, which would announce
  every scanned file to a third-party host.
- Some invisible characters are load-bearing and are kept: U+200D joins emoji and
  builds Arabic and Indic letterforms, and U+E0020–E007E encode the England,
  Scotland and Wales flags. These are decided by context, not stripped by class.
- Output defaults to `<name>.cleaned.<ext>` beside the source. `-o DIR` mirrors the
  source tree under `DIR` rather than flattening it, so `sections/intro.tex` and
  `appendix/intro.tex` no longer resolve to one destination; if two sources still
  collide, the second is refused rather than overwriting the first. `--in-place`
  overwrites, following symlinks to the real file and preserving its mode. Writes
  go through a temp file in the destination directory and an atomic rename.
- EXIF `Orientation` is always kept — dropping it renders photos rotated.
- Timestamps are kept unless you pass `--strip-dates`. Tracked-change authors are
  reported but not altered unless you pass `--strip-revisions`, since that edits
  the document's content rather than its metadata.
- Typography — smart quotes, em dashes, ellipses — is left alone unless you pass
  `--ascii-punct`.
- Text is decoded strictly as UTF-8; use `--encoding` for anything else rather than
  letting it be guessed.
- `--reseal` is not available in this version; see `src/cleaner/provenance/reseal.py`
  for why.

## Development

```bash
uv run pytest                                    # 130 tests
uv run pytest -k test_orientation_is_preserved   # a single test

uv run python tools/gen_tables.py                # regenerate Unicode tables from the UCD
uv run python tests/corpus/_gen/make_c2pa.py     # signed / sidecar / remote-ref fixtures
uv run python tests/corpus/_gen/make_phone.py    # GPS-tagged JPEG fixture
uv run python tests/corpus/_gen/make_docs.py     # PDF and DOCX fixtures
uv run python tests/corpus/_gen/make_latex.py    # LaTeX, package, .bib and .dtx fixtures
```

Test fixtures are signed with a throwaway CA in `tests/corpus/_gen/`. Their
validation state is `Invalid` by design — they are signed by a CA in no trust list,
which is exactly what makes them useful: presence of credentials, not validity,
is what gates scrubbing.

See `CLAUDE.md` for architecture and for the `c2pa-python` behaviours this depends on.
