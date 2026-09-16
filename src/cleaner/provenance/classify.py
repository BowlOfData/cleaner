"""Provenance classification: decide what may be done to a file before touching it.

Nothing in this package writes to disk without a Disposition from here.

Three ways an asset can carry C2PA provenance, all of which must be detected:

  1. An embedded manifest store (JUMBF in JPEG APP11, PNG ``caBX``, PDF ``/AF``, ...).
  2. A sidecar ``foo.c2pa`` beside ``foo.jpg``.
  3. A remote manifest whose URL lives in the asset's own metadata.

Only (1) is found by ``c2pa.Reader``. Sidecar discovery is documented as SDK
behaviour but is *not* implemented by the Python ``Reader`` -- verified against
c2pa-python 0.37.7, where a ``sidecar.jpg`` with an adjacent ``sidecar.c2pa``
raises ManifestNotFound. We therefore check for it ourselves.

Case (3) is the dangerous one: such a file has no embedded manifest at all, so a
structural scan sees a clean asset, and scrubbing its XMP destroys the only link
to its credentials.

Detection also reports *who* signed, when that can be established without
touching the network. Presence still gates scrubbing -- the signer is reported,
never acted on.
"""

from __future__ import annotations

import enum
import glob
import io
import json
import mimetypes
import re
import zipfile
from dataclasses import dataclass
from pathlib import Path

import c2pa

SIDECAR_SUFFIX = ".c2pa"

#: MIME type that lets the SDK read a detached manifest with no asset beside it.
MANIFEST_MIME = "application/c2pa"

# The SDK reports a blocked remote fetch through the untyped C2paError fallback
# rather than C2paError.RemoteManifest, so this is matched on message text.
_REMOTE_RE = re.compile(r"^Remote:.*?from url (?P<url>\S+)", re.IGNORECASE)
_REMOTE_PREFIX = "remote:"

#: A JUMBF superbox header, followed by the C2PA label. Used only for formats the
#: SDK cannot parse at all, where the alternative is refusing every such file.
_JUMBF_BOX = b"jumb"
_C2PA_LABEL = b"c2pa"


def _plausible_box(blob: bytes, index: int) -> bool:
    """Whether the four bytes before a ``jumb`` type read as a box length.

    A JUMBF superbox is an ISO BMFF box: a big-endian 4-byte length, then the
    4-byte type. Matching the bare label instead meant any text placing the word
    ``jumb`` within 64 bytes of ``c2pa`` was treated as carrying credentials --
    which refused documents *about* Content Credentials, this project's own
    subject matter, once text formats made this path reachable for every source
    file.

    Anything that cannot be checked stays true, so this only ever removes false
    positives and never weakens detection.
    """
    if index < 4:
        return True
    length = int.from_bytes(blob[index - 4:index], "big")
    if length in (0, 1):        # extends to end of file / 64-bit extended size
        return True
    return 8 <= length <= len(blob) - (index - 4)


def _looks_like_c2pa(blob: bytes) -> bool:
    index = blob.find(_JUMBF_BOX)
    while index != -1:
        if _C2PA_LABEL in blob[index:index + 64] and _plausible_box(blob, index):
            return True
        index = blob.find(_JUMBF_BOX, index + 1)
    return False


def structural_scan(path: Path) -> bool:
    """Best-effort C2PA detection for formats c2pa-python cannot open.

    OOXML is the case that forces this: as of 0.37.7 neither Reader nor Builder
    supports it, so treating "SDK could not parse" as provenance-present would
    refuse every .docx and make the scrubber useless, while treating it as
    provenance-absent would scrub a Content-Credentialed document blind.
    """
    try:
        if zipfile.is_zipfile(path):
            with zipfile.ZipFile(path) as archive:
                for info in archive.infolist():
                    if _C2PA_LABEL in info.filename.lower().encode():
                        return True
                    if info.file_size <= 8 * 1024 * 1024:
                        if _looks_like_c2pa(archive.read(info)):
                            return True
            return False
        return _looks_like_c2pa(path.read_bytes())
    except (OSError, zipfile.BadZipFile):
        return True    # unreadable: fail closed


class Disposition(enum.Enum):
    SCRUB_FREELY = "scrub_freely"
    REFUSE = "refuse"
    REFUSE_UNRECOGNIZED = "refuse_unrecognized"
    REFUSE_NEEDS_CERT = "refuse_needs_cert"
    REFUSE_IS_MANIFEST = "refuse_is_manifest"
    SCRUB_AND_RESEAL = "scrub_and_reseal"


#: Substrings that attribute a manifest to a known generator, matched
#: case-insensitively. Each entry names which fields it is allowed to match:
#: an organisation name is safe to look for anywhere, but a product name is
#: matched only in ``claim_generator``, because a certificate's common name is
#: often a *person* and "Claude" is an ordinary given name.
#:
#: These are published organisation and product names, not certificate
#: fingerprints -- no vendor publishes the exact issuer string of its production
#: signing certificate, so this attributes on self-declared identity and can be
#: wrong in both directions. It is a reporting aid; nothing branches on it.
KNOWN_GENERATORS: tuple[tuple[str, str, bool], ...] = (
    # (needle, label, may_match_certificate_fields)
    ("anthropic", "Anthropic", True),
    ("claude", "Anthropic (Claude)", False),
)


@dataclass(frozen=True)
class SignerInfo:
    """Who signed a manifest, as the manifest itself declares.

    Read-only reporting. None of these fields gate a disposition: an asset with
    credentials is protected regardless of who issued them.
    """

    issuer: str | None = None
    common_name: str | None = None
    alg: str | None = None
    cert_serial: str | None = None
    claim_generator: str | None = None
    title: str | None = None
    validation_state: str | None = None

    @property
    def attribution(self) -> str | None:
        """A known generator this manifest claims to come from, if any."""
        generator = (self.claim_generator or "").lower()
        certificate = " ".join(filter(None, (self.issuer, self.common_name))).lower()
        for needle, label, may_match_cert in KNOWN_GENERATORS:
            if needle in generator or (may_match_cert and needle in certificate):
                return label
        return None

    def describe(self) -> str:
        parts = []
        if self.attribution:
            parts.append(f"attributed to {self.attribution}")
        if self.claim_generator:
            parts.append(f"generator {self.claim_generator}")
        if self.issuer:
            parts.append(f"issuer {self.issuer}")
        if self.common_name and self.common_name != self.issuer:
            parts.append(f"signed by {self.common_name}")
        if self.alg:
            parts.append(f"alg {self.alg}")
        if self.validation_state:
            parts.append(f"validation {self.validation_state}")
        return ", ".join(parts) or "signer not stated"


def _first_generator(entries) -> str | None:
    """Render ``claim_generator_info[0]`` as "name version".

    Only the first entry is used: later entries are the toolchain the generator
    was built on (``org.contentauth.c2pa_rs`` and friends), not the producer.
    """
    if not isinstance(entries, list) or not entries:
        return None
    first = entries[0]
    if not isinstance(first, dict):
        return str(first)
    name = first.get("name")
    if not name:
        return None
    version = first.get("version")
    return f"{name} {version}" if version else str(name)


def _signer_from_reader(reader) -> SignerInfo | None:
    """Pull the active manifest's declared identity out of a Reader.

    Best-effort by design: this is reporting, and a manifest whose JSON we
    cannot parse must not change what the tool *does* with the file.
    """
    try:
        document = json.loads(reader.json())
        active = document.get("active_manifest")
        manifest = document.get("manifests", {}).get(active) or {}
        signature = manifest.get("signature_info") or {}
        state = document.get("validation_state")
    except Exception:
        return None

    info = SignerInfo(
        issuer=signature.get("issuer"),
        common_name=signature.get("common_name"),
        alg=signature.get("alg"),
        cert_serial=signature.get("cert_serial_number"),
        claim_generator=_first_generator(manifest.get("claim_generator_info")),
        title=manifest.get("title"),
        validation_state=str(state) if state else None,
    )
    return info if any(vars(info).values()) else None


def find_sidecars(path: Path) -> tuple[Path, ...]:
    """Every detached manifest that could belong to ``path``.

    Two spellings are checked. The C2PA spec's external-manifest form replaces
    the extension (``photo.jpg`` -> ``photo.c2pa``), and that is what the SDK's
    own tooling writes; the appended form (``photo.jpg.c2pa``) is checked
    defensively because some tools emit it and because the cost of the two
    checks is asymmetric -- a missed sidecar means scrubbing an asset whose
    credentials live next to it, while a spurious one only costs a refusal.

    A ``.c2pa`` file is not its own sidecar, so it is excluded: ``with_suffix``
    would otherwise return the path itself.
    """
    if path.suffix.lower() == SIDECAR_SUFFIX:
        return ()
    candidates: list[Path] = []
    try:
        candidates.append(path.with_suffix(SIDECAR_SUFFIX))
    except ValueError:      # no name to put a suffix on
        pass
    candidates.append(path.with_name(path.name + SIDECAR_SUFFIX))

    found: list[Path] = []
    for candidate in candidates:
        if candidate not in found and candidate != path and candidate.is_file():
            found.append(candidate)
    return tuple(found)


def find_sidecar_assets(manifest: Path) -> tuple[Path, ...]:
    """The assets a detached manifest could belong to.

    The inverse of ``find_sidecars``: ``photo.c2pa`` may describe ``photo.jpg``
    (extension replaced) or the manifest may be ``photo.jpg.c2pa`` (appended).
    An empty result means the manifest is orphaned -- its asset was renamed,
    moved, or scrubbed by something that did not know the sidecar was there.
    """
    assets: list[Path] = []
    appended = manifest.with_suffix("")     # photo.jpg.c2pa -> photo.jpg
    if appended.suffix and appended.is_file():
        assets.append(appended)
    stem = manifest.stem
    for sibling in sorted(manifest.parent.glob(f"{glob.escape(stem)}.*")):
        if (sibling.suffix.lower() != SIDECAR_SUFFIX and sibling.is_file()
                and sibling not in assets):
            assets.append(sibling)
    return tuple(assets)


@dataclass(frozen=True)
class Provenance:
    """What was found, and how. ``present`` is what gates scrubbing."""

    embedded: bool = False
    sidecars: tuple[Path, ...] = ()
    remote_url: str | None = None
    unrecognized: str | None = None
    is_manifest: bool = False
    manifest_assets: tuple[Path, ...] = ()
    signer: SignerInfo | None = None

    @property
    def sidecar(self) -> Path | None:
        """The first detached manifest found, or None.

        Kept as the singular accessor because that is how callers read it; the
        tuple is what detection actually produces, since both sidecar spellings
        can exist at once.
        """
        return self.sidecars[0] if self.sidecars else None

    @property
    def present(self) -> bool:
        return bool(self.embedded or self.sidecars or self.remote_url
                    or self.unrecognized or self.is_manifest)

    def describe(self) -> str:
        parts = []
        if self.is_manifest:
            if self.manifest_assets:
                belongs = ", ".join(a.name for a in self.manifest_assets)
                parts.append(f"detached C2PA manifest for {belongs}")
            else:
                parts.append("detached C2PA manifest, orphaned "
                             "(no asset of that name beside it)")
        if self.embedded:
            parts.append("embedded manifest")
        for sidecar in self.sidecars:
            parts.append(f"sidecar {sidecar.name}")
        if self.remote_url:
            parts.append(f"remote manifest at {self.remote_url}")
        if self.unrecognized:
            parts.append(f"unrecognized C2PA state ({self.unrecognized})")
        if self.signer:
            parts.append(self.signer.describe())
        return ", ".join(parts) or "none"

    @property
    def attribution(self) -> str | None:
        return self.signer.attribution if self.signer else None


def offline_context() -> c2pa.Context:
    """A Reader context that will never touch the network.

    Without this the SDK dereferences the remote-manifest URL *taken from the
    file being inspected*. For a privacy tool that is unacceptable twice over:
    it announces every scanned file to a third-party host, and it lets an
    untrusted input steer an outbound request. Disabling the fetch also turns
    the failure into a better signal -- the SDK reports the URL instead of a
    network error.
    """
    settings = c2pa.Settings.from_dict({"verify": {"remote_manifest_fetch": False}})
    return c2pa.ContextBuilder().with_settings(settings).build()


def _read_detached(manifest: Path, asset: Path | None, ctx) -> SignerInfo | None:
    """Read a detached manifest's declared identity.

    With an asset the manifest binds to, the SDK validates the binding as well;
    without one it still parses the claim, which is enough to say who signed.
    Both paths are best-effort -- a sidecar we cannot parse is still a sidecar,
    and detection has already refused the file by the time this runs.
    """
    try:
        data = manifest.read_bytes()
    except OSError:
        return None
    try:
        if asset is not None:
            with open(asset, "rb") as stream:
                with c2pa.Reader(_mime_hint(asset), stream=stream,
                                 manifest_data=data, context=ctx) as reader:
                    return _signer_from_reader(reader)
        with c2pa.Reader(MANIFEST_MIME, stream=io.BytesIO(data), context=ctx) as reader:
            return _signer_from_reader(reader)
    except Exception:
        return None


def _mime_hint(asset: Path) -> str:
    guessed, _ = mimetypes.guess_type(asset.name)
    # An empty string asks the SDK to detect the container from the bytes, which
    # is what we want when the extension tells us nothing.
    return guessed or ""


def detect_manifest_file(path: Path, context: c2pa.Context | None = None) -> Provenance:
    """Classify a ``.c2pa`` file handed to us directly.

    Without this a sidecar named as an argument, or swept up in a directory
    scan, fell through to "unsupported file type" -- the least informative thing
    the tool can say about the one file whose entire content is credentials.
    """
    ctx = context or offline_context()
    assets = find_sidecar_assets(path)
    signer = _read_detached(path, assets[0] if assets else None, ctx)
    return Provenance(is_manifest=True, manifest_assets=assets, signer=signer)


def detect(path: Path, context: c2pa.Context | None = None) -> Provenance:
    """Detect provenance without modifying or transmitting anything."""
    ctx = context or offline_context()
    if path.suffix.lower() == SIDECAR_SUFFIX:
        return detect_manifest_file(path, ctx)

    sidecars = find_sidecars(path)

    def detached_signer() -> SignerInfo | None:
        return _read_detached(sidecars[0], path, ctx) if sidecars else None

    try:
        reader = c2pa.Reader(str(path), context=ctx)
    except c2pa.C2paError.ManifestNotFound:
        return Provenance(sidecars=sidecars, signer=detached_signer())
    except c2pa.C2paError.NotSupported:
        # The SDK does not handle this container at all (OOXML, as of 0.37.7).
        # Fall back to a structural scan rather than refusing the whole format.
        if structural_scan(path):
            return Provenance(sidecars=sidecars, signer=detached_signer(),
                              unrecognized="C2PA data found in a container the SDK cannot parse")
        return Provenance(sidecars=sidecars, signer=detached_signer())
    except c2pa.C2paError as exc:
        message = str(exc)
        match = _REMOTE_RE.match(message)
        if match:
            # No signer: naming it would mean fetching the manifest, which is
            # exactly what offline_context() exists to prevent.
            return Provenance(sidecars=sidecars, signer=detached_signer(),
                              remote_url=match.group("url"))
        if message.strip().lower().startswith(_REMOTE_PREFIX):
            # A remote reference we could not parse a URL out of. Still provenance.
            return Provenance(sidecars=sidecars, signer=detached_signer(),
                              remote_url="<unparsed>")
        # Fail closed: an error we do not understand is treated as provenance
        # present, so an SDK change can never silently downgrade us to scrubbing.
        return Provenance(sidecars=sidecars, signer=detached_signer(),
                          unrecognized=message[:200])

    with reader:
        # Deliberately *not* consulting get_validation_state() as a gate: an
        # untrusted or expired signature is still provenance, and must still be
        # protected. It is read only to be reported.
        return Provenance(
            embedded=bool(reader.is_embedded()),
            sidecars=sidecars,
            remote_url=reader.get_remote_url(),
            signer=_signer_from_reader(reader),
        )


def classify(
    path: Path,
    *,
    reseal: bool = False,
    signer_configured: bool = False,
    context: c2pa.Context | None = None,
) -> tuple[Disposition, Provenance]:
    prov = detect(path, context=context)
    if not prov.present:
        return Disposition.SCRUB_FREELY, prov
    if prov.is_manifest:
        # The file *is* the credentials. There is no metadata to scrub out of it,
        # and resealing does not apply, so this refuses ahead of the reseal path.
        return Disposition.REFUSE_IS_MANIFEST, prov
    if prov.unrecognized:
        return Disposition.REFUSE_UNRECOGNIZED, prov
    if not reseal:
        return Disposition.REFUSE, prov
    if not signer_configured:
        return Disposition.REFUSE_NEEDS_CERT, prov
    return Disposition.SCRUB_AND_RESEAL, prov
