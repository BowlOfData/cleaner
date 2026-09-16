"""Re-sign a scrubbed asset, chaining to the manifest it used to carry.

You cannot scrub a signed asset and keep its original signature valid: the C2PA
hard binding hashes the asset bytes, and the spec directs claim generators to
include EXIF and XMP in that hash, so removing a GPS tag breaks the claim even
when the manifest bytes survive untouched.

The specification's answer for an editing application is to write a *new*
manifest that references the original as an ingredient. The provenance chain is
then extended rather than severed, and the edit is disclosed rather than hidden
-- which is the opposite of stripping the mark and saying nothing.
"""

from __future__ import annotations

import io
import json
from dataclasses import dataclass
from pathlib import Path

import c2pa

from ..files.base import Removal

#: Formats c2pa-python 0.37.7's Builder can write. Its Reader additionally
#: handles PDF, so a PDF's credentials can be detected but never reissued.
RESEALABLE = {"jpeg": "image/jpeg", "png": "image/png"}

#: Why --reseal is disabled in v1. Established by experiment against 0.37.7:
#:
#: The validator requires an action list to begin with either c2pa.created --
#: which additionally requires a digitalSourceType, absent which every manifest
#: fails assertion.action.malformed -- or c2pa.opened. Only two shapes are
#: therefore reachable, and neither is fit to ship:
#:
#:   * c2pa.created (+ digitalSourceType) validates cleanly, but asserts that we
#:     *created* an asset we merely scrubbed. Emitting a false creation claim is
#:     precisely the provenance falsification this tool exists to avoid.
#:   * c2pa.opened + c2pa.edited says the true thing, but the action must carry a
#:     hashed-URI reference to the ingredient assertion. The SDK does not populate
#:     it and supplying one by hand needs a hash of the assertion that does not
#:     exist until signing, so the result always fails
#:     assertion.action.ingredientMismatch -- a file verifiers flag as broken.
#:
#: Refusing signed files, the default posture anyway, is the honest outcome until
#: the SDK can link an opened action to its ingredient.
RESEAL_BLOCKED = (
    "--reseal is unavailable in this version. c2pa-python 0.37.7 cannot produce a "
    "valid manifest that both names the original as an ingredient and describes "
    "the change truthfully: the only action sequence that validates asserts "
    "c2pa.created, which would falsely claim this tool created the asset. "
    "Signed files are refused instead."
)


class ResealUnsupported(RuntimeError):
    pass


class ResealBlocked(RuntimeError):
    """Raised rather than emitting a manifest that is false or invalid."""


@dataclass(frozen=True)
class SigningIdentity:
    cert_chain: bytes
    private_key: bytes
    alg: bytes = b"es256"
    ta_url: str | None = None

    @classmethod
    def from_files(cls, cert: Path, key: Path, alg: str = "es256",
                   ta_url: str | None = None) -> "SigningIdentity":
        return cls(cert.read_bytes(), key.read_bytes(), alg.encode(), ta_url)

    def signer(self) -> c2pa.Signer:
        info = c2pa.C2paSignerInfo(
            alg=self.alg,
            sign_cert=self.cert_chain,
            private_key=self.private_key,
            # An empty bytestring is rejected at signing time, not at signer
            # construction, with a bare "Signature: empty string".
            ta_url=self.ta_url.encode() if self.ta_url else None,
        )
        return c2pa.Signer.from_info(info)


def _manifest(removals: list[Removal], title: str) -> dict:
    fields = sorted({r.what for r in removals})
    return {
        "claim_generator_info": [{"name": "cleaner", "version": "0.1.0"}],
        "title": title,
        "assertions": [
            {
                "label": "c2pa.actions.v2",
                "data": {
                    "actions": [
                        {
                            "action": "c2pa.opened",
                            "softwareAgent": {"name": "cleaner", "version": "0.1.0"},
                        },
                        {
                            "action": "c2pa.edited",
                            "softwareAgent": {"name": "cleaner", "version": "0.1.0"},
                            "parameters": {
                                "description": "Removed privacy-identifying metadata",
                                "cleaner.removed_fields": fields,
                            },
                        }
                    ]
                },
            }
        ],
    }


def reseal(original: Path, scrubbed: bytes, fmt: str, removals: list[Removal],
           identity: SigningIdentity, allow_invalid: bool = False) -> bytes:
    """Return ``scrubbed`` carrying a new manifest naming the original as an
    ingredient.

    Raises ResealBlocked unless ``allow_invalid`` is set -- see RESEAL_BLOCKED.
    The parameter exists so the chaining logic stays exercised by tests and is
    ready the moment the upstream limitation lifts; it is not wired to the CLI.
    """
    mime = RESEALABLE.get(fmt)
    if mime is None:
        raise ResealUnsupported(
            f"c2pa-python cannot write {fmt}; a scrubbed {fmt} cannot be re-signed"
        )
    if not allow_invalid:
        raise ResealBlocked(RESEAL_BLOCKED)

    builder = c2pa.Builder(json.dumps(_manifest(removals, original.name)))
    ingredient = {
        "title": original.name,
        "relationship": "parentOf",
    }
    with open(original, "rb") as handle:
        builder.add_ingredient_from_stream(json.dumps(ingredient), mime, handle)

    signer = identity.signer()
    destination = io.BytesIO()
    builder.sign(signer, mime, io.BytesIO(scrubbed), destination)
    return destination.getvalue()
