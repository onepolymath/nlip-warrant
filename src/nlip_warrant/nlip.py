"""ECMA-430 binding: carrying warrants and proofs inside NLIP messages.

Both ride as *token* submessages (ECMA-430 section 6.2), which every conforming end-point must
already accept and echo:

* ``format="token", subformat="warrant"``: the encoded warrant chain.
* ``format="token", subformat="warrant_proof"``: the sender's proof of possession.

The proof signs a digest of the whole message *excluding* proof submessages, so the warrant,
the text, every structured submessage and the conversation token are all bound to it.
"""

from __future__ import annotations

import json
from typing import Any

from nlip_sdk.nlip import NLIP_Message, NLIP_SubMessage

from .encoding import sha256_hex
from .errors import Denied
from .reasons import Reason

WARRANT_SUBFORMAT = "warrant"
PROOF_SUBFORMAT = "warrant_proof"
_TOKEN = "token"  # noqa: S105 - the ECMA-430 format name, not a secret


def _is(sub: NLIP_SubMessage, subformat: str) -> bool:
    return str(sub.format.value).lower() == _TOKEN and sub.subformat.lower() == subformat


def message_digest(msg: NLIP_Message) -> str:
    """sha256 over the message's JSON form with proof submessages removed.

    NLIP content may legitimately contain JSON floats, so this uses Python's JSON number
    formatting rather than the stricter float-free encoding used for signed warrant blocks.
    """
    data: dict[str, Any] = msg.model_dump(mode="json", exclude_none=True)
    subs = data.get("submessages") or []
    data["submessages"] = [
        s
        for s in subs
        if not (
            str(s.get("format", "")).lower() == _TOKEN
            and str(s.get("subformat", "")).lower() == PROOF_SUBFORMAT
        )
    ]
    blob = json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return sha256_hex(blob.encode())


def _attach(msg: NLIP_Message, subformat: str, token: str) -> NLIP_Message:
    # Built by hand: nlip_sdk 0.1.3's ``NLIP_Message.add_token`` passes ``self`` twice to
    # ``add_submessage`` and raises a TypeError for any non-reserved token type.
    strip(msg, subformat)
    msg.add_submessage(NLIP_SubMessage(format="token", subformat=subformat, content=token))
    return msg


def attach_warrant(msg: NLIP_Message, warrant_token: str) -> NLIP_Message:
    return _attach(msg, WARRANT_SUBFORMAT, warrant_token)


def attach_proof(msg: NLIP_Message, proof_token: str) -> NLIP_Message:
    return _attach(msg, PROOF_SUBFORMAT, proof_token)


def structured(msg: NLIP_Message, label: str) -> dict[str, Any] | None:
    """The JSON content of the first structured submessage carrying ``label``."""
    for sub in msg.submessages or []:
        if (
            str(sub.format.value).lower() == "structured"
            and sub.label == label
            and isinstance(sub.content, dict)
        ):
            return dict(sub.content)
    return None


def strip(msg: NLIP_Message, subformat: str) -> None:
    if msg.submessages:
        msg.submessages = [s for s in msg.submessages if not _is(s, subformat)]


def extract_one(msg: NLIP_Message, subformat: str) -> str | None:
    """The single token of ``subformat``; more than one is ambiguous and therefore refused."""
    found = [s for s in (msg.submessages or []) if _is(s, subformat)]
    if not found:
        return None
    if len(found) > 1:
        raise Denied(Reason.MALFORMED, f"multiple {subformat!r} token submessages")
    content = found[0].content
    if not isinstance(content, str):
        raise Denied(Reason.MALFORMED, f"{subformat!r} token must be a string")
    return content


def echo_tokens(request: NLIP_Message, response: NLIP_Message) -> NLIP_Message:
    """ECMA-430 section 6.2: return the peer's token submessages unmodified in the response."""
    existing = {
        (str(s.format.value).lower(), s.subformat, str(s.content))
        for s in (response.submessages or [])
    }
    for sub in request.submessages or []:
        if str(sub.format.value).lower() != _TOKEN:
            continue
        key = (_TOKEN, sub.subformat, str(sub.content))
        if key not in existing:
            response.add_submessage(sub.model_copy())
    return response
