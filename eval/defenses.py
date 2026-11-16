"""NLIP-Warrant and the baselines it is compared against, behind one small interface.

Every defense protects the same randomised delegation chain (see :mod:`eval.trial`). The
harness only ever calls the methods below, so each attack is executed identically against
every defense. Baselines are implemented as faithfully and as favourably as their designs allow
(per-service API keys, audience-restricted OAuth tokens, authenticated revocation).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
from abc import ABC, abstractmethod
from typing import Any

from nlip_sdk.nlip import NLIP_Factory, NLIP_Message

from eval.trial import Trial, aud
from nlip_warrant import (
    Caveats,
    Denied,
    FrozenClock,
    KeyPair,
    MemoryRevocationStore,
    Mode,
    Reason,
    Revocation,
    SessionAuthority,
    ToolCall,
    Verifier,
    Warrant,
    WarrantGuard,
)
from nlip_warrant.encoding import b64url_decode, b64url_encode, canonical_json
from nlip_warrant.nlip import (
    WARRANT_SUBFORMAT,
    attach_proof,
    attach_warrant,
    extract_one,
    message_digest,
)
from nlip_warrant.proof import make_proof
from nlip_warrant.warrant import BlockPayload, SignedBlock

Envelope = dict[str, Any]
TTL = 3600


def _request(note: str) -> NLIP_Message:
    msg = NLIP_Factory.create_text(f"please execute: {note} ({secrets.token_hex(4)})")
    msg.add_json({"note": note}, label="request")
    return msg


class Defense(ABC):
    name: str
    family: str

    def __init__(self, trial: Trial, clock: FrozenClock) -> None:
        self.trial = trial
        self.clock = clock

    @abstractmethod
    def leaf_envelope(self) -> Envelope:
        """A fresh, honest message from agent{leaf-1} (or the user) delegating to the leaf."""

    @abstractmethod
    def accept(self, receiver: int, env: Envelope) -> Any:
        """Ingress check at agent ``receiver``; raises :class:`Denied`."""

    @abstractmethod
    def tool(self, receiver: int, session: Any, call: ToolCall) -> None:
        """Tool-boundary check; raises :class:`Denied`."""

    @abstractmethod
    def steal(self, env: Envelope) -> Envelope:
        """Mallory reuses the credential captured in ``env`` on a request of her own."""

    @abstractmethod
    def tamper(self, env: Envelope, wider: Caveats) -> Envelope:
        """Mallory edits the captured credential to claim ``wider`` authority."""

    @abstractmethod
    def over_delegate(self, wider: Caveats) -> Envelope:
        """The leaf's (compromised) delegator hands it more than the delegator itself holds."""

    @abstractmethod
    def outsider_forge(self, wider: Caveats) -> Envelope:
        """Mallory, holding no credential, mints one herself."""

    @abstractmethod
    def revoke_root(self) -> None:
        """The user withdraws the root grant through the defense's revocation mechanism."""

    @abstractmethod
    def forged_revocation(self) -> None:
        """Mallory tries to revoke the user's root grant (denial of service)."""


# --------------------------------------------------------------------------- NLIP-Warrant
class NLIPWarrant(Defense):
    name, family = "NLIP-Warrant", "ours"

    def __init__(self, trial: Trial, clock: FrozenClock) -> None:
        super().__init__(trial, clock)
        n = trial.depth + 1
        self.user = KeyPair.generate("user")
        self.mallory = KeyPair.generate("mallory")
        self.agents = [KeyPair.generate(f"agent{i}") for i in range(n)]
        self.revocations = MemoryRevocationStore()
        self.guards = [
            WarrantGuard(
                self.agents[i], aud(i), Verifier({self.user.key_id}, self.revocations, clock)
            )
            for i in range(n)
        ]
        now = clock.now()
        chain = [Warrant.issue(self.user, self.agents[0].key_id, trial.hops[0], now=now, ttl=TTL)]
        for i in range(1, n):
            chain.append(
                chain[-1].attenuate(
                    self.agents[i - 1], self.agents[i].key_id, trial.hops[i], now=now, ttl=TTL
                )
            )
        self.chain = chain

    def _sender(self) -> KeyPair:
        return self.agents[self.trial.leaf - 1] if self.trial.leaf else self.user

    @staticmethod
    def _wire(msg: NLIP_Message) -> Envelope:
        wire: Envelope = msg.model_dump(mode="json", exclude_none=True)
        return wire

    def _bind(self, signer: KeyPair, warrant: Warrant, msg: NLIP_Message) -> Envelope:
        attach_warrant(msg, warrant.encode())
        proof = make_proof(
            signer,
            wid=warrant.leaf.block_id,
            aud=aud(self.trial.leaf),
            msg_digest=message_digest(msg),
            now=self.clock.now(),
        )
        return self._wire(attach_proof(msg, proof))

    def leaf_envelope(self) -> Envelope:
        return self._bind(self._sender(), self.chain[-1], _request("delegated task"))

    def accept(self, receiver: int, env: Envelope) -> SessionAuthority:
        return self.guards[receiver].ingress(NLIP_Message.model_validate(env))

    def tool(self, receiver: int, session: SessionAuthority, call: ToolCall) -> None:
        self.guards[receiver].authorize(call, session)

    def steal(self, env: Envelope) -> Envelope:
        token = extract_one(NLIP_Message.model_validate(env), WARRANT_SUBFORMAT)
        assert token is not None
        return self._bind(self.mallory, Warrant.decode(token), _request("mallory's request"))

    def tamper(self, env: Envelope, wider: Caveats) -> Envelope:
        msg = NLIP_Message.model_validate(env)
        token = extract_one(msg, WARRANT_SUBFORMAT)
        assert token is not None
        blocks = json.loads(b64url_decode(token.split(".", 1)[1]))
        blocks[-1]["p"]["caveats"].update(wider.wire())
        attach_warrant(msg, "nlipw1." + b64url_encode(canonical_json(blocks)))
        return self._wire(msg)

    def _forged_child(self, parent: Warrant, signer: KeyPair, wider: Caveats) -> Warrant:
        now = self.clock.now()
        payload = BlockPayload(
            jti=secrets.token_urlsafe(16),
            parent=parent.leaf.block_id,
            iss=signer.key_id,
            sub=self.agents[-1].key_id,
            iat=now,
            nbf=now,
            exp=parent.leaf.payload.exp,
            caveats=wider,
        )
        return Warrant((*parent.blocks, SignedBlock(payload, signer.sign(payload.signing_input()))))

    def over_delegate(self, wider: Caveats) -> Envelope:
        leaf = self.trial.leaf
        forged = self._forged_child(self.chain[leaf - 1], self.agents[leaf - 1], wider)
        return self._bind(self.agents[leaf - 1], forged, _request("over-delegated task"))

    def outsider_forge(self, wider: Caveats) -> Envelope:
        forged = Warrant.issue(
            self.mallory, self.agents[-1].key_id, wider, now=self.clock.now(), ttl=TTL
        )
        return self._bind(self.mallory, forged, _request("forged task"))

    def revoke_root(self) -> None:
        self.revocations.publish(
            Revocation.create(self.user, self.chain[0].root.block_id, at=self.clock.now())
        )

    def forged_revocation(self) -> None:
        self.revocations.publish(
            Revocation.create(self.mallory, self.chain[0].root.block_id, at=self.clock.now())
        )


class WarrantNoPoP(NLIPWarrant):
    """Ablation: warrant chains used as bearer tokens (no proof of possession)."""

    name, family = "Warrant, no PoP", "ablation"

    def accept(self, receiver: int, env: Envelope) -> SessionAuthority:
        guard = self.guards[receiver]
        token = extract_one(NLIP_Message.model_validate(env), WARRANT_SUBFORMAT)
        if token is None:
            raise Denied(Reason.MISSING_WARRANT, "none")
        verified = guard.verifier.verify(Warrant.decode(token))
        audiences = verified.caveats.audiences
        if audiences is not None and guard.audience not in audiences:
            raise Denied(Reason.WRONG_AUDIENCE, guard.audience)
        return SessionAuthority(verified, verified.holder, Mode.DELEGATION)


class WarrantIngressOnly(NLIPWarrant):
    """Ablation: Type-2 ingress checks only, no Type-3 tool-boundary enforcement."""

    name, family = "Warrant, ingress only", "ablation"

    def tool(self, receiver: int, session: SessionAuthority, call: ToolCall) -> None:
        return None


# --------------------------------------------------------------------------- baselines
class NoAuth(Defense):
    """Agents trust whatever arrives over NLIP (today's default in most agent stacks)."""

    name, family = "No authorization", "baseline"

    def leaf_envelope(self) -> Envelope:
        return {"msg": secrets.token_hex(8)}

    def accept(self, receiver: int, env: Envelope) -> None:
        return None

    def tool(self, receiver: int, session: Any, call: ToolCall) -> None:
        return None

    def steal(self, env: Envelope) -> Envelope:
        return {"msg": "mallory"}

    def tamper(self, env: Envelope, wider: Caveats) -> Envelope:
        return env

    def over_delegate(self, wider: Caveats) -> Envelope:
        return self.leaf_envelope()

    def outsider_forge(self, wider: Caveats) -> Envelope:
        return {"msg": "forged"}

    def revoke_root(self) -> None:
        return None

    def forged_revocation(self) -> None:
        return None


class StaticApiKey(NoAuth):
    """A long-lived secret per receiving service, shared with every legitimate caller."""

    name, family = "Static API keys", "baseline"

    def __init__(self, trial: Trial, clock: FrozenClock) -> None:
        super().__init__(trial, clock)
        self.keys = [secrets.token_urlsafe(24) for _ in range(trial.depth + 1)]

    def leaf_envelope(self) -> Envelope:
        return {"key": self.keys[self.trial.leaf], "msg": secrets.token_hex(8)}

    def accept(self, receiver: int, env: Envelope) -> None:
        if not hmac.compare_digest(str(env.get("key", "")), self.keys[receiver]):
            raise Denied(Reason.BAD_PROOF, "bad api key")

    def steal(self, env: Envelope) -> Envelope:
        return {"key": env["key"], "msg": "mallory"}

    def outsider_forge(self, wider: Caveats) -> Envelope:
        return {"key": secrets.token_urlsafe(24), "msg": "forged"}


class OAuthBearer(Defense):
    """OAuth 2.0-style signed bearer token with scopes, audience, expiry and revocation.

    The root token minted for agent0 is forwarded unchanged down the chain, which is how
    delegated API access is commonly wired between agents today.
    """

    name, family = "OAuth bearer (forwarded)", "baseline"

    def __init__(self, trial: Trial, clock: FrozenClock) -> None:
        super().__init__(trial, clock)
        self.as_key = secrets.token_bytes(32)
        self.revoked: set[str] = set()
        root = trial.hops[0]
        self.root = self.mint(
            sub="agent0", scope=root.actions or (), aud=root.audiences or (), exp=clock.now() + TTL
        )

    def mint(
        self,
        *,
        sub: str,
        scope: tuple[str, ...],
        aud: tuple[str, ...],
        exp: int,
        parent: str | None = None,
    ) -> str:
        claims = {
            "jti": secrets.token_hex(8),
            "sub": sub,
            "scope": list(scope),
            "aud": list(aud),
            "exp": exp,
            "parent": parent,
        }
        body = b64url_encode(canonical_json(claims))
        mac = hmac.new(self.as_key, body.encode(), hashlib.sha256).digest()
        return f"{body}.{b64url_encode(mac)}"

    def claims(self, token: str) -> dict[str, Any]:
        body, _, mac = token.partition(".")
        good = hmac.new(self.as_key, body.encode(), hashlib.sha256).digest()
        if not mac or not hmac.compare_digest(b64url_decode(mac), good):
            raise Denied(Reason.BAD_SIGNATURE, "bad token mac")
        out: dict[str, Any] = json.loads(b64url_decode(body))
        return out

    def leaf_token(self) -> str:
        return self.root

    def leaf_envelope(self) -> Envelope:
        return {"token": self.leaf_token(), "msg": secrets.token_hex(8)}

    def accept(self, receiver: int, env: Envelope) -> dict[str, Any]:
        claims = self.claims(str(env.get("token", "")))
        if self.clock.now() >= int(claims["exp"]):
            raise Denied(Reason.EXPIRED, "token expired")
        if aud(receiver) not in claims["aud"]:
            raise Denied(Reason.WRONG_AUDIENCE, "aud")
        if claims["jti"] in self.revoked:
            raise Denied(Reason.REVOKED, "introspection: revoked")
        return claims

    def tool(self, receiver: int, session: dict[str, Any], call: ToolCall) -> None:
        if call.action not in session["scope"]:
            raise Denied(Reason.ACTION_NOT_ALLOWED, "scope")

    def steal(self, env: Envelope) -> Envelope:
        return {"token": env["token"], "msg": "mallory"}

    def tamper(self, env: Envelope, wider: Caveats) -> Envelope:
        body, _, mac = str(env["token"]).partition(".")
        claims = json.loads(b64url_decode(body))
        claims["scope"] = sorted(set(claims["scope"]) | set(wider.actions or ()))
        return {"token": f"{b64url_encode(canonical_json(claims))}.{mac}", "msg": env["msg"]}

    def over_delegate(self, wider: Caveats) -> Envelope:
        # Without attenuation the delegator can only forward what it has (its full token).
        return self.leaf_envelope()

    def outsider_forge(self, wider: Caveats) -> Envelope:
        claims = {
            "jti": "x",
            "sub": "mallory",
            "scope": list(wider.actions or ()),
            "aud": [aud(self.trial.leaf)],
            "exp": self.clock.now() + TTL,
        }
        return {"token": f"{b64url_encode(canonical_json(claims))}.AAAA", "msg": "forged"}

    def revoke_root(self) -> None:
        self.revoked.add(self.claims(self.root)["jti"])

    def forged_revocation(self) -> None:
        return None  # RFC 7009 requires client authentication; Mallory's request is refused


class OAuthExchange(OAuthBearer):
    """RFC 8693 token exchange at every hop: scope and audience are narrowed per hop.

    The authorization server enforces scope ⊆ subject-token scope. Revoking the root token
    does not revoke tokens already exchanged from it (no lineage tracking), which is the
    common behaviour of RFC 7009 revocation.
    """

    name, family = "OAuth + token exchange", "baseline"

    def __init__(self, trial: Trial, clock: FrozenClock) -> None:
        super().__init__(trial, clock)
        tokens = [self.root]
        for i in range(1, trial.depth + 1):
            parent = self.claims(tokens[-1])
            hop = trial.hops[i]
            scope = tuple(a for a in (hop.actions or ()) if a in parent["scope"])
            tokens.append(
                self.mint(
                    sub=f"agent{i}",
                    scope=scope,
                    aud=hop.audiences or (),
                    exp=parent["exp"],
                    parent=parent["jti"],
                )
            )
        self.tokens = tokens

    def leaf_token(self) -> str:
        return self.tokens[-1]

    def over_delegate(self, wider: Caveats) -> Envelope:
        # The delegator asks the AS for a token with ``wider`` scope; the AS caps it at the
        # delegator's own scope. Amount, payee and purpose cannot be expressed at all.
        parent = self.claims(self.tokens[-2])
        scope = tuple(a for a in (wider.actions or ()) if a in parent["scope"])
        token = self.mint(
            sub=f"agent{self.trial.leaf}",
            scope=scope,
            aud=(aud(self.trial.leaf),),
            exp=parent["exp"],
            parent=parent["jti"],
        )
        return {"token": token, "msg": secrets.token_hex(8)}


DEFENSES: tuple[type[Defense], ...] = (
    NoAuth,
    StaticApiKey,
    OAuthBearer,
    OAuthExchange,
    WarrantNoPoP,
    WarrantIngressOnly,
    NLIPWarrant,
)
