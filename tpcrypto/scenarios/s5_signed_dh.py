"""Scénario 5 — Diffie-Hellman authentifié par signature (Ed25519).

Le scénario 2 est vulnérable à l'homme du milieu (MITM) : rien ne prouve que la
clé publique X25519 reçue appartient vraiment au pair. Ici, chaque client
possède une **clé d'identité Ed25519** de long terme et signe sa clé éphémère
X25519. La signature lie :

    salon + expéditeur + destinataire + clé DH éphémère + clé d'identité

Si un attaquant remplace la clé DH, la signature ne vérifie plus et le client
refuse la connexion.

Reste un cas : un attaquant qui remplace aussi les clés d'identité. La parade
est la vérification hors bande de l'empreinte d'identité : le « code de
sécurité » à 30 chiffres, comme les numéros de sécurité de Signal. Comparez-le
de vive voix (ou avec ``--expect-fingerprint`` pour épingler la clé du pair).

Ce scénario apporte aussi la confidentialité persistante : les clés X25519 sont
éphémères, une compromission future de l'identité ne permet pas de déchiffrer
les sessions passées.
"""

from __future__ import annotations

import argparse
import json

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519

from .. import cli, ui
from ..chat import run as chat_run
from ..codec import Codec
from ..crypto import (
    b64d,
    b64e,
    fingerprint,
    gcm_open,
    gcm_seal,
    hkdf,
    safety_number,
    sha256,
)
from ..keys import load_or_create_ed25519
from ..net import (
    HandshakeError,
    RelayClient,
    from_peer,
    is_handshake,
    recv_until,
    require_payload,
)

INFO = b"tpcrypto/s5/signed-x25519"


def transcript(
    room: str,
    sender: str,
    receiver: str,
    dh_public: bytes,
    identity_public: bytes,
) -> bytes:
    """Sérialisation canonique signée. Identique des deux côtés."""
    document = {
        "v": 1,
        "room": room,
        "from": sender,
        "to": receiver,
        "dh": b64e(dh_public),
        "id": b64e(identity_public),
    }
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")


def derive(shared_secret: bytes, room: str, public_a: bytes, public_b: bytes) -> bytes:
    first, second = sorted([public_a, public_b])
    salt = sha256(b"tpcrypto/s5/salt", room.encode("utf-8"), first, second)
    return hkdf(shared_secret, salt=salt, info=INFO)


def _decode_handshake(payload: dict) -> tuple[bytes, bytes, bytes]:
    dh_public = b64d(payload["pub"])
    identity_public = b64d(payload["id_pub"])
    signature = b64d(payload["sig"])
    if len(dh_public) != 32:
        raise HandshakeError(f"clé X25519 de taille invalide : {len(dh_public)} o")
    if len(identity_public) != 32:
        raise HandshakeError(f"clé Ed25519 de taille invalide : {len(identity_public)} o")
    return dh_public, identity_public, signature


def _verify(
    payload: dict,
    room: str,
    sender: str,
    receiver: str,
) -> tuple[bytes, bytes]:
    """Vérifie la signature du pair. Lève ``HandshakeError`` si elle est fausse."""
    dh_public, identity_public, signature = _decode_handshake(payload)
    try:
        public_key = ed25519.Ed25519PublicKey.from_public_bytes(identity_public)
        public_key.verify(
            signature,
            transcript(room, sender, receiver, dh_public, identity_public),
        )
    except InvalidSignature as exc:
        raise HandshakeError(
            f"SIGNATURE INVALIDE de {sender} !\n"
            "  La clé DH reçue ne correspond pas à la clé d'identité annoncée.\n"
            "  C'est exactement ce que produirait un homme du milieu (MITM).\n"
            "  Connexion refusée."
        ) from exc
    return dh_public, identity_public


class SignedDhCodec(Codec):
    scenario = "s5"

    def __init__(
        self,
        name: str,
        peer: str,
        key: bytes,
        *,
        identity_public: bytes,
        peer_identity_public: bytes,
        safety: str,
        pad: bool = False,
        show_wire: bool = False,
    ) -> None:
        super().__init__(name, peer, pad=pad, show_wire=show_wire)
        self.key = key
        self.identity_public = identity_public
        self.peer_identity_public = peer_identity_public
        self.safety = safety

    def _seal(self, data: bytes, number: int, aad: bytes) -> dict:
        nonce, ciphertext = gcm_seal(self.key, data, aad)
        return {"iv": b64e(nonce), "ct": b64e(ciphertext)}

    def _open(self, payload: dict, number: int, aad: bytes) -> bytes:
        return gcm_open(self.key, b64d(payload["iv"]), b64d(payload["ct"]), aad)

    def describe(self) -> str:
        return (
            "X25519 éphémère + signatures Ed25519 + HKDF + AES-256-GCM\n"
            f"  mon identité      : {fingerprint(self.identity_public)}\n"
            f"  identité du pair  : {fingerprint(self.peer_identity_public)}\n"
            f"  CODE DE SÉCURITÉ  : {self.safety}\n"
            + ui.ok(
                "  Vérifiez ce code de vive voix : s'il diffère, il y a un MITM."
            )
        )


async def handshake(
    relay: RelayClient,
    name: str,
    peer: str,
    *,
    room: str = "LAB",
    expect_fingerprint: str | None = None,
    timeout: float = 120.0,
    pad: bool = False,
    show_wire: bool = False,
) -> SignedDhCodec:
    identity_private, identity_path = load_or_create_ed25519(name)
    identity_public = identity_private.public_key().public_bytes_raw()
    print(ui.dim(f"[{name}] clé d'identité Ed25519 : {identity_path}"))
    print(ui.dim(f"[{name}] empreinte d'identité : {fingerprint(identity_public)}"))

    ephemeral = x25519.X25519PrivateKey.generate()
    ephemeral_public = ephemeral.public_key().public_bytes_raw()
    initiator = name < peer

    if initiator:
        signature = identity_private.sign(
            transcript(room, name, peer, ephemeral_public, identity_public)
        )
        await relay.send(
            {
                "t": "hs",
                "step": "signed_dh1",
                "pub": b64e(ephemeral_public),
                "id_pub": b64e(identity_public),
                "sig": b64e(signature),
            },
            to=peer,
        )
        print(ui.dim(f"[{name}] HS1 signé envoyé (Ed25519 {len(signature)} o)"))

        env = await recv_until(
            relay,
            lambda e: from_peer(e, peer) and is_handshake(e, "signed_dh2"),
            timeout=timeout,
            description=f"HS2 signé de {peer}",
            peer=peer,
        )
        payload = require_payload(env, "pub", "id_pub", "sig")
        peer_dh_public, peer_identity_public = _verify(payload, room, peer, name)
        print(ui.ok(f"[{name}] signature Ed25519 de {peer} vérifiée"))
    else:
        env = await recv_until(
            relay,
            lambda e: from_peer(e, peer) and is_handshake(e, "signed_dh1"),
            timeout=timeout,
            description=f"HS1 signé de {peer}",
            peer=peer,
        )
        payload = require_payload(env, "pub", "id_pub", "sig")
        peer_dh_public, peer_identity_public = _verify(payload, room, peer, name)
        print(ui.ok(f"[{name}] signature Ed25519 de {peer} vérifiée"))

        signature = identity_private.sign(
            transcript(room, name, peer, ephemeral_public, identity_public)
        )
        await relay.send(
            {
                "t": "hs",
                "step": "signed_dh2",
                "pub": b64e(ephemeral_public),
                "id_pub": b64e(identity_public),
                "sig": b64e(signature),
            },
            to=peer,
        )
        print(ui.dim(f"[{name}] HS2 signé envoyé (Ed25519 {len(signature)} o)"))

    # Épinglage optionnel de l'identité du pair (TOFU avec vérification).
    peer_fingerprint = fingerprint(peer_identity_public)
    if expect_fingerprint:
        expected = expect_fingerprint.replace(":", "").replace(" ", "").lower()
        actual = peer_fingerprint.replace(":", "").lower()
        if expected != actual:
            raise HandshakeError(
                "EMPREINTE D'IDENTITÉ INATTENDUE pour "
                f"{peer} :\n  attendue : {expect_fingerprint}\n  reçue    : {peer_fingerprint}\n"
                "Quelqu'un s'est peut-être intercalé, ou la clé du pair a changé."
            )
        print(ui.ok(f"[{name}] empreinte du pair épinglée et conforme"))

    shared = ephemeral.exchange(
        x25519.X25519PublicKey.from_public_bytes(peer_dh_public)
    )
    key = derive(shared, room, ephemeral_public, peer_dh_public)
    safety = safety_number(identity_public, peer_identity_public)

    print(ui.ok(f"[{name}] clé de session : {fingerprint(key)}"))
    print(ui.title(f"[{name}] CODE DE SÉCURITÉ : {safety}"))
    print(ui.dim("        À comparer avec le pair par un canal sûr (de vive voix)."))

    return SignedDhCodec(
        name, peer, key,
        identity_public=identity_public,
        peer_identity_public=peer_identity_public,
        safety=safety,
        pad=pad,
        show_wire=show_wire,
    )


# ---------------------------------------------------------------------------
# Point d'entrée
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = cli.build_parser(__doc__ or "Scénario 5 : DH signé")
    parser.add_argument(
        "--expect-fingerprint", default=None,
        help="empreinte Ed25519 attendue pour le pair (ex. ab12:cd34:...)",
    )
    return parser


async def _run(args: argparse.Namespace) -> None:
    relay = await cli.connect(args)
    try:
        codec = await handshake(
            relay, args.name, args.peer,
            room=args.room, expect_fingerprint=args.expect_fingerprint,
            timeout=args.timeout, pad=args.pad, show_wire=args.show_wire,
        )
        await chat_run(
            relay,
            codec,
            title="Diffie-Hellman X25519 authentifié par Ed25519",
            subtitle=codec.describe(),
        )
    finally:
        await relay.close()


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    cli.ensure_distinct(args.name, args.peer)
    cli.run(lambda: _run(args))


if __name__ == "__main__":
    main()
