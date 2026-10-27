"""Scénario 2 — Chat chiffré avec Diffie-Hellman (X25519).

Déroulement (convention du TP : le nom le plus petit dans l'ordre alphabétique
initie, donc ``alice`` initie face à ``bob``) :

    alice                                   bob
      |  -- HS1 {pub_A, salt} ------------->  |
      |  <------------- HS2 {pub_B} --------- |
      |                                        |
      |  secret = X25519(priv_A, pub_B)        |  secret = X25519(priv_B, pub_A)
      |  clé = HKDF(secret, salt, info)        |  clé = HKDF(secret, salt, info)
      |                                        |
      |  -- AES-256-GCM(msg) ----------------> |

Ce scénario n'authentifie PAS les clés publiques : un attaquant actif peut
s'intercaler (voir ``tpcrypto.attacks.mitm``). L'empreinte (« SAS ») affichée
doit être comparée de vive voix pour détecter un MITM.
"""

from __future__ import annotations

import argparse
import secrets

from cryptography.hazmat.primitives.asymmetric import x25519

from .. import cli, ui
from ..chat import run as chat_run
from ..codec import Codec
from ..crypto import b64d, b64e, fingerprint, gcm_open, gcm_seal, hkdf
from ..net import (
    HandshakeError,
    RelayClient,
    from_peer,
    is_handshake,
    recv_until,
    require_payload,
)

INFO = b"tpcrypto/s2/x25519"
SALT_SIZE = 16


def derive(shared_secret: bytes, salt: bytes) -> bytes:
    return hkdf(shared_secret, salt=salt, info=INFO)


class DhCodec(Codec):
    scenario = "s2"

    def __init__(self, name: str, peer: str, key: bytes, *, pad: bool = False,
                 show_wire: bool = False) -> None:
        super().__init__(name, peer, pad=pad, show_wire=show_wire)
        self.key = key

    def _seal(self, data: bytes, number: int, aad: bytes) -> dict:
        nonce, ciphertext = gcm_seal(self.key, data, aad)
        return {"iv": b64e(nonce), "ct": b64e(ciphertext)}

    def _open(self, payload: dict, number: int, aad: bytes) -> bytes:
        return gcm_open(self.key, b64d(payload["iv"]), b64d(payload["ct"]), aad)

    def describe(self) -> str:
        return (
            "X25519 + HKDF-SHA256 + AES-256-GCM\n"
            f"  SAS (empreinte de clé de session) : {fingerprint(self.key)}\n"
            + ui.warn(
                "  Échange NON authentifié : comparez le SAS par un autre canal "
                "pour contrer un MITM."
            )
        )


async def handshake(
    relay: RelayClient,
    name: str,
    peer: str,
    *,
    timeout: float = 120.0,
    pad: bool = False,
    show_wire: bool = False,
) -> DhCodec:
    """Échange X25519 puis dérive la clé AES. Renvoie le codec prêt à l'emploi."""
    initiator = name < peer

    if initiator:
        private = x25519.X25519PrivateKey.generate()
        public = private.public_key().public_bytes_raw()
        salt = secrets.token_bytes(SALT_SIZE)
        await relay.send(
            {"t": "hs", "step": "dh1", "pub": b64e(public), "salt": b64e(salt)},
            to=peer,
        )
        print(ui.dim(f"[{name}] HS1 envoyé (X25519 {len(public)} o + salt {len(salt)} o)"))

        env = await recv_until(
            relay,
            lambda e: from_peer(e, peer) and is_handshake(e, "dh2"),
            timeout=timeout,
            description=f"HS2 (clé publique X25519) de {peer}",
            peer=peer,
        )
        payload = require_payload(env, "pub")
        peer_public = x25519.X25519PublicKey.from_public_bytes(b64d(payload["pub"]))
    else:
        env = await recv_until(
            relay,
            lambda e: from_peer(e, peer) and is_handshake(e, "dh1"),
            timeout=timeout,
            description=f"HS1 (clé publique X25519) de {peer}",
            peer=peer,
        )
        payload = require_payload(env, "pub", "salt")
        peer_public = x25519.X25519PublicKey.from_public_bytes(b64d(payload["pub"]))
        salt = b64d(payload["salt"])

        private = x25519.X25519PrivateKey.generate()
        public = private.public_key().public_bytes_raw()
        await relay.send(
            {"t": "hs", "step": "dh2", "pub": b64e(public)},
            to=peer,
        )
        print(ui.dim(f"[{name}] HS2 envoyé (X25519 {len(public)} o)"))

    shared = private.exchange(peer_public)
    key = derive(shared, salt)
    print(ui.ok(f"[{name}] secret partagé X25519 : {fingerprint(shared)}"))
    print(ui.ok(f"[{name}] clé de session dérivée : {fingerprint(key)}"))
    return DhCodec(name, peer, key, pad=pad, show_wire=show_wire)


# ---------------------------------------------------------------------------
# Point d'entrée
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = cli.build_parser(__doc__ or "Scénario 2 : Diffie-Hellman")
    return parser


async def _run(args: argparse.Namespace) -> None:
    relay = await cli.connect(args)
    try:
        codec = await handshake(
            relay, args.name, args.peer,
            timeout=args.timeout, pad=args.pad, show_wire=args.show_wire,
        )
        await chat_run(
            relay,
            codec,
            title="Diffie-Hellman X25519 + AES-256-GCM",
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
