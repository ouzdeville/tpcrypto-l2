"""Scénario 3 — KEM/DEM avec RSA-OAEP + AES-GCM.

Principe KEM/DEM (« Key Encapsulation Mechanism / Data Encapsulation Mechanism ») :

1. chaque client possède une paire de clés RSA et publie sa clé publique ;
2. pour envoyer un message, l'expéditeur tire un secret aléatoire de 32 octets
   et le chiffre avec RSA-OAEP : c'est l'encapsulation (KEM) ;
3. ce secret sert à dériver une clé AES-GCM éphémère qui chiffre le message :
   c'est le chiffrement de données (DEM) ;
4. le destinataire déchiffre le secret avec sa clé privée RSA, dérive la même
   clé AES et ouvre le message.

RSA-OAEP ne peut encapsuler que de petites valeurs : c'est pour cela qu'on ne
chiffre jamais le message directement avec RSA. Le couple KEM/DEM est aussi la
structure utilisée par ML-KEM (scénario 4).
"""

from __future__ import annotations

import argparse
import secrets

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from .. import cli, ui
from ..chat import run as chat_run
from ..codec import Codec
from ..crypto import b64d, b64e, fingerprint, gcm_open, gcm_seal, hkdf, sha256
from ..keys import load_or_create_rsa, public_key_bytes
from ..net import (
    RelayClient,
    from_peer,
    is_handshake,
    recv_until,
    require_payload,
)

INFO = b"tpcrypto/s3/rsa-oaep"
OAEP_LABEL = b"tpcrypto/s3"


def oaep() -> padding.OAEP:
    return padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=OAEP_LABEL,
    )


def derive_key(shared_secret: bytes, kem_ciphertext: bytes) -> bytes:
    # Le salt lie la clé AES au chiffré KEM : deux encapsulations différentes
    # ne peuvent pas produire la même clé AES.
    return hkdf(shared_secret, salt=sha256(kem_ciphertext), info=INFO)


class RsaKemCodec(Codec):
    scenario = "s3"

    def __init__(
        self,
        name: str,
        peer: str,
        private_key: rsa.RSAPrivateKey,
        peer_public_key: rsa.RSAPublicKey,
        *,
        pad: bool = False,
        show_wire: bool = False,
    ) -> None:
        super().__init__(name, peer, pad=pad, show_wire=show_wire)
        self.private_key = private_key
        self.peer_public_key = peer_public_key

    def _seal(self, data: bytes, number: int, aad: bytes) -> dict:
        shared_secret = secrets.token_bytes(32)
        kem_ciphertext = self.peer_public_key.encrypt(shared_secret, oaep())
        key = derive_key(shared_secret, kem_ciphertext)
        nonce, ciphertext = gcm_seal(key, data, aad)
        return {
            "ek": b64e(kem_ciphertext),   # encapsulation RSA-OAEP
            "iv": b64e(nonce),
            "ct": b64e(ciphertext),
        }

    def _open(self, payload: dict, number: int, aad: bytes) -> bytes:
        kem_ciphertext = b64d(payload["ek"])
        shared_secret = self.private_key.decrypt(kem_ciphertext, oaep())
        key = derive_key(shared_secret, kem_ciphertext)
        return gcm_open(key, b64d(payload["iv"]), b64d(payload["ct"]), aad)

    def describe(self) -> str:
        bits = self.private_key.key_size
        public_der = public_key_bytes(self.peer_public_key)
        return (
            f"RSA-{bits}-OAEP (KEM) + HKDF-SHA256 + AES-256-GCM\n"
            f"  clé publique RSA du pair : {fingerprint(public_der)}\n"
            f"  taille d'une encapsulation RSA-{bits} : {bits // 8} o\n"
            + ui.warn(
                "  Pas de confidentialité persistante : si la clé privée RSA fuite "
                "plus tard, les messages enregistrés pourront être déchiffrés."
            )
        )


async def handshake(
    relay: RelayClient,
    name: str,
    peer: str,
    *,
    bits: int = 2048,
    timeout: float = 120.0,
    pad: bool = False,
    show_wire: bool = False,
) -> RsaKemCodec:
    private_key, path = load_or_create_rsa(name, bits)
    print(ui.dim(f"[{name}] clé privée RSA : {path} ({bits} bits)"))
    public_der = public_key_bytes(private_key.public_key())
    await relay.send(
        {"t": "hs", "step": "rsa_pub", "pub": b64e(public_der), "bits": bits},
        to=peer,
    )
    print(ui.dim(f"[{name}] clé publique RSA envoyée ({len(public_der)} o DER)"))

    env = await recv_until(
        relay,
        lambda e: from_peer(e, peer) and is_handshake(e, "rsa_pub"),
        timeout=timeout,
        description=f"clé publique RSA de {peer}",
        peer=peer,
    )
    payload = require_payload(env, "pub")
    peer_public = serialization.load_der_public_key(b64d(payload["pub"]))
    if not isinstance(peer_public, rsa.RSAPublicKey):
        raise TypeError("le pair n'a pas envoyé une clé RSA")

    print(ui.ok(f"[{name}] clé publique RSA du pair reçue ({peer_public.key_size} bits)"))
    return RsaKemCodec(
        name, peer, private_key, peer_public, pad=pad, show_wire=show_wire,
    )


# ---------------------------------------------------------------------------
# Point d'entrée
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = cli.build_parser(__doc__ or "Scénario 3 : KEM/DEM RSA")
    parser.add_argument(
        "--rsa-bits", type=int, choices=(2048, 3072, 4096), default=2048,
        help="taille de la clé RSA (défaut : 2048)",
    )
    return parser


async def _run(args: argparse.Namespace) -> None:
    relay = await cli.connect(args)
    try:
        codec = await handshake(
            relay, args.name, args.peer,
            bits=args.rsa_bits, timeout=args.timeout,
            pad=args.pad, show_wire=args.show_wire,
        )
        await chat_run(
            relay,
            codec,
            title="KEM/DEM RSA-OAEP + AES-256-GCM",
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
