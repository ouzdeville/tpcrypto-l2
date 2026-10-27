"""Scénario 4 — KEM/DEM avec ML-KEM (FIPS 203) + AES-GCM.

ML-KEM (« Module-Lattice Key Encapsulation Mechanism », anciennement Kyber) est
le KEM standardisé par le NIST pour l'ère post-quantique. Il remplace RSA-OAEP
dans l'échange de clé, mais on garde exactement la même structure KEM/DEM :

    alice                                        bob
      |  -- HS {ek_A} ------------------------>  |
      |  <----------------------- HS {ek_B} ---- |
      |                                           |
      |  ss, ct = Encaps(ek_B)                    |
      |  clé = HKDF(ss)                           |
      |  -- {ct, AES-GCM(msg)} ---------------->  |  ss = Decaps(dk_B, ct)
      |                                           |  clé = HKDF(ss)

Tailles à comparer avec RSA : la clé publique fait 1184 octets et le chiffré
KEM 1088 octets pour ML-KEM-768. C'est le prix de la sécurité post-quantique.

Option ``--hybrid`` : on combine ML-KEM et X25519 (comme le fait X-Wing), pour
rester sûr même si l'un des deux algorithmes est cassé un jour.
"""

from __future__ import annotations

import argparse

from cryptography.hazmat.primitives.asymmetric import x25519

from .. import cli, ui
from ..chat import run as chat_run
from ..codec import Codec
from ..crypto import b64d, b64e, fingerprint, gcm_open, gcm_seal, hkdf, sha256
from ..keys import load_or_create_x25519
from ..net import (
    HandshakeError,
    RelayClient,
    from_peer,
    is_handshake,
    recv_until,
    require_payload,
)
from ..pq import MLKEM

INFO = b"tpcrypto/s4/mlkem"
INFO_HYBRID = b"tpcrypto/s4/x25519+mlkem"


class MlKemCodec(Codec):
    scenario = "s4"

    def __init__(
        self,
        name: str,
        peer: str,
        kem: MLKEM,
        peer_public_key: bytes,
        *,
        own_public_key: bytes,
        hybrid: bool = False,
        own_x25519: x25519.X25519PrivateKey | None = None,
        peer_x25519: x25519.X25519PublicKey | None = None,
        pad: bool = False,
        show_wire: bool = False,
    ) -> None:
        super().__init__(name, peer, pad=pad, show_wire=show_wire)
        self.kem = kem
        self.peer_public_key = peer_public_key
        self.own_public_key = own_public_key
        self.hybrid = hybrid
        self.own_x25519 = own_x25519
        self.peer_x25519 = peer_x25519
        if hybrid and (own_x25519 is None or peer_x25519 is None):
            raise ValueError("mode hybride : clés X25519 manquantes")

    def _send_salt(self) -> bytes:
        # Le sel lie la clé au matériel du DESTINATAIRE (ici : le pair).
        return sha256(self.peer_public_key, self.peer_x25519.public_bytes_raw())  # type: ignore[union-attr]

    def _recv_salt(self) -> bytes:
        # Même paire, mais vue du destinataire : nos propres clés publiques.
        return sha256(self.own_public_key, self.own_x25519.public_key().public_bytes_raw())  # type: ignore[union-attr]

    def _seal(self, data: bytes, number: int, aad: bytes) -> dict:
        shared_secret, kem_ciphertext = self.kem.encapsulate(self.peer_public_key)
        payload: dict = {"kem_ct": b64e(kem_ciphertext)}

        if self.hybrid:
            ephemeral = x25519.X25519PrivateKey.generate()
            ephemeral_public = ephemeral.public_key().public_bytes_raw()
            shared_x = ephemeral.exchange(self.peer_x25519)  # type: ignore[arg-type]
            key = hkdf(
                shared_secret + shared_x,
                salt=self._send_salt(),
                info=INFO_HYBRID,
            )
            payload["x_pub"] = b64e(ephemeral_public)
        else:
            key = hkdf(shared_secret, info=INFO)

        nonce, ciphertext = gcm_seal(key, data, aad)
        payload["iv"] = b64e(nonce)
        payload["ct"] = b64e(ciphertext)
        return payload

    def _open(self, payload: dict, number: int, aad: bytes) -> bytes:
        shared_secret = self.kem.decapsulate(b64d(payload["kem_ct"]))
        if self.hybrid:
            peer_ephemeral = x25519.X25519PublicKey.from_public_bytes(
                b64d(payload["x_pub"])
            )
            shared_x = self.own_x25519.exchange(peer_ephemeral)  # type: ignore[union-attr]
            key = hkdf(
                shared_secret + shared_x,
                salt=self._recv_salt(),
                info=INFO_HYBRID,
            )
        else:
            key = hkdf(shared_secret, info=INFO)
        return gcm_open(key, b64d(payload["iv"]), b64d(payload["ct"]), aad)

    def describe(self) -> str:
        mode = "hybride X25519 + ML-KEM" if self.hybrid else self.kem.name
        return (
            f"{mode} + HKDF-SHA256 + AES-256-GCM\n"
            f"  moteur : {self.kem.backend}\n"
            f"  clé publique KEM : {self.kem.public_key_size} o | "
            f"chiffré KEM : {self.kem.ciphertext_size} o\n"
            f"  empreinte de la clé publique du pair : {fingerprint(self.peer_public_key)}"
        )


async def handshake(
    relay: RelayClient,
    name: str,
    peer: str,
    *,
    param: int = 768,
    hybrid: bool = False,
    timeout: float = 120.0,
    pad: bool = False,
    show_wire: bool = False,
) -> MlKemCodec:
    kem = MLKEM(param)
    kem.keygen()
    print(ui.dim(f"[{name}] {kem.describe()}"))

    message: dict = {
        "t": "hs",
        "step": "kem_pub",
        "alg": kem.name,
        "pub": b64e(kem.public_bytes()),
    }

    own_x25519 = None
    if hybrid:
        own_x25519, x_path = load_or_create_x25519(name)
        message["x_pub"] = b64e(own_x25519.public_key().public_bytes_raw())
        print(ui.dim(f"[{name}] clé X25519 statique : {x_path}"))

    await relay.send(message, to=peer)
    print(
        ui.dim(
            f"[{name}] clé publique {kem.name} envoyée "
            f"({kem.public_key_size} o, soit {kem.public_key_size * 8} bits)"
        )
    )

    env = await recv_until(
        relay,
        lambda e: from_peer(e, peer) and is_handshake(e, "kem_pub"),
        timeout=timeout,
        description=f"clé publique {kem.name} de {peer}",
        peer=peer,
    )
    payload = require_payload(env, "pub")
    peer_public = b64d(payload["pub"])
    if len(peer_public) != kem.public_key_size:
        raise HandshakeError(
            f"taille de clé publique inattendue : {len(peer_public)} o "
            f"(attendu {kem.public_key_size} o pour {kem.name}). "
            "Les deux clients utilisent-ils le même paramètre ?"
        )

    peer_x = None
    if hybrid:
        if "x_pub" not in payload:
            raise HandshakeError(
                "le pair n'a pas envoyé de clé X25519 : les deux clients "
                "doivent utiliser --hybrid"
            )
        peer_x = x25519.X25519PublicKey.from_public_bytes(b64d(payload["x_pub"]))

    print(ui.ok(f"[{name}] clé publique {kem.name} du pair reçue"))
    return MlKemCodec(
        name, peer, kem, peer_public,
        own_public_key=kem.public_bytes(),
        hybrid=hybrid, own_x25519=own_x25519, peer_x25519=peer_x,
        pad=pad, show_wire=show_wire,
    )


# ---------------------------------------------------------------------------
# Point d'entrée
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = cli.build_parser(__doc__ or "Scénario 4 : KEM/DEM ML-KEM")
    parser.add_argument(
        "--param", type=int, choices=(768, 1024), default=768,
        help="paramètre ML-KEM (défaut : 768, niveau de sécurité 3)",
    )
    parser.add_argument(
        "--hybrid", action="store_true",
        help="combiner ML-KEM avec X25519 (recommandé en pratique)",
    )
    return parser


async def _run(args: argparse.Namespace) -> None:
    relay = await cli.connect(args)
    try:
        codec = await handshake(
            relay, args.name, args.peer,
            param=args.param, hybrid=args.hybrid, timeout=args.timeout,
            pad=args.pad, show_wire=args.show_wire,
        )
        suffix = " (hybride X25519)" if args.hybrid else ""
        await chat_run(
            relay,
            codec,
            title=f"KEM/DEM {codec.kem.name}{suffix} + AES-256-GCM",
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
