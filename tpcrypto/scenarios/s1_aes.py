"""Scénario 1 — Chat avec un secret pré-partagé et AES.

Objectif : comprendre l'importance du **mode opératoire**.

Les deux clients partagent la même clé AES de 256 bits (fichier ``keys/lab_psk.hex``
ou option ``--key``). On peut alors choisir :

- ``ecb`` : AES-ECB, sans IV. Montre la fuite de structure (blocs identiques) ;
- ``cbc`` : AES-CBC avec IV aléatoire (ou fixe avec ``--fixed-iv``) ;
- ``ctr`` : AES-CTR avec nonce aléatoire (ou fixe avec ``--fixed-iv``) ;
- ``gcm`` : AES-GCM, le seul mode du lot qui soit authentifié (AEAD).

Aucune négociation de clé ici : c'est le point de départ du TP. Le fichier de
clé doit être distribué par un autre canal (clé USB, ENT, au tableau...).
"""

from __future__ import annotations

import argparse
import secrets
from pathlib import Path

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .. import cli, ui
from ..chat import run as chat_run
from ..codec import Codec
from ..crypto import AES_BLOCK, b64d, b64e, fingerprint, gcm_open, gcm_seal
from ..keys import keys_dir

MODES = ("ecb", "cbc", "ctr", "gcm")
DEMO_TEXT = "BLOC-REPETE-0001" * 3 + "FIN-DU-MESSAGE!!"


# ---------------------------------------------------------------------------
# Gestion de la clé pré-partagée
# ---------------------------------------------------------------------------

def key_path() -> Path:
    return keys_dir() / "lab_psk.hex"


def load_key(explicit: str | None) -> bytes:
    if explicit:
        raw = explicit.replace(":", "").replace(" ", "").strip()
        try:
            key = bytes.fromhex(raw)
        except ValueError as exc:
            raise SystemExit(f"--key doit être de l'hexadécimal : {exc}") from exc
    else:
        path = key_path()
        if path.exists():
            try:
                key = bytes.fromhex(path.read_text(encoding="ascii").strip())
            except ValueError as exc:
                raise SystemExit(f"{path} ne contient pas de l'hexadécimal valide") from exc
        else:
            key = generate_key()
    if len(key) != 32:
        raise SystemExit(
            f"la clé doit faire 32 octets (64 caractères hex), pas {len(key)}"
        )
    return key


def generate_key() -> bytes:
    """Génère et enregistre une nouvelle clé pré-partagée (à distribuer)."""
    key = secrets.token_bytes(32)
    path = key_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(key.hex() + "\n", encoding="ascii")
    print(ui.ok(f"[clé] nouvelle clé pré-partagée générée : {path}"))
    print(ui.kv("empreinte", fingerprint(key)))
    print(ui.kv("hexadécimal", key.hex()))
    print(ui.warn(
        "      distribuez ce fichier par un canal sûr (clé USB, ENT...) : "
        "toute personne qui l'a peut lire le chat."
    ))
    return key


# ---------------------------------------------------------------------------
# Codec AES
# ---------------------------------------------------------------------------

class AesCodec(Codec):
    scenario = "s1"

    def __init__(
        self,
        name: str,
        peer: str,
        key: bytes,
        mode: str,
        *,
        fixed_iv: bool = False,
        pad: bool = False,
        show_wire: bool = False,
    ) -> None:
        super().__init__(name, peer, pad=pad, show_wire=show_wire)
        if mode not in MODES:
            raise ValueError(f"mode inconnu : {mode}")
        self.key = key
        self.mode = mode
        self.fixed_iv = fixed_iv
        self._static_iv = bytes(AES_BLOCK) if fixed_iv else None

    # -- chiffrement -------------------------------------------------------

    def _seal(self, data: bytes, number: int, aad: bytes) -> dict:
        if self.mode == "gcm":
            nonce, ciphertext = gcm_seal(self.key, data, aad)
            return {"alg": "AES-256-GCM", "iv": b64e(nonce), "ct": b64e(ciphertext)}

        if self.mode == "ecb":
            ciphertext = self._encrypt_blocks(data, modes.ECB())
            return {"alg": "AES-256-ECB", "ct": b64e(ciphertext)}

        if self.mode == "cbc":
            iv = self._static_iv or secrets.token_bytes(AES_BLOCK)
            ciphertext = self._encrypt_blocks(data, modes.CBC(iv))
            return {"alg": "AES-256-CBC", "iv": b64e(iv), "ct": b64e(ciphertext)}

        # CTR : pas de padding nécessaire (chiffrement par flux)
        nonce = self._static_iv or secrets.token_bytes(AES_BLOCK)
        encryptor = Cipher(algorithms.AES(self.key), modes.CTR(nonce)).encryptor()
        ciphertext = encryptor.update(data) + encryptor.finalize()
        return {"alg": "AES-256-CTR", "iv": b64e(nonce), "ct": b64e(ciphertext)}

    def _open(self, payload: dict, number: int, aad: bytes) -> bytes:
        if self.mode == "gcm":
            return gcm_open(self.key, b64d(payload["iv"]), b64d(payload["ct"]), aad)

        ciphertext = b64d(payload["ct"])
        if self.mode == "ecb":
            return self._decrypt_blocks(ciphertext, modes.ECB())

        if self.mode == "cbc":
            return self._decrypt_blocks(ciphertext, modes.CBC(b64d(payload["iv"])))

        decryptor = Cipher(algorithms.AES(self.key), modes.CTR(b64d(payload["iv"]))).decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()

    def _encrypt_blocks(self, data: bytes, mode: modes.Mode) -> bytes:
        padder = padding.PKCS7(128).padder()
        padded = padder.update(data) + padder.finalize()
        encryptor = Cipher(algorithms.AES(self.key), mode).encryptor()
        return encryptor.update(padded) + encryptor.finalize()

    def _decrypt_blocks(self, ciphertext: bytes, mode: modes.Mode) -> bytes:
        decryptor = Cipher(algorithms.AES(self.key), mode).decryptor()
        padded = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        return unpadder.update(padded) + unpadder.finalize()

    # -- pédagogie ---------------------------------------------------------

    def on_sent(self, payload: dict) -> None:
        if self.mode != "ecb":
            return
        ciphertext = b64d(payload["ct"])
        print(ui.warn(f"  [ECB] {ui.block_analysis(ciphertext)}"))
        ui.hex_blocks(ciphertext)

    def describe(self) -> str:
        lines = [f"AES-256-{self.mode.upper()} | empreinte de la clé : {fingerprint(self.key)}"]
        if self.mode == "ecb":
            lines.append(ui.err("  ATTENTION : ECB n'est PAS sûr (fuite de structure)."))
        elif self.mode == "cbc":
            lines.append(
                ui.warn(
                    "  CBC sans authentification : malléable, ne détecte pas les "
                    "modifications."
                )
            )
        elif self.mode == "ctr":
            lines.append(
                ui.warn(
                    "  CTR sans authentification : un nonce réutilisé casse tout."
                )
            )
        else:
            lines.append(ui.ok("  GCM : confidentialité + intégrité (AEAD)."))
        if self.fixed_iv and self.mode in ("cbc", "ctr"):
            lines.append(ui.warn("  IV/NONCE FIXE : deux messages identiques fuient !"))
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Point d'entrée
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = cli.build_parser(__doc__ or "Scénario 1 : AES à clé partagée")
    parser.add_argument("--mode", choices=MODES, default="gcm",
                        help="mode opératoire AES (défaut : gcm)")
    parser.add_argument("--key", default=None,
                        help="clé AES en hexadécimal (64 caractères) au lieu du fichier")
    parser.add_argument("--fixed-iv", action="store_true",
                        help="IV/nonce fixe (démonstration de réutilisation, CBC/CTR)")
    return parser


async def _run(args: argparse.Namespace) -> None:
    key = load_key(args.key)
    codec = AesCodec(
        args.name, args.peer, key, args.mode,
        fixed_iv=args.fixed_iv, pad=args.pad, show_wire=args.show_wire,
    )

    if args.mode == "ecb":
        print(ui.warn(
            "[!] ECB est le mode « à ne jamais utiliser ». Il chiffre chaque bloc "
            "de 16 octets indépendamment : les motifs du clair restent visibles."
        ))
    if args.fixed_iv:
        print(ui.warn("[!] IV/nonce fixe demandé : uniquement pour la démonstration."))

    ui.print_rule()
    print(ui.kv("algorithme", f"AES-256-{args.mode.upper()}"))
    print(ui.kv("clé pré-partagée", fingerprint(key)))
    print(ui.kv("fichier de clé", str(key_path())))
    ui.print_rule()

    relay = await cli.connect(args)
    try:
        await chat_run(
            relay,
            codec,
            title=f"Secret partagé + AES-256-{args.mode.upper()}",
            subtitle=codec.describe(),
            demo_text=DEMO_TEXT,
        )
    finally:
        await relay.close()


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    cli.ensure_distinct(args.name, args.peer)
    cli.run(lambda: _run(args))


if __name__ == "__main__":
    main()
