"""Malléabilité : modifier un message chiffré sans connaître la clé.

Trois cas, avec le même message :

- **CBC** : l'IV n'est pas authentifié. En modifiant l'IV, on change le premier
  bloc du clair à volonté, sans clé et sans corruption ;
- **CTR** : le chiffré est un simple XOR avec un flux de clé. Modifier un octet
  du chiffré modifie le même octet du clair ;
- **GCM** : la modification est détectée par le tag, le déchiffrement échoue.

    python -m demos.malleability
"""

from __future__ import annotations

import secrets

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from tpcrypto import ui
from tpcrypto.crypto import xor

ORIGINAL = b"VIREMENT: 100 EUR VERS ALICE".ljust(48, b" ")


def show(label: str, data: bytes) -> None:
    printable = "".join(chr(b) if 32 <= b < 127 else "." for b in data)
    print(f"  {ui.dim(label)} {printable!r}")


def main() -> None:
    key = secrets.token_bytes(32)
    iv = secrets.token_bytes(16)

    ui.banner([
        "MALLÉABILITÉ — modifier un message sans la clé",
        "Le message : un ordre de virement",
    ])

    # ------------------------------------------------------------------
    # CBC : on modifie l'IV (transmis en clair avec le message)
    # ------------------------------------------------------------------
    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    cbc = encryptor.update(ORIGINAL) + encryptor.finalize()

    # On veut transformer "100" en "900" dans le premier bloc.
    mask = xor(b"100", b"900")
    tampered_iv = bytearray(iv)
    for offset, value in enumerate(mask):
        tampered_iv[10 + offset] ^= value

    decryptor = Cipher(algorithms.AES(key), modes.CBC(bytes(tampered_iv))).decryptor()
    forged = decryptor.update(cbc) + decryptor.finalize()

    print()
    print(ui.title("1. AES-CBC : l'IV n'est pas authentifié"))
    show("clair   :", ORIGINAL)
    show("forgé   :", forged)
    print(ui.err(
        "  L'attaquant a changé « 100 » en « 900 » en ne modifiant QUE l'IV, "
        "sans la clé et sans introduire d'erreur visible."
    ))
    print(ui.dim(
        "  Pour modifier un bloc suivant, on altère le bloc chiffré précédent : "
        "le bloc précédent devient illisible, mais le bloc visé change."
    ))

    # ------------------------------------------------------------------
    # CTR : bit-flipping direct
    # ------------------------------------------------------------------
    nonce = secrets.token_bytes(16)
    encryptor = Cipher(algorithms.AES(key), modes.CTR(nonce)).encryptor()
    ctr = bytearray(encryptor.update(ORIGINAL) + encryptor.finalize())
    for offset, value in enumerate(mask):
        ctr[10 + offset] ^= value
    decryptor = Cipher(algorithms.AES(key), modes.CTR(nonce)).decryptor()
    forged_ctr = decryptor.update(bytes(ctr)) + decryptor.finalize()

    print()
    print(ui.title("2. AES-CTR : bit-flipping, encore plus simple"))
    show("clair   :", ORIGINAL)
    show("forgé   :", forged_ctr)
    print(ui.err(
        "  Un simple XOR sur le chiffré suffit : aucun contrôle d'intégrité."
    ))

    # ------------------------------------------------------------------
    # GCM : le tag protège
    # ------------------------------------------------------------------
    gcm_nonce = secrets.token_bytes(12)
    sealed = AESGCM(key).encrypt(gcm_nonce, ORIGINAL, b"virement")
    tampered = bytearray(sealed)
    for offset, value in enumerate(mask):
        tampered[10 + offset] ^= value

    print()
    print(ui.title("3. AES-GCM : l'altération est détectée"))
    try:
        AESGCM(key).decrypt(gcm_nonce, bytes(tampered), b"virement")
    except InvalidTag:
        print(ui.ok(
            "  InvalidTag : le destinataire refuse le message. "
            "Aucune modification n'est possible sans la clé."
        ))
    else:
        raise AssertionError("GCM aurait dû rejeter le message altéré")

    print()
    print(ui.rule())
    print(ui.info(
        "Leçon : confidentialité sans intégrité ne suffit pas. "
        "Utilisez un AEAD (GCM, ChaCha20-Poly1305) ou chiffrez puis MAC-ez."
    ))


if __name__ == "__main__":
    main()
