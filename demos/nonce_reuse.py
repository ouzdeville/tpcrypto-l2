"""Réutilisation de nonce : la faille qui casse AES-CTR et AES-GCM.

En CTR (et donc en GCM, qui utilise CTR en interne), chiffrer deux messages
avec la même clé ET le même nonce réutilise exactement le même flux de clé :

    c1 = p1 XOR ks        c2 = p2 XOR ks
    c1 XOR c2 = p1 XOR p2

Si l'attaquant connaît un des deux messages (ou devine une partie), il récupère
l'autre. Ce script le montre sur deux messages, puis compare avec des nonces
aléatoires.

    python -m demos.nonce_reuse
"""

from __future__ import annotations

import argparse
import secrets

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from tpcrypto import ui
from tpcrypto.crypto import xor

MESSAGE_1 = b"RENDEZ-VOUS A 18H DEVANT LA GARE"
MESSAGE_2 = b"LE CODE DU COFFRE EST 4271 OK!!"
TAG_SIZE = 16


def ctr(key: bytes, nonce: bytes, data: bytes) -> bytes:
    encryptor = Cipher(algorithms.AES(key), modes.CTR(nonce)).encryptor()
    return encryptor.update(data) + encryptor.finalize()


def recover(known: bytes, ciphertext_known: bytes, ciphertext_secret: bytes) -> bytes:
    """Attaque à texte clair connu : p2 = c1 XOR c2 XOR p1."""
    return xor(xor(ciphertext_known, ciphertext_secret), known)


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Démonstration de réutilisation de nonce")
    parser.parse_args(argv)

    key = secrets.token_bytes(32)
    nonce = b"\x00" * 16

    p1 = MESSAGE_1.ljust(len(MESSAGE_2), b" ")
    p2 = MESSAGE_2.ljust(len(p1), b" ")

    c1 = ctr(key, nonce, p1)
    c2 = ctr(key, nonce, p2)
    leaked = xor(c1, c2)

    ui.banner([
        "RÉUTILISATION DE NONCE — AES-CTR",
        "Même clé, même nonce, deux messages différents",
    ])
    print(ui.kv("message 1 (connu)", p1.decode()))
    print(ui.kv("message 2 (secret)", p2.decode()))
    print(ui.kv("c1 XOR c2", leaked.hex()))
    print(ui.kv("p1 XOR p2", xor(p1, p2).hex()))
    print()
    print(ui.ok("Les deux valeurs sont identiques : le flux de clé s'annule."))
    print(ui.err(f"Message 2 retrouvé : {recover(p1, c1, c2).decode()!r}"))

    # ------------------------------------------------------------------
    # Comparaison avec des nonces aléatoires
    # ------------------------------------------------------------------
    n1 = secrets.token_bytes(16)
    n2 = secrets.token_bytes(16)
    r1 = ctr(key, n1, p1)
    r2 = ctr(key, n2, p2)
    attempt = recover(p1, r1, r2)

    print()
    print(ui.title("Avec un nonce aléatoire par message :"))
    print(ui.kv("tentative de récupération", repr(attempt.decode(errors="replace"))))
    print(ui.ok("Aucune information sur le message 2 : l'attaque échoue."))

    # ------------------------------------------------------------------
    # GCM : même problème pour la confidentialité
    # ------------------------------------------------------------------
    print()
    print(ui.title("Et avec AES-GCM ?"))
    gcm_nonce = secrets.token_bytes(12)
    g1 = AESGCM(key).encrypt(gcm_nonce, p1, b"")
    g2 = AESGCM(key).encrypt(gcm_nonce, p2, b"")
    xored = xor(g1[:-TAG_SIZE], g2[:-TAG_SIZE])
    print(ui.kv("c1 XOR c2 (hors tag)", xored.hex()))
    print(ui.kv("p1 XOR p2", xor(p1, p2).hex()))
    if xored == xor(p1, p2):
        print(ui.err(
            "GCM n'échappe pas à la règle : réutiliser un nonce casse aussi la "
            "confidentialité (et permet des falsifications)."
        ))
        print(ui.warn(
            "La bibliothèque ne vous avertit pas : la gestion des nonces est "
            "de VOTRE responsabilité. Utilisez un compteur ou os.urandom(12)."
        ))

    print()
    print(ui.rule())
    print(ui.info(
        "Règle d'or : pour une clé donnée, un nonce ne doit JAMAIS servir deux fois."
    ))


if __name__ == "__main__":
    main()
