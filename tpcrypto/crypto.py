"""Primitives cryptographiques et utilitaires partagés par les scénarios.

Choix pédagogiques :

- AES-256-GCM partout pour le chiffrement authentifié (AEAD) ;
- HKDF-SHA256 pour dériver des clés à partir d'un secret brut ;
- base64 pour rendre les messages JSON lisibles dans Wireshark ;
- un petit système de padding optionnel pour masquer la taille des messages.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import secrets

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# Taille d'un bloc AES, en octets.
AES_BLOCK = 16


# ---------------------------------------------------------------------------
# Encodage
# ---------------------------------------------------------------------------

def b64e(data: bytes) -> str:
    """Encode en base64 standard (avec padding), pratique dans du JSON."""
    return base64.b64encode(data).decode("ascii")


def b64d(text: str) -> bytes:
    """Décode du base64 en validant les erreurs (message clair si invalide)."""
    try:
        return base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError(f"base64 invalide : {exc}") from exc


def sha256(*parts: bytes) -> bytes:
    digest = hashlib.sha256()
    for part in parts:
        digest.update(part)
    return digest.digest()


def xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


# ---------------------------------------------------------------------------
# Dérivation de clé
# ---------------------------------------------------------------------------

def hkdf(
    ikm: bytes,
    *,
    salt: bytes | None = None,
    info: bytes = b"",
    length: int = 32,
) -> bytes:
    """HKDF-SHA256 : transforme un secret (ex. sortie DH) en clé de 256 bits.

    ``info`` sert de « contexte » : deux usages différents doivent utiliser des
    ``info`` différents pour ne jamais réutiliser la même clé.
    """
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt if salt else None,
        info=info,
    ).derive(ikm)


def fingerprint(data: bytes, groups: int = 8, group_len: int = 2) -> str:
    """Empreinte courte et lisible : ``ab12:cd34:...`` (16 octets tronqués)."""
    digest = hashlib.sha256(data).hexdigest()
    return ":".join(
        digest[i:i + group_len] for i in range(0, groups * group_len, group_len)
    )


def safety_number(first: bytes, second: bytes) -> str:
    """Code de sécurité façon Signal : 30 chiffres, identiques des deux côtés.

    Les deux clés publiques sont triées pour que l'ordre d'appel n'ait pas
    d'importance. Les étudiants doivent comparer ce code par un autre canal
    (de vive voix, au tableau...) pour détecter un MITM.
    """
    digest = sha256(b"tpcrypto/safety-number", *sorted([first, second]))
    number = int.from_bytes(digest[:16], "big") % (10 ** 30)
    text = f"{number:030d}"
    return " ".join(text[i:i + 5] for i in range(0, 30, 5))


# ---------------------------------------------------------------------------
# AES-GCM (chiffrement authentifié)
# ---------------------------------------------------------------------------

def gcm_seal(key: bytes, plaintext: bytes, aad: bytes = b"") -> tuple[bytes, bytes]:
    """Chiffre avec AES-GCM. Renvoie ``(nonce, chiffré+tag)``.

    Un nonce aléatoire de 12 octets est tiré à chaque message. Avec GCM, ne
    JAMAIS réutiliser un couple (clé, nonce) : cela casse toute la sécurité.
    """
    if len(key) not in (16, 24, 32):
        raise ValueError("clé AES invalide (16, 24 ou 32 octets attendus)")
    nonce = secrets.token_bytes(12)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, aad)
    return nonce, ciphertext


def gcm_open(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes = b"") -> bytes:
    """Déchiffre et vérifie le tag GCM.

    Lève ``InvalidTag`` si le message a été modifié, si l'AAD ne correspond pas
    ou si la clé est mauvaise. C'est le comportement que l'on veut !
    """
    return AESGCM(key).decrypt(nonce, ciphertext, aad)


__all__ = [
    "AES_BLOCK",
    "InvalidTag",
    "b64d",
    "b64e",
    "fingerprint",
    "gcm_open",
    "gcm_seal",
    "hkdf",
    "safety_number",
    "sha256",
    "xor",
]
