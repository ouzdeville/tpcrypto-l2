"""Stockage local des clés d'identité (laboratoire uniquement).

Les clés sont écrites en clair dans ``keys/`` : c'est acceptable dans un TP,
mais évidemment pas en production. Le dossier peut être changé avec la
variable d'environnement ``TP_KEYS_DIR``.

Les noms de fichiers sont « assainis » pour éviter toute traversée de chemin.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa


def keys_dir() -> Path:
    path = Path(os.environ.get("TP_KEYS_DIR", "keys"))
    path.mkdir(parents=True, exist_ok=True)
    return path


def _safe_name(name: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.-]", "_", name).strip("._")
    return cleaned or "anonymous"


def _write_private(path: Path, data: bytes) -> None:
    """Écriture atomique, permissions restreintes quand le système le permet."""
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_bytes(data)
    try:
        os.chmod(tmp, 0o600)
    except OSError:
        pass
    tmp.replace(path)


def load_or_create_ed25519(name: str) -> tuple[ed25519.Ed25519PrivateKey, Path]:
    path = keys_dir() / f"id_{_safe_name(name)}_ed25519.pem"
    if path.exists():
        key = serialization.load_pem_private_key(path.read_bytes(), password=None)
        if not isinstance(key, ed25519.Ed25519PrivateKey):
            raise ValueError(f"{path} ne contient pas une clé Ed25519")
        return key, path
    key = ed25519.Ed25519PrivateKey.generate()
    _write_private(
        path,
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ),
    )
    return key, path


def load_or_create_x25519(name: str) -> tuple[object, Path]:
    """Clé X25519 statique (utilisée pour l'option hybride du scénario 4)."""
    from cryptography.hazmat.primitives.asymmetric import x25519

    path = keys_dir() / f"id_{_safe_name(name)}_x25519.pem"
    if path.exists():
        key = serialization.load_pem_private_key(path.read_bytes(), password=None)
        if not isinstance(key, x25519.X25519PrivateKey):
            raise ValueError(f"{path} ne contient pas une clé X25519")
        return key, path
    key = x25519.X25519PrivateKey.generate()
    _write_private(
        path,
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ),
    )
    return key, path


def load_or_create_rsa(name: str, bits: int = 2048) -> tuple[rsa.RSAPrivateKey, Path]:
    if bits not in (2048, 3072, 4096):
        raise ValueError("taille RSA non supportée (2048, 3072 ou 4096)")
    path = keys_dir() / f"id_{_safe_name(name)}_rsa{bits}.pem"
    if path.exists():
        key = serialization.load_pem_private_key(path.read_bytes(), password=None)
        if not isinstance(key, rsa.RSAPrivateKey):
            raise ValueError(f"{path} ne contient pas une clé RSA")
        if key.key_size != bits:
            raise ValueError(
                f"{path} contient une clé de {key.key_size} bits, {bits} attendus"
            )
        return key, path
    key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    _write_private(
        path,
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ),
    )
    return key, path


def public_key_bytes(public_key: object) -> bytes:
    """Sérialise une clé publique asymétrique en DER (SubjectPublicKeyInfo)."""
    return public_key.public_bytes(  # type: ignore[attr-defined]
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
