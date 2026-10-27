"""Génère la clé pré-partagée du scénario 1 (à distribuer aux étudiants).

    python scripts/gen_psk.py

Le fichier créé est ``keys/lab_psk.hex``. Copiez-le sur les deux postes, ou
transmettez uniquement la valeur hexadécimale affichée (option ``--key``).
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tpcrypto.scenarios.s1_aes import generate_key  # noqa: E402


if __name__ == "__main__":
    generate_key()
