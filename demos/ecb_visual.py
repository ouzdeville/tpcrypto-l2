"""Pourquoi AES-ECB est dangereux — visualisation sans image externe.

On construit une petite « image » 128x128 en niveaux de gris, composée de blocs
de 4x4 pixels. Chaque bloc de 16 octets est donc une zone uniforme : l'image
contient beaucoup de blocs identiques (ciel, mur, fenêtres...).

On chiffre cette image :

- en ECB : les blocs identiques du clair donnent des blocs identiques chiffrés ;
  la structure de l'image reste parfaitement visible ;
- en CBC avec IV fixe : le chaînage casse la répétition, l'image devient du bruit.

L'expérience se lit entièrement dans le terminal, sans dépendance graphique.

    python -m demos.ecb_visual
"""

from __future__ import annotations

import argparse
import secrets

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from tpcrypto import ui

GRID_SIZE = 32          # 32 x 32 blocs
BLOCK_PIXELS = 4        # chaque bloc fait 4 x 4 pixels

# Une petite scène : ciel, soleil, maison, fenêtres identiques, arbre, sol.
SCENE = [
    "................................",
    "................................",
    "..........................******",
    "........................********",
    "........................********",
    "..........................******",
    "................................",
    "................................",
    "..............^^^^^^^^..........",
    "............^^^^^^^^^^^^........",
    "..........^^^^^^^^^^^^^^^^......",
    "........^^^^^^^^^^^^^^^^^^^^....",
    "........################........",
    "........#..............#........",
    "........#..WW....WW....#....TT..",
    "........#..WW....WW....#...TTTT.",
    "........#..............#..TTTTTT",
    "........#..............#..TTTTTT",
    "........#....DDDD......#...TTTT.",
    "........#....DDDD......#....TT..",
    "........#....DDDD......#....TT..",
    "........#....DDDD......#....TT..",
    "........#..............#....TT..",
    "........################....TT..",
    "............................TT..",
    "............................TT..",
    "............................TT..",
    "________________________________",
    "________________________________",
    "::::::::::::::::::::::::::::::::",
    "::::::::::::::::::::::::::::::::",
    "::::::::::::::::::::::::::::::::",
]

SHADES = {
    ".": 200,   # ciel clair
    ":": 120,   # herbe sombre
    "_": 90,    # sol
    "*": 250,   # soleil
    "^": 70,    # toit
    "#": 150,   # mur
    "W": 40,    # fenêtre
    "D": 60,    # porte
    "T": 30,    # arbre
}


def build_image() -> bytes:
    """Construit la scène sous forme de tuiles de 4x4 pixels.

    Chaque tuile contient 16 pixels de la même nuance, soit exactement 16
    octets : un bloc AES. On peut ainsi afficher un caractère par bloc sans
    décalage entre la géométrie de l'image et celle des blocs.
    """
    if len(SCENE) != GRID_SIZE or any(len(row) != GRID_SIZE for row in SCENE):
        raise RuntimeError("la scène doit être une grille 32 x 32")
    data = bytearray()
    for row in SCENE:
        for symbol in row:
            data += bytes([SHADES[symbol]]) * 16
    return bytes(data)


def blocks(data: bytes) -> list[bytes]:
    return [data[i:i + 16] for i in range(0, len(data), 16)]


def encrypt_ecb(key: bytes, data: bytes) -> bytes:
    encryptor = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return encryptor.update(data) + encryptor.finalize()


def encrypt_cbc(key: bytes, data: bytes, iv: bytes) -> bytes:
    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return encryptor.update(data) + encryptor.finalize()


PALETTE = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"


def render_mapping(ciphertext: bytes) -> list[str]:
    """Attribue un caractère à chaque bloc *unique* (les doublons sont visibles)."""
    mapping: dict[bytes, str] = {}
    symbols: list[str] = []
    for block in blocks(ciphertext):
        if block not in mapping:
            mapping[block] = PALETTE[len(mapping) % len(PALETTE)]
        symbols.append(mapping[block])
    return symbols


def render_noise(ciphertext: bytes) -> list[str]:
    """Rendu pseudo-aléatoire : un caractère dérivé du bloc (pour CBC)."""
    symbols = []
    for block in blocks(ciphertext):
        value = int.from_bytes(block[:2], "big")
        symbols.append(PALETTE[value % len(PALETTE)])
    return symbols


def print_grid(symbols: list[str], title: str, note: str = "") -> None:
    print()
    print(ui.title(title))
    if note:
        print(ui.dim(note))
    for y in range(GRID_SIZE):
        row = "".join(symbols[y * GRID_SIZE:(y + 1) * GRID_SIZE])
        print("  " + row)


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Démonstration AES-ECB vs AES-CBC")
    parser.add_argument("--key", default=None, help="clé AES en hexadécimal (64 caractères)")
    args = parser.parse_args(argv)

    key = bytes.fromhex(args.key) if args.key else secrets.token_bytes(32)
    if len(key) != 32:
        raise SystemExit("la clé doit faire 32 octets")

    plaintext = build_image()
    plain_blocks = blocks(plaintext)
    unique_plain = len(set(plain_blocks))

    ecb = encrypt_ecb(key, plaintext)
    cbc = encrypt_cbc(key, plaintext, bytes(16))

    unique_ecb = len(set(blocks(ecb)))
    unique_cbc = len(set(blocks(cbc)))

    ui.banner([
        "AES-ECB vs AES-CBC — fuite de structure",
        f"scène {GRID_SIZE}x{GRID_SIZE} tuiles de {BLOCK_PIXELS}x{BLOCK_PIXELS} px "
        f"(1 tuile = 1 bloc de 16 octets)",
        f"{len(plain_blocks)} blocs au total, {unique_plain} blocs de clair uniques",
    ])

    print_grid(
        list("".join(SCENE)),
        "1. IMAGE EN CLAIR (un caractère = une tuile de 4x4 pixels = 1 bloc AES)",
        "Les zones uniformes sont répétées : c'est inévitable dans une image.",
    )

    print_grid(
        render_mapping(ecb),
        "2. CHIFFREMENT ECB — chaque bloc est chiffré indépendamment",
        f"{unique_ecb} bloc(s) chiffré(s) unique(s) sur {len(plain_blocks)} : "
        "la scène reste reconnaissable !",
    )

    print_grid(
        render_noise(cbc),
        "3. CHIFFREMENT CBC avec IV fixe — chaînage des blocs",
        f"{unique_cbc} bloc(s) chiffré(s) unique(s) : le motif a disparu.",
    )

    print()
    print(ui.rule())
    print(ui.warn(
        "ECB ne cache que la valeur des blocs, pas leur organisation. "
        "Sur une photo, un logo ou un formulaire, l'attaquant lit la structure."
    ))
    print(ui.info(
        "CBC masque les motifs mais reste non authentifié (malléable) : "
        "préférez AES-GCM en pratique."
    ))
    print(ui.dim(
        f"Doublons ECB : {len(plain_blocks) - unique_ecb} blocs identiques ; "
        f"doublons CBC : {len(plain_blocks) - unique_cbc}."
    ))


if __name__ == "__main__":
    main()
