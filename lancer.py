#!/usr/bin/env python3
"""Lanceur interactif du TP crypto — pensé pour les L2.

Utilisation :

    python lancer.py

Le lanceur détecte le dossier `.venv` du projet et relance automatiquement le
script avec le bon interpréteur. Il propose un menu pour démarrer le relais,
lancer un client, le proxy MITM, le tableau de bord, les tests et les démos.

Astuce : ouvrez **trois** fenêtres de terminal et lancez `python lancer.py`
dans chacune :

- fenêtre 1 : choix 1 (le relais) ;
- fenêtre 2 : choix 2 (alice) ;
- fenêtre 3 : choix 2 (bob).
"""

from __future__ import annotations

import os
import subprocess
import sys
import webbrowser
from pathlib import Path

ROOT = Path(__file__).resolve().parent
VENV_PYTHON = ROOT / ".venv" / (
    "Scripts/python.exe" if os.name == "nt" else "bin/python"
)

MODULES = {
    "1": ("tpcrypto.scenarios.s1_aes", "Secret partagé + AES"),
    "2": ("tpcrypto.scenarios.s2_dh", "Diffie-Hellman"),
    "3": ("tpcrypto.scenarios.s3_rsa", "KEM/DEM RSA"),
    "4": ("tpcrypto.scenarios.s4_mlkem", "KEM/DEM ML-KEM"),
    "5": ("tpcrypto.scenarios.s5_signed_dh", "DH signé"),
}


def ensure_venv() -> None:
    """Relance le lanceur avec le Python du venv s'il existe."""
    if not VENV_PYTHON.exists():
        return
    try:
        same = Path(sys.executable).resolve() == VENV_PYTHON.resolve()
    except OSError:
        same = False
    if not same:
        code = subprocess.call(
            [str(VENV_PYTHON), str(Path(__file__).resolve()), *sys.argv[1:]]
        )
        raise SystemExit(code)


def check_dependencies() -> bool:
    missing = []
    for module in ("fastapi", "uvicorn", "cryptography", "websockets"):
        try:
            __import__(module)
        except ImportError:
            missing.append(module)
    if missing:
        print("\n[!] Dépendances manquantes : " + ", ".join(missing))
        print("    Installez-les avec :")
        if os.name == "nt":
            print("      .\\.venv\\Scripts\\python.exe -m pip install -r requirements.txt")
        else:
            print("      .venv/bin/python -m pip install -r requirements.txt")
        return False
    return True


def ask(prompt: str, default: str = "") -> str:
    suffix = f" [{default}]" if default else ""
    try:
        value = input(f"{prompt}{suffix} : ").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return default
    return value or default


def yes_no(prompt: str, default: bool = True) -> bool:
    value = ask(prompt + (" (O/n)" if default else " (o/N)"), "o" if default else "n")
    return value.lower().startswith("o")


def run(args: list[str]) -> None:
    print()
    try:
        subprocess.call([sys.executable, *args], cwd=ROOT)
    except KeyboardInterrupt:
        print()
    print()


def start_server() -> None:
    print("\nLe relais va démarrer. Laissez cette fenêtre ouverte.")
    print("Tableau de bord : http://127.0.0.1:8000/")
    print("Ctrl+C pour arrêter.\n")
    run(["-m", "server", "--host", "127.0.0.1", "--port", "8000"])


def start_client() -> None:
    print("\nScénarios :")
    for key, (_, label) in MODULES.items():
        print(f"  {key}) {label}")
    scenario = ask("Scénario", "2")
    if scenario not in MODULES:
        print("Scénario inconnu.")
        return
    module, label = MODULES[scenario]

    name = ask("Votre pseudo", "alice")
    peer = ask("Pseudo du pair", "bob" if name == "alice" else "alice")
    room = ask("Salon", "LAB")
    show_wire = yes_no("Afficher le trafic chiffré", True)
    use_proxy = yes_no("Passer par le proxy MITM (port 8001)", False)

    args = [
        "-m", module,
        "--name", name,
        "--peer", peer,
        "--room", room,
    ]
    if show_wire:
        args.append("--show-wire")
    if use_proxy:
        if scenario not in ("2", "5"):
            print("\n[lanceur] attention : le proxy MITM est prévu pour les")
            print("          scénarios 2 (mode dh) et 5 (mode tamper).")
        args += ["--url", "ws://127.0.0.1:8001"]

    if scenario == "1":
        mode = ask("Mode AES (ecb/cbc/ctr/gcm)", "gcm").lower()
        args += ["--mode", mode]
        if yes_no("Utiliser un IV/nonce fixe (démonstration)", False):
            args.append("--fixed-iv")
    if scenario == "3":
        bits = ask("Taille de la clé RSA (2048/3072)", "2048")
        args += ["--rsa-bits", bits]
    if scenario == "4":
        if yes_no("Mode hybride X25519 + ML-KEM", False):
            args.append("--hybrid")

    print(f"\n[launcher] {label} — {name} -> {peer} (salon {room})")
    run(args)


def start_proxy() -> None:
    print("\nModes :")
    print("  1) dh      : intercepter Diffie-Hellman (scénario 2)")
    print("  2) tamper  : altérer le handshake (scénarios 2 et 5)")
    mode = ask("Mode", "1")
    mode = "dh" if mode == "1" else "tamper"
    replay = yes_no("Ajouter un rejeu de message", False)

    args = ["-m", "tpcrypto.attacks.mitm", "--mode", mode]
    if replay:
        args.append("--replay")
    print()
    print("Pour les clients, répondez O à « Passer par le proxy MITM »")
    print("ou ajoutez : --url ws://127.0.0.1:8001")
    print("Laissez cette fenêtre ouverte. Ctrl+C pour arrêter.\n")
    run(args)


def show_demos() -> None:
    while True:
        print("\nDémonstrations :")
        print("  1) ECB vs CBC (image)")
        print("  2) réutilisation de nonce (CTR/GCM)")
        print("  3) malléabilité (CBC/CTR/GCM)")
        print("  0) retour")
        choice = ask("Choix", "0")
        if choice == "0":
            return
        module = {
            "1": "demos.ecb_visual",
            "2": "demos.nonce_reuse",
            "3": "demos.malleability",
        }.get(choice)
        if module:
            run(["-m", module])


def generate_key() -> None:
    run(["scripts/gen_psk.py"])


def main() -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
        except Exception:
            pass
    if os.name == "nt":
        os.system("")  # active les séquences ANSI sur les vieux terminaux

    ensure_venv()
    if not check_dependencies():
        return 1

    print("=" * 64)
    print("  TP CRYPTO — L2 CYBERSÉCURITÉ")
    print("  Chat chiffré de bout en bout")
    print("=" * 64)
    print(f"  Python : {sys.executable}")
    print(f"  Dossier : {ROOT}")
    print()
    print("  Il faut 3 fenêtres : le relais, alice, bob.")
    print("  Dans chaque fenêtre, lancez : python lancer.py")

    while True:
        print("\n" + "-" * 64)
        print("  1) Démarrer le relais          (fenêtre 1)")
        print("  2) Lancer un client            (fenêtres 2 et 3)")
        print("  3) Lancer le proxy MITM        (attaque)")
        print("  4) Ouvrir le tableau de bord")
        print("  5) Lancer les auto-tests")
        print("  6) Démonstrations autonomes")
        print("  7) Générer la clé du scénario 1")
        print("  0) Quitter")
        choice = ask("Votre choix", "0")

        if choice == "0":
            print("À bientôt !")
            return 0
        if choice == "1":
            start_server()
        elif choice == "2":
            start_client()
        elif choice == "3":
            start_proxy()
        elif choice == "4":
            webbrowser.open("http://127.0.0.1:8000/")
        elif choice == "5":
            run(["scripts/selftest.py"])
        elif choice == "6":
            show_demos()
        elif choice == "7":
            generate_key()
        else:
            print("Choix inconnu.")


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\nÀ bientôt !")
