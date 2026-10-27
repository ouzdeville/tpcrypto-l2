"""Utilitaires communs aux scripts de scénario (arguments, connexion, erreurs)."""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
from typing import Awaitable, Callable

from . import ui
from .net import ConnectionClosed, HandshakeError, RelayClient

DEFAULT_URL = os.environ.get("TP_URL", "ws://127.0.0.1:8000")


def build_parser(description: str) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=description,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Exemple :\n"
            "  python -m tpcrypto.scenarios.s2_dh --name alice --peer bob\n"
            "  python -m tpcrypto.scenarios.s2_dh --name bob   --peer alice\n"
            "\n"
            "Variables d'environnement : TP_URL (URL du relais), "
            "TP_KEYS_DIR (dossier des clés), NO_COLOR=1."
        ),
    )
    parser.add_argument(
        "--url", default=DEFAULT_URL,
        help=f"URL WebSocket du relais (défaut : {DEFAULT_URL})",
    )
    parser.add_argument("--room", default="LAB", help="salon de discussion (défaut : LAB)")
    parser.add_argument("--name", required=True, help="votre pseudo (ex. alice)")
    parser.add_argument("--peer", required=True, help="pseudo du destinataire (ex. bob)")
    parser.add_argument(
        "--show-wire", action="store_true",
        help="afficher les enveloppes chiffrées échangées (comme Wireshark)",
    )
    parser.add_argument(
        "--pad", action="store_true",
        help="compléter les messages à 256 octets pour masquer leur longueur",
    )
    parser.add_argument(
        "--timeout", type=float, default=120.0,
        help="délai maximal du handshake, en secondes (défaut : 120)",
    )
    return parser


async def connect(args: argparse.Namespace) -> RelayClient:
    return await RelayClient.connect(args.url, args.room, args.name)


def run(factory: Callable[[], Awaitable[None]]) -> None:
    """Exécute un scénario et transforme les erreurs en messages lisibles."""
    try:
        asyncio.run(factory())
    except KeyboardInterrupt:
        print()
        print(ui.dim("interrompu par l'utilisateur."))
    except HandshakeError as exc:
        print()
        print(ui.err(f"[handshake] {exc}"))
        raise SystemExit(2)
    except ConnectionClosed as exc:
        print()
        print(ui.err(f"[net] connexion fermée (code {exc.code}, raison {exc.reason!r})."))
        raise SystemExit(3)
    except (ConnectionError, OSError) as exc:
        print()
        print(ui.err(f"[net] {exc}"))
        raise SystemExit(3)
    except ValueError as exc:
        print(ui.err(f"[configuration] {exc}"))
        raise SystemExit(2)


def ensure_distinct(name: str, peer: str) -> None:
    if name == peer:
        raise SystemExit("--name et --peer doivent être différents.")
    if not name.strip() or not peer.strip():
        raise SystemExit("--name et --peer ne peuvent pas être vides.")


def print_banner(title: str, lines: list[str] | None = None) -> None:
    ui.banner([title, *(lines or [])])


__all__ = [
    "DEFAULT_URL",
    "build_parser",
    "connect",
    "ensure_distinct",
    "print_banner",
    "run",
]
