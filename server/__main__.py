"""Point d'entrée du relais : ``python -m server``."""

from __future__ import annotations

import argparse

import uvicorn


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        description="Relais de chat du TP crypto (WebSocket, sans chiffrement)."
    )
    parser.add_argument("--host", default="127.0.0.1",
                        help="adresse d'écoute (0.0.0.0 pour le réseau local)")
    parser.add_argument("--port", type=int, default=8000, help="port (défaut : 8000)")
    parser.add_argument("--reload", action="store_true", help="rechargement automatique")
    args = parser.parse_args(argv)

    if args.host == "0.0.0.0":
        print("[relais] attention : écoute sur toutes les interfaces. "
              "Le trafic WebSocket n'est PAS chiffré (ws://), utilisez un réseau de TP isolé.")

    uvicorn.run(
        "server.relay:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
        log_level="info",
    )


if __name__ == "__main__":
    main()
