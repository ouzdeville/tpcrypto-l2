"""Boucle de chat en ligne de commande, partagée par tous les scénarios.

Le chat ne connaît que deux opérations : ``codec.seal(texte)`` pour envoyer et
``codec.open(payload)`` pour recevoir. Toute la cryptographie est donc dans le
codec du scénario : c'est exactement le point pédagogique du TP.

Commandes disponibles :

    /help     aide
    /fp       empreintes / algorithmes en cours
    /wire     afficher ou masquer les enveloppes chiffrées
    /demo     envoyer un message structuré (utile pour ECB)
    /quit     quitter
"""

from __future__ import annotations

import asyncio

from . import ui
from .codec import Codec
from .net import ConnectionClosed, RelayClient


class QuitChat(Exception):
    """Signal interne pour sortir proprement de la boucle."""


HELP = """\
Commandes :
  /help   affiche cette aide
  /fp     empreintes, algorithmes et tailles de clés
  /wire   affiche/masque le trafic chiffré (payload JSON)
  /demo   envoie un message structuré (montre les fuites ECB)
  /quit   quitte le chat (ou Ctrl+C)
Tout le reste est envoyé comme message chiffré au pair.
"""


async def run(
    relay: RelayClient,
    codec: Codec,
    *,
    title: str,
    subtitle: str | None = None,
    demo_text: str | None = None,
) -> None:
    lines = [
        f"SCÉNARIO : {title}",
        f"{codec.name}  -->  {codec.peer}      salon : {relay.room}",
    ]
    if subtitle:
        lines.extend(subtitle.splitlines())
    ui.banner(lines)
    print(ui.dim("Tapez /help pour les commandes, /quit pour quitter."))
    print()

    recv_task = asyncio.create_task(_receive_loop(relay, codec), name="recv")
    try:
        await _input_loop(relay, codec, demo_text)
    finally:
        recv_task.cancel()
        try:
            await recv_task
        except (asyncio.CancelledError, Exception):
            pass
        codec.close()
        await relay.close()


async def _receive_loop(relay: RelayClient, codec: Codec) -> None:
    while True:
        try:
            env = await relay.recv()
        except ConnectionClosed as exc:
            print()
            print(ui.err(f"[net] connexion fermée par le serveur (code {exc.code})."))
            return
        except Exception as exc:  # JSON invalide, etc.
            print(ui.err(f"[net] erreur de réception : {exc}"))
            return

        kind = env.get("kind")
        if kind == "presence":
            name = env.get("name")
            if name == codec.peer:
                event = "a rejoint" if env.get("event") == "join" else "a quitté"
                print(ui.dim(f"* {name} {event} le salon"))
            continue
        if kind == "error":
            print(ui.err(f"[serveur] {env.get('error')}"))
            continue
        if kind != "msg":
            continue
        if env.get("from") != codec.peer:
            # message d'un autre participant du salon : ignoré
            continue
        payload = env.get("payload") or {}
        if payload.get("t") != "msg":
            continue
        text = codec.open(payload)
        if text is not None:
            print(f"{ui.peer(codec.peer)}: {text}")


async def _input_loop(relay: RelayClient, codec: Codec, demo_text: str | None) -> None:
    while True:
        try:
            line = await asyncio.to_thread(input, ui.me(f"{codec.name}> "))
        except (EOFError, KeyboardInterrupt):
            print()
            return
        line = line.strip()
        if not line:
            continue
        if line.startswith("/"):
            try:
                await _handle_command(line, relay, codec, demo_text)
            except QuitChat:
                print(ui.dim("à bientôt !"))
                return
            except Exception as exc:
                print(ui.err(f"commande impossible : {exc}"))
            continue
        try:
            await _send(relay, codec, line)
        except ConnectionClosed:
            print(ui.err("[net] impossible d'envoyer : connexion fermée."))
            return


async def _handle_command(
    line: str,
    relay: RelayClient,
    codec: Codec,
    demo_text: str | None,
) -> None:
    command = line.split(maxsplit=1)[0].lower()
    if command in ("/quit", "/q", "/exit"):
        raise QuitChat
    if command == "/help":
        print(HELP)
        return
    if command == "/fp":
        description = codec.describe()
        print(description if description else ui.dim("(pas d'empreinte disponible)"))
        return
    if command == "/wire":
        codec.show_wire = not codec.show_wire
        state = "activé" if codec.show_wire else "désactivé"
        print(ui.info(f"affichage du trafic chiffré : {state}"))
        return
    if command == "/demo":
        if not demo_text:
            print(ui.warn("pas de démo disponible dans ce scénario"))
            return
        await _send(relay, codec, demo_text)
        if codec.scenario == "s1":
            print(
                ui.dim(
                    "  ^ message construit avec des blocs de 16 octets répétés. "
                    "En ECB, regardez les blocs identiques."
                )
            )
        return
    print(ui.warn(f"commande inconnue : {command} (essayez /help)"))


async def _send(relay: RelayClient, codec: Codec, text: str) -> None:
    payload = codec.seal(text)
    await relay.send(payload, to=codec.peer)
    print(f"{ui.me('moi')}: {text}")


__all__ = ["HELP", "QuitChat", "run"]
