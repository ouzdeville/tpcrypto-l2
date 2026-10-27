"""Client WebSocket du relais central.

Le serveur ne fait que relayer des enveloppes JSON. Il ne connaît ni les clés
ni le contenu clair : tout le chiffrement est fait par les clients (bout en
bout).

Format d'une enveloppe reçue du serveur :

    {
      "kind": "msg",
      "id": "3f2a...",
      "ts": 1712345678.12,
      "room": "LAB",
      "from": "alice",
      "to": "bob",
      "payload": { ... }          # <- chiffré, opaque pour le serveur
    }

Le client envoie simplement ``{"to": "bob", "payload": {...}}``.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any, Callable
from urllib.parse import quote

try:  # websockets >= 12 : nouvelle implémentation asyncio
    from websockets.asyncio.client import connect as _ws_connect
except ImportError:  # pragma: no cover - très vieilles versions
    from websockets import connect as _ws_connect  # type: ignore[no-redef]

from websockets.exceptions import ConnectionClosed

from . import ui


class HandshakeError(RuntimeError):
    """Erreur de négociation de clé (signature invalide, timeout, etc.)."""


class RelayClient:
    """Petit client de chat : envoyer une enveloppe, en recevoir une."""

    def __init__(self, ws: Any, room: str, name: str, url: str) -> None:
        self.ws = ws
        self.room = room
        self.name = name
        self.url = url
        self._closed = False

    # -- connexion ---------------------------------------------------------

    @classmethod
    async def connect(
        cls,
        url: str,
        room: str,
        name: str,
        *,
        timeout: float = 10.0,
    ) -> "RelayClient":
        base = url.rstrip("/")
        uri = f"{base}/ws/{quote(room, safe='')}/{quote(name, safe='')}"
        try:
            ws = await asyncio.wait_for(
                _ws_connect(
                    uri,
                    compression=None,   # pas de compression : Wireshark doit voir le JSON
                    max_size=16 * 1024 * 1024,
                    open_timeout=timeout,
                ),
                timeout=timeout + 2,
            )
        except (OSError, asyncio.TimeoutError) as exc:
            raise ConnectionError(
                f"impossible de joindre le relais {uri} ({exc}).\n"
                "Le serveur est-il démarré ? (python -m server)"
            ) from exc
        client = cls(ws, room, name, base)
        print(ui.ok(f"[net] connecté à {base} (salon '{room}', nom '{name}')"))
        return client

    # -- envoi / réception -------------------------------------------------

    async def send(self, payload: dict, to: str | None = None) -> None:
        message = json.dumps(
            {"to": to, "payload": payload},
            ensure_ascii=False,
            separators=(",", ":"),
        )
        await self.ws.send(message)

    async def recv(self) -> dict:
        raw = await self.ws.recv()
        if isinstance(raw, bytes):  # ne devrait pas arriver : on n'envoie que du texte
            raw = raw.decode("utf-8", errors="replace")
        return json.loads(raw)

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            await self.ws.close()
        except Exception:
            pass

    def __repr__(self) -> str:
        return f"RelayClient(name={self.name!r}, room={self.room!r})"


# ---------------------------------------------------------------------------
# Aides à la négociation
# ---------------------------------------------------------------------------

def env_payload(env: dict) -> dict:
    return env.get("payload") or {}


def is_handshake(env: dict, step: str | None = None) -> bool:
    payload = env_payload(env)
    if env.get("kind") != "msg" or payload.get("t") != "hs":
        return False
    return step is None or payload.get("step") == step


def from_peer(env: dict, peer: str) -> bool:
    return env.get("from") == peer


async def recv_until(
    relay: RelayClient,
    predicate: Callable[[dict], bool],
    *,
    timeout: float = 120.0,
    description: str = "message attendu",
    peer: str | None = None,
    show_presence: bool = True,
) -> dict:
    """Attend la première enveloppe qui satisfait ``predicate``.

    Les messages de présence et les erreurs du serveur sont affichés puis
    ignorés. Si ``peer`` est fourni et quitte le salon pendant l'attente, on
    interrompt immédiatement le handshake au lieu de laisser l'utilisateur
    attendre le timeout.
    """
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while True:
        remaining = deadline - loop.time()
        if remaining <= 0:
            raise HandshakeError(
                f"délai dépassé en attendant {description} ({timeout:.0f} s).\n"
                "Vérifiez que le pair est bien lancé, dans le même salon, "
                "et que les deux utilisent le même scénario."
            )
        try:
            env = await asyncio.wait_for(relay.recv(), timeout=remaining)
        except asyncio.TimeoutError as exc:
            raise HandshakeError(
                f"délai dépassé en attendant {description} ({timeout:.0f} s)."
            ) from exc

        kind = env.get("kind")
        if kind == "presence":
            if show_presence:
                event = "a rejoint" if env.get("event") == "join" else "a quitté"
                print(ui.dim(f"* {env.get('name')} {event} le salon"))
            if (
                peer is not None
                and env.get("event") == "leave"
                and env.get("name") == peer
            ):
                raise HandshakeError(
                    f"{peer} a quitté le salon pendant la négociation. "
                    "Relancez les deux clients (même scénario, même salon)."
                )
            continue
        if kind == "error":
            print(ui.err(f"[serveur] {env.get('error')}"))
            continue
        if kind == "msg":
            if predicate(env):
                return env
            payload = env_payload(env)
            if payload.get("t") == "msg":
                print(
                    ui.warn(
                        "[handshake] message de chat reçu avant la fin de la "
                        "négociation : ignoré"
                    )
                )
            continue
        # type inconnu : on ignore
    # unreachable


def require_payload(env: dict, *fields: str) -> dict:
    payload = env_payload(env)
    for field in fields:
        if field not in payload:
            raise HandshakeError(f"champ manquant dans le message : {field!r}")
    return payload


__all__ = [
    "ConnectionClosed",
    "HandshakeError",
    "RelayClient",
    "env_payload",
    "from_peer",
    "is_handshake",
    "recv_until",
    "require_payload",
]
