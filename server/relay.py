"""Relais de chat central (FastAPI + WebSocket).

Rôle du serveur : router des **enveloppes JSON** entre les participants d'un
salon. Il ne possède aucune clé et ne peut pas lire le contenu : le chiffrement
est fait de bout en bout par les clients.

Le serveur conserve :

- la liste des participants par salon ;
- une file de messages hors ligne (pour ne pas perdre les messages de
  handshake quand le pair n'est pas encore connecté) ;
- un journal des enveloppes, exposé sur ``/api/log`` et affiché en direct sur
  le tableau de bord ``/`` (la « vue serveur »).

Lancer avec :

    python -m server --host 127.0.0.1 --port 8000

ou :

    uvicorn server.relay:app --reload --port 8000
"""

from __future__ import annotations

import json
import time
import uuid
from collections import defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path

from fastapi import FastAPI, Query, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse

MAX_QUEUE = 200
MAX_LOG = 2000
MAX_PAYLOAD_BYTES = 4 * 1024 * 1024

DASHBOARD = Path(__file__).with_name("dashboard.html")


@dataclass
class Client:
    name: str
    room: str
    ws: WebSocket


@dataclass
class Hub:
    rooms: dict[str, dict[str, Client]] = field(
        default_factory=lambda: defaultdict(dict)
    )
    queues: dict[tuple[str, str], deque[dict]] = field(
        default_factory=lambda: defaultdict(lambda: deque(maxlen=MAX_QUEUE))
    )
    log: deque[dict] = field(default_factory=lambda: deque(maxlen=MAX_LOG))
    stats: dict[str, int] = field(
        default_factory=lambda: {"messages": 0, "queued": 0, "rejected": 0}
    )

    # -- connexion ---------------------------------------------------------

    async def handle(self, ws: WebSocket, room: str, name: str) -> None:
        await ws.accept()

        if name in self.rooms[room]:
            await ws.send_json(
                {
                    "kind": "error",
                    "error": (
                        f"le nom '{name}' est déjà utilisé dans le salon '{room}'. "
                        "Attendez quelques secondes ou choisissez un autre nom."
                    ),
                }
            )
            await ws.close(code=4009, reason="name already used")
            self.stats["rejected"] += 1
            return

        client = Client(name=name, room=room, ws=ws)
        self.rooms[room][name] = client
        print(f"[relais] + {name} dans {room} ({len(self.rooms[room])} participant(s))")

        await self.broadcast_presence(room, "join", name, exclude=name)

        # Messages en attente (handshake arrivé avant que le pair se connecte).
        queue_key = (room, name)
        if self.queues[queue_key]:
            pending = len(self.queues[queue_key])
            print(f"[relais] {pending} message(s) en attente pour {name}")
            while self.queues[queue_key]:
                envelope = self.queues[queue_key].popleft()
                try:
                    await ws.send_json(envelope)
                except Exception:
                    self.queues[queue_key].appendleft(envelope)
                    break

        try:
            while True:
                raw = await ws.receive_text()
                if len(raw) > MAX_PAYLOAD_BYTES:
                    await ws.send_json(
                        {"kind": "error", "error": "enveloppe trop volumineuse"}
                    )
                    continue
                await self.on_message(client, raw)
        except WebSocketDisconnect:
            pass
        except Exception as exc:  # noqa: BLE001 - on ne veut jamais tuer le relais
            print(f"[relais] erreur avec {name} : {type(exc).__name__}: {exc}")
        finally:
            self.rooms[room].pop(name, None)
            print(f"[relais] - {name} a quitté {room}")
            await self.broadcast_presence(room, "leave", name)
            if not self.rooms[room]:
                self.rooms.pop(room, None)

    # -- routage -----------------------------------------------------------

    async def on_message(self, client: Client, raw: str) -> None:
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            await self._send_error(client.ws, "JSON invalide")
            return
        if not isinstance(data, dict):
            await self._send_error(client.ws, "enveloppe invalide")
            return

        payload = data.get("payload")
        to = data.get("to")
        if not isinstance(payload, dict):
            await self._send_error(client.ws, "champ 'payload' manquant ou invalide")
            return
        if to is not None and (not isinstance(to, str) or not to):
            await self._send_error(client.ws, "champ 'to' invalide")
            return

        envelope = {
            "kind": "msg",
            "id": uuid.uuid4().hex[:10],
            "ts": time.time(),
            "room": client.room,
            "from": client.name,
            "to": to,
            "payload": payload,
        }
        self.log.append(envelope)
        self.stats["messages"] += 1

        if to is not None:
            target = self.rooms[client.room].get(to)
            if target is not None:
                if not await self._safe_send(target, envelope):
                    self.rooms[client.room].pop(to, None)
            else:
                self.queues[(client.room, to)].append(envelope)
                self.stats["queued"] += 1
                print(f"[relais] message pour {to} mis en attente (hors ligne)")
            return

        # Diffusion à tout le salon sauf l'expéditeur.
        for other in list(self.rooms.get(client.room, {}).values()):
            if other.name != client.name:
                if not await self._safe_send(other, envelope):
                    self.rooms[client.room].pop(other.name, None)

    async def _safe_send(self, client: Client, envelope: dict) -> bool:
        try:
            await client.ws.send_json(envelope)
            return True
        except Exception:
            return False

    async def _send_error(self, ws: WebSocket, message: str) -> None:
        try:
            await ws.send_json({"kind": "error", "error": message})
        except Exception:
            pass

    async def broadcast_presence(
        self, room: str, event: str, name: str, *, exclude: str | None = None
    ) -> None:
        envelope = {
            "kind": "presence",
            "event": event,
            "name": name,
            "room": room,
            "ts": time.time(),
        }
        for other in list(self.rooms.get(room, {}).values()):
            if exclude is not None and other.name == exclude:
                continue
            if not await self._safe_send(other, envelope):
                self.rooms[room].pop(other.name, None)


hub = Hub()
app = FastAPI(
    title="TP Crypto — relais de chat",
    description=(
        "Relais d'enveloppes chiffrées. Le serveur ne voit jamais le clair ; "
        "il ne sert qu'à router les messages entre les clients."
    ),
    version="1.0.0",
)


# ---------------------------------------------------------------------------
# WebSocket
# ---------------------------------------------------------------------------

@app.websocket("/ws/{room}/{name}")
async def websocket_endpoint(ws: WebSocket, room: str, name: str) -> None:
    await hub.handle(ws, room, name)


# ---------------------------------------------------------------------------
# API d'observation (tableau de bord)
# ---------------------------------------------------------------------------

@app.get("/api/state")
async def api_state() -> JSONResponse:
    return JSONResponse(
        {
            "rooms": [
                {"room": room, "members": sorted(clients.keys())}
                for room, clients in sorted(hub.rooms.items())
            ],
            "stats": hub.stats,
            "log_size": len(hub.log),
        }
    )


@app.get("/api/log")
async def api_log(
    room: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
) -> JSONResponse:
    entries = [
        entry for entry in hub.log if room is None or entry["room"] == room
    ]
    return JSONResponse(entries[-limit:])


@app.delete("/api/log")
async def api_log_clear() -> JSONResponse:
    hub.log.clear()
    return JSONResponse({"ok": True})


@app.get("/api/health")
async def health() -> JSONResponse:
    return JSONResponse({"ok": True, "rooms": len(hub.rooms)})


@app.get("/", response_class=HTMLResponse)
async def dashboard() -> HTMLResponse:
    return HTMLResponse(DASHBOARD.read_text(encoding="utf-8"))


__all__ = ["app", "hub"]
