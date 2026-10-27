"""Proxy d'attaque « homme du milieu » (MITM) pour le TP.

Le proxy s'insère entre les clients et le relais :

    alice ---> ws://127.0.0.1:8001 ---> proxy ---> ws://127.0.0.1:8000
    bob   ---> ws://127.0.0.1:8001 ---> proxy ---> ws://127.0.0.1:8000

Modes disponibles :

``--mode dh`` (scénario 2)
    Remplace les clés publiques X25519 échangées par celles de l'attaquant.
    Le proxy dérive alors deux clés (une avec Alice, une avec Bob), déchiffre,
    affiche le clair, puis ré-chiffre vers l'autre. Les deux victimes ne voient
    rien : c'est l'attaque classique contre un Diffie-Hellman non authentifié.

``--mode tamper``
    Corrompt un champ d'un message de handshake. En scénario 2, les clés
    divergent et GCM rejette tout. En scénario 5, la signature Ed25519 ne
    vérifie plus : le client refuse la connexion.

``--replay``
    Rejoue un message de chat déjà livré, quelques secondes plus tard, pour
    montrer que le compteur ``n`` et l'AAD le font rejeter.

Exemple :

    python -m tpcrypto.attacks.mitm --mode dh
    # puis lancer alice et bob avec --url ws://127.0.0.1:8001
"""

from __future__ import annotations

import argparse
import asyncio
import json
from dataclasses import dataclass
from typing import Any
from urllib.parse import unquote

try:
    from websockets.asyncio.client import connect
    from websockets.asyncio.server import serve
except ImportError as exc:  # pragma: no cover
    raise SystemExit("websockets >= 13 est requis : pip install -U websockets") from exc

from cryptography.hazmat.primitives.asymmetric import x25519

from .. import ui
from ..crypto import b64d, b64e, gcm_open, gcm_seal, hkdf


@dataclass
class PeerState:
    name: str
    dh_private: x25519.X25519PrivateKey | None = None
    real_dh_public: bytes | None = None
    key: bytes | None = None


class MitmProxy:
    def __init__(
        self,
        upstream: str,
        *,
        mode: str = "dh",
        info: bytes = b"tpcrypto/s2/x25519",
        aad_scenario: str = "s2",
        replay: bool = False,
        replay_delay: float = 4.0,
    ) -> None:
        self.upstream = upstream.rstrip("/")
        self.mode = mode
        self.info = info
        self.aad_scenario = aad_scenario
        self.replay = replay
        self.replay_delay = replay_delay

        self.peers: dict[str, PeerState] = {}
        self.salt: bytes | None = None
        self.tampered = False
        self.intercepted: list[tuple[str, str, str]] = []

        # État du handshake DH intercepté :
        # - l'initiateur envoie dh1 (sa clé A) ; on lui substitue M_a ;
        # - le répondeur envoie dh2 (sa clé B) ; on lui substitue M_b.
        # Clé de l'initiateur avec Mallory : DH(m_b, A)
        # Clé du répondeur avec Mallory : DH(m_a, B)
        self.initiator: str | None = None
        self.initiator_real: bytes | None = None
        self.initiator_fake: x25519.X25519PrivateKey | None = None
        self.responder: str | None = None
        self.responder_real: bytes | None = None

    # -- gestion des connexions -------------------------------------------

    async def handle(self, ws: Any) -> None:
        path = self._path(ws)
        name = unquote(path.split("?")[0].rstrip("/").split("/")[-1])
        upstream_url = f"{self.upstream}{path}"
        print(ui.info(f"[MITM] {name} se connecte (relais {upstream_url})"))

        try:
            async with connect(
                upstream_url,
                compression=None,
                max_size=16 * 1024 * 1024,
            ) as remote:
                upstream = asyncio.create_task(
                    self._client_to_server(ws, remote, name)
                )
                downstream = asyncio.create_task(
                    self._server_to_client(remote, ws, name)
                )
                try:
                    await asyncio.wait(
                        {upstream, downstream},
                        return_when=asyncio.FIRST_COMPLETED,
                    )
                finally:
                    # Fermer l'autre sens dès qu'une extrémité s'arrête, sinon
                    # le proxy resterait bloqué sur une connexion à moitié ouverte.
                    for task in (upstream, downstream):
                        if not task.done():
                            task.cancel()
                    await asyncio.gather(upstream, downstream, return_exceptions=True)
        except Exception as exc:  # noqa: BLE001
            print(ui.warn(f"[MITM] connexion {name} terminée : {type(exc).__name__}: {exc}"))

    @staticmethod
    def _path(ws: Any) -> str:
        path = getattr(ws, "path", None)
        if path is None:
            path = ws.request.path
        return path

    # -- sens client -> serveur -------------------------------------------

    async def _client_to_server(self, ws: Any, remote: Any, name: str) -> None:
        async for raw in ws:
            if isinstance(raw, bytes):
                await remote.send(raw)
                continue
            try:
                data = json.loads(raw)
            except json.JSONDecodeError:
                await remote.send(raw)
                continue

            payload = data.get("payload")
            if isinstance(payload, dict):
                rewritten = self._transform(data.get("to"), name, payload)
                if rewritten is None:
                    continue  # message abandonné par l'attaquant
                data["payload"] = rewritten
            await remote.send(
                json.dumps(data, ensure_ascii=False, separators=(",", ":"))
            )

    def _transform(self, to: str | None, name: str, payload: dict) -> dict | None:
        kind = payload.get("t")
        if kind == "hs":
            if self.mode == "tamper":
                # Chaque nouveau handshake doit être altéré, même après un
                # premier essai raté (les étudiants recommencent souvent).
                if payload.get("step") in ("dh1", "signed_dh1"):
                    self.tampered = False
                return self._tamper(payload)
            if self.mode == "dh":
                step = payload.get("step")
                if step in ("dh1", "dh2"):
                    return self._rewrite_dh(name, step, payload)
            return payload
        if kind == "msg" and self.mode == "dh":
            return self._forward_message(name, to, payload)
        return payload

    # -- attaque DH --------------------------------------------------------

    def _rewrite_dh(self, name: str, step: str, payload: dict) -> dict:
        try:
            real_public = b64d(payload["pub"])
            if len(real_public) != 32:
                raise ValueError("clé X25519 de taille inattendue")
        except Exception as exc:
            print(ui.warn(f"[MITM] clé DH illisible de {name} : {exc}"))
            return payload

        if step == "dh1":
            self.salt = b64d(payload["salt"])
            if self.salt is None:
                print(ui.warn("[MITM] salt inconnu : impossible de dériver la clé"))
                return payload

            self.initiator = name
            self.initiator_real = real_public
            self.initiator_fake = x25519.X25519PrivateKey.generate()
            fake_public = self.initiator_fake.public_key().public_bytes_raw()

            print(ui.err(
                f"[MITM] dh1 de {name} intercepté : clé publique remplacée "
                f"({fingerprint_short(real_public)} -> {fingerprint_short(fake_public)})"
            ))
            return {**payload, "pub": b64e(fake_public)}

        # step == "dh2" : le répondeur croit parler à l'initiateur, mais il a
        # reçu M_a. On lui substitue M_b pour l'initiateur.
        if self.salt is None or self.initiator is None or self.initiator_fake is None:
            print(ui.warn("[MITM] dh2 reçu avant dh1 : handshake incohérent"))
            return payload
        if self.initiator_real is None:
            return payload

        responder_fake = x25519.X25519PrivateKey.generate()
        fake_public = responder_fake.public_key().public_bytes_raw()
        self.responder = name
        self.responder_real = real_public

        # Clé entre l'initiateur (Alice) et Mallory : DH(m_b, A).
        key_initiator = hkdf(
            responder_fake.exchange(
                x25519.X25519PublicKey.from_public_bytes(self.initiator_real)
            ),
            salt=self.salt,
            info=self.info,
        )
        # Clé entre le répondeur (Bob) et Mallory : DH(m_a, B).
        key_responder = hkdf(
            self.initiator_fake.exchange(
                x25519.X25519PublicKey.from_public_bytes(real_public)
            ),
            salt=self.salt,
            info=self.info,
        )
        self.peers[self.initiator] = PeerState(
            name=self.initiator, key=key_initiator
        )
        self.peers[name] = PeerState(name=name, key=key_responder)

        print(ui.err(
            f"[MITM] dh2 de {name} intercepté : clé publique remplacée "
            f"({fingerprint_short(real_public)} -> {fingerprint_short(fake_public)})"
        ))
        print(ui.err("[MITM] deux sessions distinctes : je peux lire tout le clair"))
        return {**payload, "pub": b64e(fake_public)}

    def _forward_message(
        self, name: str, to: str | None, payload: dict
    ) -> dict | None:
        if to is None:
            return payload
        source = self.peers.get(name)
        destination = self.peers.get(to)
        if not source or not destination or not source.key or not destination.key:
            print(ui.warn(
                f"[MITM] clés incomplètes pour {name} -> {to} : "
                "le message ne peut pas être relayé"
            ))
            return None

        try:
            number = int(payload["n"])
            aad = f"{self.aad_scenario}|{name}->{to}|{number}".encode("utf-8")
            plaintext = gcm_open(
                source.key,
                b64d(payload["iv"]),
                b64d(payload["ct"]),
                aad,
            )
        except Exception as exc:  # noqa: BLE001
            print(ui.warn(
                f"[MITM] déchiffrement impossible pour {name} -> {to} "
                f"({type(exc).__name__}) : clés désynchronisées ?"
            ))
            return None

        text = plaintext.decode("utf-8", errors="replace")
        print(ui.err(f'[MITM] {name} -> {to} : "{text}"'))
        self.intercepted.append((name, to, text))

        nonce, ciphertext = gcm_seal(destination.key, plaintext, aad)
        return {**payload, "iv": b64e(nonce), "ct": b64e(ciphertext)}

    # -- altération --------------------------------------------------------

    def _tamper(self, payload: dict) -> dict:
        if self.tampered:
            return payload
        for field in ("pub", "id_pub", "ct", "kem_ct", "sig"):
            value = payload.get(field)
            if isinstance(value, str):
                try:
                    raw = bytearray(b64d(value))
                except ValueError:
                    continue
                raw[0] ^= 0x01
                self.tampered = True
                print(ui.err(
                    f"[MITM] champ '{field}' du handshake altéré d'un bit "
                    "(la signature ou le tag va échouer)"
                ), flush=True)
                return {**payload, field: b64e(bytes(raw))}
        return payload

    # -- sens serveur -> client -------------------------------------------

    async def _server_to_client(self, remote: Any, ws: Any, name: str) -> None:
        replayed = False
        async for raw in remote:
            if not isinstance(raw, str):
                await ws.send(raw)
                continue

            if self.replay and not replayed:
                try:
                    envelope = json.loads(raw)
                    payload = envelope.get("payload") or {}
                    if envelope.get("kind") == "msg" and payload.get("t") == "msg":
                        replayed = True
                        asyncio.create_task(
                            self._replay_later(ws, raw, name)
                        )
                except json.JSONDecodeError:
                    pass

            await ws.send(raw)

    async def _replay_later(self, ws: Any, raw: str, name: str) -> None:
        await asyncio.sleep(self.replay_delay)
        try:
            await ws.send(raw)
            print(ui.err(f"[MITM] message rejoué vers {name} (le compteur devrait le rejeter)"))
        except Exception:
            pass


def fingerprint_short(data: bytes) -> str:
    return data[:4].hex() + "…" + data[-2:].hex()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--upstream", default="ws://127.0.0.1:8000",
                        help="URL du vrai relais (défaut : ws://127.0.0.1:8000)")
    parser.add_argument("--listen-host", default="127.0.0.1")
    parser.add_argument("--listen-port", type=int, default=8001,
                        help="port d'écoute du proxy (défaut : 8001)")
    parser.add_argument("--mode", choices=("dh", "tamper"), default="dh",
                        help="attaque à mener (défaut : dh)")
    parser.add_argument("--scenario", default="s2",
                        help="préfixe AAD du scénario ciblé (défaut : s2)")
    parser.add_argument("--replay", action="store_true",
                        help="rejouer un message de chat après quelques secondes")
    parser.add_argument("--replay-delay", type=float, default=4.0,
                        help="délai avant rejeu, en secondes (défaut : 4)")
    return parser


async def _run(args: argparse.Namespace) -> None:
    proxy = MitmProxy(
        args.upstream,
        mode=args.mode,
        info=b"tpcrypto/s2/x25519",
        aad_scenario=args.scenario,
        replay=args.replay,
        replay_delay=args.replay_delay,
    )
    async with serve(proxy.handle, args.listen_host, args.listen_port):
        mode = {
            "dh": "interception Diffie-Hellman (scénario 2)",
            "tamper": "altération d'un bit du handshake",
        }[args.mode]
        ui.banner(
            [
                "PROXY MITM — attaque active",
                f"écoute : ws://{args.listen_host}:{args.listen_port}",
                f"relais  : {args.upstream}",
                f"mode    : {mode}",
                "Lancez alice et bob avec --url ws://127.0.0.1:"
                f"{args.listen_port}",
            ]
        )
        if args.replay:
            print(ui.warn("[MITM] rejeu activé"))
        await asyncio.Future()


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    try:
        asyncio.run(_run(args))
    except KeyboardInterrupt:
        print()
        print(ui.info("[MITM] arrêt du proxy."))


if __name__ == "__main__":
    main()
