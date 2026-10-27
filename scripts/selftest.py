"""Auto-tests du TP : primitives, codecs et scénarios de bout en bout.

Lancement (depuis la racine du projet) :

    python scripts/selftest.py

Le script démarre un relais sur un port libre, exécute les cinq scénarios avec
deux clients réels, vérifie le rejet des messages altérés/rejoués et contrôle
que le journal du serveur ne contient aucun texte clair.

Aucune interaction n'est nécessaire : c'est utilisable en CI ou pour vérifier
l'installation avant un TP.
"""

from __future__ import annotations

import asyncio
import json
import os
import socket
import sys
import threading
import time
import traceback
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ.setdefault("TP_KEYS_DIR", str(ROOT / "keys"))

import uvicorn  # noqa: E402
from websockets.asyncio.server import serve  # noqa: E402

from server.relay import app  # noqa: E402
from tpcrypto import ui  # noqa: E402
from tpcrypto.codec import pad_message, unpad_message  # noqa: E402
from tpcrypto.attacks.mitm import MitmProxy  # noqa: E402
from tpcrypto.crypto import (
    b64d,
    b64e,
    fingerprint,
    hkdf,
    safety_number,
)
from tpcrypto.net import RelayClient, recv_until  # noqa: E402
from tpcrypto.scenarios.s1_aes import DEMO_TEXT, AesCodec  # noqa: E402
from tpcrypto.scenarios.s2_dh import handshake as dh_handshake  # noqa: E402
from tpcrypto.scenarios.s3_rsa import RsaKemCodec  # noqa: E402
from tpcrypto.scenarios.s3_rsa import handshake as rsa_handshake  # noqa: E402
from tpcrypto.scenarios.s4_mlkem import MlKemCodec  # noqa: E402
from tpcrypto.scenarios.s4_mlkem import handshake as mlkem_handshake  # noqa: E402
from tpcrypto.scenarios.s5_signed_dh import (  # noqa: E402
    _verify,
    derive as signed_derive,
    handshake as signed_handshake,
    transcript,
)
from tpcrypto.pq import MLKEM  # noqa: E402


# ---------------------------------------------------------------------------
# Petit harnais
# ---------------------------------------------------------------------------

class Results:
    def __init__(self) -> None:
        self.passed = 0
        self.failed = 0
        self.failures: list[str] = []

    def run(self, name: str, function) -> None:
        try:
            result = function()
            if asyncio.iscoroutine(result):
                asyncio.run(result)
        except Exception as exc:  # noqa: BLE001
            self.failed += 1
            self.failures.append(f"{name}: {type(exc).__name__}: {exc}")
            print(ui.err(f"  ÉCHEC  {name} — {type(exc).__name__}: {exc}"))
            if os.environ.get("TP_DEBUG"):
                traceback.print_exc()
        else:
            self.passed += 1
            print(ui.ok(f"  ok     {name}"))


def check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


# ---------------------------------------------------------------------------
# Tests unitaires (sans réseau)
# ---------------------------------------------------------------------------

def test_helpers() -> None:
    data = os.urandom(37)
    check(b64d(b64e(data)) == data, "base64 aller-retour")
    first = hkdf(b"secret", salt=b"salt", info=b"info")
    second = hkdf(b"secret", salt=b"salt", info=b"info")
    check(first == second and len(first) == 32, "HKDF déterministe, 32 octets")
    check(hkdf(b"secret", info=b"autre") != first, "HKDF dépend de info")

    message = b"un message quelconque"
    padded = pad_message(message)
    check(len(padded) % 256 == 0, "padding multiple de 256")
    check(unpad_message(padded) == message, "padding aller-retour")

    check(
        safety_number(b"alice-key", b"bob-key")
        == safety_number(b"bob-key", b"alice-key"),
        "code de sécurité symétrique",
    )
    check(len(fingerprint(data)) == 8 * 2 + 7, "format d'empreinte")


def test_aes_modes() -> None:
    key = os.urandom(32)
    for mode in ("ecb", "cbc", "ctr", "gcm"):
        alice = AesCodec("alice", "bob", key, mode)
        bob = AesCodec("bob", "alice", key, mode)
        payload = alice.seal(f"bonjour en {mode}")
        check(bob.open(payload) == f"bonjour en {mode}", f"AES-{mode} aller")
        reply = bob.seal("réponse")
        check(alice.open(reply) == "réponse", f"AES-{mode} retour")

    # ECB : le message de démo doit produire des blocs identiques.
    ecb = AesCodec("alice", "bob", key, "ecb")
    payload = ecb.seal(DEMO_TEXT)
    blocks = [b64d(payload["ct"])[i:i + 16] for i in range(0, len(b64d(payload["ct"])), 16)]
    check(len(set(blocks)) < len(blocks), "ECB laisse des blocs identiques")

    # GCM : une altération doit être rejetée.
    alice = AesCodec("alice", "bob", key, "gcm")
    bob = AesCodec("bob", "alice", key, "gcm")
    payload = alice.seal("intègre")
    tampered = dict(payload)
    raw = bytearray(b64d(payload["ct"]))
    raw[0] ^= 0x01
    tampered["ct"] = b64e(bytes(raw))
    check(bob.open(tampered) is None, "GCM rejette un chiffré altéré")
    check(bob.rejected == 1, "compteur de rejets incrémenté")

    # AAD : un autre destinataire ne peut pas ouvrir le message.
    carol = AesCodec("carol", "bob", key, "gcm")
    check(carol.open(payload) is None, "AAD lie le message au destinataire")


def test_dh_math() -> None:
    from cryptography.hazmat.primitives.asymmetric import x25519
    from tpcrypto.scenarios.s2_dh import derive

    a = x25519.X25519PrivateKey.generate()
    b = x25519.X25519PrivateKey.generate()
    salt = os.urandom(16)
    assert a.exchange(b.public_key()) == b.exchange(a.public_key())
    check(derive(a.exchange(b.public_key()), salt) == derive(b.exchange(a.public_key()), salt),
          "dérivation DH identique des deux côtés")


def test_rsa_codec() -> None:
    from cryptography.hazmat.primitives.asymmetric import rsa

    a = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    b = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    alice = RsaKemCodec("alice", "bob", a, b.public_key())
    bob = RsaKemCodec("bob", "alice", b, a.public_key())
    payload = alice.seal("message RSA")
    check(bob.open(payload) == "message RSA", "KEM/DEM RSA aller")
    reply = bob.seal("réponse RSA")
    check(alice.open(reply) == "réponse RSA", "KEM/DEM RSA retour")

    tampered = dict(payload)
    raw = bytearray(b64d(payload["ek"]))
    raw[0] ^= 0x01
    tampered["ek"] = b64e(bytes(raw))
    bob2 = RsaKemCodec("bob", "alice", b, a.public_key())
    check(bob2.open(tampered) is None, "RSA-OAEP rejette une encapsulation altérée")


def test_mlkem_codec() -> None:
    from cryptography.hazmat.primitives.asymmetric import x25519

    a_kem, b_kem = MLKEM(768), MLKEM(768)
    a_kem.keygen()
    b_kem.keygen()

    alice = MlKemCodec(
        "alice", "bob", a_kem, b_kem.public_bytes(),
        own_public_key=a_kem.public_bytes(),
    )
    bob = MlKemCodec(
        "bob", "alice", b_kem, a_kem.public_bytes(),
        own_public_key=b_kem.public_bytes(),
    )
    payload = alice.seal("message ML-KEM")
    check(len(b64d(payload["kem_ct"])) == 1088, "taille du chiffré ML-KEM-768")
    check(bob.open(payload) == "message ML-KEM", "ML-KEM aller")
    check(alice.open(bob.seal("réponse PQC")) == "réponse PQC", "ML-KEM retour")

    # Mode hybride
    a_x = x25519.X25519PrivateKey.generate()
    b_x = x25519.X25519PrivateKey.generate()
    alice_h = MlKemCodec(
        "alice", "bob", a_kem, b_kem.public_bytes(),
        own_public_key=a_kem.public_bytes(),
        hybrid=True, own_x25519=a_x, peer_x25519=b_x.public_key(),
    )
    bob_h = MlKemCodec(
        "bob", "alice", b_kem, a_kem.public_bytes(),
        own_public_key=b_kem.public_bytes(),
        hybrid=True, own_x25519=b_x, peer_x25519=a_x.public_key(),
    )
    payload = alice_h.seal("hybride")
    check(bob_h.open(payload) == "hybride", "hybride ML-KEM + X25519 aller")
    check(alice_h.open(bob_h.seal("hybride retour")) == "hybride retour",
          "hybride ML-KEM + X25519 retour")


def test_signed_dh_math() -> None:
    from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
    from tpcrypto.net import HandshakeError

    id_a = ed25519.Ed25519PrivateKey.generate()
    id_b = ed25519.Ed25519PrivateKey.generate()
    id_a_pub = id_a.public_key().public_bytes_raw()
    id_b_pub = id_b.public_key().public_bytes_raw()
    eph_a = x25519.X25519PrivateKey.generate()
    eph_b = x25519.X25519PrivateKey.generate()
    eph_a_pub = eph_a.public_key().public_bytes_raw()
    eph_b_pub = eph_b.public_key().public_bytes_raw()

    signature = id_a.sign(transcript("LAB", "alice", "bob", eph_a_pub, id_a_pub))
    payload = {
        "pub": b64e(eph_a_pub),
        "id_pub": b64e(id_a_pub),
        "sig": b64e(signature),
    }
    dh_pub, peer_id = _verify(payload, "LAB", "alice", "bob")
    check(dh_pub == eph_a_pub and peer_id == id_a_pub, "signature Ed25519 valide")

    bad = dict(payload)
    bad["pub"] = b64e(os.urandom(32))
    try:
        _verify(bad, "LAB", "alice", "bob")
    except HandshakeError:
        pass
    else:
        raise AssertionError("une signature invalide doit être refusée")

    key_a = signed_derive(eph_a.exchange(eph_b.public_key()), "LAB", eph_a_pub, eph_b_pub)
    key_b = signed_derive(eph_b.exchange(eph_a.public_key()), "LAB", eph_b_pub, eph_a_pub)
    check(key_a == key_b, "dérivation authentifiée identique")
    check(safety_number(id_a_pub, id_b_pub) == safety_number(id_b_pub, id_a_pub),
          "code de sécurité symétrique")


def test_tamper_mode() -> None:
    proxy = MitmProxy("ws://127.0.0.1:9", mode="tamper")
    payload = {
        "t": "hs",
        "step": "signed_dh1",
        "pub": b64e(os.urandom(32)),
        "id_pub": b64e(os.urandom(32)),
        "sig": b64e(os.urandom(64)),
    }
    rewritten = proxy._transform("bob", "alice", payload)
    check(rewritten is not None, "le proxy doit renvoyer un payload")
    check(rewritten["pub"] != payload["pub"], "le proxy doit altérer la clé publique")
    check(proxy.tampered, "le proxy mémorise l'altération")


# ---------------------------------------------------------------------------
# Tests de bout en bout (relais réel)
# ---------------------------------------------------------------------------

def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class RelayServer:
    def __init__(self) -> None:
        self.port = free_port()
        self.url = f"ws://127.0.0.1:{self.port}"
        self.http = f"http://127.0.0.1:{self.port}"
        config = uvicorn.Config(app, host="127.0.0.1", port=self.port, log_level="error")
        self.server = uvicorn.Server(config)
        self.thread = threading.Thread(target=self.server.run, daemon=True)

    def start(self) -> None:
        self.thread.start()
        deadline = time.time() + 10
        while not self.server.started:
            if time.time() > deadline:
                raise RuntimeError("le relais n'a pas démarré")
            time.sleep(0.02)

    def stop(self) -> None:
        self.server.should_exit = True
        self.thread.join(timeout=10)

    def get(self, path: str):
        with urllib.request.urlopen(self.http + path, timeout=5) as response:
            body = response.read().decode("utf-8")
        return body


async def e2e_aes(server: RelayServer) -> None:
    room = "e2e-aes"
    key = os.urandom(32)
    alice = await RelayClient.connect(server.url, room, "alice")
    bob = await RelayClient.connect(server.url, room, "bob")
    try:
        codec_a = AesCodec("alice", "bob", key, "gcm")
        codec_b = AesCodec("bob", "alice", key, "gcm")
        await alice.send(codec_a.seal("bonjour-aes-e2e"), to="bob")
        envelope = await recv_until(
            bob,
            lambda env: env.get("from") == "alice"
            and (env.get("payload") or {}).get("t") == "msg",
            timeout=10,
        )
        check(codec_b.open(envelope["payload"]) == "bonjour-aes-e2e", "E2E AES")
        check(codec_b.open(envelope["payload"]) is None, "E2E AES rejoue -> rejeté")
    finally:
        await alice.close()
        await bob.close()


async def e2e_s2(server: RelayServer) -> None:
    room = "e2e-s2"
    alice = await RelayClient.connect(server.url, room, "alice")
    bob = await RelayClient.connect(server.url, room, "bob")
    try:
        codec_a, codec_b = await asyncio.gather(
            dh_handshake(alice, "alice", "bob", timeout=15),
            dh_handshake(bob, "bob", "alice", timeout=15),
        )
        await alice.send(codec_a.seal("bonjour-dh-e2e"), to="bob")
        envelope = await recv_until(
            bob,
            lambda env: env.get("from") == "alice"
            and (env.get("payload") or {}).get("t") == "msg",
            timeout=10,
        )
        check(codec_b.open(envelope["payload"]) == "bonjour-dh-e2e", "E2E DH")
        await bob.send(codec_b.seal("réponse-dh"), to="alice")
        envelope = await recv_until(
            alice,
            lambda env: env.get("from") == "bob"
            and (env.get("payload") or {}).get("t") == "msg",
            timeout=10,
        )
        check(codec_a.open(envelope["payload"]) == "réponse-dh", "E2E DH retour")
    finally:
        await alice.close()
        await bob.close()


async def e2e_s3(server: RelayServer) -> None:
    room = "e2e-s3"
    alice = await RelayClient.connect(server.url, room, "e2e-alice")
    bob = await RelayClient.connect(server.url, room, "e2e-bob")
    try:
        codec_a, codec_b = await asyncio.gather(
            rsa_handshake(alice, "e2e-alice", "e2e-bob", bits=2048, timeout=30),
            rsa_handshake(bob, "e2e-bob", "e2e-alice", bits=2048, timeout=30),
        )
        await alice.send(codec_a.seal("bonjour-rsa-e2e"), to="e2e-bob")
        envelope = await recv_until(
            bob,
            lambda env: env.get("from") == "e2e-alice"
            and (env.get("payload") or {}).get("t") == "msg",
            timeout=10,
        )
        check(codec_b.open(envelope["payload"]) == "bonjour-rsa-e2e", "E2E RSA")
    finally:
        await alice.close()
        await bob.close()


async def e2e_s4(server: RelayServer) -> None:
    room = "e2e-s4"
    alice = await RelayClient.connect(server.url, room, "alice")
    bob = await RelayClient.connect(server.url, room, "bob")
    try:
        codec_a, codec_b = await asyncio.gather(
            mlkem_handshake(alice, "alice", "bob", param=768, timeout=15),
            mlkem_handshake(bob, "bob", "alice", param=768, timeout=15),
        )
        await alice.send(codec_a.seal("bonjour-mlkem-e2e"), to="bob")
        envelope = await recv_until(
            bob,
            lambda env: env.get("from") == "alice"
            and (env.get("payload") or {}).get("t") == "msg",
            timeout=10,
        )
        check(codec_b.open(envelope["payload"]) == "bonjour-mlkem-e2e", "E2E ML-KEM")
    finally:
        await alice.close()
        await bob.close()


async def e2e_s5(server: RelayServer) -> None:
    room = "e2e-s5"
    alice = await RelayClient.connect(server.url, room, "e2e-alice")
    bob = await RelayClient.connect(server.url, room, "e2e-bob")
    try:
        codec_a, codec_b = await asyncio.gather(
            signed_handshake(alice, "e2e-alice", "e2e-bob", room=room, timeout=15),
            signed_handshake(bob, "e2e-bob", "e2e-alice", room=room, timeout=15),
        )
        await alice.send(codec_a.seal("bonjour-signe-e2e"), to="e2e-bob")
        envelope = await recv_until(
            bob,
            lambda env: env.get("from") == "e2e-alice"
            and (env.get("payload") or {}).get("t") == "msg",
            timeout=10,
        )
        check(codec_b.open(envelope["payload"]) == "bonjour-signe-e2e", "E2E DH signé")
    finally:
        await alice.close()
        await bob.close()


async def e2e_mitm(server: RelayServer) -> None:
    """Le proxy s'intercale, lit le clair, et les victimes ne voient rien."""
    proxy = MitmProxy(server.url, mode="dh")
    port = free_port()
    async with serve(proxy.handle, "127.0.0.1", port):
        url = f"ws://127.0.0.1:{port}"
        alice = await RelayClient.connect(url, "e2e-mitm", "alice")
        bob = await RelayClient.connect(url, "e2e-mitm", "bob")
        try:
            codec_a, codec_b = await asyncio.gather(
                dh_handshake(alice, "alice", "bob", timeout=15),
                dh_handshake(bob, "bob", "alice", timeout=15),
            )
            await alice.send(codec_a.seal("message-interception"), to="bob")
            envelope = await recv_until(
                bob,
                lambda env: env.get("from") == "alice"
                and (env.get("payload") or {}).get("t") == "msg",
                timeout=10,
            )
            check(
                codec_b.open(envelope["payload"]) == "message-interception",
                "le message traverse le proxy sans erreur",
            )
            check(
                ("alice", "bob", "message-interception") in proxy.intercepted,
                "le MITM doit avoir lu le message en clair",
            )
            check(codec_a.key != codec_b.key,
                  "les deux victimes utilisent des clés différentes (MITM)")
        finally:
            await alice.close()
            await bob.close()


async def e2e_all(server: RelayServer) -> None:
    await e2e_aes(server)
    await e2e_s2(server)
    await e2e_s3(server)
    await e2e_s4(server)
    await e2e_s5(server)
    await e2e_mitm(server)
def main() -> int:
    results = Results()
    print(ui.title("\n=== Tests unitaires ==="))
    results.run("utilitaires (base64, HKDF, padding, empreintes)", test_helpers)
    results.run("modes AES, intégrité, AAD, rejeu", test_aes_modes)
    results.run("mathématiques Diffie-Hellman", test_dh_math)
    results.run("KEM/DEM RSA-OAEP", test_rsa_codec)
    results.run("ML-KEM et mode hybride", test_mlkem_codec)
    results.run("signatures et dérivation authentifiée", test_signed_dh_math)
    results.run("proxy MITM — altération d'un handshake", test_tamper_mode)

    print(ui.title("\n=== Tests de bout en bout (relais réel) ==="))
    server = RelayServer()
    server.start()
    print(ui.dim(f"  relais temporaire : {server.url}"))
    try:
        results.run("tableau de bord HTTP", lambda: check(
            "vue serveur" in server.get("/"), "tableau de bord accessible"
        ))
        results.run("scénario 1 — AES-GCM", lambda: asyncio.run(e2e_aes(server)))
        results.run("scénario 2 — Diffie-Hellman", lambda: asyncio.run(e2e_s2(server)))
        results.run("scénario 3 — RSA KEM/DEM", lambda: asyncio.run(e2e_s3(server)))
        results.run("scénario 4 — ML-KEM", lambda: asyncio.run(e2e_s4(server)))
        results.run("scénario 5 — DH signé", lambda: asyncio.run(e2e_s5(server)))
        results.run("attaque MITM — interception Diffie-Hellman",
                    lambda: asyncio.run(e2e_mitm(server)))

        def check_server_log() -> None:
            log = json.loads(server.get("/api/log?limit=500"))
            blob = json.dumps(log, ensure_ascii=False)
            for word in ("bonjour-aes-e2e", "bonjour-dh-e2e", "bonjour-rsa-e2e",
                         "bonjour-mlkem-e2e", "bonjour-signe-e2e"):
                check(word not in blob, f"le journal du serveur contient du clair : {word}")

        results.run("le serveur ne voit aucun texte clair", check_server_log)
    finally:
        server.stop()

    print()
    print(ui.rule())
    total = results.passed + results.failed
    if results.failed == 0:
        print(ui.ok(f"SUCCÈS — {results.passed}/{total} tests passés."))
        return 0
    print(ui.err(f"ÉCHEC — {results.failed}/{total} test(s) en erreur."))
    for failure in results.failures:
        print(ui.err(f"  - {failure}"))
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
