"""Base commune des codecs de message.

Un « codec » transforme un texte clair en payload JSON chiffré, et inversement.
Il gère pour vous :

- la numérotation des messages (protection basique contre le rejeu) ;
- l'AAD (données authentifiées non chiffrées) liant l'expéditeur, le
  destinataire et le numéro de message ;
- l'affichage du trafic chiffré avec ``--show-wire`` ;
- le padding optionnel (masquage de la longueur des messages) ;
- les erreurs de déchiffrement (tag invalide) sans faire planter le chat.

Chaque scénario hérite de ``Codec`` et implémente ``_seal`` et ``_open``.
"""

from __future__ import annotations

from typing import Any

from . import ui


class Codec:
    scenario = "base"

    def __init__(
        self,
        name: str,
        peer: str,
        *,
        pad: bool = False,
        show_wire: bool = False,
    ) -> None:
        self.name = name
        self.peer = peer
        self.pad = pad
        self.show_wire = show_wire
        self.send_n = 0
        self.recv_n = -1
        self.rejected = 0

    # -- API publique ------------------------------------------------------

    def seal(self, text: str) -> dict:
        """Chiffre un message et renvoie le payload à mettre dans l'enveloppe."""
        number = self.send_n
        data = text.encode("utf-8")
        if self.pad:
            data = pad_message(data)
        payload = self._seal(data, number, self._aad(number, outgoing=True))
        payload["t"] = "msg"
        payload["n"] = number
        self.send_n += 1
        if self.show_wire:
            ui.wire(f"{self.name}->{self.peer}", payload)
        self.on_sent(payload)
        return payload

    def open(self, payload: dict) -> str | None:
        """Déchiffre un payload reçu. Renvoie ``None`` si le message est rejeté."""
        try:
            number = int(payload["n"])
        except (KeyError, TypeError, ValueError):
            print(ui.warn(f"[{self.scenario}] message sans numéro valide : ignoré"))
            self.rejected += 1
            return None
        if number <= self.recv_n:
            print(ui.warn(
                f"[{self.scenario}] rejeu ou doublon détecté (n={number}, "
                f"dernier={self.recv_n}) : message ignoré"
            ))
            self.rejected += 1
            return None
        if self.recv_n >= 0 and number > self.recv_n + 1:
            print(ui.warn(
                f"[{self.scenario}] trou dans la numérotation "
                f"({self.recv_n} -> {number}) : message(s) perdu(s) ?"
            ))
        try:
            data = self._open(payload, number, self._aad(number, outgoing=False))
        except Exception as exc:  # InvalidTag, padding, clé absente...
            print(ui.err(
                f"[{self.scenario}] message rejeté : {type(exc).__name__} "
                f"({exc})"
            ))
            self.rejected += 1
            return None
        self.recv_n = number
        if self.pad:
            try:
                data = unpad_message(data)
            except ValueError as exc:
                print(ui.err(f"[{self.scenario}] padding invalide : {exc}"))
                self.rejected += 1
                return None
        if self.show_wire:
            ui.wire(f"{self.peer}->{self.name}", payload)
        return data.decode("utf-8", errors="replace")

    def describe(self) -> str:
        """Résumé affiché au démarrage (algorithmes, empreintes...)."""
        return ""

    def on_sent(self, payload: dict) -> None:
        """Point d'extension (ex. analyse des blocs ECB)."""

    def close(self) -> None:
        """Libère d'éventuelles ressources (surchargé si besoin)."""

    # -- À implémenter -----------------------------------------------------

    def _seal(self, data: bytes, number: int, aad: bytes) -> dict:
        raise NotImplementedError

    def _open(self, payload: dict, number: int, aad: bytes) -> bytes:
        raise NotImplementedError

    # -- AAD ---------------------------------------------------------------

    def _aad(self, number: int, *, outgoing: bool) -> bytes:
        """Contexte authentifié : scénario, sens, numéro.

        L'AAD n'est pas chiffrée mais elle est authentifiée par le tag GCM : si
        un attaquant change le destinataire ou rejoue un message sous un autre
        numéro, le tag ne vérifie plus.
        """
        if outgoing:
            source, destination = self.name, self.peer
        else:
            source, destination = self.peer, self.name
        return f"{self.scenario}|{source}->{destination}|{number}".encode("utf-8")


# ---------------------------------------------------------------------------
# Padding (masquage de la longueur)
# ---------------------------------------------------------------------------

PAD_BLOCK = 256


def pad_message(data: bytes, block: int = PAD_BLOCK) -> bytes:
    """Préfixe la longueur sur 2 octets puis complète avec des zéros.

    Cela ne chiffre pas la longueur exacte, mais la fait arrondir au multiple de
    ``block`` : un message de 3 octets et un de 200 octets ont la même taille
    sur le réseau. C'est une brique de base contre l'analyse de trafic.
    """
    if len(data) > 0xFFFF:
        raise ValueError("message trop long pour le padding (max 65535 octets)")
    padded = len(data).to_bytes(2, "big") + data
    padded += b"\x00" * (-len(padded) % block)
    return padded


def unpad_message(data: bytes) -> bytes:
    if len(data) < 2:
        raise ValueError("message trop court")
    length = int.from_bytes(data[:2], "big")
    if length > len(data) - 2:
        raise ValueError("longueur de padding incohérente")
    return data[2:2 + length]


__all__ = ["Codec", "PAD_BLOCK", "pad_message", "unpad_message"]
