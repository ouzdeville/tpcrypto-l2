"""Affichage console : couleurs, encadrés et aperçus de trafic.

Tout est en ASCII (ou en UTF-8 si le terminal le supporte) pour rester lisible
dans un ``cmd.exe`` comme dans Windows Terminal / un terminal Linux.
"""

from __future__ import annotations

import os
import re
import sys


def _enable_utf8() -> None:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
        except Exception:
            pass


_enable_utf8()

_NO_COLOR = bool(os.environ.get("NO_COLOR")) or not sys.stdout.isatty()


def _c(code: str, text: str) -> str:
    if _NO_COLOR:
        return text
    return f"\x1b[{code}m{text}\x1b[0m"


def bold(text: str) -> str:
    return _c("1", text)


def dim(text: str) -> str:
    return _c("2", text)


def info(text: str) -> str:
    return _c("36", text)          # cyan


def ok(text: str) -> str:
    return _c("32", text)          # vert


def warn(text: str) -> str:
    return _c("33", text)          # jaune


def err(text: str) -> str:
    return _c("31", text)          # rouge


def peer(text: str) -> str:
    return _c("1;35", text)        # magenta gras


def me(text: str) -> str:
    return _c("1;34", text)        # bleu gras


def title(text: str) -> str:
    return _c("1;36", text)


def rule(char: str = "=", width: int = 72) -> str:
    return dim(char * width)


def print_rule(char: str = "=", width: int = 72) -> None:
    print(rule(char, width))


def kv(key: str, value: str, indent: int = 2) -> str:
    return f"{' ' * indent}{dim(key + ' :')} {value}"


def short(value: bytes | str, limit: int = 24) -> str:
    """Résumé d'une valeur binaire : ``a1b2c3... (48 o)``."""
    if isinstance(value, str):
        value = value.encode()
    head = value[:limit].hex()
    if len(value) > limit:
        head += "..."
    return f"{head} ({len(value)} o)"


def b64len(b64: str) -> int:
    """Taille décodée approximative d'une chaîne base64."""
    if not b64:
        return 0
    return (len(b64) * 3) // 4 - b64.count("=")


def wire(direction: str, payload: dict, max_len: int = 64) -> None:
    """Affiche l'enveloppe chiffrée telle qu'elle circule sur le réseau.

    On ne montre jamais le clair ici : uniquement les champs et leurs tailles,
    exactement ce qu'un observateur (serveur, Wireshark) peut voir.
    """
    parts: list[str] = []
    for key, value in payload.items():
        if key == "t":
            continue
        if isinstance(value, str) and len(value) > max_len and _looks_b64(value):
            parts.append(f"{key}={b64len(value)}o")
        else:
            text = str(value)
            if len(text) > 40:
                text = text[:37] + "..."
            parts.append(f"{key}={text}")
    print(dim(f"  [wire {direction}] ") + dim(" ".join(parts)))


def _looks_b64(value: str) -> bool:
    if len(value) < 40:
        return False
    alphabet = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
    return set(value) <= alphabet


def block_analysis(data: bytes, block_size: int = 16, max_blocks: int = 10) -> str:
    """Analyse les blocs d'un chiffré (utile pour ECB).

    Renvoie une chaîne du type ``5 blocs, 2 uniques, 3 doublons``.
    """
    blocks = [data[i:i + block_size] for i in range(0, len(data), block_size)]
    seen: dict[bytes, int] = {}
    dups = 0
    for block in blocks:
        if block in seen:
            dups += 1
            seen[block] += 1
        else:
            seen[block] = 1
    return f"{len(blocks)} bloc(s), {len(seen)} unique(s), {dups} doublon(s)"


def hex_blocks(data: bytes, block_size: int = 16, max_blocks: int = 10) -> None:
    """Affiche les blocs hexadécimaux, en marquant les doublons d'un ``*``."""
    blocks = [data[i:i + block_size] for i in range(0, len(data), block_size)]
    seen: dict[bytes, int] = {}
    for index, block in enumerate(blocks[:max_blocks]):
        duplicate = block in seen
        seen.setdefault(block, index)
        marker = warn("  <-- identique au bloc " + str(seen[block])) if duplicate else ""
        print(dim(f"    bloc {index:02d}  ") + block.hex() + marker)
    if len(blocks) > max_blocks:
        print(dim(f"    ... ({len(blocks) - max_blocks} bloc(s) supplémentaire(s))"))


def banner(lines: list[str], char: str = "=") -> None:
    ansi = re.compile(r"\x1b\[[0-9;]*m")
    visible = [ansi.sub("", line) for line in lines]
    width = max((len(line) for line in visible), default=0) + 4
    print(title(char * width))
    for line in lines:
        print(title("| ") + line)
    print(title(char * width))
