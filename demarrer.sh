#!/usr/bin/env bash
# Lanceur Linux / macOS pour le TP crypto (L2).

cd "$(dirname "$0")" || exit 1

if command -v python3 >/dev/null 2>&1; then
    python3 lancer.py
else
    python lancer.py
fi
