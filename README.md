# TP Crypto — Chat chiffré de bout en bout

**Version étudiant — L2 cybersécurité — 3 h 15 à 3 h 30, par binôme.**

Un vrai chat avec serveur central, chiffré de bout en bout : AES,
Diffie-Hellman, RSA, ML-KEM, signatures, attaque MITM.

> Ce dépôt est la **version étudiant**. Le guide enseignant (qui contient les
> réponses) n'est pas inclus.

---

## Commencer ici

👉 **[Fiche étudiant pas à pas](docs/L2-fiche-etudiant.md)**

Tu n'as pas besoin de lire le reste : la fiche contient les commandes exactes,
les checkpoints, les questions et le carnet de bord à rendre.

---

## Démarrage rapide

```powershell
# Windows
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt

# Linux / macOS
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
```

Puis :

```powershell
python lancer.py
```

ou double-clique sur `demarrer.bat` (Windows).

Il faut **trois fenêtres** :

| Fenêtre | Rôle | Menu |
|---|---|---|
| 1 | relais | `1` |
| 2 | alice | `2` |
| 3 | bob | `2` |

Tableau de bord : <http://127.0.0.1:8000/>.

---

## Les scénarios

| # | Scénario | Ce que tu observes |
|---|---|---|
| 1 | AES + secret partagé | ECB laisse voir les motifs ; GCM protège |
| 2 | Diffie-Hellman | un MITM peut lire sans être vu |
| 3 | RSA KEM/DEM | 256 octets de clé encapsulée par message |
| 4 | ML-KEM | clés post-quantiques beaucoup plus grosses |
| 5 | DH signé | la signature bloque le MITM |

Démos autonomes :

```powershell
python -m demos.ecb_visual
python -m demos.nonce_reuse
python -m demos.malleability
```

---

## Documentation optionnelle

Tu peux approfondir un scénario après la séance :

- [Scénario 1 — AES et modes](docs/01-aes-modes.md)
- [Scénario 2 — Diffie-Hellman](docs/02-diffie-hellman.md)
- [Scénario 3 — RSA KEM/DEM](docs/03-rsa-kem-dem.md)
- [Scénario 4 — ML-KEM](docs/04-ml-kem.md)
- [Scénario 5 — DH signé](docs/05-dh-signe.md)
- [Wireshark](docs/06-wireshark.md)
- [Aller plus loin](docs/08-aller-plus-loin.md)

---

## Vérifier l'installation

```powershell
.\.venv\Scripts\python.exe scripts/selftest.py
```

Attendu : `SUCCÈS — 15/15 tests passés.`

---

## Sécurité

Projet **pédagogique** : transport `ws://` sans TLS, clés en clair dans `keys/`,
relais non authentifié. À utiliser uniquement sur un réseau de laboratoire, avec
l'accord de l'enseignant, et jamais pour de vraies communications.
