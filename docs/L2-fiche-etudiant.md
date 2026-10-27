# TP Crypto — Fiche étudiant L2 Cybersécurité

> **Tu n'as besoin que de cette fiche.** Les autres documents
> (`docs/01` à `docs/06` et `docs/08`) sont optionnels : ils approfondissent un
> scénario. Tu peux les ignorer pendant la séance.

**Chat chiffré de bout en bout — 3 h 15 à 3 h 30 avec la pause — par binôme**

> Objectif : comprendre comment un messager protège vraiment les messages, et
> voir **ce que le serveur peut lire… ou pas**.

Vous allez utiliser un vrai petit chat : un serveur central relaie les messages,
mais les clients les chiffrent avant l'envoi. Vous allez jouer les utilisateurs,
puis les attaquants.

---

## 0. Ce que vous allez faire

| Scénario | Question | Ce que vous allez voir |
|---|---|---|
| 1. AES | Comment chiffrer avec une clé partagée ? | ECB laisse voir les motifs ; GCM protège |
| 2. Diffie-Hellman | Comment se mettre d'accord sur une clé ? | un MITM peut lire sans être vu |
| 3. RSA | Comment envoyer une clé avec une clé publique ? | 256 octets par message, pas de secret éternel |
| 4. ML-KEM | Et si les ordinateurs quantiques arrivent ? | des clés beaucoup plus grosses |
| 5. Signature | Comment empêcher le MITM ? | une signature bloque l'attaquant |

**Le fil rouge :** le serveur ne doit jamais pouvoir lire vos messages. À chaque
scénario, ouvrez le tableau de bord et vérifiez-le.

> **Nuance importante :** le serveur *honnête* ne peut pas lire. Mais un
> attaquant actif — ou un serveur malveillant — peut remplacer les clés dans
> les scénarios 2, 3 et 4 s'il n'y a pas de signature. C'est exactement ce que
> corrige le scénario 5.

---

## 1. Vocabulaire utile

| Mot | Définition simple | Analogie |
|---|---|---|
| **clair** | le message lisible | la lettre |
| **chiffré** | le message illisible | la lettre dans un coffre |
| **clé** | le secret qui permet de chiffrer/déchiffrer | la clé du coffre |
| **chiffrement symétrique** | même clé pour les deux | un coffre à une seule clé |
| **chiffrement asymétrique** | une clé publique + une clé privée | un cadenas ouvert + sa clé |
| **IV / nonce** | un numéro aléatoire à usage unique | le numéro de série d'un coffre |
| **tag** | un sceau qui détecte les modifications | la cire d'un sceau |
| **handshake** | la poignée de main avant de discuter | se présenter et échanger une clé |
| **MITM** | un attaquant s'intercale entre les deux | un faux facteur qui ouvre et referme les lettres |
| **KEM** | une méthode pour envoyer une clé secrète | une boîte fermée par le cadenas du destinataire |
| **DEM** | chiffrer les données avec la clé du KEM | le contenu de la boîte |
| **HKDF** | transformer un secret brut en clé utilisable | raffiner du pétrole en essence |
| **X25519** | algorithme Diffie-Hellman sur courbe elliptique | la peinture mélangée |
| **Ed25519** | algorithme de signature à clé publique | le sceau du notaire |
| **SAS** | empreinte courte de la clé de session | le code de sécurité à comparer |
| **empreinte** | un résumé court d'une clé | l'odeur d'un parfum : facile à comparer |

---

## 2. Installation (15 minutes)

### 2.1 Vérifier Python

Ouvrez un terminal (PowerShell sous Windows) dans le dossier du TP et tapez :

```powershell
python --version
```

Vous devez voir `Python 3.10` ou plus. Sinon, installez Python depuis
<https://www.python.org/downloads/> en cochant **Add Python to PATH**.

### 2.2 Installer les dépendances

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

Sous Linux ou macOS :

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
```

> Le lanceur `lancer.py` détecte automatiquement `.venv` : vous n'avez pas
> besoin d'« activer » l'environnement à chaque fois.

### 2.3 Tester l'installation

```powershell
.\.venv\Scripts\python.exe scripts/selftest.py
```

Vous devez voir `SUCCÈS — 15/15 tests passés`. Si ce n'est pas le cas, appelez
le professeur.

---

## 3. Le lanceur (à utiliser dans chaque fenêtre)

```powershell
python lancer.py
```

ou double-cliquez sur `demarrer.bat` (Windows).

Vous voyez un menu :

```
  1) Démarrer le relais          (fenêtre 1)
  2) Lancer un client            (fenêtres 2 et 3)
  3) Lancer le proxy MITM        (attaque)
  4) Ouvrir le tableau de bord
  5) Lancer les auto-tests
  6) Démonstrations autonomes
  7) Générer la clé du scénario 1
  0) Quitter
```

> **Important :** il faut **trois fenêtres** de terminal :
> une pour le serveur, une pour alice, une pour bob. Le serveur doit rester
> ouvert pendant tout le TP.

---

## 4. Premier contact (10 minutes)

### Fenêtre 1 — le serveur

```powershell
python lancer.py
```

Choisissez **1**. Laissez la fenêtre ouverte.

### Fenêtre 2 — alice

```powershell
python lancer.py
```

Choisissez **2**, puis :

```
Scénario : 2
Votre pseudo : alice
Pseudo du pair : bob
Salon : LAB
Afficher le trafic chiffré : o
Passer par le proxy MITM : n
```

### Fenêtre 3 — bob

Pareil, mais :

```
Votre pseudo : bob
Pseudo du pair : alice
```

### Vérification

- Alice et bob doivent afficher le même **SAS** (une empreinte de clé).
- Envoyez `bonjour` depuis alice : bob doit l'afficher.
- Ouvrez le tableau de bord : <http://127.0.0.1:8000/> (menu 4 d'un autre
  lanceur). Vous devez voir les enveloppes, mais **aucun texte clair**.

✅ **Checkpoint 0 :** le message arrive, et le serveur ne voit que du charabia.

Commandes du chat : `/help`, `/fp`, `/wire`, `/demo`, `/quit`.

---

## 5. Scénario 1 — AES et le choix du mode (40 min)

### But

Chiffrer un message avec **une clé partagée** et comprendre que le **mode**
change tout : ECB est une catastrophe, GCM protège.

```
alice --[ AES(clé K, message) ]--> bob
          K est la même des deux côtés (hors bande)
```

### Préparer la clé (une seule fois)

Dans une fenêtre, lancez `python lancer.py`, choisissez **7**. Notez
l'empreinte affichée. Le fichier `keys/lab_psk.hex` contient la clé.

> Si alice et bob sont sur **deux machines**, copiez `keys/lab_psk.hex` sur les
> deux (clé USB, ENT...). Sinon, la clé serait différente et le déchiffrement
> échouerait.

### Étape 1 — La version sûre : GCM

Fenêtres 2 et 3 : scénario **1**, mode **gcm**, afficher le trafic **o**.

Envoyez quelques messages. Observez les lignes :

```
[wire alice->bob] n=0 iv=12o ct=32o
```

- `iv` = 12 octets aléatoires ;
- `ct` = le message chiffré + un **tag** de 16 octets.

Tapez `/fp` : les deux côtés doivent afficher la même empreinte de clé.

Regardez le tableau de bord : le serveur voit `iv` et `ct`, jamais `bonjour`.

✅ **Checkpoint 1a :** aucun texte clair sur le tableau de bord.

### Étape 2 — La catastrophe : ECB

Quittez les clients (`/quit`), relancez-les avec le mode **ecb**.

Tapez `/demo`. Vous devez voir :

```
[ECB] 5 bloc(s), 3 unique(s), 2 doublon(s)
    bloc 00  ...
    bloc 01  ...  <-- identique au bloc 00
```

Le message de démo contient trois fois le même bloc de 16 octets. En ECB, ces
blocs donnent **le même chiffré**. Un attaquant retrouve les répétitions.

Pour voir l'effet sur une image :

```
python lancer.py   → 6 (démonstrations) → 1 (ECB vs CBC)
```

✅ **Checkpoint 1b :** l'image reste reconnaissable en ECB, pas en CBC.

### Étape 3 — CBC et l'IV fixe

Relancez avec le mode **cbc**. Envoyez `/demo` deux fois : les chiffrés sont
différents (IV aléatoire).

Relancez avec **cbc** + **IV fixe** (le lanceur demande « IV/nonce fixe ? »).
Envoyez `/demo` deux fois : les chiffrés sont **identiques**.

Puis montrez la malléabilité :

```
python lancer.py → 6 → 3 (malléabilité)
```

Un attaquant transforme `100 EUR` en `900 EUR` **sans la clé**, juste en
modifiant l'IV. CBC n'a pas de tag.

✅ **Checkpoint 1c :** le virement est modifié sans erreur.

### Étape 4 — CTR et le nonce

Relancez avec **ctr** + **IV fixe**. Puis :

```
python lancer.py → 6 → 2 (réutilisation de nonce)
```

Deux messages chiffrés avec le même nonce : `c1 XOR c2 = p1 XOR p2`. Si on
connaît un message, on retrouve l'autre. La démo le fait sous vos yeux, et
montre que **GCM est touché aussi** si le nonce est réutilisé.

✅ **Checkpoint 1d :** le message secret est retrouvé.

### Questions scénario 1

1. Pourquoi ECB laisse-t-il apparaître les motifs du message ?
2. Que rajoute GCM par rapport à CBC ?
3. Pourquoi un nonce ne doit-il **jamais** servir deux fois ?
4. Qu'est-ce que le serveur peut voir ? Qu'est-ce qu'il ne peut pas voir ?

---

## 6. Scénario 2 — Diffie-Hellman (40 min)

### But

Se mettre d'accord sur une clé **sans jamais l'envoyer**, puis comprendre
pourquoi un attaquant peut quand même s'intercaler.

```
alice --A (clé publique)--> bob
alice <--B (clé publique)-- bob
secret = mélange(a, B) = mélange(b, A)   (jamais envoyé)
```

### Étape 1 — Sans attaquant

Relancez alice et bob en scénario **2**.

Au démarrage :

```
[alice] HS1 envoyé (X25519 32 o + salt 16 o)
[bob]   HS2 envoyé (X25519 32 o)
[alice] clé de session dérivée : ...
```

Comparez le **SAS** affiché des deux côtés : ils doivent être identiques.
Envoyez des messages.

✅ **Checkpoint 2a :** même SAS, messages reçus.

### Étape 2 — L'homme du milieu

Gardez le serveur. Dans une **nouvelle** fenêtre :

```powershell
python lancer.py → 3 (proxy MITM) → mode 1 (dh)
```

Relancez alice et bob en scénario 2, mais répondez **o** à
« Passer par le proxy MITM ».

Le proxy affiche :

```
[MITM] dh1 de alice intercepté : clé publique remplacée ...
[MITM] deux sessions distinctes : je peux lire tout le clair
[MITM] alice -> bob : "votre message secret"
```

Alice et bob continuent à discuter. **Leurs SAS sont différents**, mais ils ne
le savent pas s'ils ne les comparent pas.

✅ **Checkpoint 2b :** le proxy lit le clair, le serveur ne le lit toujours pas.

### Questions scénario 2

1. Qu'est-ce qui circule réellement pendant le handshake ? Le secret est-il
   envoyé ?
2. Pourquoi un simple observateur (passif) ne peut-il pas lire ?
3. Pourquoi l'attaque MITM fonctionne-t-elle ?
4. Comment alice et bob pourraient-ils détecter l'attaque ?

---

## 7. Scénario 3 — RSA (20 min)

### But

Utiliser une **clé publique** pour envoyer une clé secrète : c'est le schéma
**KEM/DEM**.

```
alice --ek = RSA(clé publique de bob, clé AES)--> bob
alice --AES-GCM(clé AES, message)---------------> bob
```

### Étape 1 — Observer

Fenêtres 2 et 3 : scénario **3**, afficher le trafic **o**.

Au premier lancement, chaque client crée une paire RSA (fichier dans `keys/`).
Envoyez un message. Observez :

```
[wire alice->bob] n=0 ek=256o iv=12o ct=32o
```

- `ek` = 256 octets : la clé AES, chiffrée avec la clé publique RSA de bob ;
- `iv` et `ct` : le message chiffré avec AES-GCM.

Tapez `/fp` : l'empreinte de la clé publique RSA du pair.

✅ **Checkpoint 3a :** 256 octets d'`ek` par message.

### Étape 2 — Réfléchir

- Que se passe-t-il si la clé privée de bob fuite dans 10 ans ?
- Qui peut envoyer un message à bob ? N'importe qui connaissant sa clé publique.
- Le serveur peut-il remplacer la clé publique de bob pendant le handshake ?

✅ **Checkpoint 3b :** vous savez expliquer pourquoi RSA ne suffit pas à lui
seul.

### Questions scénario 3

1. Pourquoi ne chiffre-t-on pas directement le message avec RSA ?
2. À quoi sert le champ `ek` ?
3. Si la clé privée de bob fuite plus tard, que peut faire l'attaquant ?
4. Le serveur peut-il se faire passer pour alice auprès de bob ? Pourquoi ?

---

## 8. Scénario 4 — ML-KEM (20 min)

### But

Voir à quoi ressemble la cryptographie **post-quantique** : même principe que
RSA (KEM/DEM), mais des clés beaucoup plus grosses.

```
alice --kem_ct = ML-KEM(clé publique de bob)--> bob
alice --AES-GCM(clé dérivée du secret)--------> bob
```

### Étape 1 — Observer

Fenêtres 2 et 3 : scénario **4**, afficher le trafic **o**.

Au handshake :

```
[alice] clé publique ML-KEM-768 envoyée (1184 o, soit 9472 bits)
```

À chaque message :

```
[wire alice->bob] n=0 kem_ct=1088o iv=12o ct=32o
```

Comparez avec RSA : 256 octets d'`ek` contre **1088 octets** de `kem_ct`.

✅ **Checkpoint 4a :** vous savez dire pourquoi les clés sont plus grosses.

### Étape 2 — Le mode hybride

Relancez avec le mode **hybride** (le lanceur demande « Mode hybride ? » →
**o**). Le handshake transporte en plus une clé X25519. C'est ce que font les
protocoles réels : si ML-KEM casse, X25519 protège encore ; si les ordinateurs
quantiques arrivent, ML-KEM protège encore.

✅ **Checkpoint 4b :** le chat fonctionne en hybride.

### Questions scénario 4

1. Pourquoi les clés ML-KEM sont-elles plus grosses que RSA ?
2. Pourquoi dit-on « post-quantique » ?
3. Pourquoi utiliser les deux algorithmes en même temps (hybride) ?

---

## 9. Scénario 5 — La signature qui bloque le MITM (30 min)

### But

Empêcher l'attaque du scénario 2 en **signature** la clé de session avec une
clé d'identité.

```
alice --clé DH + signature Ed25519--> bob
bob vérifie la signature avec la clé publique d'alice
puis les messages passent en AES-GCM
```

### Étape 1 — Sans attaquant

Fenêtres 2 et 3 : scénario **5**.

Au démarrage :

```
[bob] empreinte d'identité : 35:bc:f5:ac:56:a2:d8:51
[alice] signature Ed25519 de bob vérifiée
[alice] CODE DE SÉCURITÉ : 03972 04403 51051 88277 75243 94194
```

Comparez le **code de sécurité** avec votre binôme (de vive voix, pas dans le
chat !). Il doit être identique.

✅ **Checkpoint 5a :** même code de sécurité.

### Étape 2 — L'attaque échoue

Dans une nouvelle fenêtre :

```powershell
python lancer.py → 3 → mode 2 (tamper)
```

Relancez alice et bob via le proxy (répondez **o** à « Passer par le proxy »).

Cette fois, bob affiche :

```
[handshake] SIGNATURE INVALIDE de alice !
  La clé DH reçue ne correspond pas à la clé d'identité annoncée.
  Connexion refusée.
```

Le chat **ne démarre pas**. L'attaquant ne peut pas lire.

Dans la fenêtre d'alice, vous verrez aussi :

```
[handshake] bob a quitté le salon pendant la négociation.
```

✅ **Checkpoint 5b :** la connexion est refusée des deux côtés.

### Étape 3 — Épingler l'identité (optionnel)

Notez l'empreinte d'identité de bob. Relancez alice **en ligne de commande** :

```powershell
.\.venv\Scripts\python.exe -m tpcrypto.scenarios.s5_signed_dh --name alice --peer bob --expect-fingerprint EMPREINTE_DE_BOB
```

Remplacez `EMPREINTE_DE_BOB` par l'empreinte affichée au démarrage de bob
(par exemple `35:bc:f5:ac:56:a2:d8:51`).

Si bob réinstalle ses clés (empreinte différente), alice refuse la connexion.

### Questions scénario 5

1. Que signe alice exactement ?
2. À quoi sert le code de sécurité ? Pourquoi le comparer de vive voix ?
3. Un attaquant qui remplace aussi la clé d'identité est-il détecté ?
4. Qu'est-ce que le serveur apprend encore, même avec la signature ?

---

## 10. Mission finale (20 min)

En binôme, choisissez **un** scénario et préparez une démonstration de 3 minutes :

1. le protocole en 3 étapes (qui envoie quoi) ;
2. ce que le serveur voit sur le tableau de bord ;
3. une attaque (ECB, MITM, altération, rejeu) et sa parade.

Vous devez montrer **en direct** :

- un message qui arrive chez le pair ;
- le tableau de bord avec du chiffré ;
- l'attaque ou la preuve que le serveur ne peut pas lire.

### Carnet de bord à rendre

| Scénario | Ce qui circule | Taille observée | Le serveur peut lire ? | Attaque | Parade |
|---|---|---|---|---|---|
| 1 — ECB | | | | | |
| 1 — GCM | | | | | |
| 2 — DH | | | | | |
| 3 — RSA | | | | | |
| 4 — ML-KEM | | | | | |
| 5 — Signature | | | | | |

### Règles d'or à retenir

1. **ECB est interdit.** Un mode doit cacher les motifs.
2. **Un nonce ne se réutilise jamais** avec la même clé.
3. **Confidentialité ≠ intégrité** : utilisez un AEAD (GCM).
4. **Diffie-Hellman sans signature = MITM possible.**
5. **Une clé publique ne prouve pas l'identité** : vérifiez l'empreinte.
6. **Le serveur ne doit jamais avoir besoin de la clé** : chiffrement de bout en
   bout.
7. **Post-quantique = clés plus grosses**, mais même logique KEM/DEM.
8. **Ne capturez que votre propre trafic**, avec l'accord de l'enseignant.

---

## 11. Dépannage

| Message | Cause | Solution |
|---|---|---|
| `impossible de joindre le relais` | serveur arrêté | fenêtre 1 : lancer le serveur |
| `le nom 'alice' est déjà utilisé` | ancien client encore connecté | attendre, changer de pseudo, fermer l'ancien |
| `délai dépassé en attendant ...` | salon différent, pair non lancé, scénario différent | même salon, même scénario, deux clients ; sinon changez de salon (`TP2`) et relancez |
| `déchiffrement refusé` (scénario 1) | clé PSK différente | recopier `keys/lab_psk.hex`, comparer `/fp` |
| le proxy ne voit rien | clients pas passés par le proxy | répondre **o** à « Passer par le proxy » |
| `SIGNATURE INVALIDE` en scénario 5 | proxy `tamper` encore actif | arrêter le proxy, relancer sans proxy |
| `bob a quitté le salon pendant la négociation` | l'autre client a échoué ou a été fermé | relire le message d'erreur de l'autre fenêtre |
| accents bizarres | vieux `cmd.exe` | utiliser Windows Terminal |
| port 8000 occupé | ancien serveur | fermer l'ancienne fenêtre ou redémarrer |

---

## 12. Bonus — voir le trafic avec Wireshark (10 min)

> À faire uniquement sur **votre** trafic, dans le cadre du TP.

1. Installez Wireshark et Npcap (cochez « loopback » à l'installation).
2. Lancez une capture sur **Adapter for loopback traffic capture**
   (Windows) ou `lo` (Linux), filtre `tcp.port == 8000`.
3. Envoyez un message dans le chat.
4. Clic droit sur une trame WebSocket → **Follow** → **TCP Stream**.
5. Vous voyez le JSON :

```json
{"to":"bob","payload":{"t":"msg","n":0,"iv":"...","ct":"..."}}
```

6. Copiez le `ct` et décodez-le :

```powershell
.\.venv\Scripts\python.exe -c "import base64; print(len(base64.b64decode('COLLEZ_ICI')))"
```

Vous obtenez la taille du chiffré + tag, jamais le texte clair. Comparez avec
la ligne `[wire ...]` affichée par le client.

> Si le loopback n'apparaît pas sous Windows, utilisez le relais du professeur
> sur le réseau local et capturez votre carte réseau.

---

## 13. Pour aller plus loin (si vous avez fini)

- Regardez le trafic dans **Wireshark** : filtre `tcp.port == 8000` puis
  clic droit → Follow → TCP Stream. Vous verrez le JSON et le base64, jamais le
  clair.
- Essayez `--pad` (le lanceur ne le propose pas : ajoutez `--pad` à la main) :
  les tailles des messages deviennent plus uniformes.
- Lisez `docs/01` à `docs/05` pour les détails, et `docs/08` pour des idées de
  projet (Double Ratchet, groupe, fichiers...).

Bon TP !
