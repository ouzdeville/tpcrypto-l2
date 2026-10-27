# Scénario 2 — Diffie-Hellman : s'accorder sur une clé sans se la dire

**Durée conseillée : 60 à 75 minutes.**

## Objectifs

- Comprendre l'échange **Diffie-Hellman** sur courbe elliptique (X25519).
- Dériver une clé AES avec **HKDF** (sel + contexte).
- Comprendre pourquoi un DH **non authentifié** est vulnérable à l'homme du
  milieu (MITM).
- Mettre en œuvre l'attaque avec le proxy fourni et interpréter le **SAS**.

## Rappel : Diffie-Hellman en deux phrases

Alice et Bob choisissent chacun un secret `a` et `b`, publient `A = g^a` et
`B = g^b`, puis calculent `B^a = A^b = g^(ab)`. Un observateur qui voit `A` et
`B` ne peut pas calculer `g^(ab)` (problème CDH). Avec X25519, on travaille sur
la courbe Curve25519, les clés publiques font 32 octets.

Le secret brut `g^(ab)` n'est **pas** utilisé directement comme clé AES : on le
passe dans **HKDF-SHA256** avec :

- un **sel** aléatoire (public, mais unique à la session) ;
- un **contexte** (`info = "tpcrypto/s2/x25519"`).

Cela évite de réutiliser la même clé pour deux usages et dompte les propriétés
algébriques du secret DH.

## Le protocole du TP

Convention : le nom le plus petit dans l'ordre alphabétique **initie**
(`alice < bob`).

```
alice                                             bob
  |                                                |
  |  HS1 {step:"dh1", pub:A, salt:S}  -----------> |
  |                                                |  génère b, B
  |  <------------------ HS2 {step:"dh2", pub:B}   |
  |                                                |
  |  secret = X25519(a, B)                         |  secret = X25519(b, A)
  |  clé    = HKDF(secret, salt=S, info=...)        |  clé    = HKDF(secret, salt=S, info=...)
  |                                                |
  |  msg {t:"msg", n, iv, ct}  ------------------> |
  |  ct = AES-256-GCM(clé, clair, AAD)             |
```

L'AAD vaut `s2|alice->bob|n`. Elle empêche de rejouer le message dans l'autre
sens ou vers un autre destinataire.

## Mise en place

```bash
# terminal 1
python -m server

# terminal 2
python -m tpcrypto.scenarios.s2_dh --name bob --peer alice --show-wire

# terminal 3
python -m tpcrypto.scenarios.s2_dh --name alice --peer bob --show-wire
```

L'ordre de démarrage n'a pas d'importance : le serveur met en file le `dh1`
si bob n'est pas encore là.

## Étape 1 — Observer l'échange

Au démarrage, chaque client affiche :

```
[alice] HS1 envoyé (X25519 32 o + salt 16 o)
[bob]   HS2 envoyé (X25519 32 o)
[alice] secret partagé X25519 : 89:0f:fc:1b:9d:ec:73:68
[alice] clé de session dérivée : c5:ba:bd:d4:62:b4:26:00
```

Les deux côtés doivent afficher **le même SAS** (empreinte de la clé de
session). C'est un « code de sécurité » de 16 chiffres hexadécimaux, plus court
qu'une empreinte complète, destiné à être comparé de vive voix.

Tapez `/fp` :

```
X25519 + HKDF-SHA256 + AES-256-GCM
  SAS (empreinte de clé de session) : c5:ba:bd:d4:62:b4:26:00
  Échange NON authentifié : comparez le SAS par un autre canal...
```

**Question immédiate :** que se passe-t-il si vous ne comparez pas le SAS ?

## Étape 2 — Ce que voit un observateur

Avec `--show-wire` :

```
[wire alice->bob] step=dh1 pub=32o salt=16o
[wire bob->alice] step=dh2 pub=32o
[wire alice->bob] n=0 iv=12o ct=32o
```

Dans Wireshark, ce sont exactement ces champs que l'on retrouve en base64.
Un attaquant **passif** voit `A`, `B`, le sel et les chiffrés, mais ne peut pas
calculer `g^(ab)`. Il ne peut pas lire les messages.

## Étape 3 — L'attaque de l'homme du milieu

Un attaquant **actif** peut remplacer les clés publiques. Le proxy fourni le
fait pour vous.

### Mise en place

```bash
# terminal 1 : le vrai relais (port 8000)
python -m server

# terminal 2 : le proxy MITM (écoute sur 8001, relaie vers 8000)
python -m tpcrypto.attacks.mitm --mode dh

# terminal 3 : bob passe par le proxy
python -m tpcrypto.scenarios.s2_dh --name bob --peer alice \
    --url ws://127.0.0.1:8001

# terminal 4 : alice passe par le proxy
python -m tpcrypto.scenarios.s2_dh --name alice --peer bob \
    --url ws://127.0.0.1:8001
```

### Ce qui se passe

Le proxy intercepte `dh1` (clé `A` d'Alice, sel `S`), génère sa propre paire
`m_a / M_a`, et envoie `M_a` à Bob. Bob croit parler à Alice.

Quand Bob répond `dh2` avec `B`, le proxy génère une **seconde** paire
`m_b / M_b` et envoie `M_b` à Alice. Alice croit parler à Bob.

```
Alice          Mallory                         Bob
  A  --------->  M_a  ----------------------->  (croit parler à Alice)
                 clé_Alice = DH(m_b, A)
                 clé_Bob   = DH(m_a, B)
  <-----------  M_b  <-----------------------  B
  clé = DH(a, M_b)                              clé = DH(b, M_a)
```

Le proxy connaît donc les deux clés : il déchiffre avec l'une, ré-chiffre avec
l'autre, et affiche :

```
[MITM] dh1 de alice intercepté : clé publique remplacée (5f2c… -> 91ab…)
[MITM] dh2 de bob intercepté : clé publique remplacée (0d7e… -> 4c33…)
[MITM] deux sessions distinctes : je peux lire tout le clair
[MITM] alice -> bob : "le mot de passe est..."
```

Les deux clients continuent à discuter normalement. **Leurs SAS sont
différents**, mais sans comparaison hors bande, ils ne le savent pas.

### Vérification

- Le tableau de bord du serveur ne montre que du chiffré.
- Le proxy montre le clair.
- Les clients affichent des SAS différents.

## Étape 4 — Pourquoi l'attaque marche

Le protocole prouve que **quelqu'un** connaît `a` et **quelqu'un** connaît `b`,
mais rien ne prouve que `M_a` appartient à Alice, ni que `M_b` appartient à
Bob. Il manque une **authentification des clés**.

C'est exactement ce que corrige le scénario 5 : chaque clé éphémère est signée
par une clé d'identité de long terme, et le code de sécurité permet de vérifier
cette identité hors bande.

### Variante : altérer un bit

```bash
python -m tpcrypto.attacks.mitm --mode tamper
```

Le proxy corrompt une clé publique. Les deux côtés dérivent des clés
différentes ; le premier message est rejeté par GCM (`InvalidTag`). Cela montre
qu'une simple altération **détecte** le problème mais ne l'**empêche** pas :
l'attaquant peut aussi faire échouer la connexion (déni de service).

## Questions

1. Quels sont les secrets d'Alice, de Bob, et ce qui circule sur le réseau ?
2. Un attaquant passif peut-il calculer la clé de session ? Pourquoi ?
3. À quoi servent le sel et le paramètre `info` de HKDF ? Le sel est-il secret ?
4. Pourquoi le SAS doit-il être comparé par un **autre canal** ?
5. Dans le MITM, pourquoi le proxy a-t-il besoin de **deux** paires de clés ?
6. Les clients détectent-ils l'attaque ? À quelle condition ?
7. Si Alice et Bob réutilisent la même clé X25519 pour toutes leurs sessions,
   quelles propriétés perdent-ils ?
8. La convention `alice < bob` est-elle une mesure de sécurité ? Que se passe-t-il
   si les deux clients initient en même temps ?
9. Le serveur peut-il lire les messages ? Peut-il les modifier ? Peut-il les
   supprimer ?
10. Comment une signature Ed25519 peut-elle empêcher le MITM ? Que reste-t-il à
    vérifier ?

## À retenir

- Diffie-Hellman fournit un **secret partagé** sans transmission de clé.
- Il ne fournit **aucune authentification** : c'est un échange anonyme.
- HKDF transforme le secret en clé, avec un contexte explicite.
- Un SAS comparé hors bande détecte un MITM, mais c'est une étape humaine.
- La vraie solution est un **échange de clés authentifié** (scénario 5).

➡️ Suite : [Scénario 3 — RSA KEM/DEM](03-rsa-kem-dem.md)
