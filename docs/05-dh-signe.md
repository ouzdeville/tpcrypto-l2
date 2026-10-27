# Scénario 5 — Diffie-Hellman authentifié par signature

**Durée conseillée : 60 à 75 minutes.**

## Objectifs

- Corriger l'attaque MITM du scénario 2 par une **signature** de la clé
  éphémère.
- Comprendre ce qu'une **clé d'identité** de long terme apporte (et ce qu'elle
  ne résout pas).
- Mettre en place un **code de sécurité** (safety number) et l'**épinglage**
  d'identité.
- Distinguer authentification, confidentialité et confidentialité persistante.

## Le problème à résoudre

Au scénario 2, un attaquant actif remplace les clés X25519. Les clients ne
peuvent pas savoir que la clé reçue n'appartient pas au pair, car rien ne relie
la clé éphémère à une identité.

## L'idée

Chaque client possède :

- une **clé d'identité Ed25519** de long terme, stockée localement
  (`keys/id_<nom>_ed25519.pem`) ;
- une **clé éphémère X25519** par session, générée à chaque lancement.

Il **signe** sa clé éphémère avec sa clé d'identité. La signature couvre aussi
le contexte :

```
salon + expéditeur + destinataire + clé DH éphémère + clé d'identité
```

Ainsi, une clé DH ne peut pas être déplacée d'un salon, d'un destinataire ou
d'une session à l'autre.

## Le protocole du TP

```
alice                                             bob
  |                                                |
  |  HS1 {step:"signed_dh1", pub:A, id_pub:IA,     |
  |       sig:Ed25519(sk_A, transcript)}  -------> |
  |                                                |  vérifie sig avec IA
  |  <------ HS2 {step:"signed_dh2", pub:B,        |
  |            id_pub:IB, sig:Ed25519(sk_B, ...)}  |
  |  vérifie sig avec IB                           |
  |                                                |
  |  secret = X25519(a, B)                         |  secret = X25519(b, A)
  |  clé = HKDF(secret, salt=SHA256(étiquette ||  |  clé = HKDF(secret, ...)
  |              salon || A || B triés))           |
  |                                                |
  |  msg {t:"msg", n, iv, ct}  ------------------> |
```

Le `transcript` est un JSON canonique (`sort_keys=True`) :

```json
{"v":1,"room":"LAB","from":"alice","to":"bob","dh":"...","id":"..."}
```

Si un attaquant remplace `pub`, la signature ne vérifie plus : le client
affiche `SIGNATURE INVALIDE` et refuse la connexion.

## Mise en place

```bash
# terminal 1
python -m server

# terminal 2
python -m tpcrypto.scenarios.s5_signed_dh --name bob --peer alice --show-wire

# terminal 3
python -m tpcrypto.scenarios.s5_signed_dh --name alice --peer bob --show-wire
```

Au premier lancement, chaque client crée sa clé d'identité et affiche son
empreinte :

```
[bob] clé d'identité Ed25519 : keys/id_bob_ed25519.pem
[bob] empreinte d'identité : 35:bc:f5:ac:56:a2:d8:51
```

## Étape 1 — Le code de sécurité

Après le handshake, chaque client affiche :

```
[alice] signature Ed25519 de bob vérifiée
[alice] clé de session : b7:b7:6c:0c:8e:aa:b0:d7
[alice] CODE DE SÉCURITÉ : 03972 04403 51051 88277 75243 94194
```

Les deux côtés doivent avoir **exactement le même code**. Il est calculé à
partir des deux clés d'identité (triées, donc symétrique).

**Exercice :** comparez-le de vive voix (ou par un canal différent du chat).
C'est votre protection contre la substitution d'identité.

Pourquoi un code de 30 chiffres ? Il représente environ 100 bits : impossible
à faire coïncider par hasard, mais assez court pour être lu au téléphone.

## Étape 2 — L'attaque MITM échoue

```bash
# terminal 1 : relais
python -m server

# terminal 2 : proxy qui altère un bit du handshake
python -m tpcrypto.attacks.mitm --mode tamper

# terminal 3
python -m tpcrypto.scenarios.s5_signed_dh --name bob --peer alice \
    --url ws://127.0.0.1:8001

# terminal 4
python -m tpcrypto.scenarios.s5_signed_dh --name alice --peer bob \
    --url ws://127.0.0.1:8001
```

Côté Bob (le répondeur qui vérifie Alice en premier) :

```
[handshake] SIGNATURE INVALIDE de alice !
  La clé DH reçue ne correspond pas à la clé d'identité annoncée.
  C'est exactement ce que produirait un homme du milieu (MITM).
  Connexion refusée.
```

Le processus s'arrête avec le code 2. Le proxy ne peut pas lire les messages.

> **Variante :** `--mode dh` ne modifie que les messages `dh1`/`dh2` du scénario
> 2 ; pour le scénario 5, utilisez `--mode tamper` (ou un proxy qui remplace
> `pub` **et** `id_pub`).

## Étape 3 — Et si l'attaquant remplace aussi l'identité ?

Un attaquant qui remplace `id_pub` par sa propre clé peut produire une
signature valide… avec **son** identité. Alice et Bob verront alors des codes
de sécurité différents de ceux qu'ils attendaient.

C'est pour cela que le code doit être vérifié **hors bande**, ou que la clé
d'identité doit être **épinglée**.

### Épinglage avec `--expect-fingerprint`

Notez l'empreinte d'identité de Bob (affichée au démarrage), puis :

```bash
python -m tpcrypto.scenarios.s5_signed_dh --name alice --peer bob \
    --expect-fingerprint 35:bc:f5:ac:56:a2:d8:51
```

Si la clé de Bob change (réinstallation, attaque), Alice refuse :

```
EMPREINTE D'IDENTITÉ INATTENDUE pour bob
  attendue : 35:bc:f5:ac:56:a2:d8:51
  reçue    : ...
```

C'est le modèle **TOFU** (*Trust On First Use*) : on fait confiance à la
première clé, puis on alerte si elle change. Signal, SSH et WhatsApp utilisent
des variantes de ce principe.

> **Limite du TP :** l'empreinte épinglée fait 64 bits (16 caractères hex).
> En production, on compare la clé complète ou une empreinte de 128+ bits, et
> on s'appuie sur la transparence des clés (key transparency) pour détecter les
> substitutions.

## Étape 4 — Confidentialité persistante

Les clés X25519 sont **éphémères** : elles ne sont pas écrites sur disque et
changent à chaque session. La clé d'identité ne sert qu'à signer.

Conséquence : si la clé d'identité de Bob fuite dans un an, elle permet à un
attaquant de **se faire passer pour Bob** dans de nouvelles sessions (s'il
n'est pas détecté par l'épinglage), mais **pas** de déchiffrer les sessions
passées : les secrets X25519 correspondants ont été détruits.

C'est la **confidentialité persistante** (forward secrecy).

Ce qui n'est **pas** couvert :

- la **sécurité post-compromission** : après une compromission active de la
  machine, il n'y a pas de mécanisme de « ratchet » pour retrouver une clé
  propre automatiquement ;
- la compromission de l'endpoint (logiciel espion, mémoire) ;
- la révocation : si une clé d'identité est compromise, il faut la révoquer et
  prévenir les pairs.

## Questions

1. Que signe exactement Alice ? Pourquoi inclure le salon, l'expéditeur et le
   destinataire dans le transcript ?
2. Pourquoi signer la clé **éphémère** plutôt que chaque message ?
3. Comment le code de sécurité détecte-t-il une substitution d'identité ?
4. Que se passe-t-il si les utilisateurs ne comparent jamais le code ?
5. Un MITM qui remplace uniquement la clé DH est-il détecté ? Et s'il remplace
   aussi la clé d'identité ?
6. Le serveur peut-il se faire passer pour Alice auprès de Bob ? Dans quelles
   conditions ?
7. Qu'est-ce que TOFU ? Quels sont ses angles morts ?
8. Pourquoi Ed25519 plutôt que RSA pour les signatures ?
9. Que se passe-t-il si la clé d'identité fuite après la session ? Et si la clé
   éphémère fuite pendant la session ?
10. Pourquoi la confidentialité persistante n'est-elle pas automatique avec une
    simple signature ?
11. Que faudrait-il ajouter pour la sécurité post-compromission ?
12. Pourquoi l'empreinte du pair est-elle épinglée, et pas seulement le code de
    sécurité ?

## À retenir

- Une signature transforme un DH anonyme en **échange de clés authentifié**.
- L'authentification repose sur une **clé d'identité** et sur la vérification
  hors bande de cette identité.
- Les clés éphémères apportent la **confidentialité persistante** ; la clé
  d'identité ne doit pas servir à chiffrer.
- Un protocole réel ajoute un ratchet, la révocation, la transparence des clés
  et la protection des métadonnées.

➡️ Pour le TP : [guide Wireshark](06-wireshark.md) et
[pour aller plus loin](08-aller-plus-loin.md).
