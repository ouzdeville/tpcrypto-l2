# Scénario 3 — KEM/DEM avec RSA-OAEP et AES-GCM

**Durée conseillée : 45 à 60 minutes.**

## Objectifs

- Comprendre le schéma **KEM/DEM** (encapsulation de clé + chiffrement de
  données).
- Utiliser une paire de clés **RSA-OAEP** pour transmettre un secret éphémère.
- Constater qu'un chiffrement à clé publique **n'authentifie pas** l'expéditeur
  ni ne protège contre la substitution de clés.
- Discuter de la **confidentialité persistante** (ou de son absence).

## Le problème que RSA résout (et celui qu'il ne résout pas)

Avec le scénario 1, il faut une clé secrète par paire. Avec le scénario 2, on
sait dériver une clé, mais sans authentification. RSA apporte une **clé
publique** : Bob publie sa clé, Alice peut chiffrer sans avoir partagé de secret
au préalable.

Mais RSA ne sait chiffrer qu'un petit bloc (avec OAEP et SHA-256, environ
190 octets pour une clé de 2048 bits). On ne chiffre donc **jamais** le message
directement avec RSA.

## KEM/DEM

```
KEM (Key Encapsulation Mechanism)       DEM (Data Encapsulation Mechanism)
---------------------------------       -----------------------------------
1. tirer un secret s (32 octets)
2. chiffrer s avec la clé publique     3. dériver K = HKDF(s)
   du destinataire : ek = RSA-OAEP(pk, s)
4. envoyer ek                          5. chiffrer le message avec AES-GCM(K)
                                       6. envoyer (ek, iv, ct)
```

Le destinataire :

1. déchiffre `ek` avec sa clé privée RSA : `s = RSA-OAEP⁻¹(sk, ek)` ;
2. dérive `K = HKDF(s)` ;
3. ouvre le message AES-GCM.

C'est la structure utilisée par ML-KEM au scénario 4 : seul le KEM change.

## Le protocole du TP

```
alice                                              bob
  |                                                 |
  |  HS {step:"rsa_pub", pub: DER(pk_A)}  --------> |
  |  <-------- HS {step:"rsa_pub", pub: DER(pk_B)}  |
  |                                                 |
  |  choisit s aléatoire (32 o)                     |
  |  ek = RSA-OAEP(pk_B, s)                         |
  |  K  = HKDF(s, salt=SHA256(ek))                  |
  |  msg {t:"msg", n, ek, iv, ct}  ---------------> |
  |                                                 |  s = RSA-OAEP⁻¹(sk_B, ek)
  |                                                 |  K = HKDF(s, salt=SHA256(ek))
  |                                                 |  AES-GCM⁻¹(K, iv, ct)
```

Le sel `SHA256(ek)` lie la clé AES à l'encapsulation : deux encapsulations
différentes ne peuvent pas produire la même clé AES.

## Mise en place

```bash
# terminal 1
python -m server

# terminal 2
python -m tpcrypto.scenarios.s3_rsa --name bob --peer alice --rsa-bits 2048 --show-wire

# terminal 3
python -m tpcrypto.scenarios.s3_rsa --name alice --peer bob --rsa-bits 2048 --show-wire
```

Au premier lancement, chaque client génère sa paire RSA et l'écrit dans :

```
keys/id_<nom>_rsa2048.pem
```

Les lancements suivants réutilisent la même clé (c'est une clé **de long
terme**). Pour changer de taille, utilisez `--rsa-bits 3072` : un fichier
distinct est créé.

## Étape 1 — Observer les tailles

Avec `--show-wire`, chaque message affiche :

```
[wire alice->bob] n=0 ek=256o iv=12o ct=32o
```

- `ek` = 256 octets = 2048 bits : c'est le chiffré RSA-OAEP.
- `iv` = 12 octets, `ct` = message + tag GCM.

Comparez avec le scénario 2 : là, seuls 32 octets de clé publique et 12 octets
de nonce circulaient. Ici, **chaque message** transporte 256 octets
d'encapsulation. C'est le prix du chiffrement à clé publique.

`/fp` affiche l'empreinte de la clé publique RSA du pair.

## Étape 2 — Ce que RSA ne fait pas

### 2.1 Pas d'authentification de l'expéditeur

N'importe qui possédant la clé publique de Bob peut lui envoyer un message
chiffré. GCM garantit que le message n'a pas été modifié **en transit**, pas
qu'il vient bien d'Alice. Le champ `from` est fourni par le serveur, qui n'est
pas authentifié.

### 2.2 Pas d'authentification des clés

L'échange `rsa_pub` n'est pas signé. Un attaquant actif peut remplacer la clé
publique d'Alice par la sienne lors du handshake, puis lire et ré-chiffrer les
messages (MITM). La confidentialité contre un attaquant **passif** est assurée
(grâce à RSA), mais pas contre un attaquant **actif**.

C'est le même problème qu'au scénario 2, transposé aux clés publiques. La
parade est la signature des clés (scénario 5) ou la vérification d'empreintes
hors bande.

### 2.3 Pas de confidentialité persistante

Le secret `s` est bien éphémère, mais il est protégé par la clé privée RSA de
**long terme**. Si cette clé fuite dans 10 ans, un attaquant qui a enregistré
les `ek` pourra retrouver tous les `s`, puis toutes les clés AES, et déchiffrer
toutes les conversations passées.

C'est le scénario « harvest now, decrypt later » : on enregistre aujourd'hui,
on déchiffre quand la clé (ou l'ordinateur quantique) sera disponible.

## Étape 3 — Expériences

1. Envoyez plusieurs messages : chaque `ek` est différent (nouveau `s` à chaque
   fois), donc chaque clé AES est différente.
2. Supprimez le fichier de clé de Bob, relancez-le : Alice voit une nouvelle
   empreinte RSA. Les messages anciens ne sont plus déchiffrables par Bob (il a
   perdu sa clé). C'est une illustration de la gestion de clés.
3. Lancez `--rsa-bits 3072` : `ek` passe à 384 octets, la génération est plus
   lente.
4. Avec Wireshark, repérez le champ `ek` (base64) et vérifiez sa taille.

## Questions

1. Pourquoi ne chiffre-t-on pas directement le message avec RSA ?
2. Qu'est-ce qu'un KEM ? Un DEM ? Pourquoi les sépare-t-on ?
3. Pourquoi `ek` change-t-il à chaque message ?
4. Pourquoi la clé AES est-elle dérivée avec HKDF plutôt qu'utilisée brute ?
5. Que se passe-t-il si la clé privée RSA de Bob fuite dans 10 ans ?
6. Le serveur peut-il lire les messages ? Peut-il les modifier ? Peut-il se
   faire passer pour Alice ?
7. Quelle propriété manque pour empêcher un MITM sur l'échange `rsa_pub` ?
8. Pourquoi le sel `SHA256(ek)` est-il utile ?
9. RSA-2048 est-il encore sûr aujourd'hui ? Contre un ordinateur quantique ?
10. Quel est le lien entre ce scénario et le scénario 4 ?

## À retenir

- RSA-OAEP sert de **KEM** : il transporte un secret aléatoire, pas le message.
- Le **DEM** est un AEAD (AES-GCM) : rapide et authentifié.
- Le chiffrement à clé publique ne remplace ni l'authentification des clés ni
  la confidentialité persistante.
- Un `ek` de 256 octets par message, c'est lourd : les KEM post-quantiques font
  encore plus gros, mais ils résistent aux ordinateurs quantiques.

➡️ Suite : [Scénario 4 — ML-KEM](04-ml-kem.md)
