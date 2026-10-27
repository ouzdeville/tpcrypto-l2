# Scénario 4 — KEM/DEM avec ML-KEM (post-quantique)

**Durée conseillée : 45 à 60 minutes.**

## Objectifs

- Comprendre pourquoi RSA et Diffie-Hellman seront vulnérables à un
  ordinateur quantique (algorithme de Shor).
- Utiliser **ML-KEM** (FIPS 203, anciennement Kyber), le KEM post-quantique
  standardisé par le NIST.
- Comparer les tailles avec RSA.
- Construire un mode **hybride** X25519 + ML-KEM (défense en profondeur).

## Pourquoi le post-quantique ?

Un ordinateur quantique suffisamment grand casserait :

- RSA (factorisation) ;
- Diffie-Hellman et ECDH (logarithme discret) ;
- les signatures RSA/ECDSA/EdDSA.

Il ne casse pas AES (Grover ne fait que diviser la sécurité par deux : AES-256
reste confortable), ni les fonctions de hachage.

Le risque est **aujourd'hui** : un attaquant peut enregistrer du trafic
chiffré et le déchiffrer plus tard (« harvest now, decrypt later »). D'où la
migration vers des algorithmes post-quantiques.

## ML-KEM en bref

- Standard : **FIPS 203** (2024).
- Famille : réseaux euclidiens (LWE / Module-LWE).
- Propriété : **IND-CCA2** (confidentialité sémantique contre un attaquant à
  chiffrés choisis).
- Secret partagé : 32 octets.
- Paramètres : ML-KEM-512, -768, -1024 (niveaux de sécurité NIST 1, 3, 5).

| Paramètre | Clé publique `ek` | Chiffré KEM `ct` | Niveau |
|---|---:|---:|---|
| ML-KEM-512 | 800 o | 768 o | 1 |
| ML-KEM-768 | **1184 o** | **1088 o** | 3 |
| ML-KEM-1024 | 1568 o | 1568 o | 5 |

À comparer aux 256 octets d'un `ek` RSA-2048… et aux 32 octets d'une clé
publique X25519.

## Le protocole du TP

```
alice                                             bob
  |                                                |
  |  HS {step:"kem_pub", alg:"ML-KEM-768",         |
  |      pub: ek_A}  ----------------------------> |
  |  <------------------ HS {step:"kem_pub", ek_B} |
  |                                                |
  |  ss, ct = Encaps(ek_B)                         |
  |  K = HKDF(ss, info="tpcrypto/s4/mlkem")        |
  |  msg {kem_ct: ct, iv, ct_AES}  --------------> |
  |                                                |  ss = Decaps(dk_B, kem_ct)
  |                                                |  K = HKDF(ss, ...)
  |                                                |  AES-GCM⁻¹(K, ...)
```

Différences avec le scénario 3 :

- pas de padding OAEP : ML-KEM encapsule directement un secret de 32 octets ;
- `ek` et `ct` sont beaucoup plus gros ;
- la paire ML-KEM est générée **à chaque session** et gardée en mémoire (elle
  n'est pas écrite dans `keys/`).

## Mise en place

```bash
# terminal 1
python -m server

# terminal 2
python -m tpcrypto.scenarios.s4_mlkem --name bob --peer alice --param 768 --show-wire

# terminal 3
python -m tpcrypto.scenarios.s4_mlkem --name alice --peer bob --param 768 --show-wire
```

Vérifiez le moteur utilisé :

```bash
python -c "from tpcrypto.pq import MLKEM; k=MLKEM(768); print(k.backend)"
```

Attendu : `cryptography (natif)` si `cryptography >= 50`, sinon `kyber-py
(Python pur)`.

## Étape 1 — Observer les tailles

Au handshake :

```
[alice] ML-KEM-768 via cryptography (natif) (clé publique 1184 o, chiffré KEM 1088 o)
[alice] clé publique ML-KEM-768 envoyée (1184 o, soit 9472 bits)
```

À chaque message :

```
[wire alice->bob] n=0 kem_ct=1088o iv=12o ct=32o
```

Dans Wireshark, la clé publique ML-KEM occupe une très longue chaîne base64
(environ 1580 caractères). C'est normal : la sécurité post-quantique a un coût
en bande passante.

## Étape 2 — Comparer avec RSA

| | RSA-2048 (scénario 3) | ML-KEM-768 (scénario 4) |
|---|---:|---:|
| Clé publique | 294 o (DER) | 1184 o |
| Chiffré KEM par message | 256 o | 1088 o |
| Secret partagé | 32 o | 32 o |
| Résiste à Shor | ❌ | ✅ |
| Génération de clé | lente | rapide |

Le chiffré KEM ML-KEM est plus gros qu'une encapsulation RSA, mais la
génération de clé est bien plus rapide et la sécurité ne dépend pas de la
factorisation.

## Étape 3 — Le mode hybride (recommandé en pratique)

```bash
# les DEUX clients doivent utiliser --hybrid
python -m tpcrypto.scenarios.s4_mlkem --name bob   --peer alice --hybrid --show-wire
python -m tpcrypto.scenarios.s4_mlkem --name alice --peer bob   --hybrid --show-wire
```

Le handshake transporte en plus une clé X25519 statique (`x_pub`). À chaque
message, l'expéditeur génère une clé X25519 éphémère et combine :

```
ss_total = ss_ML-KEM || ss_X25519
K = HKDF(ss_total, salt=SHA256(ek_destinataire || x_pub_destinataire),
         info="tpcrypto/s4/x25519+mlkem")
```

Si ML-KEM est un jour cassé, X25519 protège encore ; si X25519 est cassé par un
ordinateur quantique, ML-KEM protège encore. C'est la stratégie des protocoles
réels (TLS hybride, X-Wing, etc.).

> **Simplification pédagogique :** notre combinaison concatène simplement les
> deux secrets. X-Wing spécifie un combinateur et des étiquettes plus précis.
> Ne réutilisez pas ce code tel quel en production.

## Étape 4 — Ce qui n'est toujours pas réglé

### 4.1 L'authentification des clés

Le handshake `kem_pub` n'est pas signé. Un attaquant actif peut remplacer la
clé ML-KEM d'Alice par la sienne, décapsuler avec sa clé, et ré-encapsuler vers
Bob. ML-KEM protège contre l'ordinateur quantique, **pas** contre un MITM.

La parade est la même qu'au scénario 5 : signer la clé échangée avec une clé
d'identité, et vérifier cette identité hors bande.

### 4.2 La confidentialité persistante

Ici, la paire ML-KEM est générée pour la session et jamais persistée : si le
processus s'arrête et que la mémoire est effacée, une compromission future ne
permet pas de déchiffrer la session passée. C'est une forme de confidentialité
persistante **de session**.

En revanche, dans le mode hybride, la clé X25519 statique est écrite dans
`keys/id_<nom>_x25519.pem`. Elle ne suffit pas à elle seule à retrouver la clé
finale (il faudrait aussi casser ML-KEM), mais elle réduit la garantie si
ML-KEM est cassé plus tard.

Pour une vraie confidentialité persistante par message, il faut un **ratchet**
(Double Ratchet de Signal) ou des clés éphémères par session, avec effacement
strict des secrets.

## Questions

1. Pourquoi RSA et ECDH sont-ils vulnérables à un ordinateur quantique ?
2. AES-256 est-il cassé par Grover ? Que signifie « sécurité divisée par deux » ?
3. Qu'est-ce qu'un KEM IND-CCA2 ? Pourquoi le CCA est-il important ?
4. Pourquoi la clé publique ML-KEM est-elle si grosse ? Est-ce un problème en
   pratique ?
5. Comparez le coût réseau d'un message RSA-OAEP et d'un message ML-KEM.
6. Pourquoi le mode hybride est-il recommandé même si ML-KEM est standardisé ?
7. Un attaquant quantique peut-il casser le scénario 4 ? Un attaquant classique
   actif ?
8. Où est stockée la clé privée ML-KEM ? Quelles conséquences pour la
   confidentialité persistante ?
9. Pourquoi la signature des clés est-elle indispensable, même en post-quantique ?
10. Que faudrait-il changer pour obtenir une confidentialité persistante par
    message ?

## À retenir

- ML-KEM remplace RSA/ECDH dans le rôle de **KEM**, pas AES dans le rôle de
  **DEM**.
- Les tailles augmentent fortement : c'est un compromis assumé.
- Le mode hybride est la norme de transition : on combine classique et
  post-quantique.
- La cryptographie post-quantique ne dispense **jamais** d'authentifier les
  clés.

➡️ Suite : [Scénario 5 — DH signé](05-dh-signe.md)
