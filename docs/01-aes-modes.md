# Scénario 1 — Secret partagé et AES : le choix du mode opératoire

**Durée conseillée : 45 à 60 minutes.**

## Objectifs

- Comprendre la différence entre un **chiffrement par blocs** (AES) et un
  **mode opératoire** (ECB, CBC, CTR, GCM).
- Voir concrètement pourquoi **ECB est interdit**.
- Comprendre le rôle de l'**IV / nonce**, du **padding** et du **tag
  d'authentification**.
- Manipuler un AEAD (AES-GCM) et son AAD.

## Le modèle du scénario

Les deux clients possèdent la **même clé AES-256**, transmise hors bande
(fichier `keys/lab_psk.hex`, clé USB, ENT...). Il n'y a **aucune négociation de
clé** : c'est le point de départ, volontairement simpliste.

```
alice                                           bob
  |  clé K (pré-partagée, hors bande)              |  clé K
  |                                               |
  |  -- {t:"msg", n, iv, ct} ------------------>  |
  |     ct = AES-mode(K, message, iv)             |
  |                                               |
  |  <----------------- {t:"msg", n, iv, ct} ---- |
```

Le champ `n` est un compteur de message. Il est inclus dans l'AAD de GCM :
un message rejoué ou déplacé est rejeté.

## Mise en place

### 1. Démarrer le relais

```bash
python -m server
```

Tableau de bord : <http://127.0.0.1:8000/>.

### 2. Générer la clé pré-partagée

Sur un seul poste :

```bash
python scripts/gen_psk.py
```

Le script affiche l'empreinte, la valeur hexadécimale et écrit
`keys/lab_psk.hex`. **Copiez ce fichier sur l'autre poste** (ou utilisez
`--key <hex>` sur les deux clients).

> Vérification : `/fp` dans les deux chats doit afficher la même empreinte.

### 3. Lancer deux clients

```bash
# terminal 2
python -m tpcrypto.scenarios.s1_aes --name bob --peer alice --mode gcm --show-wire

# terminal 3
python -m tpcrypto.scenarios.s1_aes --name alice --peer bob --mode gcm --show-wire
```

---

## Étape 1 — La référence : AES-256-GCM

En mode `gcm`, chaque message utilise :

- un nonce aléatoire de **12 octets** ;
- AES-GCM, donc confidentialité **et** intégrité ;
- une AAD `s1|alice->bob|n` qui lie le message à l'expéditeur, au destinataire
  et au numéro.

Envoyez quelques messages. Observez `--show-wire` :

```
[wire alice->bob] n=0 iv=12o ct=32o
```

Le `ct` contient le chiffré **et** le tag (16 octets). Le serveur ne peut rien
en faire.

Testez `/fp` :

```
AES-256-GCM | empreinte de la clé : 98:30:...
  GCM : confidentialité + intégrité (AEAD).
```

**À noter :** une clé pré-partagée ne passe pas à l'échelle (il faut une clé
par paire) et n'apporte pas de confidentialité persistante. Les scénarios
suivants corrigent cela.

---

## Étape 2 — ECB : la fuite de structure

Relancez les deux clients avec `--mode ecb` (même clé) :

```bash
python -m tpcrypto.scenarios.s1_aes --name bob --peer alice --mode ecb --show-wire
python -m tpcrypto.scenarios.s1_aes --name alice --peer bob --mode ecb --show-wire
```

Tapez `/demo`. Le message est construit avec trois blocs identiques :

```
BLOC-REPETE-0001 BLOC-REPETE-0001 BLOC-REPETE-0001 FIN-DU-MESSAGE!!
```

Le client affiche automatiquement l'analyse des blocs :

```
[ECB] 5 bloc(s), 3 unique(s), 2 doublon(s)
    bloc 00  3d65e99546517c15ec6ec940817dd39e
    bloc 01  3d65e99546517c15ec6ec940817dd39e  <-- identique au bloc 0
    ...
```

**Conclusion :** en ECB, un bloc de clair identique produit toujours le même
bloc chiffré. Un attaquant retrouve les répétitions, les zones uniformes, les
en-têtes, etc.

Pour visualiser à plus grande échelle :

```bash
python -m demos.ecb_visual
```

La scène reste parfaitement reconnaissable en ECB, alors qu'elle devient du
bruit en CBC.

> **Remarque :** ECB n'utilise ni IV ni padding aléatoire. Le padding PKCS#7
> est déterministe, ce qui ajoute encore des répétitions.

---

## Étape 3 — CBC : l'IV, et le piège de l'IV fixe

Relancez avec `--mode cbc` (IV aléatoire). Deux messages identiques donnent
des chiffrés **différents** : le premier bloc est masqué par l'IV, les suivants
par le chaînage.

Maintenant, testez l'IV fixe :

```bash
python -m tpcrypto.scenarios.s1_aes --name bob   --peer alice --mode cbc --fixed-iv --show-wire
python -m tpcrypto.scenarios.s1_aes --name alice --peer bob   --mode cbc --fixed-iv --show-wire
```

Envoyez deux fois exactement le même message (par exemple `/demo` deux fois).
Les deux chiffrés sont **identiques**. L'IV fixe annule le bénéfice du mode.

### Et surtout : CBC est malléable

L'IV est transmis **en clair** et n'est **pas authentifié**. Un attaquant qui
modifie l'IV modifie le premier bloc du clair, sans la clé :

```bash
python -m demos.malleability
```

```
clair   : 'VIREMENT: 100 EUR VERS ALICE ...'
forgé   : 'VIREMENT: 900 EUR VERS ALICE ...'
```

Aucune erreur n'est signalée au destinataire : CBC n'a pas de tag. Pour
modifier un bloc plus loin, on altère le bloc chiffré précédent (qui devient
illisible). C'est le principe des attaques par **bit-flipping**.

---

## Étape 4 — CTR : le nonce, et sa réutilisation catastrophique

Relancez avec `--mode ctr`. Le chiffrement est un flux : `c = p XOR ks`, où
`ks` dépend de la clé et du nonce. Conséquences :

- pas besoin de padding ;
- modifier un octet du chiffré modifie le même octet du clair ;
- **réutiliser le nonce avec la même clé réutilise le même `ks`**.

Testez :

```bash
python -m tpcrypto.scenarios.s1_aes --name bob   --peer alice --mode ctr --fixed-iv --show-wire
python -m tpcrypto.scenarios.s1_aes --name alice --peer bob   --mode ctr --fixed-iv --show-wire
```

Puis :

```bash
python -m demos.nonce_reuse
```

```
c1 XOR c2 : 1e006e070a1e...
p1 XOR p2 : 1e006e070a1e...
Message 2 retrouvé : 'LE CODE DU COFFRE EST 4271 OK!!'
```

Si l'attaquant connaît un des deux messages (un message de politesse, un
en-tête...), il récupère l'autre par simple XOR. La démo montre que **GCM est
touché aussi** : GCM utilise CTR en interne, et la bibliothèque ne vous
avertira pas.

---

## Étape 5 — GCM : l'intégrité en plus

Repassez en `--mode gcm`. Modifiez un octet du `ct` (dans Wireshark, un proxy,
ou avec un petit script) : le destinataire affiche

```
[s1] message rejeté : InvalidTag (...)
```

Le tag GCM couvre le chiffré **et** l'AAD. Impossible de modifier le message,
le numéro `n` ou les noms sans être détecté.

### AAD et anti-rejeu

- L'AAD contient `s1|alice->bob|n`. Un message renvoyé à un autre destinataire
  ou rejoué avec un autre numéro échoue.
- Le codec mémorise le dernier `n` reçu et rejette tout `n` déjà vu.

> **Limite :** GCM avec des nonces aléatoires de 96 bits est sûr pour un nombre
> raisonnable de messages par clé. En production, on utilise souvent un
> compteur strict ou un nonce plus long (AES-GCM-SIV, XChaCha20-Poly1305).

---

## Étape 6 — Masquer la longueur (option)

Avec `--pad`, les messages sont complétés à un multiple de 256 octets avant
chiffrement :

```bash
python -m tpcrypto.scenarios.s1_aes --name alice --peer bob --mode gcm --pad --show-wire
```

Les tailles sur le fil deviennent beaucoup plus uniformes. Cela ne cache ni le
moment des échanges, ni leur fréquence, ni les métadonnées `from/to`.

---

## Ce que voit le serveur

Ouvrez <http://127.0.0.1:8000/> pendant l'échange :

- `from`, `to`, l'heure, la taille ;
- `t=msg`, `n`, `iv`, `ct` en base64 ;
- **aucun texte clair**.

En ECB, le serveur (ou Wireshark) peut toutefois repérer des **blocs
identiques** dans le `ct` : c'est déjà une fuite.

---

## Questions

1. Pourquoi ECB laisse-t-il apparaître la structure de l'image ?
2. Pourquoi un IV aléatoire en CBC empêche-t-il deux messages identiques
   d'avoir le même chiffré ?
3. Que se passe-t-il si l'IV est fixe ? Et si l'IV est réutilisé mais que le
   message change ?
4. Pourquoi CTR est-il particulièrement sensible à la réutilisation de nonce ?
5. GCM est-il immunisé contre la réutilisation de nonce ? Justifiez.
6. Quelle propriété de sécurité manque à CBC et CTR ? Comment GCM l'apporte-t-il ?
7. À quoi sert l'AAD ? Que se passe-t-il si on met `n` dans l'AAD mais qu'on ne
   vérifie pas `n` à la réception ?
8. Pourquoi le padding PKCS#7 est-il nécessaire en CBC/ECB mais pas en CTR/GCM ?
9. Une clé pré-partagée entre 10 personnes : combien de clés faut-il ? Quel
   problème cela pose-t-il ?
10. Pourquoi la confidentialité persistante est-elle impossible avec une clé
    pré-partagée unique ?

## À retenir

| Mode | Confidentialité | Intégrité | IV/nonce | Verdict |
|---|---|---|---|---|
| ECB | fuite de structure | non | aucun | ❌ à bannir |
| CBC | oui (si IV aléatoire) | non | aléatoire | ⚠️ malléable |
| CTR | oui (si nonce unique) | non | unique | ⚠️ malléable |
| GCM | oui | oui (tag + AAD) | unique | ✅ recommandé |

➡️ Suite : [Scénario 2 — Diffie-Hellman](02-diffie-hellman.md)
