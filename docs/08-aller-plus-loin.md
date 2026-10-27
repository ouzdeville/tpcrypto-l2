# Aller plus loin — idées de projets et d'extensions

Le TP couvre les briques de base. Voici des prolongements classés par
difficulté, avec des pointeurs dans le code.

## Niveau 1 — consolider (1 à 3 h)

### 1.1 Chiffrer et transférer un fichier

Ajouter une commande `/file <chemin>` au chat :

- lire le fichier par blocs de 64 Kio ;
- chiffrer chaque bloc avec AES-GCM et un numéro de séquence ;
- envoyer un manifeste (nom, taille, SHA-256, nombre de blocs) ;
- réassembler et vérifier le hash à l'arrivée.

Points à traiter : reprise après erreur, blocs perdus, nom de fichier (fuite de
métadonnées), taille maximale. Le codec de `tpcrypto/codec.py` peut être
réutilisé pour le chiffrement par bloc.

### 1.2 Chiffrement de groupe

Le modèle actuel est pairwise. Pour un groupe :

- chaque membre génère une **sender key** et la distribue chiffrée à chacun
  (avec le KEM/DH de son choix) ;
- les messages sont chiffrés une fois avec la sender key ;
- la rotation est nécessaire à chaque départ.

C'est le principe de Signal (sender keys) et de MLS (RFC 9420) pour les grands
groupes.

### 1.3 Protection des métadonnées

- `--pad` est déjà là ; ajoutez un padding **aléatoire** dans une plage (pour
  éviter les multiples exacts) ;
- envoyez du **couvert** (dummy traffic) à intervalles réguliers ;
- séparez l'identité de routage de l'identité cryptographique (*sealed sender*).

Discutez des limites : le serveur voit toujours qui est en ligne et quand.

### 1.4 TLS + E2E

Faites tourner le relais derrière un reverse proxy TLS (`caddy`, `nginx`) et
passez les clients en `wss://`. Que voit Wireshark ? Que voit le serveur ?
Conclusion : TLS et E2E sont complémentaires, pas concurrents.

## Niveau 2 — protocoles (1 à 2 jours)

### 2.1 Double Ratchet

Implémentez un ratchet simplifié :

- **ratchet DH** : un nouveau X25519 à chaque tour de conversation ;
- **ratchet symétrique** : une chaîne de clés par message (KDF chain) ;
- en-tête avec l'identifiant de clé et le numéro ;
- conservation des clés de messages hors ordre dans une fenêtre bornée.

Objectifs : confidentialité persistante **et** sécurité post-compromission.
Références : spécification Double Ratchet de Signal, chapitres de
*Real-World Cryptography*.

### 2.2 X3DH et premiers contacts asynchrones

Aujourd'hui, les deux clients doivent être en ligne pour le handshake. X3DH
permet à Alice d'envoyer un message à Bob hors ligne :

- Bob publie un **identity key**, une **signed prekey** et des **one-time
  prekeys** sur le serveur ;
- Alice choisit un prekey, effectue plusieurs DH, dérive une clé de session ;
- Bob, à son réveil, reconstruit le secret.

À traiter : épuisement des one-time prekeys, authentification des prekeys,
rotation.

### 2.3 PAKE : un mot de passe partagé

Si les utilisateurs n'ont qu'un mot de passe faible, un KEM/DH classique ne
suffit pas (attaque hors ligne). Étudiez **SPAKE2** ou **OPAQUE** :

- le mot de passe ne doit jamais être envoyé ;
- un attaquant passif ne peut pas tester de mot de passe hors ligne ;
- un attaquant actif n'a qu'un essai par session.

Le TP actuel utilise une PSK de 256 bits, pas un mot de passe : c'est
volontaire.

### 2.4 Signatures post-quantiques

`cryptography >= 50` expose aussi **ML-DSA** (FIPS 204). Remplacez Ed25519 par
ML-DSA pour l'identité :

- clés et signatures plus grosses ;
- sécurité post-quantique ;
- comparez les tailles et les temps de signature.

Le reste du protocole (transcript, safety number, pinning) ne change pas.

### 2.5 Hybride formel : X-Wing

Notre mode hybride concatène simplement les secrets. Étudiez X-Wing :

- combinateur précis, étiquettes de domaine ;
- preuve de sécurité ;
- test vectors.

C'est un bon exercice de lecture de spécification.

## Niveau 3 — sécurité et qualité (2 à 5 jours)

### 3.1 Rejeu, désordre, perte

Le codec rejette déjà les `n` déjà vus. Ajoutez :

- une fenêtre glissante pour accepter les messages hors ordre ;
- un accusé de réception et une retransmission ;
- une protection contre le rejeu **du handshake** (identifiants de session,
  expiration).

### 3.2 Déni de service et robustesse

- limitez la taille des messages et la fréquence (rate limiting) ;
- validez tous les champs JSON (types, tailles, base64) ;
- testez avec des entrées malformées (fuzzing) ;
- le relais actuel met en file jusqu'à 200 messages par utilisateur : que se
  passe-t-il si on le spamme ?

### 3.3 Stockage des clés

Les clés sont en clair dans `keys/`. Proposez :

- un fichier PEM chiffré par mot de passe (PBKDF2/scrypt/Argon2) ;
- le trousseau de l'OS (Windows DPAPI, macOS Keychain, Secret Service) ;
- une séparation des privilèges (l'application ne lit la clé qu'au démarrage).

### 3.4 Vérification formelle

Modélisez le handshake du scénario 5 dans **ProVerif** ou **Tamarin** et
vérifiez :

- secret de la clé de session ;
- authentification d'Alice auprès de Bob ;
- absence de MITM.

C'est un excellent pont vers la recherche.

### 3.5 Tests et vecteurs

- ajoutez des vecteurs de test NIST pour AES-GCM, HKDF, ML-KEM ;
- testez les mauvaises tailles, les tags tronqués, les clés invalides ;
- vérifiez le comportement en cas de `base64` malformé ;
- testez sur Linux et Windows (le TP est déjà portable).

## Niveau 4 — produit (projet long)

### 4.1 Client web

Un client web avec **WebCrypto** pour AES-GCM et ECDH, et une bibliothèque
ML-KEM en WASM. Attention : WebCrypto ne fournit pas ML-KEM partout, et le
navigateur n'est pas un coffre-fort de clés.

### 4.2 Interface graphique

Une petite interface (Tkinter, Textual, web) qui affiche :

- le cadenas et le code de sécurité ;
- les empreintes à vérifier ;
- l'état du ratchet ;
- une vue « ce que le serveur voit ».

### 4.3 Journalisation sans secrets

Ajoutez des métriques (latence, taille, taux de rejet) sans jamais journaliser
de clé ni de clair. Testez avec un `grep` sur les logs.

## Lectures

- NIST **FIPS 203** (ML-KEM), **FIPS 204** (ML-DSA) ;
- RFC 7748 (X25519), RFC 5869 (HKDF), RFC 5116 (AEAD) ;
- Signal : *Double Ratchet*, *X3DH*, *Sealed Sender* ;
- D. Wong, *Real-World Cryptography* ;
- J.-P. Aumasson, *Serious Cryptography* ;
- Boneh & Shoup, *A Graduate Course in Applied Cryptography* (gratuit) ;
- MLS : RFC 9420.

## Avertissement

Ne déployez jamais ce code tel quel pour de vraies communications. Il manque :

- une génération et un stockage de clés robustes ;
- une protection mémoire et une gestion des secrets ;
- une authentification du relais et des usernames ;
- une protection contre le déni de service ;
- des audits, des tests de pénétration et une revue cryptographique ;
- une gestion de version et de révocation des identités.

Le TP est un **outil de compréhension**, pas un produit.
