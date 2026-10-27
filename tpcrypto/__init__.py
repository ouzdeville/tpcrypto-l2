"""TP Crypto : chat de bout en bout, du chiffrement symétrique aux KEM post-quantiques.

Ce paquet contient tout le code partagé par les scénarios :

- ``net``    : client WebSocket vers le relais central ;
- ``codec``  : base commune des codecs de message (AEAD, compteur anti-rejeu) ;
- ``crypto`` : primitives et utilitaires (HKDF, AES-GCM, encodage base64...) ;
- ``pq``     : adaptateur ML-KEM (cryptography >= 50, sinon kyber-py / pqcrypto) ;
- ``keys``   : stockage local des clés d'identité (Ed25519, RSA) ;
- ``chat``   : boucle de chat en ligne de commande ;
- ``scenarios`` : les cinq scénarios du TP ;
- ``attacks``   : proxy d'attaque de l'homme du milieu (MITM).
"""

__version__ = "1.0.0"
