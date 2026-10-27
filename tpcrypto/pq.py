"""Adaptateur ML-KEM (FIPS 203) avec plusieurs moteurs possibles.

Ordre de préférence :

1. ``cryptography >= 50`` : implémentation native, rapide, aucune dépendance de
   plus (c'est le cas par défaut du TP) ;
2. ``kyber-py`` : implémentation Python pure, pratique si ``cryptography`` est
   trop ancien (plus lente, mais parfaite pour lire le code) ;
3. ``pqcrypto`` : bindings C de PQClean, si installé.

L'interface exposée est volontairement minimale :

    kem = MLKEM(768)
    kem.keygen()
    cle_publique = kem.public_bytes()
    secret, chiffre = kem.encapsulate(cle_publique_du_pair)
    secret2 = kem.decapsulate(chiffre)

``encapsulate`` et ``decapsulate`` renvoient/consomment des ``bytes`` bruts, ce
qui permet de les transmettre tels quels en base64.
"""

from __future__ import annotations

from typing import Any


class MLKEM:
    """ML-KEM-768 ou ML-KEM-1024, avec bascule automatique de moteur."""

    SIZES = {
        512: {"ek": 800, "ct": 768},
        768: {"ek": 1184, "ct": 1088},
        1024: {"ek": 1568, "ct": 1568},
    }

    def __init__(self, param: int = 768) -> None:
        if param not in (512, 768, 1024):
            raise ValueError("paramètre ML-KEM non supporté (512, 768 ou 1024)")
        self.param = param
        self.backend = ""
        self._impl = ""
        self._priv: Any = None
        self._dk: bytes | None = None
        self._pub: bytes | None = None

        try:
            from cryptography.hazmat.primitives.asymmetric import mlkem  # noqa: F401

            self._impl = "cryptography"
            self.backend = "cryptography (natif)"
        except ImportError:
            try:
                from kyber_py.ml_kem import (  # noqa: F401
                    ML_KEM_512,
                    ML_KEM_768,
                    ML_KEM_1024,
                )

                self._impl = "kyber-py"
                self.backend = "kyber-py (Python pur)"
            except ImportError:
                try:
                    from pqcrypto.kem import (  # noqa: F401
                        ml_kem_512,
                        ml_kem_768,
                        ml_kem_1024,
                    )

                    self._impl = "pqcrypto"
                    self.backend = "pqcrypto (PQClean)"
                except ImportError as exc:  # pragma: no cover - dépend de l'env
                    raise RuntimeError(
                        "Aucun moteur ML-KEM disponible.\n"
                        "Installez 'cryptography>=50' (recommandé) :\n"
                        "    pip install -U 'cryptography>=50'\n"
                        "ou, en repli :\n"
                        "    pip install kyber-py"
                    ) from exc

        if param == 512 and self._impl == "cryptography":
            # cryptography n'expose que ML-KEM-768 et ML-KEM-1024.
            raise RuntimeError(
                "cryptography ne fournit pas ML-KEM-512 ; utilisez 768 ou 1024."
            )

    # -- cycle de vie ------------------------------------------------------

    def keygen(self) -> None:
        """Génère une paire de clés et mémorise la clé publique."""
        if self._impl == "cryptography":
            from cryptography.hazmat.primitives.asymmetric import mlkem

            cls = (
                mlkem.MLKEM768PrivateKey
                if self.param == 768
                else mlkem.MLKEM1024PrivateKey
            )
            self._priv = cls.generate()
            self._pub = self._priv.public_key().public_bytes_raw()
        elif self._impl == "kyber-py":
            cls = self._kyber_cls()
            ek, dk = cls.keygen()
            self._pub, self._dk = ek, dk
        else:
            module = self._pq_module()
            pk, sk = module.keygen()
            self._pub, self._dk = pk, sk

    def public_bytes(self) -> bytes:
        if self._pub is None:
            raise RuntimeError("appelez keygen() d'abord")
        return self._pub

    # -- encapsulation / décapsulation ------------------------------------

    def encapsulate(self, peer_public_key: bytes) -> tuple[bytes, bytes]:
        """Renvoie ``(secret_partagé, texte_chiffré_KEM)``.

        Attention aux conventions : le premier élément est TOUJOURS le secret,
        le second le chiffré KEM. C'est l'ordre utilisé dans tout le TP.
        """
        if self._impl == "cryptography":
            from cryptography.hazmat.primitives.asymmetric import mlkem

            cls = (
                mlkem.MLKEM768PublicKey
                if self.param == 768
                else mlkem.MLKEM1024PublicKey
            )
            public_key = cls.from_public_bytes(peer_public_key)
            shared_secret, ciphertext = public_key.encapsulate()
            return shared_secret, ciphertext
        if self._impl == "kyber-py":
            return self._kyber_cls().encaps(peer_public_key)
        module = self._pq_module()
        ciphertext, shared_secret = module.encaps(peer_public_key)
        return shared_secret, ciphertext

    def decapsulate(self, ciphertext: bytes) -> bytes:
        """Retrouve le secret partagé à partir du chiffré KEM reçu."""
        if self._priv is None:
            raise RuntimeError("appelez keygen() d'abord")
        if self._impl == "cryptography":
            return self._priv.decapsulate(ciphertext)
        if self._impl == "kyber-py":
            return self._kyber_cls().decaps(self._dk, ciphertext)
        return self._pq_module().decaps(self._dk, ciphertext)

    # -- utilitaires internes ---------------------------------------------

    def _kyber_cls(self):
        from kyber_py.ml_kem import ML_KEM_512, ML_KEM_768, ML_KEM_1024

        return {512: ML_KEM_512, 768: ML_KEM_768, 1024: ML_KEM_1024}[self.param]

    def _pq_module(self):
        from pqcrypto.kem import ml_kem_512, ml_kem_768, ml_kem_1024

        return {512: ml_kem_512, 768: ml_kem_768, 1024: ml_kem_1024}[self.param]

    @property
    def public_key_size(self) -> int:
        return len(self.public_bytes())

    @property
    def ciphertext_size(self) -> int:
        return self.SIZES[self.param]["ct"]

    @property
    def name(self) -> str:
        return f"ML-KEM-{self.param}"

    def describe(self) -> str:
        return (
            f"{self.name} via {self.backend} "
            f"(clé publique {self.public_key_size} o, chiffré KEM {self.ciphertext_size} o)"
        )
