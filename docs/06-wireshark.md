# Wireshark : voir ce que le réseau révèle

**Durée conseillée : 20 à 30 minutes, en parallèle des scénarios.**

## Objectif

Observer le trafic réel du chat et vérifier trois choses :

1. le serveur et le réseau voient bien les **enveloppes** ;
2. ils ne voient **pas** le texte clair ;
3. les tailles et les champs changent selon le scénario (X25519, RSA, ML-KEM).

## 1. Capturer le loopback

Le relais et les clients tournent souvent sur la même machine : le trafic
passe par l'interface **loopback**, pas par la carte Wi-Fi/Ethernet.

### Windows

Installez [Npcap](https://npcap.com/) avec l'option **« Support loopback
traffic capture »** (Wireshark l'installe par défaut). L'interface apparaît
sous le nom :

```
Adapter for loopback traffic capture
```

ou, en ligne de commande, `\Device\NPF_Loopback`.

### Linux

```bash
sudo tshark -i lo -f "tcp port 8000"
```

### macOS

```bash
sudo tshark -i lo0 -f "tcp port 8000"
```

### Alternative plus simple en salle de TP

Faites tourner le relais sur une machine (ou une VM) et les clients sur
d'autres machines du même réseau. Capturez l'interface réseau habituelle :
c'est plus fiable que le loopback Windows.

```bash
# sur la machine serveur
python -m server --host 0.0.0.0 --port 8000

# sur les clients
python -m tpcrypto.scenarios.s2_dh --name alice --peer bob \
    --url ws://192.168.1.42:8000
```

> Le transport reste `ws://` : le trafic n'est **pas** chiffré par TLS. C'est
> volontaire pour le TP.

## 2. Filtres utiles

| Filtre | Usage |
|---|---|
| `tcp.port == 8000` | tout le trafic du relais |
| `tcp.port == 8001` | tout le trafic passant par le proxy MITM |
| `websocket` | uniquement les trames WebSocket |
| `http` | la poignée de main HTTP (`Upgrade: websocket`) |
| `websocket && tcp.port == 8000` | les trames du relais |

Dans Wireshark :

1. cliquez sur une trame WebSocket ;
2. clic droit → **Follow** → **TCP Stream** (ou `Follow > HTTP Stream`) ;
3. le JSON apparaît en clair, avec les champs base64.

Vous devez voir quelque chose comme :

```json
{"to":"bob","payload":{"t":"msg","n":0,"iv":"5u7...","ct":"k9Q..."}}
```

Ou, dans le sens serveur → client, l'enveloppe complète avec `from`, `to`,
`ts`, `kind`.

## 3. Ce qu'on observe selon le scénario

| Scénario | Champs caractéristiques | Taille typique |
|---|---|---|
| 1 — AES | `t=msg`, `n`, `iv`, `ct` | `iv` 12/16 o, `ct` = clair + tag |
| 2 — DH | `step=dh1/dh2`, `pub` (32 o), `salt` (16 o) | 32 o de clé publique |
| 3 — RSA | `step=rsa_pub`, `pub` DER (~294 o) ; `ek` (256 o) par message | 256 o par message |
| 4 — ML-KEM | `step=kem_pub`, `pub` (1184 o) ; `kem_ct` (1088 o) | 1184 o de clé publique |
| 5 — DH signé | `pub` (32 o), `id_pub` (32 o), `sig` (64 o) | signatures Ed25519 |

### Exercice : mesurer les tailles

Dans Wireshark, sélectionnez une trame, ouvrez le panneau **WebSocket** et
regardez la longueur du payload. Comparez avec `--show-wire` côté client :

```
[wire alice->bob] n=0 ek=256o iv=12o ct=32o
```

### Exercice : décoder le base64

Copiez la valeur de `ct`, puis :

```bash
python -c "import base64; print(len(base64.b64decode('COLLEZ_ICI')))"
```

Vous obtenez la taille du chiffré + tag. Essayez de déchiffrer sans la clé :
c'est impossible (c'est le but).

### Exercice : repérer ECB

En mode ECB, le champ `ct` contient des blocs de 16 octets. Convertissez-le en
hexadécimal et cherchez des blocs identiques :

```bash
python - <<'PY'
import base64
ct = base64.b64decode("COLLEZ_ICI")
blocks = [ct[i:i+16].hex() for i in range(0, len(ct), 16)]
for i, block in enumerate(blocks):
    print(i, block)
print("doublons :", len(blocks) - len(set(blocks)))
PY
```

## 4. En ligne de commande avec tshark

```bash
# Capturer 60 secondes sur le loopback Linux
sudo tshark -i lo -f "tcp port 8000" -a duration:60 -w tp.pcapng

# Extraire les payloads WebSocket d'une capture
tshark -r tp.pcapng -Y "websocket" -T fields -e websocket.payload

# Compter les trames par port
tshark -r tp.pcapng -q -z io,stat,0,"COUNT(tcp.port==8000)tcp.port==8000"
```

Sous Windows, remplacez `-i lo` par `-i "\Device\NPF_Loopback"` (avec Npcap).

## 5. Ce que Wireshark ne montre pas

- **Le clair** : il n'est jamais transmis.
- **Les clés privées** : elles restent dans `keys/` (ou en mémoire).
- **Le contenu des messages du proxy MITM** : le proxy, lui, voit le clair,
  mais il le fait localement ; Wireshark ne voit que le trafic ré-chiffré.

En revanche, Wireshark montre :

- **qui parle à qui** (adresses, pseudos dans le JSON, salon) ;
- **quand** et **combien de fois** ;
- **la taille** des messages (sauf avec `--pad`) ;
- **le type** de handshake et les tailles de clés.

C'est exactement la différence entre **contenu** et **métadonnées**.

## 6. Pourquoi `ws://` et pas `wss://` ?

Avec TLS (`wss://`), Wireshark ne verrait que du TLS : impossible de lire le
JSON, mais aussi impossible de comprendre la structure des échanges pour le TP.
Le chiffrement de bout en bout est **au-dessus** du transport : même avec TLS,
le serveur verrait le contenu s'il n'y avait pas de chiffrement applicatif.
Les deux sont complémentaires :

- TLS protège le transport (confidentialité vis-à-vis du réseau) ;
- le chiffrement de bout en bout protège le contenu vis-à-vis du serveur.

Un vrai messager utilise souvent les deux.

## 7. Questions

1. Quelle est la différence entre ce que voit Wireshark et ce que voit le
   serveur ?
2. Pourquoi le loopback n'apparaît-il pas toujours dans Wireshark sous Windows ?
3. En TLS, que verrait-on à la place du JSON ?
4. Pourquoi la taille des messages est-elle une fuite d'information ?
5. Comment `--pad` réduit-il cette fuite ? Qu'est-ce qu'il ne cache pas ?
6. Pourquoi la clé publique ML-KEM est-elle si facile à repérer dans une
   capture ?
7. Un attaquant qui capture tout le trafic du scénario 5 peut-il déchiffrer
   les messages plus tard ? Et au scénario 3 ?

➡️ Suite : [pour aller plus loin](08-aller-plus-loin.md) ou retour à
[la fiche étudiant](L2-fiche-etudiant.md).
