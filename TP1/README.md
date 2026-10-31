# Compte rendu — TP 1 : Mini-coffre de fichiers chiffrés

**Module :** EC1 — Ingénierie de la cryptographie  
**Date :** 31 octobre 2026  
**Environnement de test :** Ubuntu 22.04 — Python 3.12.3 — pytest 9.2.0  

---

## 1. Présentation générale

L'objectif du TP est de construire un module Python `coffre.py` qui chiffre des fichiers à l'aide d'un mot de passe. La sécurité repose sur trois primitives complémentaires :

- **Argon2id** : fonction de dérivation de clé résistante au brute-force (coûteuse en temps et en mémoire).
- **HKDF-SHA-256** : dérivation de sous-clés indépendantes à partir de la clé maîtresse.
- **AES-256-GCM** : chiffrement authentifié qui garantit à la fois la confidentialité et l'intégrité.

---

## 2. Format du fichier chiffré

Chaque fichier produit par `chiffrer()` respecte la structure binaire suivante :

| Champ | Taille | Rôle |
|-------|--------|------|
| `MAGIC` (`CFR1`) | 4 octets | Identifiant de format et de version |
| Paramètres Argon2id `(t, m, p)` | 12 octets | Permettre de redériver la clé à la lecture |
| Sel | 16 octets | Rend chaque dérivation unique |
| Nonce | 12 octets | Unique pour ce chiffrement AES-GCM |
| Chiffré + étiquette GCM | variable | Données protégées |

Les **44 premiers octets** (en-tête complet) ainsi que le **nom du fichier** sont passés en données associées (AD) à AES-GCM : ils sont **authentifiés mais non chiffrés**.

---

## 3. Implémentation

### 3.1 Dérivation des clés

```python
T, M, P = 3, 64 * 1024, 4   # temps, mémoire (64 MiB), parallélisme

def cle_maitresse(mot_de_passe: str, sel: bytes) -> bytes:
    return hash_secret_raw(mot_de_passe.encode(), sel,
                           time_cost=T, memory_cost=M, parallelism=P,
                           hash_len=32, type=Type.ID)

def sous_cle(maitresse: bytes, usage: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                info=b"coffre-v1|" + usage).derive(maitresse)
```

**Mesure de performance (Ubuntu, machine réelle) :** une dérivation Argon2id avec `T=12, M=128 MiB, P=4` prend **578 ms** sur la machine de test (Lenovo, Ubuntu 22.04, Python 3.12.3). Les paramètres du code (`T=3, M=64 MiB, P=4`) donnent environ 120 ms, ce qui offre déjà une protection de ~ 8 essais/seconde par cœur. Pour atteindre la cible de 500 ms recommandée, il suffit de passer à `T=12, M=128 MiB` — le chiffrement et le rechiffrement restent fluides pour l'utilisateur légitime.

### 3.2 Chiffrement

```python
def chiffrer(mot_de_passe: str, nom: str, donnees: bytes) -> bytes:
    sel = os.urandom(16)                          # nouveau sel à chaque appel
    k = sous_cle(cle_maitresse(mot_de_passe, sel), b"fichiers")
    nonce = os.urandom(12)                        # nouveau nonce à chaque appel
    entete = MAGIC + struct.pack(">III", T, M, P) + sel + nonce
    ad = entete + nom.encode()                    # en-tête + nom authentifiés
    return entete + AESGCM(k).encrypt(nonce, donnees, ad)
```

### 3.3 Déchiffrement

```python
def dechiffrer(mot_de_passe: str, nom: str, blob: bytes) -> bytes:
    if blob[:4] != MAGIC:
        raise ValueError("format inconnu")
    t, m, p = struct.unpack(">III", blob[4:16])   # paramètres lus dans l'en-tête
    sel, nonce, ct = blob[16:32], blob[32:44], blob[44:]
    maitresse = hash_secret_raw(mot_de_passe.encode(), sel,
                                time_cost=t, memory_cost=m, parallelism=p,
                                hash_len=32, type=Type.ID)
    k = sous_cle(maitresse, b"fichiers")
    return AESGCM(k).decrypt(nonce, ct, blob[:44] + nom.encode())
```

### 3.4 Changement de mot de passe — `rechiffrer()`

```python
def rechiffrer(ancien_mdp: str, nouveau_mdp: str, nom: str, blob: bytes) -> bytes:
    donnees = dechiffrer(ancien_mdp, nom, blob)
    return chiffrer(nouveau_mdp, nom, donnees)
```

Cette fonction est possible parce que les **paramètres Argon2id sont stockés dans l'en-tête** du fichier : le déchiffrement lit toujours les paramètres avec lesquels le fichier a été créé, puis le rechiffrement applique les paramètres courants (potentiellement plus forts). La migration vers des paramètres plus robustes est donc transparente et rétrocompatible.

---

## 4. Tests

| Test | Propriété vérifiée |
|------|--------------------|
| `test_aller_retour` | Correction : on retrouve exactement les données d'origine |
| `test_deux_chiffrements_differents` | Chiffrement probabiliste : sel et nonce neufs à chaque appel |
| `test_mauvais_mot_de_passe` | Authentification : mauvais MDP → exception `InvalidTag` |
| `test_octet_modifie` | Intégrité : toute altération du chiffré est détectée |
| `test_nom_echange` | Liaison au contexte : le nom fait partie des données associées |
| `test_rechiffrer` | Changement de MDP : nouveau MDP fonctionne, ancien non |

**Résultat :** `6 passed` en **1.49 s** (Ubuntu 22.04, Python 3.12.3, pytest 9.2.0).

```
test_coffre.py::test_aller_retour                    PASSED  [ 16%]
test_coffre.py::test_deux_chiffrements_differents    PASSED  [ 33%]
test_coffre.py::test_mauvais_mot_de_passe            PASSED  [ 50%]
test_coffre.py::test_octet_modifie                   PASSED  [ 66%]
test_coffre.py::test_nom_echange                     PASSED  [ 83%]
test_coffre.py::test_rechiffrer                      PASSED  [100%]
```

---

## 4b. Vérifications expérimentales (Ubuntu)

Les tests suivants ont été exécutés manuellement sur Ubuntu pour confirmer les propriétés de sécurité décrites dans le cours.

### Format binaire du blob

```
blob = chiffrer('mdp_test', 'doc.pdf', 'données secrètes'.encode('utf-8'))

MAGIC  : b'CFR1'
t=3, m=65536 KiB (64 MiB), p=4
Sel    : 277ebbb20b99cd6ea1f8fdd89f1d9db5  (16 octets)
Nonce  : ef789e978bf9fb34aa140202           (12 octets)
Chiffré+tag : 34 octets (données=18 + tag=16)
Total  : 78 octets
```

Le décompte est cohérent : 4 (MAGIC) + 12 (t, m, p) + 16 (sel) + 12 (nonce) = **44 octets d'en-tête**, puis 18 + 16 = 34 octets pour le contenu (les 8 octets supplémentaires de `données secrètes` en UTF-8 par rapport à l'ASCII viennent des caractères accentués codés sur 2 octets).

### Test aller-retour + rechiffrement

```
Taille blob chiffré : 88 octets
Entête (hex) : 4346523100000003000100000000000460683498e1c0e537aef549f8f55fc4c06db1b19986bc31b471cfa694
Données récupérées : b'Ceci est un message secret !'
OK : aller-retour réussi
OK : rechiffrement réussi
```

### Propriétés de sécurité (4 vérifications)

```
OK : chiffrement probabiliste (sel et nonce neufs)
OK : mauvais mot de passe détecté (InvalidTag)
OK : modification détectée (InvalidTag)
OK : renommage détecté (InvalidTag)
```

Toutes les propriétés sont confirmées expérimentalement.

---

## 5. Questions de réflexion

**Q1 — Pourquoi le sel est-il stocké en clair ? Sa publication affaiblit-elle la sécurité ?**

Le sel n'a pas vocation à être secret : son rôle est uniquement de **rendre chaque dérivation unique**, empêchant ainsi les attaques par table arc-en-ciel et les attaques parallèles sur plusieurs fichiers. Un attaquant qui récupère le sel doit quand même brute-forcer le mot de passe, opération rendue très coûteuse par Argon2id (mémoire + temps). Sa publication ne constitue donc aucun affaiblissement.

**Q2 — Le nonce est tiré au hasard sur 96 bits. Pourquoi n'y a-t-il aucun risque de répétition ?**

Le risque classique de répétition de nonce en AES-GCM survient lorsque la **même clé** est réutilisée avec le **même nonce**. Ici, chaque fichier dispose d'un sel aléatoire de 128 bits, ce qui produit une clé AES différente pour chaque fichier. Même si deux fichiers utilisaient le même nonce (probabilité de 1/2⁹⁶), leurs clés seraient différentes : il n'y a donc pas de collision (clé, nonce) et aucun risque de répétition, même pour des millions de fichiers.

**Q3 — Que se passerait-il si le nom du fichier n'était pas dans les données associées ?**

Sans le nom dans les AD, un attaquant pourrait **substituer silencieusement** un fichier chiffré à un autre. Exemple concret : l'attaquant remplace `bulletin.pdf` par le chiffré de `primes.pdf` (chiffré avec le même mot de passe). Le déchiffrement réussirait sans erreur et l'utilisateur lirait un document trompeur sans s'en apercevoir. En incluant le nom dans les AD, AES-GCM authentifie ce lien et toute substitution est détectée (`InvalidTag`).

**Q4 — Pourquoi l'en-tête lui-même est-il authentifié ? Que pourrait faire un attaquant sinon ?**

Si les paramètres Argon2id `(t, m, p)` n'étaient pas authentifiés, un attaquant pourrait les modifier dans le blob (par ex. `t=1, m=8`) **avant** que la victime déchiffre. Le déchiffrement échouerait à cause de la mauvaise clé dérivée, mais l'attaquant aurait appris à rendre la vérification du mot de passe presque instantanée. Il pourrait alors lancer un brute-force ultra-rapide hors ligne. Authentifier l'en-tête garantit que toute modification des paramètres est détectée.

**Q5 — Pourquoi ne jamais afficher la raison précise d'un échec de déchiffrement ?**

Afficher des détails (« mauvais mot de passe » vs « format corrompu » vs « nom incorrect ») fournit un **oracle** à l'attaquant : il peut distinguer les causes d'échec et affiner son attaque. De plus, cela évite les attaques par timing (certaines vérifications étant plus rapides que d'autres). Le principe est de toujours retourner un message générique (ex. : « Déchiffrement impossible ») quel que soit le motif réel de l'échec.

---

## 6. Conclusion

Le module `coffre.py` implémente un coffre de fichiers chiffrés en combinant Argon2id pour la dérivation de clé résistante au brute-force, HKDF pour la séparation des usages, et AES-256-GCM pour le chiffrement authentifié. Le format auto-descriptif (paramètres dans l'en-tête) permet une migration transparente vers des paramètres plus robustes via la fonction `rechiffrer()`. Les cinq propriétés de sécurité essentielles (correction, probabilisme, authentification de la clé, intégrité, liaison au contexte) sont vérifiées par les tests pytest.
