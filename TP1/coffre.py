"""Mini-coffre de fichiers chiffres (TP 1)."""
import os, struct
from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

MAGIC = b"CFR1"                      # format et version
T, M, P = 3, 64 * 1024, 4            # parametres Argon2id

def cle_maitresse(mot_de_passe: str, sel: bytes) -> bytes:
    return hash_secret_raw(mot_de_passe.encode(), sel, time_cost=T,
                           memory_cost=M, parallelism=P, hash_len=32,
                           type=Type.ID)

def sous_cle(maitresse: bytes, usage: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                info=b"coffre-v1|" + usage).derive(maitresse)

def chiffrer(mot_de_passe: str, nom: str, donnees: bytes) -> bytes:
    sel = os.urandom(16)
    k = sous_cle(cle_maitresse(mot_de_passe, sel), b"fichiers")
    nonce = os.urandom(12)
    entete = MAGIC + struct.pack(">III", T, M, P) + sel + nonce
    ad = entete + nom.encode()       # entete et nom authentifies
    return entete + AESGCM(k).encrypt(nonce, donnees, ad)

def dechiffrer(mot_de_passe: str, nom: str, blob: bytes) -> bytes:
    if blob[:4] != MAGIC:
        raise ValueError("format inconnu")
    t, m, p = struct.unpack(">III", blob[4:16])
    sel, nonce, ct = blob[16:32], blob[32:44], blob[44:]
    maitresse = hash_secret_raw(mot_de_passe.encode(), sel, time_cost=t,
                                memory_cost=m, parallelism=p, hash_len=32,
                                type=Type.ID)
    k = sous_cle(maitresse, b"fichiers")
    return AESGCM(k).decrypt(nonce, ct, blob[:44] + nom.encode())

def rechiffrer(ancien_mdp: str, nouveau_mdp: str, nom: str, blob: bytes) -> bytes:
    """Change le mot de passe d'un fichier sans exposer les donnees en clair.

    Le format stocke les parametres Argon2id dans l'en-tete : on peut donc
    toujours relire un ancien fichier (parametres faibles) et le reecrire
    avec les parametres courants (T, M, P) plus forts, sans changer le code
    de dechiffrement.
    """
    donnees = dechiffrer(ancien_mdp, nom, blob)
    return chiffrer(nouveau_mdp, nom, donnees)
