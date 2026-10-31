# Compte rendu — TP 2 : Infrastructure de gestion de clés (PKI)

**Module :** EC1 — Ingénierie de la cryptographie  
**Date :** 31 octobre 2026  
**Environnement de test :** Ubuntu 22.04 — OpenSSL 3.x  

---

## 1. Architecture de la PKI

L'infrastructure construite suit une hiérarchie à deux niveaux :

```
AC Racine  (P-384, 10 ans, hors ligne)
    └── AC Intermédiaire  (P-256, 5 ans, nameConstraints: *.tp.local)
            ├── serveur www.tp.local  (P-256, 90 jours)
            └── client alice@tp.local (P-256, 90 jours — RÉVOQUÉE)
```

| Élément | Clé | Durée | Validité réelle | Extensions essentielles |
|---------|-----|-------|----------------|------------------------|
| AC Racine | P-384 | 10 ans | 31 oct. 2026 → 28 oct. 2036 | `CA:TRUE, pathlen:1` |
| AC Intermédiaire | P-256 | 5 ans | 31 oct. 2026 → 30 oct. 2031 | `CA:TRUE, pathlen:0, nameConstraints` |
| Serveur `www.tp.local` | P-256 | 90 jours | 31 oct. 2026 → 29 jan. 2027 | `CA:FALSE, serverAuth, SAN` |
| Client Alice | P-256 | 90 jours | 31 oct. 2026 → 29 jan. 2027 | `CA:FALSE, clientAuth` (**RÉVOQUÉE**) |

**Détails de la racine (observés avec `openssl x509 -noout -text`) :**
- Algorithme de signature : `ecdsa-with-SHA384`
- Issuer = Subject = `C=BF, O=Universite TP, CN=Racine TP` → certificat **auto-signé**
- `basicConstraints: critical, CA:TRUE, pathlen:1`
- `keyUsage: critical, Certificate Sign, CRL Sign`

**Détails de l'intermédiaire :**
- Issuer = `CN=Racine TP` (signé par la racine)
- `basicConstraints: critical, CA:TRUE, pathlen:0`
- `nameConstraints: critical, Permitted: DNS:.tp.local, DNS:tp.local, email:tp.local`

---

## 2. Explication des sections d'extensions

### Section `ext_inter` (dans `racine.cnf`) — appliquée au certificat de l'AC intermédiaire

| Ligne | Rôle |
|-------|------|
| `basicConstraints = critical,CA:TRUE,pathlen:0` | Autorise cette entité à signer des certificats (`CA:TRUE`), mais interdit toute sous-AC (`pathlen:0`). Le marqueur `critical` force les clients à respecter ce champ. |
| `keyUsage = critical,keyCertSign,cRLSign` | La clé ne sert qu'à signer des certificats et des CRL ; tout autre usage est interdit. |
| `nameConstraints = critical,permitted;DNS:.tp.local,...` | Restreint les noms que l'AC peut certifier au domaine `.tp.local` et à l'adresse e-mail `tp.local`. Tout certificat hors de cet espace sera rejeté à la validation. |
| `subjectKeyIdentifier = hash` | Identifiant de la clé publique de l'intermédiaire (empreinte SHA-1). |
| `authorityKeyIdentifier = keyid` | Référence à la clé de l'AC racine signataire, permettant de remonter la chaîne. |

### Section `ext_serveur` (dans `inter.cnf`) — appliquée au certificat serveur

| Ligne | Rôle |
|-------|------|
| `basicConstraints = critical,CA:FALSE` | Ce n'est pas une AC ; elle ne peut pas signer d'autres certificats. |
| `keyUsage = critical,digitalSignature` | La clé sert uniquement à la signature dans le handshake TLS. |
| `extendedKeyUsage = serverAuth` | Usage étendu : authentification serveur TLS (OID 1.3.6.1.5.5.7.3.1). |
| `subjectKeyIdentifier = hash` | Identifiant de la clé publique du serveur. |
| `authorityKeyIdentifier = keyid` | Lien vers la clé de l'AC intermédiaire signataire. |

### Section `ext_client` (dans `inter.cnf`) — appliquée au certificat client

| Ligne | Rôle |
|-------|------|
| `basicConstraints = critical,CA:FALSE` | Certificat feuille, non-autorité. |
| `keyUsage = critical,digitalSignature` | Signature du handshake TLS côté client. |
| `extendedKeyUsage = clientAuth` | Usage étendu : authentification client TLS (OID 1.3.6.1.5.5.7.3.2). |
| `subjectAltName = email:alice@tp.local` | Identité e-mail d'Alice, utilisée pour l'authentification mTLS. |
| `subjectKeyIdentifier = hash` | Identifiant de la clé publique d'Alice. |
| `authorityKeyIdentifier = keyid` | Lien vers la clé de l'AC intermédiaire. |

---

## 3. Observations des validations (résultats réels Ubuntu)

### Exécution du script `pki.sh`

La PKI a été construite intégralement en une seule commande `bash pki.sh`. Chaque étape s'est terminée avec succès :

```
==> [1/7] Creation de l'arborescence...
==> [2/7] Generation de la cle et du certificat racine (P-384, 10 ans)...
    racine/racine.crt OK
==> [3/7] Generation de l'AC intermediaire (P-256, 5 ans)...
    inter/inter.crt + inter/chaine.crt OK
==> [4/7] Certificat serveur (P-256, 90 jours) — www.tp.local...
    serveur.crt OK
==> [5/7] Certificat client Alice (P-256, 90 jours)...
    alice.crt OK
==> [6/7] Validation des chaines...
serveur.crt: OK
alice.crt: OK
==> [7/7] Revocation d'Alice et generation des CRL...
CN = alice@tp.local
error 23 at 0 depth lookup: certificate revoked
error alice.crt: verification failed
============================================================
 PKI construite avec succes !
============================================================
```

### Validité et numéros de série (extraits réels)

| Certificat | Série | Valide jusqu'au | Algorithme |
|-----------|-------|----------------|-----------|
| AC Racine | `65:6b:a7:79:...` | 28 oct. 2036 | ECDSA P-384 |
| AC Intermédiaire | `0x1000` (4096) | 30 oct. 2031 | ECDSA P-256 |
| Serveur `www.tp.local` | — | 29 jan. 2027 | ECDSA P-256 |
| Alice `alice@tp.local` | `0x2001` | 29 jan. 2027 | ECDSA P-256 (**révoqué**) |

### Validation du serveur — résultat réel `OK`
```
openssl verify -CAfile racine/racine.crt -untrusted inter/inter.crt \
  -verify_hostname www.tp.local serveur.crt
serveur.crt: OK
```
La chaîne est complète : racine → intermédiaire → serveur. Le SAN `DNS:www.tp.local` correspond au nom vérifié.

### Validation avec mauvais hostname — résultat réel `ÉCHEC`
```
openssl verify -CAfile racine/racine.crt -untrusted inter/inter.crt \
  -verify_hostname autre.example serveur.crt
CN = www.tp.local
error 62 at 0 depth lookup: hostname mismatch
error serveur.crt: verification failed
```
Le SAN du certificat ne contient pas `autre.example`. **Erreur 62 = hostname mismatch.**

### Validation subtree violation — `www.example.com`
```
openssl verify -CAfile racine/racine.crt -untrusted inter/inter.crt mauvais.crt
CN = www.example.com
error 47 at 0 depth lookup: permitted subtree violation
error mauvais.crt: verification failed
```
**Observation notable :** OpenSSL a *accepté de signer* le CSR `www.example.com` lors du `openssl ca` (la contrainte `nameConstraints` n'est pas vérifiée à l'émission par l'AC). Elle n'est vérifiée que côté client lors de la validation de la chaîne, conformément à la RFC 5280. **Erreur 47 = permitted subtree violation.**



## 4. Révocation (résultats réels Ubuntu)

La clé d'Alice est supposée compromise. La révocation est intégrée dans `pki.sh` (étape 7) et a produit les résultats suivants :

### Vérification après révocation
```
openssl verify -crl_check_all -CRLfile crls.pem \
  -CAfile racine/racine.crt -untrusted inter/inter.crt alice.crt
CN = alice@tp.local
error 23 at 0 depth lookup: certificate revoked
error alice.crt: verification failed
```
**Erreur 23 = certificate revoked** → la révocation est bien prise en compte.

### Contenu réel de la CRL intermédiaire

```
Certificate Revocation List (CRL):
        Version 2 (0x1)
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: C = BF, O = Universite TP, CN = Intermediaire TP
        Last Update: Oct 31 06:00:29 2026 GMT
        Next Update: Nov  7 06:00:29 2026 GMT
        CRL extensions:
            X509v3 CRL Number: 8192
Revoked Certificates:
    Serial Number: 2001
        Revocation Date: Oct 31 06:00:29 2026 GMT
        CRL entry extensions:
            X509v3 CRL Reason Code:
                Key Compromise
    Signature Algorithm: ecdsa-with-SHA256
```

**Observations :**
- Le certificat d'Alice (numéro de série `0x2001`) est bien listé comme révoqué avec la raison **Key Compromise**.
- La CRL est valide 7 jours (`Next Update: Nov 7`) — conforme au `default_crl_days = 7` dans `inter.cnf`.
- Le `CRL Number: 8192` (0x2000) est un numéro de séquence incrémental qui permet de détecter les CRL plus récentes.
- La CRL elle-même est signée par ECDSA-SHA256 avec la clé de l'AC intermédiaire.

### Vérification d'Alice AVANT révocation (hors de pki.sh)
```
openssl verify -CAfile racine/racine.crt -untrusted inter/inter.crt \
  -purpose sslclient alice.crt
alice.crt: OK
```
Ce test confirme qu'avant la prise en compte de la CRL, le certificat d'Alice était parfaitement valide. La différence de résultat illustre l'importance de distribuer et consulter les CRL à jour.

---

## 5. Questions de réflexion

**Q1 — Pourquoi la clé de la racine doit-elle rester hors ligne ?**

La racine est l'ancre de confiance absolue : si sa clé est compromise, toute la PKI est compromise. En la gardant hors ligne (machine déconnectée, coffre-fort), on élimine le vecteur d'attaque réseau. Si **l'intermédiaire** est compromis, on révoque son certificat via la racine et on émet un nouvel intermédiaire. Si **la racine** est compromise, il faut redistribuer une nouvelle racine à tous les clients — opération extrêmement coûteuse (mise à jour de navigateurs, systèmes d'exploitation, etc.).

**Q2 — À quoi sert `pathlen:0` sur l'intermédiaire ? Quel risque si on l'oublie ?**

`pathlen:0` signifie que l'intermédiaire ne peut pas créer de sous-AC. Sans cette contrainte, un attaquant qui vole la clé intermédiaire pourrait créer des AC frauduleuses capables d'émettre des certificats pour n'importe quel domaine, contournant les `nameConstraints`.

**Q3 — Pourquoi la clé privée du serveur est-elle générée par le serveur et non par l'AC ?**

Principe de séparation des responsabilités : l'AC n'a jamais besoin de voir la clé privée du serveur. Si l'AC était compromise, les clés des serveurs resteraient secrètes. Le serveur génère sa clé, en conserve le secret, et ne transmet que la partie publique via la CSR pour signature.

**Q4 — CN vs SAN : lequel les clients modernes vérifient-ils ?**

Les clients modernes (navigateurs, openssl, curl) vérifient **uniquement le SAN** (Subject Alternative Name). Le CN (Common Name) est ignoré pour la validation d'hôte depuis la RFC 2818 (2000) et officiellement déprécié. C'est pourquoi le certificat serveur inclut `subjectAltName=DNS:www.tp.local,DNS:tp.local` dans la CSR.

**Q5 — Limites des CRL. Comparaison avec OCSP et certificats courts.**

| Mécanisme | Avantages | Inconvénients |
|-----------|-----------|---------------|
| **CRL** | Simple, hors ligne | Taille croissante, délai (CRL périmée), téléchargement lourd |
| **OCSP** | Réponse en temps réel, légère | Dépendance au serveur OCSP (disponibilité), vie privée (l'AC sait quels certificats sont vérifiés) |
| **Certificats courts** | Révocation implicite à expiration | Nécessite un renouvellement automatique fiable |

La tendance actuelle (CA/Browser Forum) va vers des certificats de plus en plus courts (100 jours en 2027, 47 jours en 2029), rendant la révocation moins critique.

**Q6 — Politique de certification minimale (10 lignes)**

1. **Demandeurs autorisés :** uniquement les agents de l'Université TP, après vérification d'identité en face à face.
2. **Domaines certifiables :** exclusivement `*.tp.local` (nameConstraints).
3. **Vérification d'identité :** présentation d'une pièce d'identité officielle pour les personnes physiques ; extrait de registre pour les serveurs.
4. **Durées maximales :** racine 10 ans, intermédiaire 5 ans, serveurs et clients 90 jours.
5. **Clés :** minimum P-256 (ECDSA) ou RSA-3072.
6. **Révocation :** CRL émise dans les 24h suivant toute compromission signalée ; délai `default_crl_days = 7`.
7. **Stockage des clés :** clé racine sur HSM hors ligne ; clés intermédiaires sur HSM en ligne.
8. **Audit :** journalisation de toute émission et révocation dans `index.txt`.
9. **Renouvellement :** automatisé via `renouveler.sh`, déclenché 30 jours avant expiration.
10. **Incident :** toute suspicion de compromission entraîne révocation immédiate et notification aux administrateurs.
