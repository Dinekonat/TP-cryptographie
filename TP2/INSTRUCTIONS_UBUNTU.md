# 🐧 Instructions Ubuntu — TP 2 : Infrastructure PKI

## Avant de commencer : accéder à tes fichiers depuis Ubuntu

Ton dossier Windows est accessible depuis Ubuntu via :
```bash
ls /mnt/c/Users/Lenovo/Downloads/TPCRYPTO/TP2/
```

Crée un dossier de travail dans Ubuntu et copie les fichiers :
```bash
mkdir -p ~/tp2_pki
cp /mnt/c/Users/Lenovo/Downloads/TPCRYPTO/TP2/* ~/tp2_pki/
cd ~/tp2_pki
```

---

## Étape 0 — Vérifier que OpenSSL est installé

```bash
openssl version
# Attendu : OpenSSL 3.x.x ...
```

Si absent :
```bash
sudo apt update && sudo apt install -y openssl
```

---

## Étape 1 — Lancer le script PKI complet

```bash
cd ~/tp2_pki
chmod +x pki.sh
bash pki.sh
```

Le script fait tout automatiquement :
- Crée l'arborescence (`racine/`, `inter/`)
- Génère les clés et certificats racine, intermédiaire, serveur (www.tp.local), client (alice)
- Valide les chaînes
- Révoque Alice et génère les CRL



samchou@lenovo:~/Bureau/TPCRYPTO/TP2$ chmod +x pki.sh
bash pki.sh
==> [1/7] Creation de l'arborescence...
==> [2/7] Generation de la cle et du certificat racine (P-384, 10 ans)...
    racine/racine.crt OK
==> [3/7] Generation de l'AC intermediaire (P-256, 5 ans)...
Using configuration from racine.cnf
Check that the request matches the signature
Signature ok
The Subject's Distinguished Name is as follows
countryName           :PRINTABLE:'BF'
organizationName      :ASN.1 12:'Universite TP'
commonName            :ASN.1 12:'Intermediaire TP'
Certificate is to be certified until Oct 30 06:00:29 2031 GMT (1825 days)

Write out database with 1 new entries
Database updated
    inter/inter.crt + inter/chaine.crt OK
==> [4/7] Certificat serveur (P-256, 90 jours) — www.tp.local...
Using configuration from inter.cnf
Check that the request matches the signature
Signature ok
The Subject's Distinguished Name is as follows
commonName            :ASN.1 12:'www.tp.local'
Certificate is to be certified until Jan 29 06:00:29 2027 GMT (90 days)

Write out database with 1 new entries
Database updated
    serveur.crt OK
==> [5/7] Certificat client Alice (P-256, 90 jours)...
Using configuration from inter.cnf
Check that the request matches the signature
Signature ok
The Subject's Distinguished Name is as follows
commonName            :ASN.1 12:'alice@tp.local'
Certificate is to be certified until Jan 29 06:00:29 2027 GMT (90 days)

Write out database with 1 new entries
Database updated
    alice.crt OK
==> [6/7] Validation des chaines...
serveur.crt: OK
alice.crt: OK
==> [7/7] Revocation d'Alice et generation des CRL...
Using configuration from inter.cnf
Revoking Certificate 2001.
Database updated
Using configuration from inter.cnf
Using configuration from racine.cnf
CN = alice@tp.local
error 23 at 0 depth lookup: certificate revoked
error alice.crt: verification failed

============================================================
 PKI construite avec succes !
 Fichiers importants :
   racine/racine.crt   — certificat racine (a distribuer)
   inter/inter.crt     — certificat intermediaire
   inter/chaine.crt    — chaine complete
   serveur.crt/.key    — serveur www.tp.local
   alice.crt/.key      — client alice (REVOQUEE)
   crls.pem            — CRL concatenees
============================================================


---

## Étape 2 — Inspecter le certificat racine (pour le compte rendu)

```bash
openssl x509 -in racine/racine.crt -noout -text
```

Observer dans la sortie :
- **Issuer = Subject** → auto-signé (c'est normal pour une racine)
- **Public Key Algorithm: id-ecPublicKey, P-384**
- **Extensions critiques** : `basicConstraints`, `keyUsage`
- **pathlen:1** → peut signer une seule couche d'AC intermédiaires


samchou@lenovo:~/Bureau/TPCRYPTO/TP2$ openssl x509 -in racine/racine.crt -noout -text
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            65:6b:a7:79:55:44:93:57:54:6d:f6:95:08:c4:1a:97:00:34:eb:d9
        Signature Algorithm: ecdsa-with-SHA384
        Issuer: C = BF, O = Universite TP, CN = Racine TP
        Validity
            Not Before: Oct 31 06:00:29 2026 GMT
            Not After : Oct 28 06:00:29 2036 GMT
        Subject: C = BF, O = Universite TP, CN = Racine TP
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (384 bit)
                pub:
                    04:23:e2:5d:22:74:27:52:5d:fc:0f:dc:08:49:b1:
                    e9:0d:94:fa:91:89:96:7a:71:26:a3:9b:8a:2d:2e:
                    de:a8:6d:9c:af:d8:fb:75:b4:1c:31:ac:08:d9:38:
                    30:9b:99:f7:5f:57:26:ec:be:63:77:61:ad:b9:2c:
                    04:40:35:8c:dc:2a:b3:f4:61:12:83:67:4b:ee:0d:
                    6b:c0:bc:9c:2b:47:1e:c8:3a:66:58:24:0c:10:9f:
                    ee:14:09:1d:36:61:0e
                ASN1 OID: secp384r1
                NIST CURVE: P-384
        X509v3 extensions:
            X509v3 Authority Key Identifier: 
                EF:18:C5:A2:62:05:76:2F:16:5E:BF:4E:CD:8B:24:CE:CD:15:6C:B1
            X509v3 Basic Constraints: critical
                CA:TRUE, pathlen:1
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Subject Key Identifier: 
                EF:18:C5:A2:62:05:76:2F:16:5E:BF:4E:CD:8B:24:CE:CD:15:6C:B1
    Signature Algorithm: ecdsa-with-SHA384
    Signature Value:
        30:66:02:31:00:8e:c2:13:94:15:57:eb:c9:4e:0c:97:a4:65:
        94:1b:07:1e:c8:f0:be:c8:b3:99:9b:f8:22:f4:35:c0:67:12:
        d7:d1:a3:b9:90:ad:31:56:6a:d0:c1:ff:4b:37:a2:fa:d8:02:
        31:00:c1:4b:76:99:9c:68:43:ee:8a:59:11:b0:3e:e1:25:71:
        a1:90:7a:71:e2:a6:8a:fd:9b:47:c4:e5:38:04:3a:96:c4:eb:
        8d:6a:64:83:74:49:0a:c8:c0:f9:e2:e3:8d:45


---

## Étape 3 — Inspecter l'AC intermédiaire

```bash
openssl x509 -in inter/inter.crt -noout -text
```

Vérifier la présence de :
- `pathlen:0` dans `basicConstraints`
- `nameConstraints` avec `Permitted: DNS:.tp.local`
- Issuer différent du Subject (signé par la racine)



samchou@lenovo:~/Bureau/TPCRYPTO/TP2$ openssl x509 -in inter/inter.crt -noout -text
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 4096 (0x1000)
        Signature Algorithm: ecdsa-with-SHA384
        Issuer: C = BF, O = Universite TP, CN = Racine TP
        Validity
            Not Before: Oct 31 06:00:29 2026 GMT
            Not After : Oct 30 06:00:29 2031 GMT
        Subject: C = BF, O = Universite TP, CN = Intermediaire TP
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:b3:60:05:cc:67:52:c8:46:fb:3a:b7:92:90:84:
                    26:47:29:88:5f:d4:44:ed:b3:90:19:d7:70:29:09:
                    01:8d:d6:da:00:7e:a1:3c:ef:53:2c:86:09:0e:30:
                    76:47:86:39:b6:55:12:22:d3:24:97:01:e6:ce:38:
                    79:b0:86:a9:b5
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Basic Constraints: critical
                CA:TRUE, pathlen:0
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Name Constraints: critical
                Permitted:
                  DNS:.tp.local
                  DNS:tp.local
                  email:tp.local
            X509v3 Subject Key Identifier: 
                E1:B7:84:4B:4E:8E:77:38:11:FE:D3:29:29:54:2D:19:D5:34:E5:A1
            X509v3 Authority Key Identifier: 
                EF:18:C5:A2:62:05:76:2F:16:5E:BF:4E:CD:8B:24:CE:CD:15:6C:B1
    Signature Algorithm: ecdsa-with-SHA384
    Signature Value:
        30:65:02:30:2e:df:e4:40:87:82:14:b6:ca:ff:0d:2d:3c:81:
        79:ee:a9:44:bd:aa:92:fc:dc:d6:32:d0:62:36:3b:47:38:90:
        b4:25:60:7b:dd:88:7e:bb:f8:45:56:87:76:3e:95:99:02:31:
        00:91:61:6f:53:d5:17:e8:4f:ca:1b:60:fb:94:96:bc:3d:77:
        ce:7a:1b:be:4a:0a:e9:72:fb:88:6a:8b:6e:98:1c:0d:87:d5:
        d5:cb:5b:cf:d6:cc:75:6d:60:cb:08:b8:c2
samchou@lenovo:~/Bureau/TPCRYPTO/TP2$ 



---

## Étape 4 — Inspecter les certificats feuilles

```bash
# Certificat serveur
openssl x509 -in serveur.crt -noout -text | grep -A5 "Subject Alternative"
# Doit afficher : DNS:www.tp.local, DNS:tp.local
samchou@lenovo:~/Bureau/TPCRYPTO/TP2$ openssl x509 -in serveur.crt -noout -text | grep -A5 "Subject Alternative"
            X509v3 Subject Alternative Name: 
                DNS:www.tp.local, DNS:tp.local
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:46:02:21:00:e8:6f:34:e7:a8:bd:a8:89:60:66:31:32:13:
        4e:18:02:56:64:9e:b0:b0:66:49:f0:c9:f1:df:9f:3a:5b:80:

# Certificat client
openssl x509 -in alice.crt -noout -text | grep -A3 "Extended Key"
# Doit afficher : TLS Web Client Authentication


samchou@lenovo:~/Bureau/TPCRYPTO/TP2$ openssl x509 -in alice.crt -noout -text | grep -A3 "Extended Key"
            X509v3 Extended Key Usage: 
                TLS Web Client Authentication
            X509v3 Subject Alternative Name: 
                email:alice@tp.local
samchou@lenovo:~/Bureau/TPCRYPTO/TP2$ 

```

---

## Étape 5 — Valider les chaînes

```bash
# Serveur — doit être OK
openssl verify -CAfile racine/racine.crt -untrusted inter/inter.crt \
  -verify_hostname www.tp.local serveur.crt
  
  samchou@lenovo:~/Bureau/TPCRYPTO/TP2$ openssl verify -CAfile racine/racine.crt -untrusted inter/inter.crt \
  -verify_hostname www.tp.local serveur.crt
serveur.crt: OK
samchou@lenovo:~/Bureau/TPCRYPTO/TP2$ 


# Mauvais hostname — doit échouer
openssl verify -CAfile racine/racine.crt -untrusted inter/inter.crt \
  -verify_hostname autre.example serveur.crt
  
  samchou@lenovo:~/Bureau/TPCRYPTO/TP2$ openssl verify -CAfile racine/racine.crt -untrusted inter/inter.crt \
  -verify_hostname autre.example serveur.crt
CN = www.tp.local
error 62 at 0 depth lookup: hostname mismatch
error serveur.crt: verification failed
samchou@lenovo:~/Bureau/TPCRYPTO/TP2$ 


# Client Alice — doit être OK (avant révocation)
openssl verify -CAfile racine/racine.crt -untrusted inter/inter.crt \
  -purpose sslclient alice.crt
  
  samchou@lenovo:~/Bureau/TPCRYPTO/TP2$ openssl verify -CAfile racine/racine.crt -untrusted inter/inter.crt \
  -purpose sslclient alice.crt
alice.crt: OK
samchou@lenovo:~/Bureau/TPCRYPTO/TP2$ 


```

### Test de la contrainte de nommage (permitted subtree violation)
```bash
# Émettre un certificat pour un domaine hors .tp.local
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out mauvais.key
openssl req -new -key mauvais.key -subj "/CN=www.example.com" \
  -addext "subjectAltName=DNS:www.example.com" -out mauvais.csr
openssl ca -batch -config inter.cnf -extensions ext_serveur -days 90 \
  -in mauvais.csr -out mauvais.crt
  
  samchou@lenovo:~/Bureau/TPCRYPTO/TP2$ openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out mauvais.key
openssl req -new -key mauvais.key -subj "/CN=www.example.com" \
  -addext "subjectAltName=DNS:www.example.com" -out mauvais.csr
openssl ca -batch -config inter.cnf -extensions ext_serveur -days 90 \
  -in mauvais.csr -out mauvais.crt
Using configuration from inter.cnf
Check that the request matches the signature
Signature ok
The Subject's Distinguished Name is as follows
commonName            :ASN.1 12:'www.example.com'
Certificate is to be certified until Jan 29 06:11:40 2027 GMT (90 days)

Write out database with 1 new entries
Database updated


# Valider — doit échouer avec "permitted subtree violation"
openssl verify -CAfile racine/racine.crt -untrusted inter/inter.crt mauvais.crt


samchou@lenovo:~/Bureau/TPCRYPTO/TP2$ openssl verify -CAfile racine/racine.crt -untrusted inter/inter.crt mauvais.crt
CN = www.example.com
error 47 at 0 depth lookup: permitted subtree violation
error mauvais.crt: verification failed
samchou@lenovo:~/Bureau/TPCRYPTO/TP2$ 

```

---

## Étape 6 — Vérifier la révocation samchou@lenovo:~/Bureau/TPCRYPTO/TP2$ openssl verify -CAfile racine/racine.crt -untrusted inter/inter.crt \
  -purpose sslclient alice.crt
alice.crt: OK
samchou@lenovo:~/Bureau/TPCRYPTO/TP2$ 

d'Alice

```bash
openssl verify -crl_check_all -CRLfile crls.pem \
  -CAfile racine/racine.crt -untrusted inter/inter.crt alice.crt
# Attendu : error 23 at 0 depth lookup: certificate revoked

samchou@lenovo:~/Bureau/TPCRYPTO/TP2$ openssl verify -crl_check_all -CRLfile crls.pem \
  -CAfile racine/racine.crt -untrusted inter/inter.crt alice.crt
CN = alice@tp.local
error 23 at 0 depth lookup: certificate revoked
error alice.crt: verification failed
samchou@lenovo:~/Bureau/TPCRYPTO/TP2$ 



# Lire le contenu de la CRL
openssl crl -in inter/crl/inter.crl -noout -text
# Observer : Revoked Certificates, Reason: Key Compromise

samchou@lenovo:~/Bureau/TPCRYPTO/TP2$ openssl crl -in inter/crl/inter.crl -noout -text
Certificate Revocation List (CRL):
        Version 2 (0x1)
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: C = BF, O = Universite TP, CN = Intermediaire TP
        Last Update: Oct 31 06:00:29 2026 GMT
        Next Update: Nov  7 06:00:29 2026 GMT
        CRL extensions:
            X509v3 CRL Number: 
                8192
Revoked Certificates:
    Serial Number: 2001
        Revocation Date: Oct 31 06:00:29 2026 GMT
        CRL entry extensions:
            X509v3 CRL Reason Code: 
                Key Compromise
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:45:02:21:00:e7:d7:a7:0e:99:af:5f:82:20:53:c4:84:ff:
        33:25:61:3c:fc:f1:e8:20:b7:a3:4e:1d:40:8f:5f:ac:b6:1e:
        e8:02:20:63:12:45:a2:4c:60:c9:73:b5:ad:b2:65:a5:01:02:
        e9:73:e1:12:93:df:3e:7e:29:e5:24:b5:29
```

---

## Étape 7 — Copier les résultats vers Windows

```bash
# Copier les certificats publics (JAMAIS les clés .key)
cp racine/racine.crt inter/inter.crt serveur.crt alice.crt \
   inter/chaine.crt crls.pem \
   /mnt/c/Users/Lenovo/Downloads/TPCRYPTO/TP2/resultats/
```

---

## Résumé des fichiers produits

| Fichier | Rôle | À livrer ? |
|---------|------|-----------|
| `racine/racine.crt` | Certificat racine | ✅ Oui |
| `inter/inter.crt` | Certificat intermédiaire | ✅ Oui |
| `inter/chaine.crt` | Chaîne complète | ✅ Oui |
| `serveur.crt` | Certificat serveur | ✅ Oui |
| `alice.crt` | Certificat client (révoqué) | ✅ Oui |
| `crls.pem` | CRL concaténées | ✅ Oui |
| `racine/racine.key` | Clé privée racine | ❌ JAMAIS |
| `inter/inter.key` | Clé privée intermédiaire | ❌ JAMAIS |
| `serveur.key` | Clé privée serveur | ❌ JAMAIS |
| `alice.key` | Clé privée Alice | ❌ JAMAIS |
