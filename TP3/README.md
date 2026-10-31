# Compte rendu — TP 3 : Déployer un canal sécurisé et gérer les certificats

**Module :** EC1 — Ingénierie de la cryptographie  
**Date :** 30 octobre 2026  

---

## 1. Préparation des fichiers TLS

La chaîne présentée par le serveur ne doit **jamais** contenir le certificat racine (le client l'a déjà dans son magasin de confiance). Elle contient uniquement le certificat du serveur suivi de l'intermédiaire :

```bash
cat serveur.crt inter/inter.crt > serveur_chaine.crt
sudo install -m 600 serveur.key         /etc/nginx/tls/serveur.key
sudo install -m 644 serveur_chaine.crt  /etc/nginx/tls/serveur_chaine.crt
sudo install -m 644 racine/racine.crt   /etc/nginx/tls/racine.crt
sudo install -m 644 crls.pem            /etc/nginx/tls/crls.pem
echo "127.0.0.1 www.tp.local" | sudo tee -a /etc/hosts
```

---

## 2. Configuration nginx — justification de chaque directive

```nginx
server {
    listen 443 ssl;
    server_name www.tp.local;

    ssl_certificate     /etc/nginx/tls/serveur_chaine.crt;  # (1)
    ssl_certificate_key /etc/nginx/tls/serveur.key;          # (2)
    ssl_protocols TLSv1.2 TLSv1.3;                           # (3)
    ssl_prefer_server_ciphers off;                            # (4)
    ssl_session_tickets off;                                  # (5)

    ssl_client_certificate /etc/nginx/tls/racine.crt;        # (6)
    ssl_verify_client on;                                     # (7)
    ssl_verify_depth 2;                                       # (8)
    ssl_crl /etc/nginx/tls/crls.pem;                         # (9)

    add_header Strict-Transport-Security "max-age=31536000" always; # (10)

    location / {
        return 200 "Bonjour $ssl_client_s_dn\n";             # (11)
    }
}
```

| N° | Directive | Justification |
|----|-----------|---------------|
| 1 | `ssl_certificate` | Chemin vers la chaîne serveur (cert + intermédiaire) |
| 2 | `ssl_certificate_key` | Clé privée du serveur, permission 600 |
| 3 | `ssl_protocols TLSv1.2 TLSv1.3` | TLS 1.0/1.1 obsolètes (POODLE, BEAST) et interdits par le CA/Browser Forum |
| 4 | `ssl_prefer_server_ciphers off` | En TLS 1.3 toutes les suites sont sûres ; laisser le client choisir améliore la compatibilité |
| 5 | `ssl_session_tickets off` | Les tickets utilisent une clé statique ; si elle fuit, la forward secrecy est perdue pour toutes les sessions passées |
| 6 | `ssl_client_certificate` | AC racine servant à vérifier les certificats clients |
| 7 | `ssl_verify_client on` | Active l'authentification mutuelle (mTLS) : toute connexion sans certificat client est refusée |
| 8 | `ssl_verify_depth 2` | Profondeur de la chaîne : racine → intermédiaire → client |
| 9 | `ssl_crl` | Liste de révocation : les certificats révoqués (ex. Alice) sont rejetés |
| 10 | `Strict-Transport-Security` | HSTS : force HTTPS pour 1 an, protège contre le downgrade et sslstrip |
| 11 | `$ssl_client_s_dn` | Affiche le DN du client authentifié dans la réponse |

---

## 3. Analyse de la poignée de main TLS

### Connexion avec certificat client valide (Bob)
```bash
openssl s_client -connect www.tp.local:443 -servername www.tp.local \
  -verify_hostname www.tp.local -CAfile racine/racine.crt \
  -cert bob.crt -key bob.key -cert_chain inter/inter.crt -brief
```
Résultats observés :
- **Version TLS :** TLSv1.3
- **Suite de chiffrement :** `TLS_AES_256_GCM_SHA384`
- **Groupe d'échange de clés :** `X25519` (ECDHE)
- **Vérification :** `Verification: OK`

### Sans certificat client — refus attendu
```bash
openssl s_client -connect www.tp.local:443 -CAfile racine/racine.crt -brief
# SSL_connect: ... alert handshake failure
```
Le serveur envoie une alerte `handshake_failure` car `ssl_verify_client on` exige un certificat client.

### Avec le certificat révoqué d'Alice
```bash
openssl s_client -connect www.tp.local:443 \
  -cert alice.crt -key alice.key -CAfile racine/racine.crt -brief
# SSL_connect: ... alert certificate revoked
```
nginx consulte `crls.pem`, détecte la révocation et rejette la connexion.

### Pourquoi le certificat serveur est-il invisible en TLS 1.3 sous Wireshark ?
En TLS 1.3, le message `Certificate` est **chiffré** dès le début du handshake (après le `ServerHello`). La clé de session est établie via ECDHE avant l'envoi du certificat, contrairement à TLS 1.2 où le certificat était en clair. On identifie les messages par leur type dans `ClientHello` (champs `supported_versions`, `key_share`) et dans `ServerHello` (version négociée).

---

## 4. Vérification de la configuration

```bash
# TLS 1.1 doit être refusé
openssl s_client -connect www.tp.local:443 -tls1_1 -brief
# => handshake failure (attendu)

# Lister les suites acceptées en TLS 1.2
nmap --script ssl-enum-ciphers -p 443 www.tp.local
```
Toutes les suites sans **Perfect Forward Secrecy** (ECDHE/DHE) ou sans **chiffrement authentifié** (AEAD) doivent être absentes. Si elles apparaissent, ajouter dans nginx :
```nginx
ssl_ciphers ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:TLS_AES_256_GCM_SHA384;
```

---

## 5. Supervision des expirations — `surveiller.py`

Le script lit tous les fichiers `.crt` d'un dossier et affiche leur état :

```python
SEUILS = (30, 14, 7)   # jours pour ALERTE et CRITIQUE

def jours_restants(cert):
    fin = cert.not_valid_after_utc
    return (fin - datetime.datetime.now(datetime.timezone.utc)).days

# Niveaux : OK / ALERTE (<= 30j) / CRITIQUE (<= 7j) / EXPIRE (< 0j)
# Code de sortie : 0 = OK, 1 = alerte, 2 = critique ou expiré
```

**Test avec un certificat de 5 jours :**
```bash
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out test5j.key
openssl req -x509 -new -key test5j.key -days 5 -subj "/CN=test" -out test5j.crt
python3 surveiller.py .
# CRITIQUE     5 j  CN=test  (test5j.crt)
echo $?   # 2
```

---

## 6. Renouvellement automatique — `renouveler.sh`

Le script `renouveler.sh` effectue les opérations suivantes :

1. **Vérifie** si le certificat expire dans moins de 30 jours (`openssl x509 -checkend`).
2. **Génère** une nouvelle clé P-256 et une CSR pour `www.tp.local`.
3. **Fait signer** la demande par l'AC intermédiaire.
4. **Vérifie** la chaîne complète avant tout déploiement.
5. **Sauvegarde** l'ancien certificat (`serveur_backup_YYYYMMDD.crt/key`).
6. **Installe** les nouveaux fichiers et recharge nginx sans interruption.

**Planification cron (exécution quotidienne à 03h00) :**
```bash
crontab -e
# Ajouter :
0 3 * * * /chemin/vers/TP2/renouveler.sh >> /var/log/renouveler.log 2>&1
```

---

## 7. Questions de réflexion

**Q1 — Pourquoi le serveur ne doit-il pas envoyer le certificat racine ?**

Le certificat racine est l'ancre de confiance : il doit être installé manuellement dans le magasin de confiance du client (navigateur, OS). L'envoyer dans la chaîne TLS est inutile car le client ne l'accepterait que s'il le connaît déjà, et alourdit inutilement le handshake.

**Q2 — Intérêt de désactiver les tickets de session quand les clés ne sont pas renouvelées ?**

Les tickets de session chiffrent l'état de session avec une clé symétrique statique côté serveur. Si cette clé est compromise, un adversaire peut déchiffrer **toutes les sessions passées** capturées (perte de la forward secrecy). En les désactivant, chaque session négocie une clé éphémère via ECDHE, indépendante des autres.

**Q3 — Ce que garantit HSTS et contre quelle attaque ?**

HSTS (HTTP Strict Transport Security) indique au navigateur de n'accéder au site qu'en HTTPS pendant la durée spécifiée (`max-age=31536000` = 1 an). Il protège contre les attaques de **downgrade** comme `sslstrip`, où un attaquant en position d'homme du milieu transforme les redirections HTTPS en HTTP pour intercepter le trafic en clair.

**Q4 — Conséquences des certificats à 100 jours (2027) puis 47 jours (2029) ?**

Une organisation qui renouvelle à la main doit passer à un renouvellement tous les ~65 jours (100-30), puis tous les ~17 jours (47-30). C'est humainement ingérable sans automatisation. La conséquence directe est l'**obligation d'automatiser** le renouvellement (ACME/Let's Encrypt, scripts comme `renouveler.sh`), sous peine d'expiration fréquente et de coupure de service.

**Q5 — Chaîne incomplète : pourquoi certains clients acceptent et d'autres non ?**

Certains clients (navigateurs comme Chrome/Firefox) maintiennent un cache des certificats intermédiaires déjà rencontrés (AIA fetching ou cache local). Si l'intermédiaire est connu, la chaîne incomplète est tolérée. D'autres clients (openssl, curl, Java sans cache) exigent la chaîne complète et rejettent la connexion avec une erreur `unable to get local issuer certificate`.

**Q6 — Procédure de réaction si la clé privée du serveur fuit**

1. **Isoler immédiatement** : couper ou bloquer le trafic vers le serveur compromis.
2. **Révoquer** le certificat actuel : `openssl ca -config inter.cnf -revoke serveur.crt -crl_reason keyCompromise`.
3. **Générer une nouvelle CRL** et la déployer dans tous les points de vérification.
4. **Générer une nouvelle clé** et un nouveau certificat via `renouveler.sh`.
5. **Notifier** les utilisateurs et les équipes sécurité.
6. **Analyser** l'origine de la fuite (logs, permissions, accès non autorisé).
7. **Durcir** les permissions (`chmod 600`) et envisager un HSM pour la future clé.
