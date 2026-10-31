#!/usr/bin/env bash
# ============================================================
#  renouveler.sh — Renouvellement automatique du certificat serveur
#  TP3 — Canal TLS securise
#  Usage : bash renouveler.sh
#  Cron  : 0 3 * * * /chemin/vers/renouveler.sh >> /var/log/renouveler.log 2>&1
# ============================================================
set -euo pipefail

# --- Configuration ---
SEUIL_JOURS=30                          # renouveler si < 30 jours restants
CERT_ACTUEL="serveur.crt"
CLE_ACTUELLE="serveur.key"
CSR="serveur_new.csr"
CLE_NEW="serveur_new.key"
CERT_NEW="serveur_new.crt"
CHAINE_NEW="serveur_chaine_new.crt"
NGINX_TLS="/etc/nginx/tls"
LOG_DATE=$(date '+%Y-%m-%d %H:%M:%S')

echo "[$LOG_DATE] === Debut du renouvellement ==="

# --- Etape 1 : Verifier si le renouvellement est necessaire ---
if [ ! -f "$CERT_ACTUEL" ]; then
  echo "[$LOG_DATE] ERREUR : $CERT_ACTUEL introuvable."
  exit 1
fi

JOURS_RESTANTS=$(openssl x509 -in "$CERT_ACTUEL" -noout -checkend $((SEUIL_JOURS * 86400)) \
  && echo "ok" || echo "expire")

if [ "$JOURS_RESTANTS" = "ok" ]; then
  echo "[$LOG_DATE] Certificat valide plus de $SEUIL_JOURS jours. Aucun renouvellement necessaire."
  exit 0
fi

echo "[$LOG_DATE] Certificat expire dans moins de $SEUIL_JOURS jours. Renouvellement en cours..."

# --- Etape 2 : Generer une nouvelle cle et une nouvelle demande (CSR) ---
echo "[$LOG_DATE] Generation de la nouvelle cle et du CSR..."
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$CLE_NEW"
openssl req -new -key "$CLE_NEW" -subj "/CN=www.tp.local" \
  -addext "subjectAltName=DNS:www.tp.local,DNS:tp.local" -out "$CSR"

# --- Etape 3 : Faire signer par l'AC intermediaire ---
echo "[$LOG_DATE] Signature par l'AC intermediaire..."
openssl ca -batch -config inter.cnf -extensions ext_serveur -days 90 \
  -in "$CSR" -out "$CERT_NEW"
cat "$CERT_NEW" inter/inter.crt > "$CHAINE_NEW"

# --- Etape 4 : Verifier la chaine AVANT tout deploiement ---
echo "[$LOG_DATE] Verification de la chaine de confiance..."
openssl verify -CAfile racine/racine.crt -untrusted inter/inter.crt \
  -verify_hostname www.tp.local "$CERT_NEW"
echo "[$LOG_DATE] Chaine valide. Deploiement en cours..."

# --- Etape 5a : Sauvegarder l'ancien certificat pour rollback ---
BACKUP_DATE=$(date '+%Y%m%d_%H%M%S')
cp "$CERT_ACTUEL"  "serveur_backup_${BACKUP_DATE}.crt"
cp "$CLE_ACTUELLE" "serveur_backup_${BACKUP_DATE}.key"
echo "[$LOG_DATE] Sauvegarde : serveur_backup_${BACKUP_DATE}.{crt,key}"

# --- Etape 5b : Installer les nouveaux fichiers ---
echo "[$LOG_DATE] Installation dans $NGINX_TLS ..."
sudo install -m 600 "$CLE_NEW"    "$NGINX_TLS/serveur.key"
sudo install -m 644 "$CHAINE_NEW" "$NGINX_TLS/serveur_chaine.crt"

# Remplacer les fichiers courants
cp "$CERT_NEW"  "$CERT_ACTUEL"
cp "$CLE_NEW"   "$CLE_ACTUELLE"
cp "$CHAINE_NEW" serveur_chaine.crt

# Nettoyer les fichiers temporaires
rm -f "$CSR" "$CLE_NEW" "$CERT_NEW" "$CHAINE_NEW"

# --- Etape 5c : Tester la configuration nginx et recharger sans interruption ---
echo "[$LOG_DATE] Test de la configuration nginx..."
sudo nginx -t

echo "[$LOG_DATE] Rechargement de nginx (sans interruption de service)..."
sudo systemctl reload nginx

echo "[$LOG_DATE] === Renouvellement termine avec succes ! ==="
echo "[$LOG_DATE] Prochain controle dans 24h. Le cron verifie chaque jour."
