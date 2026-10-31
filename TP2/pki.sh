#!/usr/bin/env bash
# ============================================================
#  PKI TP2 — Infrastructure de gestion de cles
#  Auteur : etudiant EC1
#  Usage  : bash pki.sh   (depuis le dossier TP2/)
# ============================================================
set -euo pipefail

echo "==> [1/7] Creation de l'arborescence..."
mkdir -p racine/{certs,crl,newcerts} inter/{certs,crl,newcerts}
touch racine/index.txt inter/index.txt
echo 1000 > racine/serial;   echo 2000 > inter/serial
echo 1000 > racine/crlnumber; echo 2000 > inter/crlnumber

echo "==> [2/7] Generation de la cle et du certificat racine (P-384, 10 ans)..."
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out racine/racine.key
openssl req -x509 -new -key racine/racine.key -sha384 -days 3650 \
  -subj "/C=BF/O=Universite TP/CN=Racine TP" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:1" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -addext "subjectKeyIdentifier=hash" -out racine/racine.crt
echo "    racine/racine.crt OK"

echo "==> [3/7] Generation de l'AC intermediaire (P-256, 5 ans)..."
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out inter/inter.key
openssl req -new -key inter/inter.key \
  -subj "/C=BF/O=Universite TP/CN=Intermediaire TP" -out inter/inter.csr
openssl ca -batch -config racine.cnf -extensions ext_inter -days 1825 \
  -in inter/inter.csr -out inter/inter.crt
cat inter/inter.crt racine/racine.crt > inter/chaine.crt
echo "    inter/inter.crt + inter/chaine.crt OK"

echo "==> [4/7] Certificat serveur (P-256, 90 jours) — www.tp.local..."
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out serveur.key
openssl req -new -key serveur.key -subj "/CN=www.tp.local" \
  -addext "subjectAltName=DNS:www.tp.local,DNS:tp.local" -out serveur.csr
openssl ca -batch -config inter.cnf -extensions ext_serveur -days 90 \
  -in serveur.csr -out serveur.crt
echo "    serveur.crt OK"

echo "==> [5/7] Certificat client Alice (P-256, 90 jours)..."
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out alice.key
openssl req -new -key alice.key -subj "/CN=alice@tp.local" -out alice.csr
openssl ca -batch -config inter.cnf -extensions ext_client -days 90 \
  -in alice.csr -out alice.crt
echo "    alice.crt OK"

echo "==> [6/7] Validation des chaines..."
openssl verify -CAfile racine/racine.crt -untrusted inter/inter.crt \
  -verify_hostname www.tp.local serveur.crt
openssl verify -CAfile racine/racine.crt -untrusted inter/inter.crt \
  -purpose sslclient alice.crt

echo "==> [7/7] Revocation d'Alice et generation des CRL..."
openssl ca -config inter.cnf -revoke alice.crt -crl_reason keyCompromise
openssl ca -config inter.cnf  -gencrl -out inter/crl/inter.crl
openssl ca -config racine.cnf -gencrl -out racine/crl/racine.crl
cat inter/crl/inter.crl racine/crl/racine.crl > crls.pem
openssl verify -crl_check_all -CRLfile crls.pem \
  -CAfile racine/racine.crt -untrusted inter/inter.crt alice.crt || true

echo ""
echo "============================================================"
echo " PKI construite avec succes !"
echo " Fichiers importants :"
echo "   racine/racine.crt   — certificat racine (a distribuer)"
echo "   inter/inter.crt     — certificat intermediaire"
echo "   inter/chaine.crt    — chaine complete"
echo "   serveur.crt/.key    — serveur www.tp.local"
echo "   alice.crt/.key      — client alice (REVOQUEE)"
echo "   crls.pem            — CRL concatenees"
echo "============================================================"
