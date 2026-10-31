# TP3 — Canal TLS et gestion des certificats

Ce TP met en place une configuration nginx en TLS avec authentification mutuelle (mTLS), vérification des révocations et outils de suivi et de renouvellement des certificats.

## Contenu

- `nginx_tp.conf` : exemple de configuration nginx TLS/mTLS.
- `surveiller.py` : affiche le temps restant avant expiration des certificats `.crt`.
- `renouveler.sh` : exemple de script de renouvellement de certificat serveur.
- `rapport_tp3.md` et `rapport_tp3.docx` : compte rendu.
- `inter/`, `racine/` et les fichiers `.crt`/`.pem` : certificats, chaînes et CRL de démonstration.

## Prérequis

- Ubuntu ou une distribution Linux compatible.
- OpenSSL 3.x et nginx avec le module SSL.
- Python 3 et le paquet `cryptography` pour `surveiller.py`.

## Utilisation

Vérifier les certificats présents dans un dossier :

```bash
python3 -m pip install cryptography
python3 surveiller.py .
```

La configuration nginx et `renouveler.sh` contiennent des chemins et des commandes système destinés à un environnement Linux configuré pour ce TP. Examinez-les et adaptez-les à votre machine avant toute exécution. Le script de renouvellement peut installer des fichiers dans `/etc/nginx` et recharger nginx.

**Ne publiez jamais de clé privée (`*.key`).** Elles sont exclues par le `.gitignore` à la racine. Les certificats `.crt` sont publics, mais vérifiez qu’ils ne contiennent pas d’information personnelle avant publication.
