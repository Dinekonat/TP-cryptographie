# TP1 — Mini-coffre de fichiers chiffrés

Ce TP implémente en Python un module de chiffrement et de déchiffrement de données protégées par un mot de passe.

## Fonctionnalités

- Dérivation de clé avec Argon2id, puis séparation de clé avec HKDF-SHA-256.
- Chiffrement authentifié AES-256-GCM.
- Authentification de l’en-tête et du nom de fichier.
- Changement de mot de passe par déchiffrement puis rechiffrement (`rechiffrer`).
- Tests des cas normaux et des erreurs d’authentification dans `test_coffre.py`.

## Installation

Python 3.10 ou plus récent est recommandé.

```bash
python -m venv .venv
source .venv/bin/activate       # Windows : .venv\Scripts\activate
python -m pip install argon2-cffi cryptography pytest
```

## Exécuter les tests

Depuis ce dossier :

```bash
python -m pytest -q
```

## Fichiers

- `coffre.py` : fonctions de chiffrement, déchiffrement et rechiffrement.
- `test_coffre.py` : tests automatisés.
- `rapport_tp1.md` et `rapport_tp1.docx` : compte rendu du TP.

> Ce projet est un travail pédagogique. Il n’a pas fait l’objet d’un audit de sécurité et ne doit pas être utilisé pour protéger des données réelles.
