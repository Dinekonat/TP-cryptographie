# TP2 — Infrastructure à clés publiques (PKI)

Ce TP construit une autorité de certification racine et une autorité intermédiaire avec OpenSSL, puis émet des certificats serveur et client et produit des listes de révocation.

## Contenu

Les fichiers du TP se trouvent dans le sous-dossier `TP2/` :

- `TP2/pki.sh` : script de création de l’infrastructure.
- `TP2/racine.cnf` et `TP2/inter.cnf` : configurations OpenSSL.
- `TP2/INSTRUCTIONS_UBUNTU.md` : instructions détaillées pour Ubuntu.
- `TP2/rapport_tp2.md` et `TP2/rapport_tp2.docx` : compte rendu.

## Prérequis

- Ubuntu ou une distribution Linux compatible.
- OpenSSL 3.x.
- Bash.

## Exécution

Depuis ce dossier du dépôt :

```bash
cd TP2
bash pki.sh
```

Le script crée des clés privées et des fichiers d’état nécessaires au fonctionnement de la PKI. **Ne publiez jamais les fichiers de clé privée (`*.key`) ni les secrets associés.** Le `.gitignore` à la racine du dépôt exclut ces clés et les fichiers d’état locaux. Les certificats `.crt` et CRL sont des données publiques, mais vérifiez qu’ils ne contiennent pas d’information personnelle avant publication.

> Ce TP est un environnement pédagogique local. Les commandes de révocation peuvent produire un échec de validation attendu lorsqu’un certificat révoqué est testé.
