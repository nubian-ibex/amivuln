# Architecture

amivuln est un workspace Cargo. Le binaire `amivuln` se contente d'orchestrer ;
les règles du domaine n'effectuent aucune E/S.

## Pipeline

1. **Cible.** Ce que l'utilisateur a demandé : un nom de paquet, un chemin de
   fichier, une unité `.service`, `name@version` ou un purl (`amivuln-resolve`).
2. **Identité.** Le paquet installé, lu depuis le gestionnaire de paquets
   (`rpm`, `pacman`) par un exécuteur de sous-processus borné et restreint à
   une liste d'autorisation, depuis la base de paquets exportée d'un conteneur
   (dpkg, apk ou rpm), depuis une liste ou un SBOM, ou depuis les métadonnées
   propres à un fichier (note de paquet, informations de compilation Go,
   `cargo-auditable`).
3. **Données de la distribution.** Les données d'avis propres à la
   distribution, récupérées par un client HTTP conscient du cache
   (`amivuln-sources`, `amivuln-cache`).
4. **Correspondance.** Le statut de la distribution décide, jamais une plage de
   versions amont. `Fixed(v)` avec une version installée égale ou supérieure à
   `v` est corrigé ; une version plus ancienne est concernée et nomme la
   version qui corrige (`amivuln-core`).
5. **Enrichissement.** CISA KEV et FIRST EPSS.
6. **Politique.** `--fail-on`, `--fail-on-epss`, `--strict`, et la précédence
   des codes de sortie 70, 64, 2, 3, 1, 0.
7. **Rapport.** `summary`, `detail`, JSON, SARIF, Markdown, CSV et Prometheus (`amivuln-report`).

## Crates

- `amivuln` : ligne de commande, configuration et orchestration.
- `amivuln-core` : types du domaine, règles de correspondance, politique, codes
  de sortie et traits pour le monde extérieur.
- `amivuln-resolve` : résolution des cibles et exécuteur de processus système.
- `amivuln-version` : comparaison des versions RPM, pacman, Debian, apk et
  sémantiques, vérifiée avec `rpm`, `vercmp`, `dpkg` et `apk version -t`.
- `amivuln-sandbox` : le bac à sable Landlock et seccomp de la sonde de version
  facultative, la seule crate contenant du code `unsafe`.
- `amivuln-sources` : analyseurs pour l'Arch Security Tracker, Fedora
  `updateinfo`, OSV, NVD, CISA KEV et FIRST EPSS, et le client HTTP borné.
- `amivuln-cache` : cache HTTP SQLite avec revalidation par ETag et
  classification frais/périmé/expiré.
- `amivuln-report` : formateurs de sortie.

Toutes les crates sont publiées sur crates.io parce que le binaire en dépend.
Les crates de bibliothèque partagent la version du binaire et ne portent
aucune promesse de stabilité d'API, à la 1.0 comme après : le contrat est la
commande (voir la politique de support).

## Invariants

- Le statut de la distribution l'emporte sur la comparaison des versions amont.
- Un constat sans déclaration de la distribution est *non vérifié*, listé à
  part, et jamais compté comme concerné.
- Une source requise en échec rend le résultat incomplet (code de sortie 2).
  Les données en cache périmées dans la limite de `stale_max_age` sont
  utilisées et signalées comme `stale`.
- Chaque lecture de fichier, réponse HTTP et sortie de sous-processus est
  bornée en taille, chaque sous-processus a un délai d'expiration et un chemin
  absolu autorisé, et aucun shell n'intervient.
- Le texte venant de l'extérieur du processus est assaini avant d'atteindre un
  terminal.
- Aucun champ identifiant l'hôte n'existe dans la sortie ni dans les requêtes.
