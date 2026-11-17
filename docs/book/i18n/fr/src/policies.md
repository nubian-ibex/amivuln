# Politiques de sécurité

## Politique des dépendances (SCA)

`cargo deny`, `cargo audit` et `cargo vet` s'exécutent à chaque pull request et
dans le pipeline de publication (`just ci`). Le seuil est zéro constat non
déclaré : un constat d'avis, de licence ou de provenance bloque le changement
sauf s'il est déclaré avec une raison dans `deny.toml` (avis, licences) ou
`supply-chain/config.toml` (exemptions vet). Les exemptions déclarées sont
réexaminées à chaque version.

Un avis de dépendance qui n'affecte pas amivuln est consigné dans `deny.toml`
avec l'identifiant de l'avis et la raison pour laquelle il n'est pas
exploitable ici ; cet enregistrement est la déclaration VEX de référence du
projet. Aucune version n'est publiée avec un constat SCA non déclaré : les
contrôles échouent en mode fermé.

## Politique d'analyse statique (SAST)

Le seuil est zéro constat. `cargo clippy --workspace --all-targets
--all-features -- -D warnings` et `cargo fmt --check` bloquent chaque
changement dans `just ci`. Une suppression exige un `#[allow]` en ligne dont le
commentaire explique pourquoi le constat ne s'applique pas ; l'ensemble des
lints n'est jamais abaissé pour faire passer du code.

## Politique des secrets

- Aucun identifiant n'a sa place dans le dépôt ni dans le suivi des tickets.
- Les identifiants de la CI (la clé minisign de publication,
  `MINISIGN_SECRET_KEY` et `MINISIGN_PASSWORD`, les jetons cosign et
  crates.io) sont des secrets GitHub Actions limités aux workflows et à
  l'environnement `release` qui en ont besoin, et ne sont jamais écrits dans
  les journaux.
- Les secrets sont renouvelés quand un workflow, une machine ou une personne
  ayant accès change, et immédiatement en cas de soupçon de fuite ; après une
  fuite, les journaux d'audit sont examinés pour détecter l'usage de la valeur
  exposée.
- Le développement local ne nécessite aucun identifiant : les tests n'utilisent
  pas le réseau.

## Politique d'accès et de revue

Seul le compte du mainteneur détient l'accès en écriture, les droits sur les
tags et l'approbation de l'environnement de publication. Un nouveau
collaborateur est examiné avant que toute permission élevée lui soit accordée :
historique de contributions au projet, pratiques de sécurité (commits signés,
discipline sur les dépendances) et identité publique. Les rulesets sur `main`
et sur les tags `v*` imposent les commits signés et bloquent les force-push et
les suppressions, quel que soit le détenteur de la permission.

## Politique de tests

Chaque changement majeur ajoute ou met à jour des tests dans la suite
automatisée ; une correction de bug ajoute le test de régression avant le
correctif. Les tests ne doivent pas toucher le réseau : le comportement HTTP
est couvert par des fixtures enregistrées et `wiremock`. Lancez `just ci` avant
d'ouvrir une pull request ; la CI exécute la suite complète à chaque pull
request et la fusion est bloquée tant qu'elle échoue.
