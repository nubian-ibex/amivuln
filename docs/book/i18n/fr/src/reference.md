# Référence

## Commandes

- `amivuln [OPTIONS] TARGET...` est un raccourci pour `amivuln check`.
- `amivuln check [TARGET...] [--all]`
- `amivuln cve CVE-ID...` : cet hôte est-il concerné ? Code 1 quand c'est le cas.
- `amivuln pending` : les mises à jour qui réduisent le plus le risque, classées.
- `amivuln services` : vérifie le paquet derrière chaque service systemd en cours d'exécution.
- `amivuln restart` : processus qui exécutent encore des fichiers remplacés par une mise à jour. Code 1 quand un redémarrage est nécessaire.
- `amivuln config show | init [--path FILE] | validate`
- `amivuln cache info | clear`
- `amivuln completions bash|zsh|fish|elvish|powershell`
- `amivuln db build|pull|verify|info` : la base d'avis hors ligne (voir le guide de l'utilisateur)
- `amivuln tui` : une vue plein écran avec des filtres (à compiler avec `--features tui`)
- `amivuln mcp` : un serveur Model Context Protocol en lecture seule sur stdio (voir le guide de l'utilisateur)
- `amivuln version [--json]`

## Options

- `-f, --format` : `summary`, `detail`, `json`, `sarif`, `markdown`, `csv`, `prometheus`, `cyclonedx` ou `openvex`
- `[network] retries = 2` : tentatives par appel en échec ; `cooldown = "30s"` : pause du disjoncteur ; `min_interval` : espacement facultatif par hôte
- `--output FILE` : écrit le résultat dans FILE au lieu de stdout ; le fichier est remplacé de façon atomique par un renommage
- `--fail-on` : `none`, `low`, `medium`, `high`, `critical` ou `kev`
- `--fail-on-epss SCORE` : code 1 quand un constat concerné atteint ce score EPSS
- `--strict` : les constats non vérifiés comptent pour `--fail-on`
- `--offline`, `--no-cache` : comportement du réseau et du cache
- `--config FILE` : utilise uniquement ce fichier de configuration
- `--color auto|always|never` : `NO_COLOR` est respecté
- `--distro fedora:NN|arch|debian:NN|ubuntu:NN.NN|alpine:N.NN|opensuse:NN.N|opensuse:tumbleweed|gentoo|rhel:N|rocky:N|alma:N` : traite l'hôte comme cette distribution
- `--baseline FILE` : un rapport `-f json` précédent ; seuls les constats absents de celui-ci violent `--fail-on`
- `--pid PID` : vérifie l'exécutable d'un processus en cours (répétable) ; un processus disparu, illisible ou dont l'exécutable a été remplacé sur le disque est signalé comme non résolu
- `--sbom FILE` : vérifie les paquets du système d'un SBOM CycloneDX JSON (purls rpm, deb, apk et alpm) ; les autres composants sont listés comme non résolus, une entrée par type de purl
- `--vex FILE` : un document `OpenVEX` ; une déclaration `not_affected` remplace le verdict et affiche l'auteur et la justification
- `--kernel` : vérifie aussi le noyau en cours d'exécution, quels que soient les autres installés (voir le guide)
- `--explain` : sous chaque constat de la sortie detail, dit en termes simples pourquoi il est signalé (des modèles de texte remplis avec les données de l'exécution ; aucun modèle d'IA, rien n'est envoyé)
- `--mitigations` : cherche aussi la mesure d'atténuation que Red Hat publie pour chaque CVE concernée (envoie les identifiants de CVE à access.redhat.com)
- `--flatpak` : vérifie aussi les composants des runtimes Flatpak installés (voir le guide pour le coût et ce qu'il ne peut pas dire)
- `--container ID` : vérifie les paquets d'un conteneur podman ou docker (répétable) ; les images Alpine, Debian, Ubuntu, Fedora, openSUSE, Gentoo, Rocky, AlmaLinux et Red Hat (UBI) sont lues depuis un système de fichiers racine exporté et rien ne s'exécute à l'intérieur
- `--packages-from FILE` : vérifie les paquets listés dans FILE (un `name@version` ou un purl par ligne) au lieu des paquets installés
- `ignore_file` (configuration) : constats acceptés ; les entrées expirées sont des erreurs
- `-q, --quiet` : seulement les erreurs

`AMIVULN_FORMAT`, `AMIVULN_FAIL_ON`, `AMIVULN_OFFLINE`, `AMIVULN_CONFIG` et
`AMIVULN_COLOR` définissent les options correspondantes.

## Codes de sortie

- 0 : terminé, rien au niveau de `--fail-on` ou au-dessus
- 1 : terminé, constats au niveau de `--fail-on` ou au-dessus
- 2 : incomplet : une source obligatoire était indisponible
- 3 : une cible n'a pas pu être résolue
- 64 : erreur d'usage ou de configuration
- 70 : erreur interne

Quand plusieurs cas s'appliquent, l'ordre de priorité est 70, 64, 2, 3, 1, 0.

## Sortie JSON (version 1 du schéma)

```json
{
  "schema_version": 1,
  "tool": {"name": "amivuln", "version": "0.1.0"},
  "generated_at": "2026-11-08T12:00:00Z",
  "host": {"os_id": "fedora", "os_version": "44", "arch": "x86_64"},
  "complete": true,
  "sources": [{"id": "fedora-updateinfo", "status": "ok", "age_s": 0, "required": true}],
  "targets": [{
    "input": "nginx",
    "package": {"name": "nginx", "version": "1:1.26.2-1.fc44", "arch": "x86_64",
                "ecosystem": "fedora", "purl": "pkg:rpm/fedora/nginx@1.26.2-1.fc44?arch=x86_64&epoch=1",
                "provenance": "package_db"},
    "summary": {"critical": 0, "high": 1, "medium": 0, "low": 0, "kev": 0, "epss_max": 0.02, "unverified": 0},
    "findings": [{"id": "CVE-2026-0001", "severity": "high",
                  "distro_status": {"state": "affected", "fixed_in": "1:1.26.3-1.fc44"},
                  "kev": null, "epss": {"score": 0.02, "percentile": 0.6, "date": "2026-11-07"}}],
    "unverified": []
  }],
  "unresolved": []
}
```

Le schéma JSON est publié à l'adresse [schema/v1.json](https://ibexwall.com/amivuln/schema/v1.json) et vérifié en CI contre la sortie réelle. Les constats et les constats non vérifiés sont des tableaux séparés. Le bloc host ne
contient jamais de nom d'hôte, d'adresse ni d'utilisateur. Ajouter des champs
facultatifs ne change pas `schema_version` ; en supprimer ou en changer le type, si.

## Fichier de configuration

```toml
schema_version = 1
[general]
offline = false
cache_ttl = "6h"
stale_max_age = "72h"
timeout = "10s"
exec_version_probe = false
[output]
format = "summary"
color = "auto"
[policy]
fail_on = "none"
fail_on_incomplete = true
strict = false
[sources.distro]
enabled = true
required = true
# url = "https://mirror.example/fedora/linux/updates"
[sources.kev]
enabled = true
[sources.epss]
enabled = true
```
