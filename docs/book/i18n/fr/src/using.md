# Utiliser amivuln

Des recettes pour les endroits où amivuln s'exécute le plus souvent. Chacune est
assez complète pour être copiée ; le
[guide de l'utilisateur](https://nubian-ibex.github.io/amivuln/guide.html)
explique les options en détail et la
[référence](https://nubian-ibex.github.io/amivuln/reference.html) les liste
toutes.

Deux choses valent partout. Lisez `complete` et les lignes `source` avant de
faire confiance à un résultat vide : le code de sortie `2` signifie qu'une
source obligatoire était indisponible, ce qui n'équivaut pas à propre. Et seuls
l'écosystème, le nom du paquet et la version quittent la machine.

## Sur votre portable ou votre poste de travail

```bash
amivuln --all                      # note et totaux de tous les paquets installés
amivuln pending                    # quelles mises à jour réduisent le plus le risque, les plus risquées d'abord
amivuln openssl --format detail    # un paquet, chaque constat avec son correctif
amivuln /usr/bin/ssh               # le paquet auquel appartient un fichier
```

`pending` est le plus utile sur un poste de bureau : il regroupe les
sous-paquets construits à partir d'une même source, classe selon les failles
exploitées (KEV), la gravité et l'EPSS, et affiche la commande de mise à jour.
amivuln ne l'exécute jamais.

Pour une vue plein écran avec des filtres, compilez avec la fonctionnalité
`tui` :

```bash
cargo install amivuln --locked --features tui
amivuln tui          # flèches ou j/k pour se déplacer, K : KEV seulement, H : HIGH seulement, q : quitter
```

## Quand une nouvelle CVE fait la une

```bash
amivuln cve CVE-2024-6387          # code 1 quand un paquet installé est concerné
amivuln cve CVE-2024-6387 CVE-2025-26465
amivuln restart                    # processus utilisant encore des fichiers remplacés par une mise à jour
```

`cve` répond `affected`, `not affected` ou `unknown`. `unknown` signifie que la
distribution n'a aucune trace de la CVE : ce n'est pas une affirmation que
l'hôte est sûr. Après l'installation de la mise à jour, `restart` liste les
processus qui exécutent encore l'ancien code.

## Sur un serveur, de façon planifiée

Les unités de `contrib/systemd` analysent l'hôte toutes les six heures et
écrivent des métriques pour le textfile collector de node_exporter.

```bash
sudo install -m 0644 contrib/systemd/amivuln.{service,timer} /etc/systemd/system/
sudo systemctl enable --now amivuln.timer
```

Importez `contrib/grafana/amivuln.json` dans Grafana pour obtenir le tableau de
bord. Pour une simple tâche cron qui envoie le résultat par courrier seulement
quand quelque chose ne va pas :

```cron
17 6 * * *  root  amivuln --all --fail-on high -f markdown || mail -s "amivuln: $(hostname)" ops@example.org
```

Pour recevoir un message plutôt qu'un tableau de bord, ajoutez un webhook à la
configuration :

```toml
[notify]
webhook = "https://ntfy.sh/example-topic"
on = "violation"
```

## Dans un pipeline CI

GitHub Actions, avec la version vérifiée et le code scanning :

```yaml
permissions:
  contents: read
  attestations: read
  security-events: write
steps:
  - uses: nubian-ibex/amivuln-action@5c61781a5497fbcb34401a5b2d2eee54a59e9ebc # v0.1.1
    with:
      args: --all --fail-on high -f sarif --output amivuln.sarif
  - uses: github/codeql-action/upload-sarif@33d7b85da1a04171e211befe2c739303b9a4c066 # v4.39.3
    if: always()
    with:
      sarif_file: amivuln.sarif
```

Épinglez les actions tierces sur un SHA de commit complet, comme la première.
GitLab CI ou tout autre runner :

```yaml
amivuln:
  image: fedora:44
  script:
    - curl -sSLO https://github.com/nubian-ibex/amivuln/releases/latest/download/amivuln-x86_64-unknown-linux-musl.tar.zst
    - tar --zstd -xf amivuln-x86_64-unknown-linux-musl.tar.zst --strip-components=1
    - ./amivuln --all --fail-on kev -f json --output amivuln.json
  artifacts:
    when: always
    paths: [amivuln.json]
```

Vérifiez le téléchargement comme indiqué dans [Installation](installation.md)
avant de vous y fier. Pour qu'une pull request n'échoue que sur les constats
qu'elle introduit, comparez avec un rapport de la branche principale :

```bash
amivuln --all -f json --output baseline.json        # sur main, conservé comme artefact
amivuln --all --baseline baseline.json --fail-on high   # sur la pull request
```

## Conteneurs et images

Analysez un conteneur par id ou par nom ; le runtime peut être podman ou
docker. amivuln lit sa base de paquets depuis un système de fichiers exporté et
n'exécute jamais rien à l'intérieur.

```bash
id=$(podman create docker.io/library/alpine:3.18.0 true)
amivuln --container "$id" --fail-on high
podman rm "$id"
```

Les conteneurs Alpine, Debian, Ubuntu, Fedora, Rocky, AlmaLinux et Red Hat (UBI)
sont jugés selon leur propre version. Une image Alpine edge ou alpha n'a pas de
données d'avis et est refusée plutôt que déclarée propre. Passez plusieurs
options `--container` pour vérifier toute une pile dans un seul rapport.

## Beaucoup d'hôtes, ou un hôte où vous ne pouvez rien installer

Exportez une liste depuis l'autre hôte et vérifiez-la là où amivuln s'exécute.
Un `nom@version` par ligne ; `--distro` indique à quelle version appartient la
liste.

```bash
# Fedora, RHEL, Rocky, AlmaLinux (sur l'hôte cible)
rpm -qa --qf '%{NAME}@%|EPOCH?{%{EPOCH}:}|%{VERSION}-%{RELEASE}\n' > host.txt
# Debian et Ubuntu : les avis utilisent le nom du paquet source
dpkg-query -W -f '${source:Package}@${Version}\n' > host.txt
# Alpine : les avis utilisent le paquet d'origine
awk -F: '/^P:/{p=$2} /^V:/{v=$2} /^o:/{o=$2} /^$/{print (o?o:p)"@"v; p="";v="";o=""}' \
  /lib/apk/db/installed > host.txt

amivuln --packages-from host.txt --distro debian:12 --fail-on high
```

Pour une liste de composants issue d'un build, pointez vers un SBOM CycloneDX :

```bash
amivuln --sbom product.cdx.json --distro debian:12
```

## Sans internet sur l'hôte

Construisez la base d'avis là où un réseau existe, transportez un seul fichier
et répondez à partir de celui-ci, hors ligne.

```bash
amivuln --all -f json > /dev/null                 # réchauffe le cache une fois
amivuln db build --archive db.tar.zst
# copiez db.tar.zst vers l'hôte isolé, puis :
amivuln db verify db.tar.zst --key amivuln.pub --sig db.tar.zst.minisig
amivuln db pull db.tar.zst
amivuln --all --offline --fail-on high
```

Les résultats issus de la base sont signalés `stale`, avec leur âge. Le projet
publie une base signée par famille de distributions ; voir le guide.

## Derrière un proxy ou une AC d'entreprise

```toml
[network]
proxy = "http://proxy.corp.example:3128"
ca_file = "/etc/pki/ca-trust/source/anchors/corp.pem"
```

Ou faites pointer `sources.<nom>.url` vers un miroir interne. Voir le guide.

## Depuis des scripts et des tableaux de bord

Le rapport JSON est un contrat versionné, donc `jq` suffit :

```bash
amivuln --all -f json | jq -r '.targets[] | select(.summary.kev > 0) | .package.name'
amivuln --all -f json | jq '[.targets[].findings[]] | group_by(.severity) | map({(.[0].severity): length}) | add'
amivuln --all -f csv > findings.csv        # sûr pour les tableurs
amivuln --all -f prometheus --output /var/lib/node_exporter/textfile_collector/amivuln.prom
```

## Depuis un assistant d'IA

`amivuln mcp` est un serveur Model Context Protocol en lecture seule.
Enregistrez-le une fois :

```json
{ "mcpServers": { "amivuln": { "command": "amivuln", "args": ["mcp"] } } }
```

L'assistant peut alors vérifier des paquets, demander si une CVE concerne l'hôte
et lister les mises à jour en attente. Il n'a pas de shell, ne reçoit aucun
chemin de fichier et ne peut passer aucune option.

## Fichiers qu'aucun paquet ne possède

Un binaire copié dans `/opt`, un programme Go ou un programme Rust issu d'un
build :

```bash
amivuln /opt/tool/bin/server          # note, build info Go ou données cargo-auditable
```

Si le fichier ne déclare rien, amivuln cherche les bannières de version d'une
courte liste de produits C et marque le résultat comme peu fiable. Avec
`exec_version_probe = true` dans `[general]`, il exécute en plus `--version` sur
le fichier dans un bac à sable Landlock et seccomp, désactivé par défaut.
