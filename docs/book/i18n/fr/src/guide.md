# Guide de l'utilisateur

## Vérifier des paquets

```bash
amivuln nginx                 # paquet installé, par nom
amivuln /usr/sbin/nginx       # le paquet auquel appartient ce fichier
amivuln openssl@3.5.1-1       # une version précise, sans lire l'hôte
amivuln pkg:rpm/fedora/nginx@1.26.2-1.fc44?arch=x86_64   # une package URL
amivuln --all                 # tous les paquets installés
```

`--file PATH`, `--package NAME[@VERSION]` et `--purl PURL` sont des formes
explicites des mêmes cibles et peuvent être répétées. Quand un nom est ambigu
(par exemple plusieurs versions du noyau installées), amivuln échoue avec le
code de sortie 3 et indique quel sélecteur utiliser. Il ne devine jamais.

## Lire le résultat

Le résumé affiche, par paquet, le nombre de constats concernés par gravité, le
nombre de ceux qui figurent dans le catalogue CISA KEV, le score EPSS le plus
élevé, et la version corrigée avec la commande à exécuter pour l'appliquer.
amivuln n'exécute jamais cette commande.

Les constats que la distribution n'a pas pu confirmer sont listés à part comme
*unverified* et ne sont pas comptés avec les constats concernés. `--strict` les
fait compter pour `--fail-on`.

Les dernières lignes listent chaque source consultée, son statut (`ok`,
`stale`, `failed`, `skipped`), son âge, et si le résultat est complet. Une
source obligatoire en échec rend le résultat **incomplet** : la sortie le dit
bien fort et le code de sortie est 2, si bien qu'une panne ne peut jamais
passer pour une analyse propre.

## Utilisation en CI

```bash
amivuln --all --fail-on high           # fait échouer le job sur HIGH ou pire
amivuln --all --fail-on kev            # n'échoue que sur les CVE activement exploitées
amivuln --all --fail-on-epss 0.5       # échoue sur une forte probabilité d'exploitation
amivuln --all -f json > amivuln.json   # conserve une trace lisible par machine
```

Pour vérifier une version pour une autre distribution, par exemple un paquet
Fedora dans un runner basé sur Debian, passez `--distro fedora:44` ou
`--distro arch` avec `name@version`. Seuls l'écosystème, le nom du paquet et la
version sont envoyés sur le réseau.

## Hors ligne et cache

Les réponses sont mises en cache dans `$XDG_CACHE_HOME/amivuln/cache.sqlite`
(par défaut `~/.cache/amivuln`). Une réponse plus récente que `cache_ttl` (6 h)
est utilisée sans interroger le réseau ; quand le réseau échoue, une réponse
vieille d'au plus `stale_max_age` (72 h) est utilisée et signalée `stale`.
`--offline` ne touche jamais au réseau et échoue de façon fermée (code 2)
quand le cache n'a rien d'utilisable. `amivuln cache info` et
`amivuln cache clear` gèrent le cache ; `--no-cache` ignore le cache disque.

## Configuration

`amivuln config init` écrit un fichier par défaut commenté ; `amivuln config show`
affiche la configuration effective et `amivuln config validate` la vérifie.
Les clés inconnues sont rejetées pour que les fautes de frappe ne passent pas
inaperçues.

## Langue

Le texte lu par une personne (la sortie summary et detail, `pending`, `cve`,
`restart`, ainsi que les erreurs et avertissements courants) suit la locale :
la première variable définie parmi `LC_ALL`, `LC_MESSAGES` et `LANG`, comme pour
tout outil en ligne de commande. L'anglais et le portugais du Brésil (`pt`)
existent ; tout le reste, y compris `C`, donne de l'anglais. Pour une seule
exécution : `LC_ALL=pt_BR.UTF-8 amivuln --all`.

Les sorties JSON, SARIF, CSV, Markdown, Prometheus, CycloneDX et OpenVEX restent
en anglais quelle que soit la locale, car d'autres programmes les lisent, de
même que le texte de `--help`, les erreurs de configuration et les messages des
bibliothèques dont l'outil est construit. Les noms de gravité, `KEV` et `EPSS`
ne sont pas traduits. La traduction a été écrite par l'assistant du projet et
n'a pas été relue par un locuteur natif ; une correction se fait par une pull
request sur un seul fichier texte (voir CONTRIBUTING).

## Le noyau en cours d'exécution

Plusieurs noyaux sont installés côte à côte sur la plupart des hôtes et un seul
s'exécute, si bien que `amivuln kernel-core` échoue comme ambigu.
`amivuln --kernel` vérifie le paquet qui possède l'image du noyau en cours
d'exécution (la version indiquée dans `/proc/sys/kernel/osrelease`), quels que
soient les autres noyaux installés :

```text
$ amivuln --kernel
kernel-core 7.2.15-200.fc44 (Fedora 44)  <- --kernel 7.2.15-200.fc44.x86_64
  CRITICAL 0   HIGH 0   MEDIUM 1   LOW 0   KEV 0
  Fixed in: 7.3.3-200.fc44  (dnf upgrade kernel-core)
```

Il est jugé d'après les données de la distribution comme tout paquet : une
version amont n'est jamais comparée aux enregistrements CVE propres du noyau,
car un noyau de distribution embarque des correctifs que le numéro de version
ne montre pas. `--all` juge toujours chaque noyau installé. Les correctifs à
chaud (kpatch, livepatch) sont inconnus d'amivuln : il rapporte ce que dit la
version du paquet. Voir ADR-0015.

## Expliquer un constat

`amivuln --explain -f detail` ajoute, sous chaque constat, les phrases qui
disent pourquoi il est signalé :

```text
CVE-2026-111253  UNKNOWN  fix: 5.4.7.0-1.fc44  EPSS 0.00
      why: dnf5 5.4.6.0-1.fc44 is older than 5.4.7.0-1.fc44, the build that fixes this CVE in the distribution's data. Installing 5.4.7.0-1.fc44 or later closes it.
      why: FIRST EPSS puts the chance it is exploited in the next 30 days at 0%, above 3% of scored CVEs.
```

C'est désactivé par défaut, ne s'applique qu'à la sortie detail (les formats
destinés aux machines sont identiques avec ou sans) et suit la langue de la
locale.

Aucun modèle de langage ne l'écrit. Chaque phrase est un modèle rempli à partir
d'un champ que l'exécution détient déjà (la version installée, la version
corrigée, l'état donné par les données de la distribution, la façon dont le
paquet a été identifié, CISA KEV, EPSS, une mesure d'atténuation du
fournisseur), si bien que le même constat donne toujours le même texte et que
chaque phrase peut être rattachée à sa source. Rien n'est envoyé nulle part. Ce
qu'il ne fait pas : il ne raisonne pas sur l'accessibilité du code vulnérable
sur cet hôte, et il ne résume pas la CVE (la description n'est pas conservée).
Une correspondance de bannière de version et un paquet intégré à un fichier le
disent, car ce sont des preuves plus faibles.

## Atténuations

`amivuln --mitigations` montre aussi, pour chaque CVE qui concerne encore
l'hôte, ce que Red Hat indique comme possible tant que le correctif n'est pas
installé : désactiver un module, changer un réglage, exécuter un script. C'est
le texte propre de Red Hat, lu dans ses données de sécurité publiques
(`access.redhat.com/hydra/rest/securitydata/cve/<id>.json`), et présenté comme
tel :

```text
CVE-2024-6387  HIGH  fix: 1:9.6p1-3.fc40.3
      mitigation (Red Hat, not checked on this host): ... set LoginGraceTime to 0 ...
```

C'est **désactivé par défaut**, car cela envoie l'identifiant de chaque CVE
ouverte à `access.redhat.com` ; `--mitigations` l'active pour une exécution, et
`[sources.mitigations] enabled = true` pour toutes. Ne nommer que `url` dans
cette table ne l'active pas. Les réponses sont conservées une semaine.

- Le texte est écrit pour les produits de Red Hat. amivuln ne vérifie pas qu'il
  s'applique à cet hôte ni que le réglage est en vigueur, et la ligne le dit.
- Red Hat remplit le champ pour la plupart des CVE afin d'indiquer qu'il n'y a
  rien à faire (« Mitigation for this issue is either not available or ...
  criteria »). C'est l'absence de mesure d'atténuation et cela est écarté : sur
  un conteneur Debian, 30 CVE sur 94 en avaient une réelle.
- Elle apparaît comme l'objet `mitigation` d'un constat dans le JSON (seulement
  quand elle existe), comme `workaround` dans le document CycloneDX et dans la
  sortie detail.
- Une recherche qui échoue est nommée dans la source `redhat-cve` (et avec
  `required = true` le résultat est incomplet) ; elle n'est jamais lue comme
  « aucune mesure d'atténuation n'existe ». Au plus 400 CVE sont recherchées
  par exécution.

## Runtimes Flatpak

`amivuln --flatpak` vérifie aussi les composants des runtimes Flatpak installés
(l'installation système et celle de l'utilisateur ; `FLATPAK_SYSTEM_DIR` et
`FLATPAK_USER_DIR` sont respectés). Rien n'est exécuté : le `manifest.json` de
chaque runtime est lu. Les runtimes construits sur freedesktop-sdk (Platform,
Sdk, GNOME, KDE) listent chaque composant avec sa version amont, ainsi qu'un
bloc `x-cpe` avec le nom de produit NVD, les CVE que le build a déjà corrigées
(`patches`) et celles que ses mainteneurs ont jugées sans objet (`ignored`).

Il n'existe pas de statut de correctif de distribution pour ces composants ; les
CVE viennent donc de la NVD, interrogée pour la version amont de chaque
composant, et les déclarations du constructeur décident du reste comme les
données d'une distribution : une CVE corrigée est réglée et une CVE ignorée est
« not affected », ni l'une ni l'autre n'est un constat. Ce qui reste ne nomme
aucune version corrigée, car le correctif est un runtime plus récent
(`flatpak update`). Un composant est nommé `runtime/branch/component`.

Sachez ce que cela ne vous dit pas :

- Une CVE que le build a corrigée sans la lister dans `patches` apparaît comme
  ouverte. Le zlib du runtime 25.08 est listé pour CVE-2026-22184, qui se trouve
  dans un outil (`untgz`) que le runtime ne construit pas, et le manifeste ne le
  dit pas.
- La NVD est lente et limitée en débit : 5 requêtes en 30 secondes sans clé
  d'API et 50 avec une. Une installation compte des centaines de composants
  distincts, donc une première exécution prend une heure ou plus sans clé et
  quelques minutes avec une (`[sources.nvd] api_key_file`). Les réponses sont
  conservées un jour et utilisées pendant une semaine quand la NVD est
  injoignable, donc les exécutions suivantes sont rapides.
- Un composant pour lequel la NVD n'a pas pu répondre (requête échouée, limite
  de débit, liste tronquée) est nommé dans le détail de la source, la source est
  `failed`, et avec `required = true` le résultat est incomplet (code 2). Il
  n'est jamais lu comme « aucune CVE ».
- Les runtimes sans `manifest.json` (extensions de locales, pilotes GL et
  codecs) sont comptés dans une seule entrée `unresolved`. Les applications
  elles-mêmes ne sont pas lues : elles embarquent leurs propres bibliothèques et
  n'ont pas un tel manifeste.

## SBOM et VEX

`amivuln --all -f cyclonedx` écrit un document CycloneDX 1.6 : chaque paquet
installé est un composant, avec son purl et la façon dont il a été identifié
(`amivuln:provenance`), et chaque constat est une vulnérabilité avec son
analyse. `amivuln --all -f openvex` écrit un document OpenVEX 0.2.0 avec une
déclaration par paquet et par CVE. Les deux concernent `check` ; `pending`,
`cve` et `restart` les refusent.

L'état vient des données propres de la distribution :

- concerné, avec la version qui le corrige quand elle est publiée :
  `exploitable` dans CycloneDX, `affected` dans OpenVEX ;
- corrigé à la version installée ou avant, ce qui inclut les correctifs qu'une
  distribution a rétroportés : `resolved` et `fixed` ;
- déclaré non concerné, par la distribution ou par un fichier VEX passé avec
  `--vex` : `not_affected` dans les deux, avec la raison ;
- non vérifiable (aucune déclaration de la distribution, ou versions
  incomparables) : `in_triage` et `under_investigation`.

Ce qui apparaît dépend de ce que la source liste. Les `updateinfo` de Fedora et
l'Arch Security Tracker listent ce qu'ils ont corrigé, donc les CVE corrigées y
apparaissent. OSV est interrogé sur la version installée ; sur les hôtes
Debian, Ubuntu, Alpine et Red Hat, les documents listent donc les problèmes
ouverts, pas ceux déjà clos.

Les déclarations sont l'évaluation de cet outil pour cet hôte, pas une
attestation de la distribution. Une exécution incomplète est marquée
`amivuln:complete = false` dans les métadonnées CycloneDX, et un paquet
qu'amivuln n'a pas pu résoudre est compté dans `amivuln:unresolved` ; le code
de sortie est 2 comme d'habitude. La sortie est déterministe : composants et
déclarations sont triés par purl, et rien d'aléatoire (pas de numéro de série)
n'est ajouté. Les tests valident les deux documents contre les schémas
officiels.

## Prometheus et le textfile collector de node_exporter

`amivuln --all -f prometheus` écrit des métriques texte :
`amivuln_findings{severity,kev}`, `amivuln_unverified_findings`,
`amivuln_source_up{source}`, `amivuln_source_age_seconds{source}`,
`amivuln_run_complete` et `amivuln_last_run_timestamp_seconds`. Les étiquettes
viennent de vocabulaires fixes, si bien qu'aucun nom de paquet, nom d'hôte ou
chemin n'atteint le magasin de métriques. Écrivez la sortie dans un fichier
`.prom` du répertoire textfile via un fichier temporaire et un renommage, pour
que le collecteur ne lise jamais un fichier partiel.

## Exécution sur un timer

`contrib/systemd/amivuln.service` et `amivuln.timer` analysent l'hôte toutes
les six heures et écrivent `amivuln.prom` pour le textfile collector, via
`--output` pour que le fichier soit remplacé de façon atomique. Le service
s'exécute sous un utilisateur dynamique sans capacités, avec un système de
fichiers en lecture seule et un filtre d'appels système ;
`systemd-analyze security amivuln.service` rapporte une exposition de 1.2.

```bash
sudo install -m 0644 contrib/systemd/amivuln.{service,timer} /etc/systemd/system/
sudo systemctl enable --now amivuln.timer
```

Adaptez `ExecStart` et `ReadWritePaths` quand le répertoire textfile diffère.
Les codes de sortie 1 (politique), 2 (incomplet) et 3 (non résolu) écrivent
toujours un fichier valide, donc l'unité n'échoue que sur une erreur d'usage ou
interne.

## Derrière un proxy ou une AC d'entreprise

Renseignez la table `[network]` du fichier de configuration :

```toml
[network]
proxy = "http://proxy.corp.example:3128"   # default: HTTPS_PROXY and NO_PROXY
ca_file = "/etc/pki/ca-trust/source/anchors/corp.pem"
user_agent_suffix = "team-sre"
```

`ca_file` ajoute des racines de confiance à celles intégrées (PEM, 1 Mio au
plus). `user_agent_suffix` est ajouté au `User-Agent` et c'est le seul texte
propre à l'hôte qui puisse quitter la machine, uniquement si vous le définissez.
L'URL d'un proxy peut contenir des identifiants ; amivuln ne l'affiche jamais.
Pour utiliser plutôt un miroir interne, définissez `sources.<nom>.url`.

## Pour les agents d'IA : le serveur MCP

`amivuln mcp` parle le Model Context Protocol sur stdio (JSON-RPC 2.0 délimité
par des sauts de ligne, révisions du protocole 2025-06-18, 2025-03-26 et
2024-11-05). Enregistrez-le dans un client, par exemple :

```json
{ "mcpServers": { "amivuln": { "command": "amivuln", "args": ["mcp"] } } }
```

Les outils sont en lecture seule et chacun exécute une ligne de commande fixe
avec `-f json` ; le résultat est le même rapport versionné que celui qu'affiche
la ligne de commande.

- `check_target` : `targets` (1 à 20 noms de paquets, `name@version` ou URL `pkg:`) et un `distro` facultatif.
- `check_cve` : `id` comme `CVE-2024-6387` ; analyse tous les paquets installés.
- `pending_updates`, `needs_restart` et `list_services` : aucun argument.

Il n'y a pas de shell, pas de chemin de fichier en entrée et aucun moyen de
passer des options : une cible qui commence par `-` ou contient des caractères
de contrôle est refusée. Le serveur met à jour le cache local comme toute autre
exécution ; passez `--offline` ou `--no-cache` à `amivuln mcp` pour le limiter.
Lisez toujours `complete` et `sources` dans un résultat avant de considérer une
liste vide comme propre.

## Vérifier un SBOM

`amivuln --sbom bom.cdx.json --distro fedora:44 --fail-on high` lit un document
CycloneDX JSON (toute version 1.x), vérifie chaque composant dont le purl est un
paquet `rpm`, `deb` ou `alpm` et laisse l'hôte tranquille. Un purl dont
l'espace de noms est en désaccord avec `--distro` est une erreur. Les
composants qui ne sont pas des paquets du système (npm, PyPI, Maven, etc.) ne
sont pas écartés en silence : ils apparaissent comme entrées `unresolved`, une
par type de purl avec un décompte, et l'exécution se termine avec le code 3.
Pour ne vérifier que les paquets du système, filtrez d'abord le SBOM, par
exemple avec
`jq '.components |= map(select(.purl // "" | startswith("pkg:rpm/")))'`.

## Réseaux résilients

Les sources peuvent avoir des miroirs. Une source qui échoue sur son point
d'accès principal est interrogée à nouveau sur chaque miroir de `fallback`,
dans l'ordre écrit, avant d'être comptée comme en échec. Chaque appel en échec
est retenté avec un recul exponentiel et de la gigue (`retries`, 2 par défaut,
10 au plus) ; un `Retry-After` envoyé par le serveur est respecté dans le
budget de tentatives. Un point d'accès qui échoue de façon répétée déclenche un
disjoncteur par point d'accès et est ignoré pour le reste d'une exécution
(`cooldown`, 30 s par défaut), si bien qu'un miroir mort ne bloque pas
l'analyse. Un hôte lent peut être ralenti volontairement avec `min_interval`,
qui espace les requêtes vers le même hôte (par exemple `"100ms"`).

L'ordre de repli est : point d'accès principal, puis miroirs, puis le cache,
puis la base hors ligne installée (voir la section sur la base hors ligne), puis
l'échec. `sources` dans chaque sortie dit lesquels ont répondu, leur âge, et si
le résultat est complet.

## Notifications par webhook

Une section `[notify]` envoie un résumé compact après une exécution de `check` :
faits sur l'hôte, complétude, note, totaux, identifiants des constats. C'est
facultatif et cela ne transporte rien de plus que ce que le rapport JSON indique
déjà.

```toml
[notify]
webhook = "https://ntfy.sh/example-topic"   # any endpoint that accepts a POST
bearer_file = "/etc/amivuln/notify-token"   # optional; sent as Authorization: Bearer
on = "violation"                            # violation (default) | incomplete | always
```

Un envoi en échec affiche un avertissement et ne change jamais le code de
sortie : la décision de politique a été prise à partir de l'analyse, pas de la
notification.

## La base hors ligne

`amivuln db` déplace des données d'avis entre des hôtes qui peuvent atteindre
le réseau et des hôtes qui ne le peuvent pas. L'archive est un `tar.zst`
contenant le cache SQLite et un manifeste avec un SHA-256 de la base ; `--key`
et `--sig` ajoutent une signature minisign du manifeste.

```bash
amivuln --all -f json            # réchauffe le cache (nécessite le réseau une fois)
amivuln db build --archive db.tar.zst
amivuln db verify db.tar.zst --key amivuln.pub --sig db.tar.zst.minisig
amivuln db pull db.tar.zst       # vérifie et installe pour cet utilisateur
amivuln db info db.tar.zst
```

`db pull` installe sous `$XDG_DATA_HOME/amivuln/offline` et refuse une archive
plus ancienne que celle installée (anti-retour en arrière) ; `--force`
passe outre. Une fois installée, une exécution avec `--offline` répond à partir
d'elle et signale ces sources comme `stale`, si bien qu'un hôte isolé produit
les mêmes formes de rapport avec des codes de sortie qui respectent toujours
`--fail-on`. `amivuln db verify` se termine avec le code 65 quand une archive
est altérée ; un `db pull` régressif se termine aussi avec 65.

La signature n'est volontairement pas intégrée : générez la clé du projet avec
l'outil `minisign` et signez en dehors d'amivuln
(`minisign -S -s key.sec -m manifest.json -x db.tar.zst.minisig`), pour que la
clé secrète ne passe jamais par ce binaire.

## Fichiers qu'aucun paquet ne possède

Une cible de type chemin que le gestionnaire de paquets ne connaît pas (un
binaire copié dans un conteneur, un logiciel embarqué) est identifiée par sa
propre `.note.package` systemd quand elle en a une. Le paquet, la version et le
système de paquets viennent du fichier, et le rapport marque le paquet avec la
provenance `embedded_note`. Une note pour un autre système de paquets que celui
de l'hôte (une note `deb` sur un hôte RPM) est refusée comme non résolue au lieu
d'être devinée, et le fichier n'est jamais exécuté.

## Programmes Go et Rust qu'aucun paquet ne possède

Quand une cible de type chemin n'appartient à aucun paquet et n'a pas de note de
paquet, amivuln lit les modules Go (informations de build) ou les crates Rust
(données cargo-auditable) que le programme déclare et interroge OSV sur chaque
version exacte. Les constats montrent la plus basse version corrigée supérieure
à celle installée, et `update_hint` dit que le programme doit être recompilé,
car aucun gestionnaire de paquets ne peut mettre à jour une dépendance liée
statiquement. Les fichiers qu'un paquet possède ne sont volontairement pas
développés ainsi : une distribution rétroporte des correctifs dans du code
embarqué sans changer les versions, donc les versions de modules d'un binaire
possédé produiraient des faux positifs.

Le point d'accès OSV pour cette passe est `[sources.osv]` (obligatoire par
défaut : une passe en échec laisse ces modules sans verdict, ce qui ne doit pas
passer pour propre). La gravité textuelle vient de l'avis quand il en indique
une (les avis GitHub le font ; les entrées RUSTSEC non, et rapportent
`unknown`).

## La clé minisign du projet

`contrib/offline-db/amivuln.pub` est la clé publique minisign du projet. C'est
aussi ce que le workflow nocturne utilise pour vérifier la base avant sa
publication dans la release. La clé privée du projet ne vit que dans les
secrets du dépôt (`MINISIGN_SECRET_KEY` plus `MINISIGN_PASSWORD`) et jamais sur
la machine d'un développeur, si bien qu'un miroir compromis ne peut pas simuler
la fraîcheur ni rejouer une ancienne base au-delà de l'horodatage
anti-retour en arrière.

## Analyser un conteneur

`amivuln --container ID` vérifie les paquets installés dans un conteneur. Le
runtime (podman, puis docker) n'est invoqué que pour exporter le rootfs, ce qui
n'exécute jamais rien dans le conteneur. L'`os-release` du conteneur décide de
l'écosystème, si bien que la distribution de l'hôte ne fuit jamais dans la
réponse, et les paquets sont jugés par la source correspondante (OSV pour
Debian, Ubuntu, Rocky, `AlmaLinux`, Red Hat Enterprise Linux (UBI compris) ; la
base rpm via le `rpm` de l'hôte pour les conteneurs de la famille Fedora). Les
constats sont étiquetés avec l'identifiant du conteneur, par exemple
`web:nginx`.

```bash
amivuln --container web --container db --fail-on high
```

Les conteneurs Alpine sont jugés par OSV (`Alpine:v3.20` pour la version 3.20).
La base installée nomme l'origine de chaque sous-paquet, et OSV indexe les avis
Alpine par origine, donc `libcrypto3` est interrogé comme `openssl`. Les images
edge et alpha n'ont pas de version OSV et sont refusées. Les versions suivent
l'ordre `apk` (`1.0_rc1` avant `1.0`, `-r1` après `-r0`).

## Bannières de version dans les binaires

Quand rien d'autre n'identifie un binaire (ni propriétaire de paquet, ni note de
paquet, ni métadonnées Go ou Rust), amivuln cherche les bannières de version
qu'affiche un ensemble choisi de produits C : OpenSSL, curl, zlib, SQLite, nginx
et d'autres. Une correspondance devient une cible avec la version amont telle
qu'affichée, marquée `string_heuristic` dans tous les formats.

C'est un signal de **faible confiance** : la distribution a pu rétroporter des
correctifs sans changer la bannière embarquée. Le verdict est réel, mais
l'utilisateur doit le vérifier avec le journal des changements de la
distribution.

### La sonde de version en bac à sable

Avec `exec_version_probe = true` dans `[general]`, amivuln exécute aussi
`<file> --version` pour les fichiers qu'aucun autre moyen n'identifie et lit les
bannières dans ce qu'il affiche. C'est le seul endroit où amivuln exécute une
cible ; c'est donc désactivé par défaut et cela s'exécute dans un bac à sable
appliqué avant `exec` :

- aucune écriture sur le système de fichiers (Landlock), et lectures limitées
  aux répertoires de bibliothèques du système et au répertoire de la cible ;
- aucun socket et aucun accès aux autres processus (seccomp) ;
- `no_new_privs`, un passage à `nobody` quand il est lancé en root, 2 s de temps
  CPU, aucune croissance de fichier, aucun core dump, 64 fichiers ouverts ;
- 2 s de temps réel et 64 Kio de sortie par flux.

Quand le noyau ne peut pas appliquer le bac à sable (pas de Landlock, ou une
architecture autre que x86_64 et aarch64), l'exécution rapporte une erreur pour
ce fichier. Elle n'exécute jamais la cible sans confinement. Le filtre seccomp
est une liste de refus, pas une liste d'autorisations : les cibles sont des
binaires arbitraires dont les appels système de démarrage ne peuvent pas être
listés, et Landlock supprime déjà le côté système de fichiers.

## Repli NVD pour les produits sans propriétaire

Les cibles de l'heuristique de chaînes (produits sans données de distribution)
sont aussi vérifiées auprès de l'API NVD 2.0 par nom CPE. La table de
correspondance CPE est choisie à la main (`nginx` correspond à `f5:nginx`,
`curl` à `haxx:curl`) ; un produit que la table ne couvre pas est ignoré. La
source est facultative (`sources.nvd.required = false` par défaut), donc un
échec ne rend pas le résultat incomplet. La clé d'API facultative fait passer la
limite de débit de 5 à 50 requêtes par 30 secondes.

```toml
[sources.nvd]
enabled = true
required = false
# api_key_file = "/etc/amivuln/nvd-api-key"
```

Les constats NVD portent la gravité CVSS de la version de métrique la plus
récente disponible, et le verdict est `affected` sans version corrigée : la NVD
est un catalogue de CVE, pas une source de correctifs de distribution.
