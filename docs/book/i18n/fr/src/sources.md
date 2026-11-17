# Sources de données

- **Arch Security Tracker** : statut des CVE et version corrigée sur Arch (`https://security.archlinux.org/issues/all.json`)
- **Fedora `updateinfo`** : mises à jour de sécurité et CVE qu'elles corrigent sur Fedora (`https://dl.fedoraproject.org/pub/fedora/linux/updates/<release>/Everything/<arch>/repodata/`)
- **OSV** : Debian, Ubuntu, Alpine, openSUSE, Red Hat Enterprise Linux, Rocky Linux, `AlmaLinux`, modules Go et `crates.io` (`https://api.osv.dev/v1/querybatch`, un document d'avis par identifiant). Les avis qui existent aussi dans les trackers des distributions ont le même sens ; pour Go et les crates, ce sont les versions exactes qui décident.
- **CISA KEV** : CVE activement exploitées (`https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`)
- **FIRST EPSS** : probabilité d'exploitation (`https://api.first.org/data/v1/epss`)

La source de la distribution est requise par défaut. KEV et EPSS enrichissent
le résultat et sont facultatives : si elles échouent, la sortie le dit, mais le
résultat reste complet.

## Pourquoi pas OSV pour Fedora et Arch

La liste des écosystèmes d'OSV (vérifiée le 2026-11-07) contient Debian,
Ubuntu, Alpine, Red Hat, Rocky, AlmaLinux, SUSE et d'autres, mais ni Fedora ni
Arch Linux. Pour ces deux-là, les données propres à la distribution font
référence.

## Particularités de Fedora

`updateinfo` indique quelles CVE une mise à jour a corrigées. amivuln signale
une CVE comme touchant un paquet installé quand Fedora a publié un correctif
dans une version plus récente. Seuls les identifiants de CVE qui ouvrent le
titre d'un bug bugzilla sont retenus ; les identifiants qui n'apparaissent que
dans des descriptions en texte libre sont ignorés, car « régression due au
correctif de CVE-X » marquerait sinon CVE-X comme corrigée. Une mise à jour de
sécurité qui ne nomme aucune CVE est signalée sous son identifiant de mise à
jour. Une CVE sans correctif publié n'est pas visible dans ces données.

## Red Hat Enterprise Linux

RHEL est jugé à partir de l'écosystème `Red Hat` d'OSV, qui republie les avis
de sécurité de Red Hat (RHSA et RHBA). OSV range un paquet sous le dépôt où il
est livré (`Red Hat:enterprise_linux:9::baseos`, `::appstream`, `::crb`) et la
base rpm n'enregistre pas lequel, donc amivuln interroge les trois et fusionne
les réponses. Une CVE a généralement plusieurs correctifs, un par flux mineur
(GA, EUS, E4S). amivuln suit la règle de Fedora : une version installée égale
ou supérieure à un correctif publié est corrigée, et une version plus ancienne
est signalée par rapport au correctif le plus bas. Un hôte qui n'est pas sur le
flux le plus bas peut donc voir un correctif qu'il ne peut pas installer ; le
constat nomme la version afin que le flux puisse être vérifié.

**CVE non corrigées.** OSV porte les avis qui ont livré un correctif. Une CVE
que Red Hat n'a pas corrigée (`Affected`, `Fix deferred`, `Will not fix`, `Out
of support scope`) n'y a aucun avis, donc sur RHEL 8 et 9 amivuln lit aussi le
fichier OVAL de Red Hat « including unpatched » (ADR-0014, source
`redhat-oval`) : environ 11 Mo, lu une fois à chaque rafraîchissement du cache
et réduit à un petit index. Un paquet de l'hôte est mis en correspondance par
le nom de son paquet binaire ou source, et chaque CVE trouvée est signalée
comme concernée sans version corrigée, jamais comme propre. Une CVE pour
laquelle OSV a déjà une réponse garde la réponse d'OSV. `Under investigation`
n'est pas signalé. Le fichier n'a pas d'état pour RHEL 10, donc la source est
affichée comme ignorée à cet endroit et le résultat RHEL 10 reste une borne
inférieure. Rien sur l'hôte n'est envoyé ; désactivez-la avec
`sources.rhel_unpatched.enabled = false`. Les données sont publiées par Red Hat
sous CC BY 4.0. Les paquets du noyau sont listés face à des centaines de CVE,
la plupart faibles et différées : c'est ce que dit Red Hat.
La sévérité provient de la note que Red Hat lie dans chaque avis (Important
correspond à high).

## Où vivent les données hors ligne

`amivuln db build` regroupe tout ce qui a été consulté dans un `tar.zst`
qu'un autre hôte vérifie, `amivuln db pull`, et interroge avec `--offline`
(voir le guide). Les entrées VEX proviennent des documents que vous fournissez
avec `--vex`.

## Distributions prises en charge

Comment une cible est identifiée, et ce que les données peuvent montrer ou non :

- **Fedora.** L'hôte est lu via `rpm`. Données : `updateinfo`. Une CVE sans correctif publié n'est pas visible.
- **Arch Linux.** L'hôte est lu via `pacman`. Données : l'Arch Security Tracker, qui liste aussi les paquets vulnérables sans correctif.
- **Red Hat Enterprise Linux 8, 9 et 10.** L'hôte est lu via `rpm` ; les conteneurs UBI fonctionnent. Données : l'écosystème Red Hat d'OSV, plus les CVE non corrigées du fichier OVAL de Red Hat sur RHEL 8 et 9 (voir plus haut) ; RHEL 10 reste une borne inférieure.
- **Rocky Linux et AlmaLinux 8 et 9.** L'hôte est lu via `rpm`. Données : OSV ; seules les CVE qui ont livré un correctif sont visibles.
- **Debian et Ubuntu (LTS).** L'hôte est lu depuis `/var/lib/dpkg` (rien n'est exécuté) ; les conteneurs, les listes `--packages-from`, les SBOM et `name@version` fonctionnent aussi. Données : OSV, qui liste aussi les problèmes ouverts (signalés comme concernés sans version corrigée).
- **openSUSE Leap 15.x et 16.0, et Tumbleweed.** L'hôte est lu via
  `rpm`, et les conteneurs fonctionnent. Données : OSV, indexé par le paquet
  *source* (la bibliothèque `libopenssl3` est construite à partir de
  `openssl-3`) : amivuln lit le nom source dans la base rpm, mais une liste de
  paquets ou un SBOM doit le porter (voir la page Utiliser amivuln). Seules les
  mises à jour de sécurité (`SUSE-SU`, `openSUSE-SU`) comptent, et seules les
  CVE qui ont livré un correctif sont visibles. SUSE Linux Enterprise a ses
  propres données et n'est pas encore lu.
- **Gentoo.** L'hôte est lu depuis `/var/db/pkg` (rien n'est exécuté), et les
  conteneurs fonctionnent. Données : les GLSA de l'arbre Portage de l'hôte
  (`/var/db/repos/gentoo/metadata/glsa`), lues hors ligne ; rien n'est
  téléchargé. Les avis sont jugés par slot, et une plage avec un `slot`
  ne s'applique qu'à un paquet de ce slot. Seuls les avis qui ont livré un
  correctif existent, donc une CVE sans correctif pour l'instant n'est pas
  visible. L'âge de la source est l'heure de la dernière synchronisation de
  l'arbre ; un arbre absent, illisible ou vide rend le résultat incomplet. Pour
  un conteneur ou une autre machine, pointez `[sources.distro] path` vers un
  répertoire contenant les fichiers `glsa-*.xml`. L'attribut `arch` d'un avis
  n'est pas lu.
- **Alpine 3.x.** L'hôte est lu depuis `/lib/apk/db/installed` ; les autres entrées sont les mêmes que pour Debian et Ubuntu. Les images Edge et alpha n'ont pas de données d'avis et sont refusées. Données : OSV, indexé par le paquet d'origine ; seules les CVE qui ont livré un correctif sont visibles.
- **Données CVE de Red Hat (facultatif, désactivé par défaut).** Le texte
  `mitigation` que Red Hat publie par CVE, utilisé par `--mitigations`. Voir le
  guide pour ce qui est envoyé et ce qui n'est pas affirmé.
- **Runtimes Flatpak.** Lus depuis le `manifest.json` de chaque runtime, jugés
  par la NVD pour la version amont de chaque composant, en appliquant les
  listes `patches` et `ignored` propres au constructeur. Lent et soumis à une
  limite de débit ; voir le guide.
- **Modules Go et crates Rust** trouvés dans des binaires, via OSV.

## Prévu

L'API Bodhi de Fedora comme recoupement, la NVD par CPE comme solution de repli,
et endoflife.date. L'archive CSAF VEX de Red Hat (412 Mo) a été évaluée et non
retenue : le fichier OVAL donne les CVE non corrigées en 11 Mo (ADR-0014).

## Particularités d'Arch

Le tracker marque un groupe *Vulnerable* sans version corrigée pour le build
qui était courant à l'écriture de l'entrée, et certaines entrées restent ainsi
pendant des années. amivuln ne signale un paquet installé comme concerné que
s'il a la même version amont que le build enregistré (une reconstruction de
celui-ci est toujours concernée). Une version amont plus récente est signalée
comme *non vérifiée*, car l'entrée ne peut pas dire si elle s'applique encore.
Une installation plus ancienne que le build enregistré est hors de l'entrée et
n'est pas signalée.
