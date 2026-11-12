# amivuln

Langues : [English](https://ibexwall.com/amivuln/) · [Português](https://ibexwall.com/amivuln/pt/) · [Español](https://ibexwall.com/amivuln/es/) · [Deutsch](https://ibexwall.com/amivuln/de/) · **Français**

![amivuln : Suis-je vulnérable ? Vérification des CVE pour Linux tenant compte des backports](https://ibexwall.com/amivuln/images/banner.jpg)

**amivuln** répond à une question : *quelles CVE concernent ce paquet, ce
fichier ou cette version sur cet hôte, compte tenu des correctifs que ma
distribution a déjà livrés ?*

Les scanners génériques comparent des plages de versions amont et signalent des
CVE que votre distribution a corrigées depuis longtemps par des backports.
amivuln interroge d'abord les données de sécurité de la distribution elle-même :
un paquet que la distribution a déjà corrigé n'est pas signalé comme
vulnérable, et une mise à jour de sécurité que vous n'avez pas encore installée
l'est.

```console
$ amivuln pcre2 --format detail
pcre2 10.47-1.fc44.1 (Fedora 44)
  CRITICAL 0   HIGH 8   MEDIUM 0   LOW 0   KEV 0   EPSS max 0.00
  Fixed in: 10.49-1.fc44  (dnf upgrade pcre2)
  Affected:
    CVE-2026-103111  HIGH   fix: 10.49-1.fc44  EPSS 0.00
    ...

source fedora-updateinfo  ok  age 0s  required
source kev                ok  age 0s
source epss               ok  age 0s
result: complete
```

## Principes

- **La précision avant la couverture.** Un faux positif dû à un backport est un
  bogue.
- **Ne jamais dégrader en silence.** Chaque résultat indique l'état de chaque
  source. Une source obligatoire en échec rend le résultat *incomplet* (code de
  sortie 2) : une panne ne ressemble donc jamais à une analyse propre.
- **Rien qui identifie l'hôte ne quitte la machine.** Seuls l'écosystème, le
  nom du paquet et la version sont envoyés. Pas de télémétrie.
- **La sortie est un contrat.** Du JSON avec un
  [schéma](https://ibexwall.com/amivuln/json-schema.html) versionné.
- **Des versions vérifiables.** Sommes de contrôle, attestations de build
  GitHub, une signature cosign et un SBOM accompagnent chaque version.

## État

Fedora, Arch Linux, Debian, Ubuntu, Alpine, Red Hat Enterprise Linux, Rocky
Linux et AlmaLinux sont pris en charge. Les résultats RHEL ne comprennent pas
les CVE que Red Hat n'a pas encore corrigées ; les limites de chaque
distribution sont décrites dans
[Data sources](https://ibexwall.com/amivuln/sources.html).

Commencez par [Installation](installation.md), [Démarrage rapide](quickstart.md)
et [Utiliser amivuln](using.md).

## Uniquement en anglais

Ces pages ne sont pas encore traduites : le
[guide de l'utilisateur](https://ibexwall.com/amivuln/guide.html), la
[référence](https://ibexwall.com/amivuln/reference.html),
l'[architecture](https://ibexwall.com/amivuln/architecture.html), le
[fonctionnement du matching](https://ibexwall.com/amivuln/matching.html),
les [sources de données](https://ibexwall.com/amivuln/sources.html), les
[politiques de sécurité](https://ibexwall.com/amivuln/policies.html) et
la [FAQ sur les faux positifs](https://ibexwall.com/amivuln/faq.html).
En cas de divergence, la version anglaise fait foi.
