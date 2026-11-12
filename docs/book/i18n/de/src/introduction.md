# amivuln

Sprachen: [English](https://nubian-ibex.github.io/amivuln/) · [Português](https://nubian-ibex.github.io/amivuln/pt/) · [Español](https://nubian-ibex.github.io/amivuln/es/) · **Deutsch** · [Français](https://nubian-ibex.github.io/amivuln/fr/)

![amivuln: Bin ich verwundbar? CVE-Prüfung für Linux mit Backport-Erkennung](https://nubian-ibex.github.io/amivuln/images/banner.jpg)

**amivuln** beantwortet eine Frage: *Welche CVEs betreffen dieses Paket, diese
Datei oder diese Version auf diesem Host, wenn man die Patches berücksichtigt,
die meine Distribution bereits ausgeliefert hat?*

Allgemeine Scanner vergleichen Versionsbereiche des Upstreams und melden CVEs,
die Ihre Distribution längst per Backport behoben hat. amivuln fragt zuerst die
eigenen Sicherheitsdaten der Distribution: Ein Paket, das die Distribution
bereits korrigiert hat, wird nicht als verwundbar gemeldet, und ein
Sicherheitsupdate, das Sie noch nicht installiert haben, schon.

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

## Grundsätze

- **Genauigkeit vor Abdeckung.** Ein Fehlalarm durch einen Backport ist ein
  Fehler.
- **Nie stillschweigend abschwächen.** Jedes Ergebnis nennt den Status jeder
  Quelle. Fällt eine erforderliche Quelle aus, ist das Ergebnis
  *unvollständig* (Exit-Code 2), sodass ein Ausfall nie wie ein sauberer Scan
  aussieht.
- **Nichts, was den Host identifiziert, verlässt den Rechner.** Gesendet werden
  nur Ökosystem, Paketname und Version. Keine Telemetrie.
- **Die Ausgabe ist ein Vertrag.** JSON mit versioniertem
  [Schema](https://nubian-ibex.github.io/amivuln/json-schema.html).
- **Überprüfbare Releases.** Prüfsummen, GitHub-Build-Attestierungen, eine
  cosign-Signatur und ein SBOM begleiten jedes Release.

## Stand

Unterstützt werden Fedora, Arch Linux, Debian, Ubuntu, Alpine, Red Hat
Enterprise Linux, Rocky Linux und AlmaLinux. RHEL-Ergebnisse enthalten die
CVEs nicht, die Red Hat noch nicht behoben hat; die Grenzen jeder Distribution
stehen unter [Data sources](https://nubian-ibex.github.io/amivuln/sources.html).

Beginnen Sie mit [Installation](installation.md), [Schnellstart](quickstart.md)
und [amivuln verwenden](using.md).

## Nur auf Englisch

Diese Seiten sind noch nicht übersetzt: das
[Benutzerhandbuch](https://nubian-ibex.github.io/amivuln/guide.html), die
[Referenz](https://nubian-ibex.github.io/amivuln/reference.html), die
[Architektur](https://nubian-ibex.github.io/amivuln/architecture.html), die
[Funktionsweise des Matchings](https://nubian-ibex.github.io/amivuln/matching.html),
die [Datenquellen](https://nubian-ibex.github.io/amivuln/sources.html), die
[Sicherheitsrichtlinien](https://nubian-ibex.github.io/amivuln/policies.html) und
die [FAQ zu Fehlalarmen](https://nubian-ibex.github.io/amivuln/faq.html).
Bei Abweichungen gilt die englische Fassung.
