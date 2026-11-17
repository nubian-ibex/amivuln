# Datenquellen

- **Arch Security Tracker**: CVE-Status und behobene Version unter Arch (`https://security.archlinux.org/issues/all.json`)
- **Fedora `updateinfo`**: Sicherheitsupdates und die CVEs, die sie unter Fedora beheben (`https://dl.fedoraproject.org/pub/fedora/linux/updates/<release>/Everything/<arch>/repodata/`)
- **OSV**: Debian, Ubuntu, Alpine, openSUSE, Red Hat Enterprise Linux, Rocky Linux, `AlmaLinux`, Go-Module und `crates.io` (`https://api.osv.dev/v1/querybatch`, ein Advisory-Dokument pro ID). Advisories, die auch in den Distributions-Trackern existieren, haben dieselbe Bedeutung; bei Go und Crates entscheiden die exakten Versionen.
- **CISA KEV**: aktiv ausgenutzte CVEs (`https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`)
- **FIRST EPSS**: Ausnutzungswahrscheinlichkeit (`https://api.first.org/data/v1/epss`)

Die Distributionsquelle ist standardmäßig erforderlich. KEV und EPSS
reichern das Ergebnis an und sind optional: Wenn sie ausfallen, sagt die
Ausgabe das, aber das Ergebnis bleibt vollständig.

## Warum nicht OSV für Fedora und Arch

Die OSV-Ökosystemliste (geprüft am 2026-11-07) enthält Debian, Ubuntu, Alpine,
Red Hat, Rocky, AlmaLinux, SUSE und weitere, aber weder Fedora noch Arch Linux.
Für diese beiden sind die eigenen Daten der Distribution die maßgebliche
Quelle.

## Fedora im Detail

`updateinfo` gibt an, welche CVEs ein Update behoben hat. amivuln meldet eine
CVE als betreffend für ein installiertes Paket, wenn Fedora eine Korrektur in
einer neueren Version veröffentlicht hat. Nur CVE-IDs, die einen
Bugzilla-Bug-Titel eröffnen, gelten als vertrauenswürdig; IDs, die nur in
Freitextbeschreibungen vorkommen, werden ignoriert, weil sonst „Regression
from the fix for CVE-X“ CVE-X als behoben markieren würde. Ein
Sicherheitsupdate, das keine CVE nennt, wird unter seiner Update-ID gemeldet.
Eine CVE ohne veröffentlichte Korrektur ist in diesen Daten nicht sichtbar.

## Red Hat Enterprise Linux

RHEL wird anhand des Ökosystems `Red Hat` von OSV beurteilt, das die
Sicherheits-Advisories von Red Hat (RHSA und RHBA) neu veröffentlicht. OSV
ordnet ein Paket dem Repository zu, in dem es ausgeliefert wird
(`Red Hat:enterprise_linux:9::baseos`, `::appstream`, `::crb`), und die
rpm-Datenbank hält nicht fest, welchem, daher fragt amivuln alle drei ab und
führt die Antworten zusammen. Eine CVE hat meist mehrere Korrekturen, eine pro
Minor-Stream (GA, EUS, E4S). amivuln folgt der Fedora-Regel: Eine installierte
Version ab einer beliebigen veröffentlichten Korrektur gilt als gepatcht, und
eine ältere wird gegen die niedrigste Korrektur gemeldet. Ein Host, der nicht
auf dem niedrigsten Stream ist, kann daher eine Korrektur sehen, die er nicht
installieren kann; der Fund nennt die Version, damit sich der Stream prüfen
lässt.

**Unbehobene CVEs.** OSV enthält Advisories, die eine Korrektur ausgeliefert
haben. Eine CVE, die Red Hat nicht behoben hat (`Affected`, `Fix deferred`,
`Will not fix`, `Out of support scope`), hat dort kein Advisory, daher liest
amivuln unter RHEL 8 und 9 zusätzlich die OVAL-Datei von Red Hat „including
unpatched“ (ADR-0014, Quelle `redhat-oval`): etwa 11 MB, einmal pro
Cache-Aktualisierung gelesen und auf einen kleinen Index reduziert. Ein Paket
des Hosts wird über seinen Binär- oder Quellpaketnamen zugeordnet, und jede
gefundene CVE wird als betroffen ohne Korrekturversion gemeldet, nie als
sauber. Eine CVE, für die OSV bereits eine Antwort hat, behält die Antwort von
OSV. `Under investigation` wird nicht gemeldet. Die Datei kennt keinen Zustand
für RHEL 10, daher wird die Quelle dort als übersprungen angezeigt, und das
RHEL-10-Ergebnis bleibt eine untere Schranke. Über den Host wird nichts
gesendet; schalten Sie sie mit `sources.rhel_unpatched.enabled = false` ab. Die
Daten werden von Red Hat unter CC BY 4.0 veröffentlicht. Kernel-Pakete werden
zu Hunderten von CVEs aufgeführt, die meisten davon niedrig und zurückgestellt:
Das sagt Red Hat. Der Schweregrad stammt aus der Bewertung, die Red Hat in
jedem Advisory verlinkt (Important entspricht high).

## Wo die Daten offline liegen

`amivuln db build` packt alles Befragte in ein `tar.zst`, das ein anderer Host
verifiziert, `amivuln db pull`, und mit `--offline` abfragt (siehe das
Benutzerhandbuch). VEX-Eingaben stammen aus Dokumenten, die Sie mit `--vex`
bereitstellen.

## Unterstützte Distributionen

Wie ein Ziel identifiziert wird und was die Daten zeigen können und was nicht:

- **Fedora.** Der Host wird über `rpm` gelesen. Daten: `updateinfo`. Eine CVE ohne veröffentlichte Korrektur ist nicht sichtbar.
- **Arch Linux.** Der Host wird über `pacman` gelesen. Daten: der Arch Security Tracker, der auch verwundbare Pakete ohne Korrektur aufführt.
- **Red Hat Enterprise Linux 8, 9 und 10.** Der Host wird über `rpm` gelesen; UBI-Container funktionieren. Daten: das Red-Hat-Ökosystem von OSV, plus die unbehobenen CVEs der OVAL-Datei von Red Hat unter RHEL 8 und 9 (siehe unten); RHEL 10 bleibt eine untere Schranke.
- **Rocky Linux und AlmaLinux 8 und 9.** Der Host wird über `rpm` gelesen. Daten: OSV; sichtbar sind nur CVEs, für die eine Korrektur ausgeliefert wurde.
- **Debian und Ubuntu (LTS).** Der Host wird aus `/var/lib/dpkg` gelesen (es wird nichts ausgeführt); Container, `--packages-from`-Listen, SBOMs und `name@version` funktionieren ebenfalls. Daten: OSV, das auch offene Probleme aufführt (gemeldet als betroffen ohne Korrekturversion).
- **openSUSE Leap 15.x und 16.0 sowie Tumbleweed.** Der Host wird über
  `rpm` gelesen, und Container funktionieren. Daten: OSV, geschlüsselt nach dem
  *Quell*paket (die Bibliothek `libopenssl3` wird aus `openssl-3` gebaut):
  amivuln liest den Quellnamen aus der rpm-Datenbank, aber eine Paketliste
  oder SBOM muss ihn mitbringen (siehe die Seite [amivuln verwenden](using.md)).
  Nur die Sicherheitsupdates (`SUSE-SU`, `openSUSE-SU`) zählen, und sichtbar
  sind nur CVEs, für die eine Korrektur ausgeliefert wurde. SUSE Linux
  Enterprise hat eigene Daten und wird noch nicht gelesen.
- **Gentoo.** Der Host wird aus `/var/db/pkg` gelesen (es wird nichts
  ausgeführt), und Container funktionieren. Daten: die GLSAs im eigenen
  Portage-Tree des Hosts (`/var/db/repos/gentoo/metadata/glsa`), offline
  gelesen; es wird nichts heruntergeladen. Advisories werden pro Slot
  beurteilt, und ein Bereich mit einem `slot` gilt nur für ein Paket in
  diesem Slot. Es existieren nur Advisories, die eine Korrektur ausgeliefert
  haben, daher ist eine CVE ohne Korrektur nicht sichtbar. Das Alter der
  Quelle ist der Zeitpunkt der letzten Synchronisierung des Trees; ein
  fehlender, nicht lesbarer oder leerer Tree macht das Ergebnis
  unvollständig. Für einen Container oder eine andere Maschine zeigen Sie mit
  `[sources.distro] path` auf ein Verzeichnis mit den `glsa-*.xml`-Dateien.
  Das Attribut `arch` eines Advisorys wird nicht gelesen.
- **Alpine 3.x.** Der Host wird aus `/lib/apk/db/installed` gelesen; dieselben weiteren Eingaben wie bei Debian und Ubuntu. Edge- und Alpha-Images haben keine Advisory-Daten und werden abgelehnt. Daten: OSV, geschlüsselt nach dem Origin-Paket; sichtbar sind nur CVEs, für die eine Korrektur ausgeliefert wurde.
- **Red-Hat-CVE-Daten (optional, standardmäßig aus).** Der `mitigation`-Text,
  den Red Hat pro CVE veröffentlicht, verwendet von `--mitigations`. Was das
  sendet und was es nicht behauptet, steht im Benutzerhandbuch.
- **Flatpak-Runtimes.** Gelesen aus der `manifest.json` jeder Runtime,
  beurteilt durch die NVD für die Upstream-Version jeder Komponente, wobei die
  eigenen Listen `patches` und `ignored` des Builders angewandt werden.
  Langsam und ratenbegrenzt; siehe das Benutzerhandbuch.
- **Go-Module und Rust-Crates**, die in Binaries gefunden werden, über OSV.

## Geplant

Die Fedora-Bodhi-API als Gegenprüfung, NVD per CPE als Fallback und
endoflife.date. Das CSAF-VEX-Archiv von Red Hat (412 MB) wurde erwogen und
nicht gewählt: Die OVAL-Datei liefert die unbehobenen CVEs in 11 MB
(ADR-0014).

## Arch im Detail

Der Tracker markiert eine Gruppe als *Vulnerable* ohne behobene Version für
den Build, der aktuell war, als der Eintrag geschrieben wurde, und manche
Einträge bleiben jahrelang so. amivuln meldet ein installiertes Paket nur dann
als betroffen, wenn es dieselbe Upstream-Version wie der verzeichnete Build
hat (ein Rebuild davon ist weiterhin betroffen). Eine neuere Upstream-Version
wird als *nicht verifiziert* gemeldet, weil der Eintrag nicht sagen kann, ob
er noch zutrifft. Eine Installation, die älter als der verzeichnete Build ist,
liegt außerhalb des Eintrags und wird nicht gemeldet.
