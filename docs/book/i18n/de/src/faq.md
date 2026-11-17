# FAQ zu Falsch-Positiven

**amivuln meldet eine CVE, die meine Distribution bereits behoben hat.** Der
Distributionsstatus hat Vorrang vor dem Versionsvergleich, das sollte also nicht
vorkommen. Öffnen Sie ein Issue vom Typ *false positive* mit der Ausgabe von
`amivuln PACKAGE -f json` und dem Link zum Advisory oder Changelog, der die
Behebung belegt.

**amivuln meldet nichts, aber ich kenne eine CVE.** Unter Fedora, Red Hat,
Rocky und AlmaLinux sieht amivuln nur Behebungen, die veröffentlicht wurden.
Eine CVE ohne Update ist noch nicht in den Daten, ein Ergebnis dort ist also
eine untere Schranke. Öffnen Sie ein Issue vom Typ *false negative*, wenn die
Daten den Eintrag doch enthalten.

**Das Ergebnis lautet INCOMPLETE.** Eine erforderliche Quelle war nicht
erreichbar, und es gab keine zwischengespeicherte Kopie innerhalb von
`stale_max_age`. Versuchen Sie es erneut, prüfen Sie das Netzwerk oder nutzen
Sie einen Mirror mit `sources.distro.url`. Der Exit-Code ist absichtlich 2.

**Warum ist ein Paket „unverified“?** Die Distribution hat keine Aussage dazu.
Es wird gesondert aufgeführt und lässt einen Build nicht fehlschlagen, es sei
denn, Sie übergeben `--strict`.

**Mein `updates`-Repository ist deaktiviert.** amivuln betrachtet die
veröffentlichten `updates`-Daten von Fedora unabhängig von Ihrer lokalen
Repository-Konfiguration, kann also ein Update melden, das Ihr System noch
nicht sieht.
