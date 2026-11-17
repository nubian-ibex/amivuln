# Wie der Abgleich funktioniert

Jedes Urteil beantwortet eine Frage: Ist der Host betroffen, gegeben die
installierte Version eines Pakets und alles, was die befragten Quellen dazu
gesagt haben?

## Die Distribution entscheidet

Die eigenen Advisory-Daten der Distribution entscheiden. Upstream-Bereiche
werden nie verwendet, um ein Paket als betroffen einzustufen: Distributoren
liefern Korrekturen aus, ohne die Upstream-Version zu ändern, ein
Upstream-Bereich würde daher auf RPM-basierten und Debian-basierten Systemen
gleichermaßen Falsch-Positive melden.

## Rangfolge

Pro CVE und pro Paket werden die Aussagen zusammengeführt, die
restriktivste zuerst:

1. **not-affected** von der Distribution oder aus einer OpenVEX-Aussage
   (`--vex`), wobei die Begründung in jedes Ausgabeformat übernommen wird.
2. **patched**, wenn die installierte Version mindestens der veröffentlichten
   Korrektur entspricht.
3. **affected** in allen anderen Fällen; der Fund nennt die Version, die den
   Fehler behebt.
4. **unverified**, wenn es einen Eintrag gibt, aber keine vergleichbare
   Version: Die Distribution sagt *will not fix* oder *fix deferred* (der
   Bericht führt ihn unter seiner eigenen ID auf), oder die behobene Version
   lässt sich nicht mit der installierten vergleichen (etwa eine rpm-Korrektur
   bei einer deb-Installation).

Alles, wozu eine Quelle nichts sagen konnte, wird gesondert als `unverified`
aufgeführt und nie stillschweigend als betroffen gezählt. Die Anreicherung
(KEV, EPSS) ändert nie ein Urteil.

## Pro Quelle

- **Fedora.** `updateinfo` veröffentlicht die Version, die die CVE behoben hat.
  Eine installierte Version ab einer beliebigen veröffentlichten Korrektur
  gilt als gepatcht. Eine CVE ohne veröffentlichte Korrektur ist in diesen
  Daten nicht sichtbar.
- **Arch.** Der Tracker verzeichnet einen Build; dieselbe Upstream-Version ist
  verwundbar, ein Rebuild davon ebenfalls, eine neuere gilt als
  *nicht verifiziert*.
- **Debian, Ubuntu, Alpine, openSUSE, Red Hat, Rocky, `AlmaLinux`, Go-Module
  und Rust-Crates.** OSV serialisiert Advisories pro Ökosystem; die
  behobenen Versionen, die das Paket nennen, entscheiden. Wenn mehrere
  Advisories eine CVE beheben (Red Hat gibt pro Minor-Stream eines aus), gilt
  eine installierte Version ab einer beliebigen davon als gepatcht. Ein
  Eintrag, den OSV der installierten Version zugeordnet hat, der aber gar
  keine Korrektur nennt, ist ein offenes Problem: betroffen, ohne Version, auf
  die man wechseln könnte (Debian und Ubuntu haben solche Einträge; Alpine und
  Red Hat führen nur Advisories auf, die eine Korrektur ausgeliefert haben;
  openSUSE ebenso). Alpine, Debian, Ubuntu und openSUSE werden nach
  Quellpaket befragt. Bei Sprachpaketen antwortet OSV pro exakter Version,
  daher betrifft jedes zurückgegebene Advisory die abgefragte Version, und die
  gemeldete Korrektur ist die niedrigste darüber. Ein Sprach-Advisory ohne
  CVE-Alias wird unter seiner eigenen ID gemeldet (GHSA, GO, RUSTSEC), statt
  zu verschwinden.
- **Baseline.** `--baseline prev.json` behält nur Funde, die seit diesem
  Bericht neu sind; es macht nie aus einem Betroffen-Urteil ein sauberes.
- **Ignore-Datei.** Ein akzeptierter Fund wird unterdrückt, wobei Grund,
  Verantwortlicher und Ablaufdatum in der Ausgabe erscheinen; ein
  abgelaufener Eintrag ist ein Fehler.

## Determinismus

Die Regeln sind reine Funktionen in `amivuln_core` (`matching::merge`): Zwei
Läufe auf denselben Daten stimmen überein, und das Ground-Truth-Korpus
(Fedora- und Arch-Fälle mit aufgezeichneten HTTP-Fixtures) legt sie gegen
aufgezeichnete Daten fest.
