# Mitwirken

Die vollständige Anleitung ist `CONTRIBUTING.md` im Repository. Kurz gefasst:

```bash
git clone https://github.com/nubian-ibex/amivuln && cd amivuln
just ci        # fmt, clippy, tests, docs, assets, deny, audit, vet, typos, reuse, actionlint, zizmor
```

- Commits folgen Conventional Commits und sind signiert (`git commit -s`).
- Tests berühren nie das Netzwerk: aufgezeichnete Fixtures und ein Mock-Server.
- Melden Sie ein falsches Ergebnis mit dem Formular *false positive* oder
  *false negative*, einschließlich der Ausgabe von `amivuln PACKAGE -f json`.
- KI-gestützte Beiträge sind willkommen; weisen Sie mit einem
  `Assisted-by:`-Trailer darauf hin. Die menschliche Autorin oder der
  menschliche Autor ist für die Änderung verantwortlich.

Architekturentscheidungen werden als ADRs in `docs/adr/` festgehalten.
