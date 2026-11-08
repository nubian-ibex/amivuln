# Contributing

The full guide is `CONTRIBUTING.md` in the repository. In short:

```bash
git clone https://github.com/nubian-ibex/amivuln && cd amivuln
just ci        # fmt, clippy, tests, docs, assets, deny, audit, vet, typos, reuse, actionlint, zizmor
```

- Commits follow Conventional Commits and are signed off (`git commit -s`).
- Tests never touch the network: recorded fixtures and a mock server.
- Report a wrong result with the *false positive* or *false negative* issue
  form, including the output of `amivuln PACKAGE -f json`.
- AI-assisted contributions are welcome; disclose them with an `Assisted-by:`
  trailer. The human author is responsible for the change.

Architecture decisions are recorded as ADRs in `docs/adr/`.
