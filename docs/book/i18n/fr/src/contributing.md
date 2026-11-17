# Contribuer

Le guide complet est `CONTRIBUTING.md` dans le dépôt. En bref :

```bash
git clone https://github.com/nubian-ibex/amivuln && cd amivuln
just ci        # fmt, clippy, tests, docs, assets, deny, audit, vet, typos, reuse, actionlint, zizmor
```

- Les commits suivent Conventional Commits et sont signés (`git commit -s`).
- Les tests ne touchent jamais le réseau : fixtures enregistrées et serveur
  factice.
- Signalez un résultat erroné avec le formulaire de ticket *faux positif* ou
  *faux négatif*, en incluant la sortie de `amivuln PACKAGE -f json`.
- Les contributions assistées par IA sont bienvenues ; indiquez-les avec un
  trailer `Assisted-by:`. L'auteur humain est responsable du changement.

Les décisions d'architecture sont consignées sous forme d'ADR dans `docs/adr/`.
