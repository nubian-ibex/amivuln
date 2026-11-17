# Contribuir

La guía completa es `CONTRIBUTING.md` en el repositorio. En resumen:

```bash
git clone https://github.com/nubian-ibex/amivuln && cd amivuln
just ci        # fmt, clippy, tests, docs, assets, deny, audit, vet, typos, reuse, actionlint, zizmor
```

- Los commits siguen Conventional Commits y se firman (`git commit -s`).
- Las pruebas nunca tocan la red: fixtures grabadas y un servidor simulado.
- Informe de un resultado erróneo con el formulario de incidencia de *falso
  positivo* o *falso negativo*, incluyendo la salida de
  `amivuln PACKAGE -f json`.
- Las contribuciones asistidas por IA son bienvenidas; indíquelas con un
  trailer `Assisted-by:`. La persona autora es responsable del cambio.

Las decisiones de arquitectura se registran como ADR en `docs/adr/`.
