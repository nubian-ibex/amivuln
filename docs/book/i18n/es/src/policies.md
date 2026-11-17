# Políticas de seguridad

## Política de dependencias (SCA)

`cargo deny`, `cargo audit` y `cargo vet` se ejecutan en cada pull request y en
la canalización de publicación (`just ci`). El umbral es cero hallazgos sin
declarar: un hallazgo de aviso, licencia o procedencia bloquea el cambio salvo
que se declare con un motivo en `deny.toml` (avisos, licencias) o en
`supply-chain/config.toml` (exenciones de vet). Las exenciones declaradas se
vuelven a revisar en cada versión.

Un aviso de dependencia que no afecta a amivuln se registra en `deny.toml` con
el id del aviso y el motivo por el que aquí no es explotable; ese registro es la
declaración VEX de referencia del proyecto. Ninguna versión se publica con un
hallazgo SCA sin declarar: las comprobaciones fallan de forma cerrada.

## Política de análisis estático (SAST)

El umbral es cero hallazgos. `cargo clippy --workspace --all-targets
--all-features -- -D warnings` y `cargo fmt --check` bloquean todo cambio en
`just ci`. Una supresión necesita un `#[allow]` en línea cuyo comentario diga
por qué el hallazgo no se aplica; el conjunto de lints nunca se rebaja para que
el código pase.

## Política de secretos

- Ninguna credencial pertenece al repositorio ni al gestor de incidencias.
- Las credenciales de CI (la clave minisign de publicación, `MINISIGN_SECRET_KEY`
  y `MINISIGN_PASSWORD`, y los tokens de cosign y crates.io) son secretos de
  GitHub Actions acotados a los workflows y al entorno `release` que los
  necesitan, y nunca se muestran en los registros.
- Los secretos se rotan cuando cambia un workflow, una máquina o una persona con
  acceso, e inmediatamente ante la sospecha de una fuga; tras una fuga se
  revisan los registros de auditoría por si se usó el valor expuesto.
- El desarrollo local no necesita credenciales: las pruebas no usan la red.

## Política de acceso y revisión

Solo la cuenta del mantenedor tiene acceso de escritura, derechos sobre las
etiquetas y la aprobación del entorno de publicación. Una nueva persona
colaboradora se revisa antes de concederle cualquier permiso elevado: historial
de contribuciones al proyecto, prácticas de seguridad (commits firmados,
disciplina con las dependencias) e identidad pública. Los rulesets de `main` y
de las etiquetas `v*` exigen commits firmados y bloquean los force-push y los
borrados, con independencia de quién tenga el permiso.

## Política de pruebas

Todo cambio importante añade o actualiza pruebas en la suite automatizada; una
corrección de un error añade la prueba de regresión antes de la corrección. Las
pruebas no deben tocar la red: el comportamiento HTTP se cubre con fixtures
grabadas y `wiremock`. Ejecute `just ci` antes de abrir un pull request; CI
ejecuta la suite completa en cada pull request y la fusión queda bloqueada
mientras falle.
