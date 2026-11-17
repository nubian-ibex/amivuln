# Política de soporte

## Versiones

Antes de la 1.0 solo la última versión recibe correcciones, de seguridad o de
otro tipo. Desde la 1.0 la última versión menor recibe correcciones de
seguridad, y una corrección de seguridad se porta a la versión menor anterior
durante 90 días después de publicarse una nueva versión menor.

## Versión mínima compatible de Rust

La MSRV es el `rust-version` de `Cargo.toml` (hoy 1.97) y el trabajo de CI
`msrv` compila con ella en cada cambio. Solo se sube en una versión menor,
nunca en una versión de parche, y cada subida se nombra en el registro de
cambios.

## Qué es un contrato

El contrato es el comando `amivuln`. Los crates de biblioteca con los que se
construye (`amivuln-core`, `-resolve`, `-version`, `-sources`, `-cache`,
`-report`, `-sandbox`) se publican solo porque el binario depende de ellos.
Comparten su número de versión, incluida la 1.0, y **no** ofrecen ninguna
promesa de estabilidad de API, en la 1.0 ni después: una versión de parche puede
cambiar o eliminar sus elementos públicos. Dependa de ellos bajo su propia
responsabilidad, o ejecute el comando y lea su JSON.

- **Salida JSON.** Los documentos llevan `schema_version`. Dentro de una versión,
  los campos nunca se eliminan, renombran ni cambian de tipo; un campo nuevo o un
  valor nuevo de una enumeración es un cambio aditivo y se publica en una versión
  menor con una nota en el registro de cambios y en el [esquema](json-schema.md)
  publicado. Romper la forma significa un nuevo `schema_version`. Los documentos
  golden de `tests/golden` fijan la salida exacta, orden de campos incluido, y
  deben seguir validándose con el esquema vigente; un cambio en ellos es visible
  en la revisión.
- **Códigos de salida.** 0, 1, 2, 3, 64, 65 y 70 y su precedencia son estables.
- **Configuración.** Las claves no se eliminan ni se renombran dentro de una
  versión mayor; las claves nuevas tienen valores por defecto que mantienen el
  comportamiento actual.
- **Línea de comandos.** Los flags no se eliminan ni se reutilizan con otro fin
  dentro de una versión mayor. La salida de texto (`summary`, `detail`) es para
  personas y puede cambiar.

### Cómo se comprueba el contrato

Cada promesa tiene una prueba que falla cuando se rompe por accidente:

- cada valor que la herramienta puede escribir (cada ecosistema, fuente,
  procedencia, severidad, estado y la `mitigation` opcional) se valida con los
  esquemas publicados de `check`, `pending` y `cve`; las listas son `match`
  exhaustivos, de modo que un valor nuevo de una enumeración deja de compilar
  hasta que el esquema y la prueba lo conocen;
- los documentos JSON golden fijan la salida exacta de `check`;
- la configuración por defecto es un archivo golden, y cada clave opcional que
  nombra `config init` se vuelve a cargar (una clave renombrada o eliminada
  falla);
- los códigos de salida se comprueban por valor;
- la página de manual y los autocompletados del shell se generan a partir de la
  línea de comandos y se comparan en CI, de modo que un flag eliminado o
  renombrado aparece como una diferencia.

Añadir algo a un conjunto cerrado (un ecosistema nuevo, una fuente nueva) es un
cambio aditivo y se publica en una versión menor; el esquema y el registro de
cambios lo nombran.

## Plataformas

Linux en x86_64 y aarch64 (compilaciones estáticas `musl` y `glibc`). macOS y
Windows no son compatibles. Qué distribuciones se juzgan, y cómo, está en
[Fuentes de datos](sources.md#distribuciones-compatibles).
