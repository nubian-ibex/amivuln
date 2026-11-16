# Guía del usuario

## Revisar paquetes

```bash
amivuln nginx                 # paquete instalado por nombre
amivuln /usr/sbin/nginx       # el paquete al que pertenece este archivo
amivuln openssl@3.5.1-1       # una versión concreta, sin leer el host
amivuln pkg:rpm/fedora/nginx@1.26.2-1.fc44?arch=x86_64   # un package URL
amivuln --all                 # todos los paquetes instalados
```

`--file PATH`, `--package NAME[@VERSION]` y `--purl PURL` son formas explícitas
de los mismos destinos y se pueden repetir. Cuando un nombre es ambiguo (por
ejemplo, varias versiones del kernel instaladas), amivuln falla con el código de
salida 3 y le indica qué selector usar. Nunca adivina.

## Leer el resultado

El resumen imprime, por paquete, el número de hallazgos afectados por
severidad, cuántos están en el catálogo CISA KEV, la mayor puntuación EPSS y la
versión corregida con el comando que ejecutaría para aplicarla. amivuln nunca
ejecuta ese comando.

Los hallazgos que la distribución no pudo confirmar se listan aparte como
*unverified* y no se cuentan con los afectados. `--strict` hace que cuenten para
`--fail-on`.

Las últimas líneas listan cada fuente consultada, su estado
(`ok`, `stale`, `failed`, `skipped`), su antigüedad y si el resultado está
completo. Una fuente obligatoria que falló hace que el resultado sea
**incompleto**: la salida lo dice de forma destacada y el código de salida es 2,
de modo que una caída nunca puede parecer un análisis limpio.

## Uso en CI

```bash
amivuln --all --fail-on high           # falla el trabajo con HIGH o peor
amivuln --all --fail-on kev            # falla solo con CVE explotadas activamente
amivuln --all --fail-on-epss 0.5       # falla con alta probabilidad de explotación
amivuln --all -f json > amivuln.json   # conserva un registro legible por máquina
```

Para revisar una versión de otra distribución, por ejemplo un paquete de Fedora
en un runner basado en Debian, pase `--distro fedora:44` o `--distro arch`
junto con `name@version`. Solo el ecosistema, el nombre del paquete y la versión
se envían por la red.

## Sin conexión y caché

Las respuestas se guardan en caché en `$XDG_CACHE_HOME/amivuln/cache.sqlite`
(por defecto `~/.cache/amivuln`). Una respuesta más reciente que `cache_ttl`
(6 h) se usa sin consultar la red; cuando la red falla, se usa una de hasta
`stale_max_age` (72 h) de antigüedad y se informa como `stale`. `--offline`
nunca toca la red y falla de forma cerrada (código 2) cuando la caché no tiene
nada utilizable. `amivuln cache info` y `amivuln cache clear` gestionan la
caché; `--no-cache` omite la caché en disco.

## Configuración

`amivuln config init` escribe un archivo por defecto comentado;
`amivuln config show` imprime la configuración efectiva y
`amivuln config validate` la comprueba. Las claves desconocidas se rechazan
para que los errores tipográficos no pasen en silencio.

## Idioma

El texto que lee una persona (la salida summary y detail, `pending`, `cve`,
`restart`, y los errores y avisos habituales) sigue la configuración regional:
la primera de `LC_ALL`, `LC_MESSAGES` y `LANG` que esté definida, como en
cualquier herramienta de línea de comandos. Existen inglés y portugués de
Brasil (`pt`); cualquier otra, incluida `C`, es inglés. Para una sola
ejecución: `LC_ALL=pt_BR.UTF-8 amivuln --all`.

La salida JSON, SARIF, CSV, Markdown, Prometheus, CycloneDX y OpenVEX sigue en
inglés sea cual sea la configuración regional, porque la leen otros programas,
y lo mismo ocurre con el texto de `--help`, los errores de configuración y los
mensajes de las bibliotecas con las que se construye la herramienta. Los
nombres de severidad, `KEV` y `EPSS` no se traducen. La traducción la escribió
el asistente del proyecto y no la ha revisado un hablante nativo; una
corrección es un pull request sobre un solo archivo de texto (vea
CONTRIBUTING).

## El kernel en ejecución

En la mayoría de los hosts hay varios kernels instalados en paralelo y uno en
ejecución, así que `amivuln kernel-core` falla por ambigüedad.
`amivuln --kernel` revisa el paquete al que pertenece la imagen del kernel que
está en ejecución (la versión en `/proc/sys/kernel/osrelease`), sea cual sea el
resto de lo instalado:

```text
$ amivuln --kernel
kernel-core 7.2.15-200.fc44 (Fedora 44)  <- --kernel 7.2.15-200.fc44.x86_64
  CRITICAL 0   HIGH 0   MEDIUM 1   LOW 0   KEV 0
  Fixed in: 7.3.3-200.fc44  (dnf upgrade kernel-core)
```

Se juzga con los datos de la distribución como cualquier paquete: una versión
upstream nunca se compara con los registros de CVE propios del kernel, porque
el kernel de una distribución incluye correcciones que el número de versión no
muestra. `--all` sigue juzgando cada kernel instalado. amivuln no conoce los
parches en vivo (kpatch, livepatch): informa de lo que dice la versión del
paquete. Vea ADR-0015.

## Explicar un hallazgo

`amivuln --explain -f detail` añade, bajo cada hallazgo, las frases que dicen
por qué se informa:

```text
CVE-2026-111253  UNKNOWN  fix: 5.4.7.0-1.fc44  EPSS 0.00
      why: dnf5 5.4.6.0-1.fc44 is older than 5.4.7.0-1.fc44, the build that fixes this CVE in the distribution's data. Installing 5.4.7.0-1.fc44 or later closes it.
      why: FIRST EPSS puts the chance it is exploited in the next 30 days at 0%, above 3% of scored CVEs.
```

Está desactivado por defecto, se aplica solo a la salida detail (los formatos
de máquina son idénticos con y sin él) y sigue el idioma de la configuración
regional.

Ningún modelo de lenguaje lo escribe. Cada frase es una plantilla rellenada con
un campo que la ejecución ya tiene (la versión instalada, la versión corregida,
el estado que dieron los datos de la distribución, cómo se identificó el
paquete, CISA KEV, EPSS, una mitigación del proveedor), de modo que el mismo
hallazgo da siempre el mismo texto y cada frase se puede rastrear hasta su
origen. No se envía nada a ninguna parte. Lo que no hace: no razona sobre si el
código vulnerable es alcanzable en este host y no resume la CVE (la descripción
no se almacena). Una coincidencia de banner de versión y un paquete incrustado
en un archivo lo dicen, porque son evidencia más débil.

## Mitigaciones

`amivuln --mitigations` muestra además, para cada CVE que todavía afecta al
host, lo que Red Hat dice que se puede hacer mientras la corrección no está
instalada: desactivar un módulo, cambiar un ajuste, ejecutar un script. Es el
texto propio de Red Hat, leído de sus datos públicos de seguridad
(`access.redhat.com/hydra/rest/securitydata/cve/<id>.json`), y se muestra como
tal:

```text
CVE-2024-6387  HIGH  fix: 1:9.6p1-3.fc40.3
      mitigation (Red Hat, not checked on this host): ... set LoginGraceTime to 0 ...
```

Está **desactivado por defecto** porque envía el id de cada CVE abierta a
`access.redhat.com`; `--mitigations` lo activa para una ejecución, y
`[sources.mitigations] enabled = true` para todas. Nombrar solo `url` en esa
tabla no lo activa. Las respuestas se conservan una semana.

- El texto está escrito para los productos propios de Red Hat. amivuln no
  comprueba que se aplique a este host ni que el ajuste esté en vigor, y la
  línea lo dice.
- Red Hat rellena el campo en la mayoría de las CVE para decir que no hay nada
  que hacer ("Mitigation for this issue is either not available or ...
  criteria"). Eso es la ausencia de una mitigación y se omite: en un
  contenedor Debian, 30 de 94 CVE tenían una real.
- Aparece como el objeto `mitigation` de un hallazgo en el JSON (solo cuando
  existe), como `workaround` en el documento CycloneDX y en la salida detail.
- Una consulta que falla se nombra en la fuente `redhat-cve` (y con
  `required = true` el resultado es incompleto); nunca se interpreta como
  "no existe mitigación". Se consultan como máximo 400 CVE por ejecución.

## Runtimes Flatpak

`amivuln --flatpak` revisa también los componentes de los runtimes Flatpak
instalados (la instalación del sistema y la del usuario; se respetan
`FLATPAK_SYSTEM_DIR` y `FLATPAK_USER_DIR`). No se ejecuta nada: se lee el
`manifest.json` de cada runtime. Los runtimes construidos sobre freedesktop-sdk
(Platform, Sdk, GNOME, KDE) listan cada componente con su versión upstream y un
bloque `x-cpe` con el nombre de producto en la NVD, las CVE que la compilación
ya parcheó (`patches`) y las que sus mantenedores decidieron que no se aplican
(`ignored`).

Para estos componentes no hay estado de corrección de la distribución, así que
las CVE vienen de la NVD, consultada por la versión upstream de cada
componente, y las declaraciones del constructor deciden el resto como lo hacen
los datos de una distribución: una CVE parcheada está resuelta y una ignorada es
"not affected"; ninguna es un hallazgo. Lo que queda no nombra ninguna versión
corregida, porque la corrección es un runtime más nuevo (`flatpak update`).
Un componente se nombra `runtime/branch/component`.

Conviene saber lo que esto no le dice:

- Una CVE que la compilación parcheó pero no listó en `patches` aparece como
  abierta. La zlib del runtime 25.08 está listada para CVE-2026-22184, que está
  en una herramienta (`untgz`) que el runtime no compila, y el manifiesto no lo
  dice.
- La NVD es lenta y limita la tasa: 5 solicitudes cada 30 segundos sin clave de
  API y 50 con una. Una instalación tiene cientos de componentes distintos, así
  que una primera ejecución tarda una hora o más sin clave y varios minutos con
  una (`[sources.nvd] api_key_file`). Las respuestas se conservan un día y se
  usan durante una semana cuando no se puede alcanzar la NVD, así que las
  ejecuciones posteriores son rápidas.
- Un componente para el que la NVD no pudo responder (una solicitud fallida, un
  límite de tasa, una lista cortada) se nombra en el detalle de la fuente, la
  fuente queda como `failed` y, con `required = true`, el resultado es
  incompleto (código 2). Nunca se interpreta como "sin CVE".
- Los runtimes sin `manifest.json` (extensiones de locales, controladores GL y
  códecs) se cuentan en una sola entrada `unresolved`. Las aplicaciones en sí no
  se leen: incluyen sus propias bibliotecas y no llevan tal manifiesto.

## SBOM y VEX

`amivuln --all -f cyclonedx` escribe un documento CycloneDX 1.6: cada paquete
instalado es un componente, con su purl y cómo se identificó
(`amivuln:provenance`), y cada hallazgo es una vulnerabilidad con su análisis.
`amivuln --all -f openvex` escribe un documento OpenVEX 0.2.0 con una
declaración por paquete y CVE. Ambos son para `check`; `pending`, `cve` y
`restart` los rechazan.

El estado procede de los datos de la propia distribución:

- afectado, con la versión que lo corrige cuando hay una publicada:
  `exploitable` en CycloneDX, `affected` en OpenVEX;
- corregido en la versión instalada o antes, lo que incluye correcciones que una
  distribución portó (backport): `resolved` y `fixed`;
- declarado no afectado, por la distribución o por un archivo VEX que usted pasó
  con `--vex`: `not_affected` en ambos, con el motivo;
- no verificable (sin declaración de la distribución, o con versiones que no se
  pueden comparar): `in_triage` y `under_investigation`.

Cuáles aparecen depende de lo que liste la fuente. El `updateinfo` de Fedora y
el Arch Security Tracker listan lo que corrigieron, así que allí aparecen las
CVE corregidas. A OSV se le pregunta por la versión instalada, de modo que en
hosts Debian, Ubuntu, Alpine y Red Hat los documentos listan los problemas
abiertos, no los ya cerrados.

Las declaraciones son la evaluación de esta herramienta sobre este host, no una
certificación de la distribución. Una ejecución incompleta se marca como
`amivuln:complete = false` en los metadatos de CycloneDX, y un paquete que
amivuln no pudo resolver se cuenta en `amivuln:unresolved`; el código de salida
es 2 como de costumbre. La salida es determinista: los componentes y las
declaraciones se ordenan por purl y no se añade nada aleatorio (ni número de
serie). Las pruebas validan ambos documentos contra los esquemas oficiales.

## Prometheus y el textfile collector de node_exporter

`amivuln --all -f prometheus` escribe métricas de texto: `amivuln_findings{severity,kev}`,
`amivuln_unverified_findings`, `amivuln_source_up{source}`,
`amivuln_source_age_seconds{source}`, `amivuln_run_complete` y
`amivuln_last_run_timestamp_seconds`. Las etiquetas salen de vocabularios fijos,
así que ningún nombre de paquete, nombre de host o ruta llega al almacén de
métricas. Escriba la salida en un archivo `.prom` del directorio textfile
mediante un archivo temporal y un renombrado, para que el collector nunca lea un
archivo parcial.

## Ejecutar con un temporizador

`contrib/systemd/amivuln.service` y `amivuln.timer` analizan el host cada seis
horas y escriben `amivuln.prom` para el textfile collector, mediante `--output`
para que el archivo se reemplace de forma atómica. El servicio se ejecuta como
usuario dinámico, sin capacidades, con sistema de archivos de solo lectura y un
filtro de llamadas al sistema; `systemd-analyze security amivuln.service`
informa de una exposición de 1.2.

```bash
sudo install -m 0644 contrib/systemd/amivuln.{service,timer} /etc/systemd/system/
sudo systemctl enable --now amivuln.timer
```

Ajuste `ExecStart` y `ReadWritePaths` cuando el directorio textfile sea
distinto. Los códigos de salida 1 (política), 2 (incompleto) y 3 (no resuelto)
siguen escribiendo un archivo válido, así que la unidad solo falla ante un error
de uso o interno.

## Detrás de un proxy o de una CA corporativa

Defina la tabla `[network]` en el archivo de configuración:

```toml
[network]
proxy = "http://proxy.corp.example:3128"   # default: HTTPS_PROXY and NO_PROXY
ca_file = "/etc/pki/ca-trust/source/anchors/corp.pem"
user_agent_suffix = "team-sre"
```

`ca_file` añade raíces de confianza a las incorporadas (PEM, como máximo
1 MiB). `user_agent_suffix` se añade al `User-Agent` y es el único texto
específico del host que puede salir de la máquina, solo cuando usted lo define.
La URL de un proxy puede llevar credenciales; amivuln nunca la imprime. Para
usar en su lugar un espejo interno, defina `sources.<name>.url`.

## Para agentes de IA: el servidor MCP

`amivuln mcp` habla el Model Context Protocol por stdio (JSON-RPC 2.0 delimitado
por saltos de línea, revisiones del protocolo 2025-06-18, 2025-03-26 y
2024-11-05). Regístrelo en un cliente como:

```json
{ "mcpServers": { "amivuln": { "command": "amivuln", "args": ["mcp"] } } }
```

Las herramientas son de solo lectura y cada una ejecuta una línea de comandos
fija con `-f json`; el resultado es el mismo informe versionado que imprime la
línea de comandos.

- `check_target`: `targets` (de 1 a 20 nombres de paquete, `name@version` o URL `pkg:`) y un `distro` opcional.
- `check_cve`: `id` como `CVE-2024-6387`; analiza todos los paquetes instalados.
- `pending_updates`, `needs_restart` y `list_services`: sin argumentos.

No hay shell, ni entrada de rutas de archivo, ni forma de pasar opciones: se
rechaza un destino que empiece por `-` o contenga caracteres de control. El
servidor actualiza la caché local como cualquier otra ejecución; pase
`--offline` o `--no-cache` a `amivuln mcp` para restringirlo. Lea siempre
`complete` y `sources` en un resultado antes de tratar una lista vacía como
limpia.

## Revisar un SBOM

`amivuln --sbom bom.cdx.json --distro fedora:44 --fail-on high` lee un
documento CycloneDX JSON (cualquier 1.x), revisa cada componente cuyo purl es
un paquete `rpm`, `deb` o `alpm` y deja el host en paz. Un purl cuyo namespace
discrepa de `--distro` es un error. Los componentes que no son paquetes del
sistema operativo (npm, PyPI, Maven, etc.) no se descartan en silencio:
aparecen como entradas `unresolved`, una por tipo de purl con un recuento, y la
ejecución sale con 3. Para restringir solo a los paquetes del sistema operativo,
filtre antes el SBOM, por ejemplo con
`jq '.components |= map(select(.purl // "" | startswith("pkg:rpm/")))'`.

## Redes resilientes

Las fuentes pueden tener espejos. A una fuente que falla en su endpoint
principal se le vuelve a preguntar en cada espejo de `fallback`, en el orden
escrito, antes de contarla como fallida. Cada llamada fallida se reintenta con
retroceso exponencial y jitter (`retries`, por defecto 2, como máximo 10); un
`Retry-After` que envíe el servidor se respeta dentro del presupuesto de
reintentos. Un endpoint que falla repetidamente activa un cortacircuitos por
endpoint y se omite durante el resto de la ejecución (`cooldown`, 30 s por
defecto), de modo que un espejo caído no detiene el análisis. Un host lento
puede ralentizarse a propósito con `min_interval`, que espacia las solicitudes
al mismo host (por ejemplo `"100ms"`).

El orden de respaldo es: endpoint principal, luego los espejos, luego la caché,
luego la base de datos sin conexión instalada (vea la sección de la base de
datos sin conexión) y, por último, el fallo. `sources` en toda salida dice cuál
de ellos respondió, su antigüedad y si el resultado está completo.

## Notificaciones por webhook

Una sección `[notify]` envía un resumen compacto después de una ejecución de
`check`: datos del host, completitud, puntuación, totales, ids de hallazgos. Es
opcional y no lleva nada más allá de lo que el informe JSON ya declara.

```toml
[notify]
webhook = "https://ntfy.sh/example-topic"   # any endpoint that accepts a POST
bearer_file = "/etc/amivuln/notify-token"   # optional; sent as Authorization: Bearer
on = "violation"                            # violation (default) | incomplete | always
```

Una entrega fallida imprime un aviso y nunca cambia el código de salida: la
decisión de política se tomó a partir del análisis, no de la notificación.

## La base de datos sin conexión

`amivuln db` traslada datos de avisos entre hosts que pueden llegar a la red y
hosts que no. El archivo es un `tar.zst` que contiene la caché SQLite y un
manifiesto con un SHA-256 de la base de datos; `--key` y `--sig` añaden una
firma minisign sobre el manifiesto.

```bash
amivuln --all -f json            # warm the cache (needs the network once)
amivuln db build --archive db.tar.zst
amivuln db verify db.tar.zst --key amivuln.pub --sig db.tar.zst.minisig
amivuln db pull db.tar.zst       # verify and install for this user
amivuln db info db.tar.zst
```

`db pull` instala bajo `$XDG_DATA_HOME/amivuln/offline` y rechaza un archivo más
antiguo que el instalado (anti-retroceso); `--force` lo anula. Una vez
instalada, una ejecución con `--offline` responde desde ella e informa de esas
fuentes como `stale`, de modo que un host aislado de la red produce los mismos
formatos de informe con códigos de salida que siguen respetando `--fail-on`.
`amivuln db verify` sale con 65 cuando un archivo ha sido manipulado; un
`db pull` regresivo también sale con 65.

La firma deliberadamente no está incorporada: genere la clave del proyecto con
la herramienta `minisign` y firme fuera de amivuln
(`minisign -S -s key.sec -m manifest.json -x db.tar.zst.minisig`), para que la
clave secreta nunca pase por este binario.

## Archivos que ningún paquete posee

Un destino de ruta que el gestor de paquetes no conoce (un binario copiado a un
contenedor, software vendorizado) se identifica por su propio `.note.package`
de systemd cuando lo tiene. El paquete, la versión y el sistema de empaquetado
proceden del archivo, y el informe marca el paquete con la procedencia
`embedded_note`. Una nota de un sistema de empaquetado distinto del del host
(una nota `deb` en un host RPM) se rechaza como no resuelta en lugar de
adivinarse, y el archivo nunca se ejecuta.

## Programas Go y Rust que nada posee

Cuando un destino de ruta no pertenece a ningún paquete y no tiene nota de
paquete, amivuln lee los módulos de Go (información de compilación) o los
crates de Rust (datos de cargo-auditable) que el programa declara y pregunta a
OSV por cada versión exacta. Los hallazgos muestran la versión corregida más
baja por encima de la instalada, y `update_hint` dice que el programa debe
recompilarse, porque ningún gestor de paquetes puede actualizar una dependencia
enlazada estáticamente. Los archivos que posee un paquete deliberadamente no se
expanden así: una distribución porta correcciones al código vendorizado sin
cambiar las versiones, de modo que las versiones de módulo de un binario
poseído producirían falsos positivos.

El endpoint de OSV para esta pasada es `[sources.osv]` (obligatorio por
defecto: una pasada fallida deja esos módulos sin juzgar, lo cual no debe
parecer limpio). La severidad textual procede del aviso cuando la declara (los
avisos de GitHub lo hacen; las entradas RUSTSEC no, e informan `unknown`).

## La clave minisign del proyecto

`contrib/offline-db/amivuln.pub` es la clave pública minisign del proyecto.
También es lo que usa el flujo de trabajo nocturno para verificar la base de
datos antes de publicarla en la versión. La clave privada del proyecto vive solo
en los secretos del repositorio (`MINISIGN_SECRET_KEY` más `MINISIGN_PASSWORD`)
y nunca en la máquina de un desarrollador, de modo que un espejo comprometido no
puede fingir frescura ni reproducir una base de datos antigua sorteando la marca
de tiempo anti-retroceso.

## Analizar un contenedor

`amivuln --container ID` revisa los paquetes instalados dentro de un
contenedor. El runtime (podman y, si no, docker) se invoca solo para exportar el
rootfs, lo que nunca ejecuta nada dentro del contenedor. El `os-release` del
propio contenedor decide el ecosistema, así que la distribución del host nunca
se filtra en la respuesta, y los paquetes se juzgan con la fuente
correspondiente (OSV para Debian, Ubuntu, Rocky, `AlmaLinux`, Red Hat
Enterprise Linux (UBI incluido); la base de datos rpm a través del `rpm` del
host para los contenedores de la familia Fedora). Los hallazgos se etiquetan con
el id del contenedor, por ejemplo `web:nginx`.

```bash
amivuln --container web --container db --fail-on high
```

Los contenedores Alpine se juzgan con OSV (`Alpine:v3.20` para la versión 3.20).
La base de datos instalada nombra el origen de cada subpaquete, y OSV indexa
los avisos de Alpine por origen, así que a `libcrypto3` se le pregunta como
`openssl`. Las imágenes edge y alpha no tienen versión en OSV y se rechazan. Las
versiones siguen el orden de `apk` (`1.0_rc1` antes de `1.0`, `-r1` después de
`-r0`).

## Banners de versión en binarios

Cuando nada más identifica un binario (sin propietario de paquete, sin nota de
paquete, sin metadatos de Go o Rust), amivuln busca los banners de versión que
imprime un conjunto seleccionado de productos en C: OpenSSL, curl, zlib, SQLite,
nginx y otros. Una coincidencia se convierte en un destino con la versión
upstream tal como se imprime, marcado como `string_heuristic` en todos los
formatos.

Esta es una señal de **baja confianza**: la distribución pudo portar
correcciones sin cambiar el banner incrustado. El veredicto es real, pero el
usuario debe verificarlo contra el registro de cambios de la distribución.

### La sonda de versión en sandbox

Con `exec_version_probe = true` en `[general]`, amivuln también ejecuta
`<file> --version` para los archivos que nada más identifica y lee los banners
de lo que imprime. Es el único lugar donde amivuln ejecuta un destino, así que
está desactivado por defecto y se ejecuta en un sandbox que se aplica antes de
`exec`:

- sin escrituras en el sistema de archivos (Landlock), y lecturas limitadas a
  los directorios de bibliotecas del sistema y al directorio del propio
  destino;
- sin sockets y sin acceso a otros procesos (seccomp);
- `no_new_privs`, un cambio a `nobody` cuando se inicia como root, 2 s de tiempo
  de CPU, sin crecimiento de archivos, sin volcados de memoria, 64 archivos
  abiertos;
- 2 s de tiempo real y 64 KiB de salida por flujo.

Cuando el kernel no puede aplicar el sandbox (sin Landlock, o una arquitectura
distinta de x86_64 y aarch64), la ejecución informa de un error para ese
archivo. Nunca ejecuta el destino sin confinar. El filtro seccomp es una lista
de denegación, no de permitidos: los destinos son binarios arbitrarios cuyas
llamadas al sistema de arranque no se pueden enumerar, y Landlock ya elimina el
lado del sistema de archivos.

## Respaldo NVD para productos sin propietario

Los destinos de la heurística de cadenas (productos sin datos de distribución)
también se comprueban contra la API NVD 2.0 por nombre CPE. La tabla de
correspondencia CPE está seleccionada a mano (`nginx` corresponde a
`f5:nginx`, `curl` a `haxx:curl`); un producto que la tabla no cubre se omite.
La fuente es opcional (`sources.nvd.required = false` por defecto), así que un
fallo no hace que el resultado sea incompleto. La clave de API opcional sube el
límite de tasa de 5 a 50 solicitudes cada 30 segundos.

```toml
[sources.nvd]
enabled = true
required = false
# api_key_file = "/etc/amivuln/nvd-api-key"
```

Los hallazgos de la NVD llevan la severidad CVSS de la versión de métrica más
reciente disponible, y el veredicto es `affected` sin versión de corrección: la
NVD es un catálogo de CVE, no una fuente de correcciones de distribución.
