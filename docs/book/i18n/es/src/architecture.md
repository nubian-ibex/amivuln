# Arquitectura

amivuln es un workspace de Cargo. El binario `amivuln` solo orquesta; las
reglas de dominio no realizan E/S.

## Flujo de procesamiento

1. **Destino.** Lo que pidió la persona usuaria: un nombre de paquete, una ruta
   de archivo, una unidad `.service`, `name@version` o un purl
   (`amivuln-resolve`).
2. **Identidad.** El paquete instalado, leído del gestor de paquetes
   (`rpm`, `pacman`) mediante un ejecutor de subprocesos con lista de permitidos
   y límites, de la base de datos de paquetes exportada de un contenedor (dpkg,
   apk o rpm), de una lista o un SBOM, o de los metadatos del propio archivo
   (nota de paquete, información de compilación de Go, `cargo-auditable`).
3. **Datos de la distribución.** Los datos de avisos de la propia distribución,
   obtenidos mediante un cliente HTTP con caché (`amivuln-sources`,
   `amivuln-cache`).
4. **Coincidencia.** Decide el estado de la distribución, nunca un rango de
   versiones upstream. `Fixed(v)` con una versión instalada igual o superior a
   `v` está corregido; una más antigua está afectada e indica la versión que la
   corrige (`amivuln-core`).
5. **Enriquecimiento.** CISA KEV y FIRST EPSS.
6. **Política.** `--fail-on`, `--fail-on-epss`, `--strict` y la precedencia de
   los códigos de salida 70, 64, 2, 3, 1, 0.
7. **Informe.** `summary`, `detail`, JSON, SARIF, Markdown, CSV y Prometheus (`amivuln-report`).

## Crates

- `amivuln`: línea de comandos, configuración y orquestación.
- `amivuln-core`: tipos de dominio, reglas de coincidencia, política, códigos
  de salida y los traits para el mundo exterior.
- `amivuln-resolve`: resolución de destinos y ejecutor de procesos del sistema.
- `amivuln-version`: comparación de versiones RPM, pacman, Debian, apk y
  semánticas, verificada con `rpm`, `vercmp`, `dpkg` y `apk version -t`.
- `amivuln-sandbox`: el sandbox Landlock y seccomp de la sonda de versión
  opcional, el único crate con código `unsafe`.
- `amivuln-sources`: analizadores del Arch Security Tracker, Fedora
  `updateinfo`, OSV, NVD, CISA KEV y FIRST EPSS, y el cliente HTTP con límites.
- `amivuln-cache`: caché HTTP en SQLite con revalidación por ETag y
  clasificación en fresca, obsoleta y caducada.
- `amivuln-report`: formateadores de salida.

Todos los crates se publican en crates.io porque el binario depende de ellos.
Los crates de biblioteca comparten la versión del binario y no ofrecen ninguna
promesa de estabilidad de API en la 1.0 ni después: el contrato es el comando
(vea la política de soporte).

## Invariantes

- El estado de la distribución prevalece sobre la comparación de versiones
  upstream.
- Un hallazgo sin declaración de la distribución es *unverified*, se lista
  aparte y nunca se cuenta como afectado.
- Una fuente obligatoria que falla hace que el resultado sea incompleto (código
  de salida 2). Los datos en caché obsoletos dentro de `stale_max_age` se usan y
  se informan como `stale`.
- Toda lectura de archivo, respuesta HTTP y salida de subproceso tiene un límite
  de tamaño, todo subproceso tiene un tiempo máximo y una ruta absoluta
  permitida, y no interviene ningún shell.
- El texto procedente de fuera del proceso se sanea antes de llegar a un
  terminal.
- No existe ningún campo que identifique al host en la salida ni en las
  solicitudes.
