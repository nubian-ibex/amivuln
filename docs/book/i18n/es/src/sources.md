# Fuentes de datos

- **Arch Security Tracker**: estado de las CVE y versión corregida en Arch (`https://security.archlinux.org/issues/all.json`)
- **Fedora `updateinfo`**: actualizaciones de seguridad y las CVE que corrigen en Fedora (`https://dl.fedoraproject.org/pub/fedora/linux/updates/<release>/Everything/<arch>/repodata/`)
- **OSV**: Debian, Ubuntu, Alpine, openSUSE, Red Hat Enterprise Linux, Rocky Linux, `AlmaLinux`, módulos de Go y `crates.io` (`https://api.osv.dev/v1/querybatch`, un documento de aviso por id). Los avisos que también existen en los trackers de las distribuciones tienen el mismo significado; para Go y los crates deciden las versiones exactas.
- **CISA KEV**: CVE explotadas activamente (`https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`)
- **FIRST EPSS**: probabilidad de explotación (`https://api.first.org/data/v1/epss`)

La fuente de la distribución es obligatoria por defecto. KEV y EPSS enriquecen el
resultado y son opcionales: si fallan, la salida lo dice, pero el resultado
sigue siendo completo.

## Por qué no OSV para Fedora y Arch

La lista de ecosistemas de OSV (comprobada el 2026-11-07) contiene Debian,
Ubuntu, Alpine, Red Hat, Rocky, AlmaLinux, SUSE y otros, pero no Fedora ni Arch
Linux. Para estas dos, los datos propios de la distribución son la fuente de
verdad.

## Particularidades de Fedora

`updateinfo` indica qué CVE corrigió una actualización. amivuln informa de una
CVE como afectando a un paquete instalado cuando Fedora ha publicado una
corrección en una versión más reciente. Solo se confía en los ids de CVE que
abren el título de un bug de bugzilla; los ids que aparecen únicamente en
descripciones de texto libre se ignoran, porque «regression from the fix for
CVE-X» marcaría de otro modo CVE-X como corregida. Una actualización de
seguridad que no nombra ninguna CVE se informa bajo su id de actualización. Una
CVE sin corrección publicada no es visible en estos datos.

## Red Hat Enterprise Linux

RHEL se juzga con el ecosistema `Red Hat` de OSV, que republica los avisos de
seguridad de Red Hat (RHSA y RHBA). OSV archiva un paquete bajo el repositorio
en el que se distribuye (`Red Hat:enterprise_linux:9::baseos`, `::appstream`,
`::crb`) y la base de datos de rpm no registra cuál, así que amivuln consulta los
tres y combina las respuestas. Una CVE suele tener varias correcciones, una por
rama menor (GA, EUS, E4S). amivuln sigue la regla de Fedora: una versión
instalada igual o superior a cualquier corrección publicada está corregida, y una
más antigua se informa frente a la corrección más baja. Un host que no está en la
rama más baja puede por tanto ver una corrección que no puede instalar; el
hallazgo indica la versión para que se pueda comprobar la rama.

**CVE sin corregir.** OSV contiene los avisos que publicaron una corrección. Una
CVE que Red Hat no ha corregido (`Affected`, `Fix deferred`, `Will not fix`,
`Out of support scope`) no tiene allí ningún aviso, así que en RHEL 8 y 9
amivuln también lee el archivo OVAL de Red Hat «including unpatched» (ADR-0014,
fuente `redhat-oval`): unos 11 MB, leídos una vez por cada actualización de la
caché y reducidos a un índice pequeño. Un paquete del host se asocia por el
nombre de su paquete binario o fuente, y cada CVE encontrada se informa como
afectada sin versión corregida, nunca como limpia. Una CVE para la que OSV ya
tiene respuesta conserva la respuesta de OSV. `Under investigation` no se
informa. El archivo no tiene estado para RHEL 10, así que allí la fuente aparece
como omitida y el resultado de RHEL 10 sigue siendo una cota inferior. No se
envía nada sobre el host; desactívela con `sources.rhel_unpatched.enabled =
false`. Red Hat publica los datos bajo CC BY 4.0. Los paquetes del kernel se
listan frente a cientos de CVE, la mayoría de gravedad baja y diferidas: eso es
lo que dice Red Hat. La severidad procede de la valoración que Red Hat enlaza en
cada aviso (Important equivale a high).

## Dónde viven los datos sin conexión

`amivuln db build` empaqueta todo lo consultado en un `tar.zst` que otro host
verifica con `amivuln db pull` y consulta con `--offline` (vea la guía). La
entrada VEX procede de los documentos que usted proporciona con `--vex`.

## Distribuciones compatibles

Cómo se identifica un destino, y qué pueden y qué no pueden mostrar los datos:

- **Fedora.** El host se lee mediante `rpm`. Datos: `updateinfo`. Una CVE sin corrección publicada no es visible.
- **Arch Linux.** El host se lee mediante `pacman`. Datos: el Arch Security Tracker, que también lista paquetes vulnerables sin corrección.
- **Red Hat Enterprise Linux 8, 9 y 10.** El host se lee mediante `rpm`; los contenedores UBI funcionan. Datos: el ecosistema Red Hat de OSV, más las CVE sin corregir del archivo OVAL de Red Hat en RHEL 8 y 9 (vea más arriba); RHEL 10 sigue siendo una cota inferior.
- **Rocky Linux y AlmaLinux 8 y 9.** El host se lee mediante `rpm`. Datos: OSV; solo son visibles las CVE que publicaron una corrección.
- **Debian y Ubuntu (LTS).** El host se lee de `/var/lib/dpkg` (no se ejecuta nada); también funcionan contenedores, listas de `--packages-from`, SBOM y `name@version`. Datos: OSV, que también lista problemas abiertos (informados como afectados sin versión corregida).
- **openSUSE Leap 15.x y 16.0, y Tumbleweed.** El host se lee mediante
  `rpm`, y los contenedores funcionan. Datos: OSV, indexado por el paquete
  *fuente* (la biblioteca `libopenssl3` se compila a partir de `openssl-3`):
  amivuln lee el nombre fuente de la base de datos de rpm, pero una lista de
  paquetes o un SBOM tiene que incluirlo (vea la página Usar amivuln). Solo
  cuentan las actualizaciones de seguridad (`SUSE-SU`, `openSUSE-SU`), y solo son
  visibles las CVE que publicaron una corrección. SUSE Linux Enterprise tiene
  sus propios datos y todavía no se lee.
- **Gentoo.** El host se lee de `/var/db/pkg` (no se ejecuta nada), y los
  contenedores funcionan. Datos: los GLSA del propio árbol Portage del host
  (`/var/db/repos/gentoo/metadata/glsa`), leídos sin conexión; no se descarga
  nada. Los avisos se juzgan por slot, y un rango con `slot` solo se aplica a un
  paquete de ese slot. Solo existen los avisos que publicaron una corrección, así
  que una CVE sin corrección todavía no es visible. La antigüedad de la fuente es
  la hora de la última sincronización del árbol; un árbol que falta, no se puede
  leer o está vacío hace que el resultado sea incompleto. Para un contenedor u
  otra máquina, apunte `[sources.distro] path` a un directorio con los archivos
  `glsa-*.xml`. El atributo `arch` de un aviso no se lee.
- **Alpine 3.x.** El host se lee de `/lib/apk/db/installed`; las demás entradas son las mismas que en Debian y Ubuntu. Las imágenes edge y alpha no tienen datos de avisos y se rechazan. Datos: OSV, indexado por el paquete de origen; solo son visibles las CVE que publicaron una corrección.
- **Datos de CVE de Red Hat (opcional, desactivado por defecto).** El texto de
  `mitigation` que Red Hat publica por CVE, usado por `--mitigations`. Vea la
  guía para saber qué envía y qué no afirma.
- **Runtimes de Flatpak.** Se leen del `manifest.json` de cada runtime y se
  juzgan con la NVD para la versión upstream de cada componente, aplicando las
  listas `patches` e `ignored` del propio constructor. Es lento y tiene límite de
  tasa; vea la guía.
- **Módulos de Go y crates de Rust** encontrados en binarios, mediante OSV.

## Previsto

La API Bodhi de Fedora como comprobación cruzada, NVD por CPE como alternativa y
endoflife.date. El archivo CSAF VEX de Red Hat (412 MB) se sopesó y no se
eligió: el archivo OVAL da las CVE sin corregir en 11 MB (ADR-0014).

## Particularidades de Arch

El tracker marca un grupo como *Vulnerable* sin versión corregida para la
compilación que estaba vigente cuando se escribió la entrada, y algunas entradas
se quedan así durante años. amivuln informa de un paquete instalado como
afectado solo cuando tiene la misma versión upstream que la compilación
registrada (una recompilación de ella sigue afectada). Una versión upstream más
nueva se informa como *unverified*, porque la entrada no puede decir si todavía
se aplica. Una instalación anterior a la compilación registrada queda fuera de
la entrada y no se informa.
