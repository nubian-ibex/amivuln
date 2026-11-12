# Usar amivuln

Recetas para los lugares donde amivuln suele ejecutarse. Cada una está lo
bastante completa como para copiarla; la
[guía del usuario](https://nubian-ibex.github.io/amivuln/guide.html) explica
las opciones en profundidad y la
[referencia](https://nubian-ibex.github.io/amivuln/reference.html) las lista
todas.

Dos cosas valen en todas partes. Lea `complete` y las líneas `source` antes de
fiarse de un resultado vacío: el código de salida `2` significa que una fuente
obligatoria no estaba disponible, lo cual no equivale a limpio. Y solo el
ecosistema, el nombre del paquete y la versión salen de la máquina.

## En su portátil o estación de trabajo

```bash
amivuln --all                      # puntuación y totales de todos los paquetes instalados
amivuln pending                    # qué actualizaciones reducen más el riesgo, las más arriesgadas primero
amivuln openssl --format detail    # un paquete, cada hallazgo con su corrección
amivuln /usr/bin/ssh               # el paquete al que pertenece un archivo
```

`pending` es lo más útil en un escritorio: agrupa los subpaquetes construidos
desde una misma fuente, ordena por hallazgos explotados (KEV), severidad y EPSS
e imprime el comando de actualización. amivuln nunca lo ejecuta.

Para una vista de pantalla completa con filtros, compile con la característica
`tui`:

```bash
cargo install amivuln --locked --features tui
amivuln tui          # flechas o j/k para moverse, K: solo KEV, H: solo HIGH, q: salir
```

## Cuando una CVE nueva sale en las noticias

```bash
amivuln cve CVE-2024-6387          # código 1 cuando un paquete instalado está afectado
amivuln cve CVE-2024-6387 CVE-2025-26465
amivuln restart                    # procesos que siguen usando archivos que una actualización reemplazó
```

`cve` responde `affected`, `not affected` o `unknown`. `unknown` significa que
la distribución no tiene registro de la CVE: no afirma que el host sea seguro.
Tras instalar la actualización, `restart` lista los procesos que siguen
ejecutando el código antiguo.

## En un servidor, de forma programada

Las unidades de `contrib/systemd` analizan el host cada seis horas y escriben
métricas para el textfile collector de node_exporter.

```bash
sudo install -m 0644 contrib/systemd/amivuln.{service,timer} /etc/systemd/system/
sudo systemctl enable --now amivuln.timer
```

Importe `contrib/grafana/amivuln.json` en Grafana para obtener el panel. Para un
cron sencillo que envía el resultado por correo solo cuando algo va mal:

```cron
17 6 * * *  root  amivuln --all --fail-on high -f markdown || mail -s "amivuln: $(hostname)" ops@example.org
```

Para recibir un mensaje en lugar de un panel, añada un webhook a la
configuración:

```toml
[notify]
webhook = "https://ntfy.sh/example-topic"
on = "violation"
```

## En un pipeline de CI

GitHub Actions, con la versión verificada y code scanning:

```yaml
permissions:
  contents: read
  attestations: read
  security-events: write
steps:
  - uses: nubian-ibex/amivuln-action@5c61781a5497fbcb34401a5b2d2eee54a59e9ebc # v0.1.1
    with:
      args: --all --fail-on high -f sarif --output amivuln.sarif
  - uses: github/codeql-action/upload-sarif@33d7b85da1a04171e211befe2c739303b9a4c066 # v4.39.3
    if: always()
    with:
      sarif_file: amivuln.sarif
```

Fije las actions de terceros a un SHA de commit completo, como la primera.
GitLab CI o cualquier otro runner:

```yaml
amivuln:
  image: fedora:44
  script:
    - curl -sSLO https://github.com/nubian-ibex/amivuln/releases/latest/download/amivuln-x86_64-unknown-linux-musl.tar.zst
    - tar --zstd -xf amivuln-x86_64-unknown-linux-musl.tar.zst --strip-components=1
    - ./amivuln --all --fail-on kev -f json --output amivuln.json
  artifacts:
    when: always
    paths: [amivuln.json]
```

Verifique la descarga como se muestra en [Instalación](installation.md) antes de
confiar en ella. Para que un pull request falle solo por los hallazgos que
introduce, compárelo con un informe de la rama principal:

```bash
amivuln --all -f json --output baseline.json        # en main, guardado como artefacto
amivuln --all --baseline baseline.json --fail-on high   # en el pull request
```

## Contenedores e imágenes

Analice un contenedor por id o nombre; el runtime puede ser podman o docker.
amivuln lee su base de datos de paquetes desde un sistema de archivos exportado
y nunca ejecuta nada dentro de él.

```bash
id=$(podman create docker.io/library/alpine:3.18.0 true)
amivuln --container "$id" --fail-on high
podman rm "$id"
```

Los contenedores Alpine, Debian, Ubuntu, Fedora, Rocky, AlmaLinux y Red Hat
(UBI) se evalúan según su propia versión. Una imagen Alpine edge o alpha no
tiene datos de avisos y se rechaza en lugar de notificarla como limpia. Pase
varias opciones `--container` para comprobar una pila completa en un solo
informe.

## Muchos hosts, o un host donde no puede instalar nada

Exporte una lista desde el otro host y compruébela desde donde se ejecute
amivuln. Un `nombre@versión` por línea; `--distro` indica a qué versión
pertenece la lista.

```bash
# Fedora, RHEL, Rocky, AlmaLinux (en el host de destino)
rpm -qa --qf '%{NAME}@%|EPOCH?{%{EPOCH}:}|%{VERSION}-%{RELEASE}\n' > host.txt
# Debian y Ubuntu: los avisos usan el nombre del paquete fuente
dpkg-query -W -f '${source:Package}@${Version}\n' > host.txt
# Alpine: los avisos usan el paquete de origen
awk -F: '/^P:/{p=$2} /^V:/{v=$2} /^o:/{o=$2} /^$/{print (o?o:p)"@"v; p="";v="";o=""}' \
  /lib/apk/db/installed > host.txt

amivuln --packages-from host.txt --distro debian:12 --fail-on high
```

Para una lista de componentes de una compilación, apunte a un SBOM CycloneDX:

```bash
amivuln --sbom product.cdx.json --distro debian:12
```

## Sin internet en el host

Construya la base de datos de avisos donde haya red, lleve un único archivo y
responda desde él sin conexión.

```bash
amivuln --all -f json > /dev/null                 # calienta la caché una vez
amivuln db build --archive db.tar.zst
# copie db.tar.zst al host aislado y después:
amivuln db verify db.tar.zst --key amivuln.pub --sig db.tar.zst.minisig
amivuln db pull db.tar.zst
amivuln --all --offline --fail-on high
```

Los resultados procedentes de la base de datos se marcan como `stale`, con su
antigüedad. El proyecto publica una base de datos firmada por familia de
distribución; consulte la guía.

## Detrás de un proxy o de una CA corporativa

```toml
[network]
proxy = "http://proxy.corp.example:3128"
ca_file = "/etc/pki/ca-trust/source/anchors/corp.pem"
```

O apunte `sources.<nombre>.url` a un espejo interno. Consulte la guía.

## Desde scripts y paneles

El informe JSON es un contrato versionado, así que `jq` basta:

```bash
amivuln --all -f json | jq -r '.targets[] | select(.summary.kev > 0) | .package.name'
amivuln --all -f json | jq '[.targets[].findings[]] | group_by(.severity) | map({(.[0].severity): length}) | add'
amivuln --all -f csv > findings.csv        # seguro para hojas de cálculo
amivuln --all -f prometheus --output /var/lib/node_exporter/textfile_collector/amivuln.prom
```

## Desde un asistente de IA

`amivuln mcp` es un servidor Model Context Protocol de solo lectura. Regístrelo
una vez:

```json
{ "mcpServers": { "amivuln": { "command": "amivuln", "args": ["mcp"] } } }
```

El asistente podrá entonces comprobar paquetes, preguntar si una CVE afecta al
host y listar las actualizaciones pendientes. No tiene shell, no recibe rutas
de archivo y no puede pasar opciones.

## Archivos que ningún paquete posee

Un binario copiado en `/opt`, un programa Go o un programa Rust de una
compilación:

```bash
amivuln /opt/tool/bin/server          # nota, build info de Go o datos de cargo-auditable
```

Si el archivo no declara nada, amivuln busca los banners de versión de una
lista corta de productos en C y marca el resultado como de baja confianza. Con
`exec_version_probe = true` en `[general]` también ejecuta `--version` sobre el
archivo dentro de un sandbox Landlock y seccomp, que está desactivado por
defecto.
