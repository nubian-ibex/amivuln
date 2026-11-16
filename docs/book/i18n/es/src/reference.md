# Referencia

## Comandos

- `amivuln [OPTIONS] TARGET...` es un atajo de `amivuln check`.
- `amivuln check [TARGET...] [--all]`
- `amivuln cve CVE-ID...`: ¿está afectado este host? Sale con 1 cuando lo está.
- `amivuln pending`: las actualizaciones que cierran más riesgo, ordenadas.
- `amivuln services`: revisa el paquete que hay detrás de cada servicio systemd en ejecución.
- `amivuln restart`: procesos que siguen ejecutando archivos que una actualización reemplazó. Sale con 1 cuando hace falta reiniciar.
- `amivuln config show | init [--path FILE] | validate`
- `amivuln cache info | clear`
- `amivuln completions bash|zsh|fish|elvish|powershell`
- `amivuln db build|pull|verify|info`: la base de datos de avisos sin conexión (vea la guía del usuario)
- `amivuln tui`: una vista a pantalla completa con filtros (compile con `--features tui`)
- `amivuln mcp`: un servidor Model Context Protocol de solo lectura por stdio (vea la guía del usuario)
- `amivuln version [--json]`

## Opciones

- `-f, --format`: `summary`, `detail`, `json`, `sarif`, `markdown`, `csv`, `prometheus`, `cyclonedx` u `openvex`
- `[network] retries = 2`: reintentos por llamada fallida; `cooldown = "30s"`: pausa del cortacircuitos; `min_interval`: espaciado opcional por host
- `--output FILE`: escribe el resultado en FILE en lugar de stdout; el archivo se reemplaza de forma atómica mediante un renombrado
- `--fail-on`: `none`, `low`, `medium`, `high`, `critical` o `kev`
- `--fail-on-epss SCORE`: sale con 1 cuando un hallazgo afectado alcanza esta puntuación EPSS
- `--strict`: los hallazgos no verificados cuentan para `--fail-on`
- `--offline`, `--no-cache`: comportamiento de red y de caché
- `--config FILE`: usa solo este archivo de configuración
- `--color auto|always|never`: se respeta `NO_COLOR`
- `--distro fedora:NN|arch|debian:NN|ubuntu:NN.NN|alpine:N.NN|opensuse:NN.N|opensuse:tumbleweed|gentoo|rhel:N|rocky:N|alma:N`: trata el host como esta distribución
- `--baseline FILE`: un informe `-f json` anterior; solo los hallazgos ausentes de él violan `--fail-on`
- `--pid PID`: revisa el ejecutable de un proceso en ejecución (repetible); un proceso que ya no existe, que no se puede leer o cuyo ejecutable fue reemplazado en disco se informa como no resuelto
- `--sbom FILE`: revisa los paquetes del sistema operativo de un SBOM CycloneDX JSON (purls rpm, deb, apk y alpm); los demás componentes se listan como no resueltos, una entrada por tipo de purl
- `--vex FILE`: un documento `OpenVEX`; una declaración `not_affected` prevalece sobre el veredicto y muestra el autor y la justificación
- `--kernel`: revisa también el kernel que está en ejecución, sea cual sea el resto de lo instalado (vea la guía)
- `--explain`: bajo cada hallazgo de la salida detail, dice en palabras llanas por qué se informa (plantillas sobre los datos de la propia ejecución; sin modelo, sin enviar nada)
- `--mitigations`: busca también la mitigación que publica Red Hat para cada CVE afectada (envía los ids de CVE a access.redhat.com)
- `--flatpak`: revisa también los componentes de los runtimes Flatpak instalados (vea la guía para saber qué cuesta y qué no puede decir)
- `--container ID`: revisa los paquetes de un contenedor podman o docker (repetible); las imágenes de Alpine, Debian, Ubuntu, Fedora, openSUSE, Gentoo, Rocky, AlmaLinux y Red Hat (UBI) se leen desde un sistema de archivos raíz exportado y no se ejecuta nada dentro
- `--packages-from FILE`: revisa los paquetes listados en FILE (un `name@version` por línea) en lugar de los instalados
- `ignore_file` (configuración): hallazgos aceptados; las entradas caducadas son errores
- `-q, --quiet`: solo errores

`AMIVULN_FORMAT`, `AMIVULN_FAIL_ON`, `AMIVULN_OFFLINE`, `AMIVULN_CONFIG` y
`AMIVULN_COLOR` establecen las opciones correspondientes.

## Códigos de salida

- 0: terminó, nada en `--fail-on` o por encima
- 1: terminó, hay hallazgos en `--fail-on` o por encima
- 2: incompleto: una fuente obligatoria no estaba disponible
- 3: no se pudo resolver un destino
- 64: error de uso o de configuración
- 70: error interno

Cuando se dan varios, la precedencia es 70, 64, 2, 3, 1, 0.

## Salida JSON (versión de esquema 1)

```json
{
  "schema_version": 1,
  "tool": {"name": "amivuln", "version": "0.1.0"},
  "generated_at": "2026-11-08T12:00:00Z",
  "host": {"os_id": "fedora", "os_version": "44", "arch": "x86_64"},
  "complete": true,
  "sources": [{"id": "fedora-updateinfo", "status": "ok", "age_s": 0, "required": true}],
  "targets": [{
    "input": "nginx",
    "package": {"name": "nginx", "version": "1:1.26.2-1.fc44", "arch": "x86_64",
                "ecosystem": "fedora", "purl": "pkg:rpm/fedora/nginx@1.26.2-1.fc44?arch=x86_64&epoch=1",
                "provenance": "package_db"},
    "summary": {"critical": 0, "high": 1, "medium": 0, "low": 0, "kev": 0, "epss_max": 0.02, "unverified": 0},
    "findings": [{"id": "CVE-2026-0001", "severity": "high",
                  "distro_status": {"state": "affected", "fixed_in": "1:1.26.3-1.fc44"},
                  "kev": null, "epss": {"score": 0.02, "percentile": 0.6, "date": "2026-11-07"}}],
    "unverified": []
  }],
  "unresolved": []
}
```

El JSON Schema se publica en
[schema/v1.json](https://ibexwall.com/amivuln/schema/v1.json) y se comprueba
contra la salida real en CI. Los hallazgos y los hallazgos no verificados son
arreglos separados. El bloque host nunca contiene un nombre de host, una
dirección ni un usuario. Añadir campos opcionales no cambia `schema_version`;
quitar uno o cambiarle el tipo sí.

## Archivo de configuración

```toml
schema_version = 1
[general]
offline = false
cache_ttl = "6h"
stale_max_age = "72h"
timeout = "10s"
exec_version_probe = false
[output]
format = "summary"
color = "auto"
[policy]
fail_on = "none"
fail_on_incomplete = true
strict = false
[sources.distro]
enabled = true
required = true
# url = "https://mirror.example/fedora/linux/updates"
[sources.kev]
enabled = true
[sources.epss]
enabled = true
```
