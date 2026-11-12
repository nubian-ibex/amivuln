# Inicio rápido

```bash
amivuln nginx                          # un paquete instalado
amivuln /usr/sbin/nginx                # el paquete al que pertenece un archivo
amivuln nginx.service                  # el paquete detrás de una unidad de systemd
amivuln openssl@3.5.1-1 --distro arch  # una versión, sin leer el host
amivuln --all                          # todos los paquetes instalados
```

## Preguntas sobre todo el host

```bash
amivuln cve CVE-2024-6387      # ¿está afectado algún paquete instalado?
amivuln pending                # qué actualizaciones reducen más el riesgo, las más arriesgadas primero
amivuln services               # comprueba el paquete detrás de cada servicio en ejecución
amivuln restart                # qué procesos siguen usando archivos que una actualización reemplazó
amivuln --packages-from list.txt   # comprueba una lista de paquetes exportada de otro host
```

`cve` termina con código 1 cuando un paquete está afectado. Cuando los datos de
la distribución no tienen registro de la CVE, lo dice de forma explícita: eso
no significa que el host sea seguro. `pending` agrupa en una sola actualización
los subpaquetes construidos desde una misma fuente y ordena por hallazgos
explotados (KEV), severidad y EPSS. `restart` lee `/proc` (ejecútelo como root
para ver todos los procesos; la salida indica cuántos no pudo inspeccionar) y
termina con código 1 cuando algo debe reiniciarse. `services` lista los
servicios de systemd en ejecución que no proceden de un paquete, sin hacer
fallar la ejecución. Un análisis de todo el sistema también imprime una
puntuación del host de la A a la F (véase el ADR-0011 del repositorio).

## Leer el resultado

Para cada paquete obtiene el número de hallazgos afectados por severidad,
cuántos se sabe que se explotan (CISA KEV), la puntuación EPSS más alta y la
versión que los corrige, con el comando que ejecutaría. amivuln nunca ejecuta
ese comando.

Los hallazgos que la distribución no puede confirmar se muestran aparte como
*no verificados* y no se cuentan con los afectados.

## Hacer fallar una compilación

```bash
amivuln --all --fail-on high           # código 1 con HIGH o peor
amivuln --all --fail-on kev            # código 1 solo con CVE explotadas
amivuln --all -f sarif > amivuln.sarif # SARIF 2.1.0 para code scanning
amivuln --all -f csv > amivuln.csv     # seguro para hojas de cálculo (inyección de fórmulas bloqueada)
```

Códigos de salida: `0` limpio, `1` hallazgos en el nivel de `--fail-on` o por
encima, `2` incompleto, `3` objetivo sin resolver, `64` error de uso, `70`
error interno. El código `2` evita que una caída de los datos de seguridad se
confunda con una comprobación limpia.

## Un paso de GitHub Actions

La [amivuln-action](https://github.com/nubian-ibex/amivuln-action) descarga una
versión, verifica su atestación y su suma de comprobación y después la ejecuta.
Fíjela a un SHA de commit completo:

```yaml
permissions:
  contents: read
  attestations: read
steps:
  - uses: nubian-ibex/amivuln-action@5c61781a5497fbcb34401a5b2d2eee54a59e9ebc # v0.1.1
    with:
      args: --all --fail-on high
```

Los mismos pasos, a mano:

```yaml
- name: Descargar amivuln
  run: |
    gh release download --repo nubian-ibex/amivuln --pattern 'amivuln-x86_64-unknown-linux-musl.tar.zst'
    gh attestation verify amivuln-x86_64-unknown-linux-musl.tar.zst --repo nubian-ibex/amivuln
    tar --zstd -xf amivuln-x86_64-unknown-linux-musl.tar.zst --strip-components=1
- name: Comprobar los paquetes
  run: ./amivuln --all --fail-on high
```

Vea también [Usar amivuln](using.md) para más escenarios.
