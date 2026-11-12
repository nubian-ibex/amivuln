# amivuln

Idiomas: [English](https://ibexwall.com/amivuln/) · [Português](https://ibexwall.com/amivuln/pt/) · **Español** · [Deutsch](https://ibexwall.com/amivuln/de/) · [Français](https://ibexwall.com/amivuln/fr/)

![amivuln: ¿Soy vulnerable? Comprobación de CVE para Linux que tiene en cuenta los backports](https://ibexwall.com/amivuln/images/banner.jpg)

**amivuln** responde a una pregunta: *¿qué CVE afectan a este paquete, archivo
o versión en este host, teniendo en cuenta los parches que mi distribución ya
ha publicado?*

Los escáneres genéricos comparan rangos de versiones del upstream y notifican
CVE que su distribución corrigió hace tiempo mediante backports. amivuln
consulta primero los datos de seguridad de la propia distribución: un paquete
que la distro ya ha corregido no se notifica como vulnerable, y una
actualización de seguridad que aún no ha instalado sí.

```console
$ amivuln pcre2 --format detail
pcre2 10.47-1.fc44.1 (Fedora 44)
  CRITICAL 0   HIGH 8   MEDIUM 0   LOW 0   KEV 0   EPSS max 0.00
  Fixed in: 10.49-1.fc44  (dnf upgrade pcre2)
  Affected:
    CVE-2026-103111  HIGH   fix: 10.49-1.fc44  EPSS 0.00
    ...

source fedora-updateinfo  ok  age 0s  required
source kev                ok  age 0s
source epss               ok  age 0s
result: complete
```

## Principios

- **Precisión antes que cobertura.** Un falso positivo causado por un backport
  es un error.
- **Nunca degradar en silencio.** Cada resultado lista el estado de cada
  fuente. Una fuente obligatoria que falla hace que el resultado sea
  *incompleto* (código de salida 2), de modo que una caída nunca se confunde
  con una comprobación limpia.
- **Nada que identifique el host sale de la máquina.** Solo se envían el
  ecosistema, el nombre del paquete y la versión. Sin telemetría.
- **La salida es un contrato.** JSON con un
  [esquema](https://ibexwall.com/amivuln/json-schema.html) versionado.
- **Versiones verificables.** Sumas de comprobación, atestaciones de compilación
  de GitHub, una firma cosign y un SBOM acompañan cada versión.

## Estado

Se admiten Fedora, Arch Linux, Debian, Ubuntu, Alpine, Red Hat Enterprise
Linux, Rocky Linux y AlmaLinux. Los resultados de RHEL no incluyen las CVE que
Red Hat aún no ha corregido; los límites de cada distribución están en
[Data sources](https://ibexwall.com/amivuln/sources.html).

Empiece por [Instalación](installation.md), [Inicio rápido](quickstart.md) y
[Usar amivuln](using.md).

## Solo en inglés

Estas páginas aún no están traducidas: la
[guía del usuario](https://ibexwall.com/amivuln/guide.html), la
[referencia](https://ibexwall.com/amivuln/reference.html), la
[arquitectura](https://ibexwall.com/amivuln/architecture.html), el
[funcionamiento del matching](https://ibexwall.com/amivuln/matching.html),
las [fuentes de datos](https://ibexwall.com/amivuln/sources.html), las
[políticas de seguridad](https://ibexwall.com/amivuln/policies.html) y
las [preguntas sobre falsos positivos](https://ibexwall.com/amivuln/faq.html).
Si hay discrepancias, prevalece la versión en inglés.
