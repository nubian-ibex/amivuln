# Cómo funciona la coincidencia

Cada veredicto responde a una pregunta: dada la versión instalada de un paquete
y todo lo que dijeron sobre él las fuentes consultadas, ¿está afectado el host?

## La distribución manda

Deciden los datos de avisos de la propia distribución. Los rangos upstream nunca
se usan para considerar afectado un paquete: las distribuciones publican
correcciones sin cambiar la versión upstream, así que un rango upstream
informaría falsos positivos tanto en sistemas basados en RPM como en los basados
en Debian.

## Precedencia

Por cada CVE y cada paquete las declaraciones se combinan, de la más restrictiva
a la menos:

1. **not-affected** de la distribución o de una declaración OpenVEX (`--vex`),
   con la justificación trasladada a todos los formatos de salida.
2. **patched**, cuando la versión instalada es igual o superior a la corrección
   publicada.
3. **affected**, en cualquier otro caso; el hallazgo indica la versión que lo
   corrige.
4. **unverified**, cuando hay un registro pero ninguna versión comparable: la
   distribución dice *will not fix* o *fix deferred* (el informe lo lista bajo
   su propio id), o la versión corregida no se puede comparar con la versión
   instalada (una corrección rpm frente a una instalación deb, por ejemplo).

Todo aquello sobre lo que una fuente no pudo responder se lista aparte como
`unverified` y nunca se cuenta en silencio como afectado. El enriquecimiento
(KEV, EPSS) nunca cambia un veredicto.

## Por fuente

- **Fedora.** `updateinfo` publica la versión que corrigió la CVE. Una versión
  instalada igual o superior a cualquier corrección publicada está corregida. Una
  CVE sin corrección publicada no es visible en estos datos.
- **Arch.** El tracker registra una compilación; la misma versión upstream es
  vulnerable, una recompilación de ella también, y una más nueva es
  *unverified*.
- **Debian, Ubuntu, Alpine, openSUSE, Red Hat, Rocky, `AlmaLinux`, módulos de Go y crates de
  Rust.** OSV serializa los avisos por ecosistema; deciden las versiones
  corregidas que nombran el paquete. Cuando varios avisos corrigen una misma CVE
  (Red Hat emite uno por rama menor), una versión instalada igual o superior a
  cualquiera de ellos está corregida. Un registro que OSV asoció con la versión
  instalada pero que no lista ninguna corrección es un problema abierto:
  afectado, sin versión a la que migrar (Debian y Ubuntu tienen estos registros;
  Alpine y Red Hat solo listan avisos que publicaron una corrección; openSUSE
  igual). Alpine, Debian, Ubuntu y openSUSE se consultan por paquete fuente. Para
  los paquetes de lenguajes OSV responde por versión exacta, de modo que todo
  aviso devuelto afecta a la versión consultada y la corrección informada es la
  más baja por encima de ella. Un aviso de lenguaje sin alias CVE se informa bajo
  su propio id (GHSA, GO, RUSTSEC) en lugar de desaparecer.
- **Línea base.** `--baseline prev.json` conserva solo los hallazgos que son
  nuevos desde ese informe; nunca convierte un veredicto de afectado en limpio.
- **Archivo de ignorados.** Un hallazgo aceptado se suprime y su motivo,
  responsable y caducidad se muestran en la salida; una entrada caducada es un
  error.

## Determinismo

Las reglas son funciones puras en `amivuln_core` (`matching::merge`): dos
ejecuciones con los mismos datos coinciden, y el corpus de verdad de referencia
(casos de Fedora y Arch con fixtures HTTP grabadas) las fija frente a datos
grabados.
