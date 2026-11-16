# FAQ de falsos positivos

**amivuln informa de una CVE que mi distribución ya corrigió.** El estado que
publica la distribución prevalece sobre la comparación de versiones, así que
esto no debería ocurrir. Abra una incidencia de *falso positivo* con la salida
de `amivuln PACKAGE -f json` y el enlace al aviso o al registro de cambios que
muestra la corrección.

**amivuln no informa de nada, pero conozco una CVE.** En Fedora, Red Hat, Rocky
y AlmaLinux, amivuln solo ve las correcciones que se han publicado. Una CVE sin
actualización todavía no está en los datos, de modo que un resultado allí es un
límite inferior. Abra una incidencia de *falso negativo* si los datos sí tienen
el registro.

**El resultado dice INCOMPLETE.** Una fuente obligatoria no estaba disponible y
no había copia en caché dentro de `stale_max_age`. Reintente, revise la red o
use un espejo con `sources.distro.url`. El código de salida es 2 a propósito.

**¿Por qué un paquete aparece como «unverified»?** La distribución no tiene
ninguna declaración sobre él. Se lista aparte y no hace fallar una compilación
salvo que pase `--strict`.

**Mi repositorio `updates` está desactivado.** amivuln consulta los datos
`updates` que Fedora publica, sin importar la configuración de repositorios de
su equipo, por lo que puede informar de una actualización que su sistema aún no
ve.
