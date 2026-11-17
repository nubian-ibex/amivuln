# Seguridad y privacidad

## Qué sale del host

Solo el ecosistema, el nombre del paquete y la versión, en las solicitudes a las
fuentes listadas en [Fuentes de datos](sources.md). Las solicitudes de EPSS
llevan ids de CVE. Nunca se envía ningún nombre de host, ruta, nombre de usuario
ni dirección, y una prueba inspecciona cada solicitud para asegurarlo. No hay
telemetría ni comprobación de actualizaciones.

## Cómo se protege la herramienta

- Nunca ejecuta el binario de destino. Las versiones proceden del gestor de
  paquetes.
- Las herramientas del sistema se ejecutan desde rutas absolutas fijas con un
  entorno vacío, `LC_ALL=C`, argumentos fijos, un tiempo máximo y un límite de
  salida.
- Los datos de avisos no son de confianza: se limitan los tamaños y la
  profundidad de anidamiento, se descartan los identificadores que no parecen
  ids de CVE y los caracteres de control nunca llegan al terminal.
- Los metadatos de Fedora se comprueban con el SHA-256 de `repomd.xml`, de modo
  que se rechaza un espejo que sirva otros bytes.
- El acceso de red usa solo HTTPS, con rustls, y como máximo tres redirecciones.

## Informar de una vulnerabilidad

Use el informe privado de vulnerabilidades de GitHub:
[github.com/nubian-ibex/amivuln/security/advisories/new](https://github.com/nubian-ibex/amivuln/security/advisories/new).
Consulte el `SECURITY.md` del repositorio para los plazos de respuesta.

## Integridad de las versiones

Las versiones se construyen con GitHub Actions a partir de una etiqueta firmada
e incluyen atestaciones de procedencia de la compilación, una firma cosign sobre
`SHA256SUMS` y un SBOM. Las compilaciones de publicación son reproducibles
cuando se construyen en el mismo entorno; vea `docs/reproducible-builds.md` en
el repositorio.
