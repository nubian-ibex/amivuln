# amivuln

Idiomas: [English](https://ibexwall.com/amivuln/) · **Português** · [Español](https://ibexwall.com/amivuln/es/) · [Deutsch](https://ibexwall.com/amivuln/de/) · [Français](https://ibexwall.com/amivuln/fr/)

![amivuln: Estou vulnerável? Verificação de CVEs para Linux que considera backports](https://ibexwall.com/amivuln/images/banner.jpg)

O **amivuln** responde a uma pergunta: *quais CVEs se aplicam a este pacote,
arquivo ou versão neste host, levando em conta as correções que a minha
distribuição já entregou?*

Scanners genéricos comparam faixas de versões do upstream e relatam CVEs que a
sua distribuição corrigiu há muito tempo por meio de backports. O amivuln
consulta primeiro os dados de segurança da própria distribuição: um pacote que
a distro já corrigiu não é relatado como vulnerável, e uma atualização de
segurança que você ainda não instalou é.

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

## Princípios

- **Precisão antes de cobertura.** Um falso positivo causado por backport é um
  bug.
- **Nunca degradar em silêncio.** Todo resultado lista o estado de cada fonte.
  Uma fonte obrigatória que falhou torna o resultado *incompleto* (código de
  saída 2), de modo que uma queda nunca se passa por uma verificação limpa.
- **Nada que identifique o host sai da máquina.** Só são enviados o
  ecossistema, o nome do pacote e a versão. Sem telemetria.
- **A saída é um contrato.** JSON com [schema](https://ibexwall.com/amivuln/json-schema.html)
  versionado.
- **Releases verificáveis.** Checksums, atestados de build do GitHub, uma
  assinatura cosign e um SBOM acompanham cada release.

## Situação

Fedora, Arch Linux, Debian, Ubuntu, Alpine, Red Hat Enterprise Linux, Rocky
Linux e AlmaLinux são suportados. Os resultados do RHEL não incluem as CVEs que
a Red Hat ainda não corrigiu; os limites de cada distribuição estão em
[Data sources](https://ibexwall.com/amivuln/sources.html).

Comece por [Instalação](installation.md), [Início rápido](quickstart.md) e
[Usando o amivuln](using.md).

## Só em inglês

Estas páginas ainda não foram traduzidas: o
[guia do usuário](https://ibexwall.com/amivuln/guide.html), a
[referência](https://ibexwall.com/amivuln/reference.html), a
[arquitetura](https://ibexwall.com/amivuln/architecture.html), o
[funcionamento do matching](https://ibexwall.com/amivuln/matching.html),
as [fontes de dados](https://ibexwall.com/amivuln/sources.html), as
[políticas de segurança](https://ibexwall.com/amivuln/policies.html) e
o [FAQ de falsos positivos](https://ibexwall.com/amivuln/faq.html).
Em caso de divergência, vale a versão em inglês.
