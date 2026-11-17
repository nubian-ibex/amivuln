# Segurança e privacidade

## O que sai do host

Apenas o ecossistema, o nome do pacote e a versão, nas requisições às fontes
listadas em [Fontes de dados](sources.md). As requisições ao EPSS carregam ids
de CVE. Nenhum nome de host, caminho, nome de usuário ou endereço é enviado, e
um teste inspeciona cada requisição para garantir isso. Não há telemetria nem
verificação de atualização.

## Como a ferramenta se protege

- Ela nunca executa o binário alvo. As versões vêm do gerenciador de pacotes.
- As ferramentas do sistema rodam a partir de caminhos absolutos fixos, com
  ambiente limpo, `LC_ALL=C`, argumentos fixos, timeout e limite de saída.
- Os dados de advisories não são confiáveis: tamanhos e profundidade de
  aninhamento são limitados, identificadores que não parecem ids de CVE são
  descartados e caracteres de controle nunca chegam ao terminal.
- Os metadados do Fedora são conferidos contra o SHA-256 em `repomd.xml`, então
  um mirror que sirva outros bytes é rejeitado.
- O acesso à rede usa apenas HTTPS, com rustls, e no máximo três
  redirecionamentos.

## Relatando uma vulnerabilidade

Use o relato privado de vulnerabilidades do GitHub:
[github.com/nubian-ibex/amivuln/security/advisories/new](https://github.com/nubian-ibex/amivuln/security/advisories/new).
Veja o `SECURITY.md` do repositório para as metas de resposta.

## Integridade dos releases

Os releases são construídos pelo GitHub Actions a partir de uma tag assinada e
trazem atestados de procedência do build, uma assinatura cosign sobre
`SHA256SUMS` e um SBOM. Os builds de release são reproduzíveis quando
construídos no mesmo ambiente; veja `docs/reproducible-builds.md` no
repositório.
