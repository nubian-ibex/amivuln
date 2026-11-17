# Políticas de segurança

## Política de dependências (SCA)

`cargo deny`, `cargo audit` e `cargo vet` rodam em todo pull request e no
pipeline de release (`just ci`). O limite é zero achados não declarados: um
achado de advisory, licença ou procedência bloqueia a mudança, a menos que
seja declarado com um motivo em `deny.toml` (advisories, licenças) ou em
`supply-chain/config.toml` (isenções do vet). As isenções declaradas são
reavaliadas a cada release.

Um advisory de dependência que não afeta o amivuln é registrado em `deny.toml`
com o id do advisory e o motivo de não ser explorável aqui; esse registro é a
declaração VEX oficial do projeto. Nenhum release sai com um achado de SCA não
declarado: as verificações falham de forma fechada.

## Política de análise estática (SAST)

O limite é zero achados. `cargo clippy --workspace --all-targets
--all-features -- -D warnings` e `cargo fmt --check` bloqueiam toda mudança em
`just ci`. Uma supressão exige um `#[allow]` inline cujo comentário diga por que
o achado não se aplica; o conjunto de lints nunca é reduzido para fazer o
código passar.

## Política de segredos

- Nenhuma credencial pertence ao repositório nem ao rastreador de issues.
- As credenciais de CI (a chave minisign de release, `MINISIGN_SECRET_KEY` e
  `MINISIGN_PASSWORD`, tokens do cosign e do crates.io) são secrets do GitHub
  Actions restritos aos workflows e ao ambiente `release` que precisam deles, e
  nunca são ecoados nos logs.
- Os segredos são rotacionados quando muda um workflow, máquina ou pessoa com
  acesso, e imediatamente diante de suspeita de vazamento; após um vazamento,
  os logs de auditoria são revisados quanto ao uso do valor exposto.
- O desenvolvimento local não precisa de credenciais: os testes não usam a
  rede.

## Política de acesso e revisão

Somente a conta do mantenedor tem acesso de escrita, direito sobre tags e
aprovação do ambiente de release. Um novo colaborador é avaliado antes de
receber qualquer permissão elevada: histórico de contribuições no projeto,
práticas de segurança (commits assinados, disciplina com dependências) e uma
identidade pública. Os rulesets em `main` e nas tags `v*` exigem commits
assinados e bloqueiam force-pushes e exclusões, independentemente de quem
detenha a permissão.

## Política de testes

Toda mudança importante adiciona ou atualiza testes na suíte automatizada; uma
correção de bug adiciona o teste de regressão antes da correção. Os testes não
podem tocar a rede: o comportamento HTTP é coberto por fixtures gravadas e
`wiremock`. Rode `just ci` antes de abrir um pull request; o CI roda a suíte
completa em todo pull request e o merge fica bloqueado enquanto ela falhar.
