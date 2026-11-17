# Contribuindo

O guia completo é o `CONTRIBUTING.md` no repositório. Em resumo:

```bash
git clone https://github.com/nubian-ibex/amivuln && cd amivuln
just ci        # fmt, clippy, tests, docs, assets, deny, audit, vet, typos, reuse, actionlint, zizmor
```

- Os commits seguem o Conventional Commits e são assinados (`git commit -s`).
- Os testes nunca tocam a rede: fixtures gravadas e um servidor simulado.
- Relate um resultado errado com o formulário de issue de *falso positivo* ou
  *falso negativo*, incluindo a saída de `amivuln PACKAGE -f json`.
- Contribuições assistidas por IA são bem-vindas; declare-as com um trailer
  `Assisted-by:`. O autor humano é responsável pela mudança.

As decisões de arquitetura são registradas como ADRs em `docs/adr/`.
