# Uso etico e responsavel

Este projeto automatiza ferramentas que, usadas sem autorizacao, configuram **crime**. Leia antes
de usar.

## Regra de ouro
**So teste o que voce tem autorizacao por escrito para testar.** Um e-mail, um contrato de
pentest, um termo de escopo (Rules of Engagement) ou um ambiente de laboratorio que e seu.

## Como o STG ajuda a manter a etica
1. **Gate de escopo** (`config/authorization.yaml`): conectores ativos sao **bloqueados** contra
   alvos fora do escopo declarado.
2. **`--force` auditado**: e possivel sobrepor o gate, mas a acao fica **registrada** na trilha de
   auditoria, com usuario e horario.
3. **Trilha de auditoria** (`stg-data/audit.jsonl`): prova do que foi executado, quando e por quem.
4. **Conectores passivos**: OSINT (Shodan, HIBP) e marcado como `passive` &mdash; nao "toca" o alvo,
   mas ainda assim deve respeitar termos de uso das APIs.

## Boas praticas
- Mantenha `authorization.yaml` **restrito** ao escopo real do engajamento.
- Nunca versione `.env`, `config/authorization.yaml` nem `stg-data/` (ja estao no `.gitignore`).
- Guarde a trilha de auditoria como parte das evidencias do trabalho.
- Em pentests, alinhe janelas de execucao e intensidade (`timing`, `risk`, `level`) com o cliente.

## Referencias legais (Brasil)
- **Lei 12.737/2012** (Lei Carolina Dieckmann) &mdash; invasao de dispositivo informatico.
- **Marco Civil da Internet (Lei 12.965/2014)**.
- **LGPD (Lei 13.709/2018)** &mdash; cuidado com dados pessoais coletados (ex.: resultados de HIBP).

> O autor e os contribuidores nao se responsabilizam por uso indevido. A responsabilidade legal e
> integralmente de quem opera a ferramenta.
