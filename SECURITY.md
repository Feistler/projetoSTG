# Politica de Seguranca

## Uso responsavel
O STG automatiza ferramentas ofensivas e defensivas. Ele **so deve ser usado contra sistemas para
os quais ha autorizacao explicita e por escrito**. O proprio toolkit aplica um gate de escopo e uma
trilha de auditoria para reforcar esse principio. Consulte [docs/ETHICS.md](docs/ETHICS.md).

## Reportando uma vulnerabilidade no proprio STG
Encontrou uma falha no codigo deste projeto (ex.: injecao de comando, vazamento de segredo,
bypass do gate de autorizacao)?

1. **Nao** abra uma issue publica com detalhes exploraveis.
2. Envie um e-mail para o mantenedor descrevendo o problema, impacto e passos de reproducao.
3. Aguarde retorno antes de divulgar publicamente (disclosure coordenado).

## Boas praticas ao usar
- Nunca versione `.env`, `config/authorization.yaml` ou `stg-data/` (ja ignorados).
- Rotacione chaves de API que tenham sido expostas.
- Trate a trilha de auditoria (`stg-data/audit.jsonl`) como evidencia sensivel.
