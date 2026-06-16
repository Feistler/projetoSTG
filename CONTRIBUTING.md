# Contribuindo

## Ambiente de desenvolvimento
```bash
pip install -e ".[dev]"
pytest           # roda os testes
ruff check stg tests   # lint
```
Ou via Docker, sem instalar nada localmente:
```bash
docker run --rm -e PYTHONPATH=/app -v "$PWD":/app -w /app python:3.12-slim \
  sh -c "pip install -q -e '.[dev]' && pytest -q"
```

## Adicionando um conector
1. Crie `stg/connectors/<categoria>/<ferramenta>.py` herdando de `CommandConnector` ou `ApiConnector`.
2. Preencha os metadados: `name`, `tool`, `category`, `requires_binaries`/`requires_api_keys`/`requires_modules`, `target_types`, `passive`.
3. Implemente:
   - `CommandConnector`: `build_command(target, options, workdir)` e `parse(raw, target)`.
   - `ApiConnector`: `fetch(target, options)` e `parse(raw, target)`.
4. Registre a classe no `CONNECTORS` do `__init__.py` da categoria.
5. Adicione um teste de parser em `tests/` (use uma fixture; nao dependa do binario real).

## Padroes
- Sem `shell=True`; comandos sempre como lista de argumentos.
- Erros viram `ScanStatus` no `ScanResult`, nunca exceptions soltas para o usuario.
- Segredos via `.env`/ambiente, nunca hardcoded.
- Conectores ativos respeitam o gate de autorizacao; OSINT/passivo marca `passive = True`.

## Commits
Mensagens claras e no imperativo. Garanta `ruff check` e `pytest` verdes antes de abrir PR.
