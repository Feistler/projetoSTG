.PHONY: install dev test lint docker run clean

install:
	pip install .

dev:
	pip install -e ".[dev]"

test:
	pytest

lint:
	ruff check stg tests

docker:
	docker build -t stg-toolkit .

# Ex.: make run ARGS="scan nmap 192.168.56.10"
run:
	docker compose run --rm stg $(ARGS)

clean:
	rm -rf stg-data build dist *.egg-info .pytest_cache
