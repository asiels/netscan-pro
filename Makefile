.PHONY: install dev lint typecheck test run clean

install:
	pip install -e .

dev:
	pip install -e ".[dev]"
	pre-commit install

lint:
	ruff check . && ruff format --check .

typecheck:
	mypy netscan

test:
	pytest --cov=netscan

run:
	python main.py -t scanme.nmap.org -p 1-1024

clean:
	rm -rf .cache reports .coverage coverage.xml htmlcov dist *.egg-info
	find . -type d -name __pycache__ -exec rm -rf {} +
