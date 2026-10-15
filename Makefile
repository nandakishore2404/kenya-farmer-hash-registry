.PHONY: up down test demo clean

up:
	docker compose up -d --build

down:
	docker compose down

test:
	python -m pytest tests/ -v

demo:
	python simulator/runner.py http://localhost:8000

clean:
	rm -f registry.db test_registry.db
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type d -name ".pytest_cache" -exec rm -rf {} +
