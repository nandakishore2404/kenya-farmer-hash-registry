.PHONY: up down test demo clean local local-reset scenario scenarios keys

# Docker targets (Production & Dev Overrides)
up:
	docker compose up -d --build

up-dev:
	docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d --build

down:
	docker compose down

# Local machine targets (SQLite, Port 8008, Zero Docker dependency)
local:
	python scripts/generate_keys.py --write-env
	python -m uvicorn app.main:app --host 127.0.0.1 --port 8008 --reload

local-reset:
	python scripts/reset_db.py

# Key generation
keys:
	python scripts/generate_keys.py

# Automated Scenarios & Testing
scenario:
	python -m simulator.scenarios $(NAME)

scenarios:
	python -m simulator.scenarios all

test:
	python -m pytest tests/ -v

demo:
	python simulator/runner.py http://localhost:8008

clean:
	python -c "import os, glob; [os.remove(f) for f in glob.glob('*.db') if os.path.exists(f)]"
	python -c "import shutil, glob; [shutil.rmtree(d, ignore_errors=True) for d in glob.glob('**/__pycache__', recursive=True)]"
	python -c "import shutil; shutil.rmtree('.pytest_cache', ignore_errors=True)"
