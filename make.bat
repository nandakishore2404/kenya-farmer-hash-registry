@echo off
if "%1"=="" goto help
if "%1"=="test" (
    python -m pytest tests/ -v
    goto end
)
if "%1"=="scenarios" (
    python -m simulator.scenarios all
    goto end
)
if "%1"=="scenario" (
    python -m simulator.scenarios %2
    goto end
)
if "%1"=="demo" (
    python simulator/runner.py http://localhost:8008
    goto end
)
if "%1"=="local" (
    python scripts\generate_keys.py --write-env
    python -m uvicorn app.main:app --host 127.0.0.1 --port 8008 --reload
    goto end
)
if "%1"=="local-reset" (
    python scripts\reset_db.py
    goto end
)
if "%1"=="keys" (
    python scripts\generate_keys.py
    goto end
)
if "%1"=="clean" (
    python -c "import os, glob; [os.remove(f) for f in glob.glob('*.db') if os.path.exists(f)]"
    python -c "import shutil, glob; [shutil.rmtree(d, ignore_errors=True) for d in glob.glob('**/__pycache__', recursive=True)]"
    python -c "import shutil; shutil.rmtree('.pytest_cache', ignore_errors=True)"
    goto end
)
:help
echo Usage: make [test|scenarios|scenario [NAME]|demo|local|local-reset|keys|clean]
:end
