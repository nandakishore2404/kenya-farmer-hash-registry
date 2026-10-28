import os
import sys
import time
import subprocess
import shutil

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
os.chdir(ROOT)
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

os.environ["ENV"] = "development"
os.environ["EVALUATOR_SECRET_K"] = "e8c7b6a5d4c3b2a1908f7e6d5c4b3a2918273645e5d4c3b2a10987654321abcd"
os.environ["EVALUATOR_KEY_ID"] = "ke-pilot-v3"
os.environ["SERVER_KEY"] = "test_server_secret_rekey_key_abc123"
os.environ["ADMIN_KEY"] = "test_admin_key_super_secret"
os.environ["DASHBOARD_PASSWORD"] = "dev_dashboard_password"
os.environ["DATABASE_URL"] = "sqlite:///./dev_registry.db"

# 1. Start OAN server directly using existing populated dev_registry.db
print("Starting OAN server...")
proc = subprocess.Popen([sys.executable, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", "8008"])

edge_path = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
os.makedirs("docs/screenshots", exist_ok=True)
frontend_png = os.path.abspath("docs/screenshots/actual_prototype_frontend.png")
monitoring_png = os.path.abspath("docs/screenshots/actual_monitoring_dashboard.png")

artifact_dir = r"C:\Users\nanda\.gemini\antigravity\brain\17dc6c6d-72a4-4e5f-ad57-86fd4a30df0a"

try:
    time.sleep(4.0)

    # Capture actual prototype frontend (/dev/console)
    print("Capturing Prototype Front End...")
    cmd1 = [
        edge_path,
        "--headless",
        "--hide-scrollbars",
        "--window-size=1400,1050",
        f"--screenshot={frontend_png}",
        "http://127.0.0.1:8008/dev/console"
    ]
    subprocess.run(cmd1, check=True)

    # Capture actual monitoring dashboard (/dashboard)
    print("Capturing Monitoring Dashboard...")
    cmd2 = [
        edge_path,
        "--headless",
        "--hide-scrollbars",
        "--window-size=1400,1200",
        f"--screenshot={monitoring_png}",
        "http://admin:dev_dashboard_password@127.0.0.1:8008/dashboard"
    ]
    subprocess.run(cmd2, check=True)

    # Copy to artifacts directory
    if os.path.exists(frontend_png):
        shutil.copy(frontend_png, os.path.join(artifact_dir, "actual_prototype_frontend.png"))
        print(f"Copied {frontend_png} -> {artifact_dir}")

    if os.path.exists(monitoring_png):
        shutil.copy(monitoring_png, os.path.join(artifact_dir, "actual_monitoring_dashboard.png"))
        print(f"Copied {monitoring_png} -> {artifact_dir}")

    print("Success! Screenshots generated and copied.")
finally:
    proc.terminate()
    proc.wait()
