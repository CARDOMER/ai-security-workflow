from os import getenv
from pathlib import Path

from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from backend.main import DATABASE, ROOT, app

PROJECT = ROOT.parents[1]
FRONTEND = Path(getenv("WORKFLOW_FRONTEND_DIR", str(PROJECT / "frontend" / "dist")))

if not (ROOT / "build.gradle.kts").is_file() or not DATABASE.is_file():
    raise RuntimeError("The Repair Desk training data is missing from the deployment.")

app.mount("/assets", StaticFiles(directory=FRONTEND / "assets"), name="assets")
app.mount("/demo", StaticFiles(directory=PROJECT / "demo"), name="demo")


@app.get("/", include_in_schema=False)
def index():
    return FileResponse(FRONTEND / "index.html")
