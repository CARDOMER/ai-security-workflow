"""Run the security gate against a Kotlin/Gradle project or a training fixture."""

import argparse
from collections.abc import Callable
from functools import partial
import json
from os import walk
from pathlib import Path
from tempfile import TemporaryDirectory
from time import monotonic, sleep
from zipfile import ZipFile

import httpx
from fastapi import FastAPI
from fastapi.testclient import TestClient

from backend.main import ANALYZERS, ROOT, summarize_metadata
from backend.workflow import make_workflow_router, scan_graph


def gate(snapshot: dict) -> tuple[int, str]:
    failed = [name for name in ANALYZERS if snapshot["nodes"].get(name, {}).get("status") != "done"]
    report = snapshot.get("report")
    if snapshot["status"] != "done" or failed or report is None:
        suffix = f" Analyzer status: {', '.join(failed)}." if failed else ""
        return 2, f"Incomplete security report.{suffix}"
    critical = sum(finding["severity"] == "CRITICAL" for finding in report["findings"])
    if critical:
        return 1, f"Security gate failed: {critical} critical finding(s)."
    return 0, f"Security gate passed: {len(report['findings'])} finding(s), none critical."


def run_training(scenario: str, directory: Path) -> dict:
    return run_workflow(ROOT, directory, clean_fixture=scenario == "clean-training")


def run_project(project: Path, directory: Path, *, checkout: Path | None = None) -> dict:
    if checkout is not None and not project.resolve().is_relative_to(checkout.resolve()):
        raise ValueError("The project directory must be inside the source checkout.")
    if not (project / "build.gradle.kts").is_file():
        raise ValueError("The project directory must contain build.gradle.kts.")
    for folder, directories, files in walk(project):
        if any((Path(folder) / name).is_symlink() for name in directories + files):
            raise ValueError("Symbolic links are unsupported in the project tree.")
    return run_workflow(project, directory)


def run_workflow(project: Path, directory: Path, *, clean_fixture: bool = False) -> dict:
    history = directory / "history.sqlite3"
    app = FastAPI()
    app.include_router(make_workflow_router(project, ANALYZERS, summarize_metadata, history))
    with TestClient(app) as client:
        if clean_fixture:
            archive = directory / "clean-training.zip"
            with ZipFile(archive, "w") as fixture:
                fixture.writestr("build.gradle.kts", "dependencies {}\n")
                fixture.writestr("src/main/kotlin/Training.kt", "package training\nfun label() = \"Training\"\n")
            response = client.post("/api/workflow/uploads", content=archive.read_bytes(),
                                   headers={"X-Training-Project": "authorized"})
            response.raise_for_status()
            graph = scan_graph(response.json()["uploadId"], "Clean Training")
        else:
            graph = scan_graph()
        response = client.post("/api/workflow/runs", json=graph.model_dump(mode="json", exclude_none=True))
        response.raise_for_status()
        run_id = response.json()["id"]
        deadline = monotonic() + 30
        while monotonic() < deadline:
            response = client.get(f"/api/workflow/runs/{run_id}")
            response.raise_for_status()
            snapshot = response.json()
            if snapshot["status"] in {"done", "error"}:
                return snapshot
            sleep(.05)
    raise TimeoutError("Security workflow timed out.")


def run_gate(scenario: str | Path, output: Path, runner: Callable | None = None) -> tuple[int, str]:
    if runner is None:
        runner = run_project if isinstance(scenario, Path) else run_training
    output.mkdir(parents=True, exist_ok=True)
    with TemporaryDirectory() as directory:
        try:
            snapshot = runner(scenario, Path(directory))
            code, reason = gate(snapshot)
            (output / "security-report.json").write_text(
                json.dumps(snapshot.get("report") or {"findings": []}, ensure_ascii=False, indent=2), encoding="utf-8",
            )
        except ValueError as error:
            code, reason = 2, str(error)
            (output / "security-report.json").write_text('{"findings":[]}', encoding="utf-8")
        except (TimeoutError, KeyError, OSError, httpx.HTTPError) as error:
            code, reason = 2, f"Security workflow could not finish ({type(error).__name__})."
            (output / "security-report.json").write_text('{"findings":[]}', encoding="utf-8")
    (output / "security-gate.json").write_text(
        json.dumps({"scenario": "project" if isinstance(scenario, Path) else scenario,
                    "exitCode": code, "reason": reason}, indent=2), encoding="utf-8",
    )
    return code, reason


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("scenario", nargs="?", choices=["clean-training", "repair-desk"])
    parser.add_argument("--project", type=Path, help="Path to the project containing build.gradle.kts")
    parser.add_argument("--checkout", type=Path, help="Restrict --project to this checkout")
    parser.add_argument("--output", type=Path, default=Path("ci-artifacts"))
    arguments = parser.parse_args()
    if (arguments.scenario is None) == (arguments.project is None):
        parser.error("Specify either a training scenario or --project.")
    if arguments.checkout is not None and arguments.project is None:
        parser.error("--checkout requires --project.")
    if arguments.project is None:
        code, reason = run_gate(arguments.scenario, arguments.output)
    else:
        code, reason = run_gate(arguments.project, arguments.output, partial(run_project, checkout=arguments.checkout))
    print(reason)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
