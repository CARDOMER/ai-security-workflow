import time
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from fastapi import FastAPI
from fastapi.testclient import TestClient

from backend.history import compare_runs
from backend.main import ANALYZERS, ROOT, summarize_metadata
from backend.workflow import make_workflow_router


DEMO = Path(__file__).resolve().parents[2] / "demo"


class HistoryTests(unittest.TestCase):
    def setUp(self):
        folder = TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.database = Path(folder.name) / "history.sqlite3"

    def client(self):
        app = FastAPI()
        app.include_router(make_workflow_router(ROOT, ANALYZERS, summarize_metadata, self.database))
        return TestClient(app)

    def run_project(self, client, filename, project_name, analyzers=("secret", "sast", "sca")):
        upload = client.post(
            "/api/workflow/uploads", content=(DEMO / filename).read_bytes(),
            headers={"X-Training-Project": "authorized"},
        )
        self.assertEqual(upload.status_code, 201)
        nodes = [*("manual", "source"), *analyzers, "merge", "report"]
        edges = [("manual", "source"), ("merge", "report")]
        for name in analyzers:
            edges.extend([("source", name), (name, "merge")])
        started = client.post("/api/workflow/runs", json={
            "uploadId": upload.json()["uploadId"], "projectLabel": project_name,
            "nodes": [{"id": kind, "kind": kind} for kind in nodes],
            "edges": [{"source": source, "target": target} for source, target in edges],
        })
        self.assertEqual(started.status_code, 202, started.text)
        run_id = started.json()["id"]
        for _ in range(80):
            latest = client.get(f"/api/workflow/runs/{run_id}").json()
            if latest["status"] == "done":
                return run_id
            time.sleep(.025)
        self.fail("Workflow did not finish")

    def test_persistent_history_and_comparison_of_independent_archives(self):
        first_client = self.client()
        before = self.run_project(first_client, "check-before.zip", "Demo Desk")
        after = self.run_project(first_client, "check-after.zip", "Demo Desk")
        second_client = self.client()
        response = second_client.get("/api/workflow/history")
        self.assertEqual([entry["id"] for entry in response.json()], [after, before])
        saved = second_client.get(f"/api/workflow/history/{before}").json()
        self.assertEqual(saved["nodes"]["merge"]["status"], "done")
        self.assertEqual(saved["analyzers"], ["sast", "sca", "secret"])
        self.assertEqual(len(saved["report"]["findings"]), 3)
        encoded = self.database.read_bytes()
        self.assertNotIn(b"synthetic-catalog-demo-value", encoded)
        self.assertNotIn(b"file-store-access-key", encoded)
        result = second_client.post("/api/workflow/history/compare", params={"before": before, "after": after})
        self.assertEqual(result.status_code, 200, result.text)
        self.assertEqual({key: len(items) for key, items in result.json().items()},
                         {"added": 0, "removed": 2, "unchanged": 1})

    def test_one_click_demo_saves_and_compares_two_new_runs(self):
        with patch.dict("os.environ", {"WORKFLOW_PUBLIC_DEMO": "1"}):
            client = self.client()
            response = client.post("/api/workflow/demo-comparison")
        self.assertEqual(response.status_code, 200, response.text)
        result = response.json()
        self.assertEqual({key: len(items) for key, items in result["difference"].items()},
                         {"added": 0, "removed": 2, "unchanged": 1})
        runs = client.get("/api/workflow/history").json()
        self.assertEqual([run["id"] for run in runs], [result["after"], result["before"]])
        self.assertEqual([run["count"] for run in runs], [1, 3])
        self.assertTrue(all(run["source"] == "Demo Desk" for run in runs))

    def test_rejects_changed_analyzer_set_and_other_target(self):
        client = self.client()
        before = self.run_project(client, "check-before.zip", "Demo Desk")
        reduced = self.run_project(client, "check-after.zip", "Demo Desk", ("sca",))
        other = self.run_project(client, "check-after.zip", "Another Demo")
        for after in (reduced, other):
            result = client.post("/api/workflow/history/compare", params={"before": before, "after": after})
            self.assertEqual(result.status_code, 422)

    def test_sca_comparison_keeps_exact_versions_before_matching_upgrades(self):
        finding = {
            "category": "SCA", "path": "build.gradle.kts",
            "group": "sample", "artifact": "library", "advisoryId": "GHSA-example",
        }
        common = {"comparable": True, "projectKey": "sample", "analyzers": ["sca"]}
        original = dict(finding, version="1.0")
        retained = dict(finding, version="1.1")
        updated = dict(finding, version="1.2")
        before = {**common, "report": {"findings": [original, retained]}}
        after = {**common, "report": {"findings": [retained]}}
        self.assertEqual(compare_runs(before, after), {"added": [], "removed": [original], "unchanged": [retained]})
        after["report"]["findings"].append(updated)
        self.assertEqual(compare_runs(before, after), {"added": [], "removed": [], "unchanged": [retained, updated]})
