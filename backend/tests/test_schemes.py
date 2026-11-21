import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import Mock, patch

from fastapi import FastAPI
from fastapi.testclient import TestClient

from backend.main import ANALYZERS, ROOT, summarize_metadata
from backend.schemes import make_scheme_router
from backend.workflow import make_workflow_router, scan_graph


def example_draft():
    graph = scan_graph().model_dump(mode="json", exclude_none=True)
    nodes = [dict(node, x=index * 220, y=0) for index, node in enumerate(graph["nodes"])]
    return {"version": 1, "nodes": nodes, "edges": graph["edges"]}


class SchemeTests(unittest.TestCase):
    def setUp(self):
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        database = Path(directory.name) / "history.sqlite3"
        app = FastAPI()
        app.include_router(make_scheme_router(database))
        app.include_router(make_workflow_router(ROOT, ANALYZERS, summarize_metadata, database))
        self.app = app
        self.client = TestClient(app)

    def test_template_can_be_copied_and_changed_without_mutating_original(self):
        draft = example_draft()
        response = self.client.post("/api/workflow/templates", json={
            "title": "Training", "description": "Static review", "draft": draft,
        })
        self.assertEqual(response.status_code, 201, response.text)
        with TestClient(self.app) as another_session:
            copied = another_session.get("/api/workflow/templates").json()[0]["draft"]
            copied["nodes"][0]["x"] = 333
            self.assertEqual(another_session.get("/api/workflow/templates").json()[0]["draft"]["nodes"][0]["x"], 0)

    def test_template_rejects_payload_with_archive_or_token(self):
        for extra in ({"uploadId": "archive"}, {"token": "synthetic-token"}):
            result = self.client.post("/api/workflow/templates", json={
                "title": "Training", "description": "Static review", "draft": {**example_draft(), **extra},
            })
            self.assertEqual(result.status_code, 422)

    def test_generation_uses_llm_and_rejects_invalid_graph(self):
        provider = Mock()
        scenario = {"supported": True, "trigger": "manual", "analyzers": ["secret", "sca"],
                    "condition": {"metric": "severity", "severity": "HIGH"}, "ai": True, "webhook": True}
        provider.complete.side_effect = [json.dumps(scenario), json.dumps(dict(scenario, analyzers=["secret", "secret"]))]
        with (
            patch.dict("os.environ", {"WORKFLOW_PUBLIC_DEMO": "0"}),
            patch("backend.schemes.get_summary_provider", return_value=provider),
        ):
            result = self.client.post("/api/workflow/generate", json={"prompt": "Проверь учебный проект."})
            self.assertEqual(result.status_code, 200, result.text)
            self.assertEqual(result.json()["nodes"][0]["kind"], "manual")
            self.assertIn({"source": "condition", "target": "ai", "branch": "yes"}, result.json()["edges"])
            invalid = self.client.post("/api/workflow/generate", json={"prompt": "Проверь учебный проект."})
            self.assertEqual(invalid.status_code, 422)
        with patch.dict("os.environ", {"WORKFLOW_PUBLIC_DEMO": "1"}):
            unavailable = self.client.post("/api/workflow/generate", json={"prompt": "Проверь учебный проект."})
            self.assertEqual(unavailable.status_code, 503)

    def test_generated_schedule_needs_a_valid_time(self):
        provider = Mock()
        provider.complete.return_value = json.dumps({
            "supported": True, "trigger": "schedule", "analyzers": ["sca"], "ai": False, "webhook": False,
        })
        with (
            patch.dict("os.environ", {"WORKFLOW_PUBLIC_DEMO": "0"}),
            patch("backend.schemes.get_summary_provider", return_value=provider),
        ):
            response = self.client.post("/api/workflow/generate", json={"prompt": "Проверь позже."})
        self.assertEqual(response.status_code, 422)
