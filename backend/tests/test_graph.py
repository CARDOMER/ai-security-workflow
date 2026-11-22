import json
import time
import unittest
from datetime import datetime, timedelta, timezone
from io import BytesIO
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Event
from types import SimpleNamespace
from unittest.mock import patch
from zipfile import ZipFile

import httpx
from fastapi import FastAPI
from fastapi.testclient import TestClient

from backend.main import ANALYZERS, ROOT, summarize_metadata
from backend.workflow import Step, Workflow, condition_matches, make_workflow_router, ordered_steps, scan_graph


def graph(schedule=False):
    trigger = "schedule" if schedule else "manual"
    kinds = [trigger, "source", "secret", "sca", "sast", "merge", "report", "condition", "ai", "webhook"]
    nodes = [{"id": kind, "kind": kind} for kind in kinds]
    nodes[-3].update(metric="severity", severity="CRITICAL")
    links = [(trigger, "source"), ("source", "secret"), ("source", "sca"), ("source", "sast"),
             ("secret", "merge"), ("sca", "merge"), ("sast", "merge"), ("merge", "report"),
             ("report", "condition"), ("ai", "webhook")]
    return {
        "nodes": nodes, "trigger": trigger,
        "edges": [{"source": source, "target": target} for source, target in links]
        + [{"source": "condition", "target": "ai", "branch": "yes"}],
    }


def variant(prefix=""):
    raw = BytesIO()
    with ZipFile(raw, "w") as archive:
        archive.writestr(prefix + "build.gradle.kts", '''
dependencies {
    add(
        "implementation",
        "org.apache.commons:commons-text:1.9",
    )
}
''')
        archive.writestr(prefix + "src/main/resources/alternate.properties", "service.api-key=synthetic-key-for-fixture-only\n")
        archive.writestr(prefix + "src/main/kotlin/AlternatePolicy.kt", '''
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.HostnameVerifier

fun HttpsURLConnection.trainingPolicy() {
    hostnameVerifier = HostnameVerifier { _, _ -> true }
}
''')
    return raw.getvalue()


class GraphTests(unittest.TestCase):
    def setUp(self):
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        app = FastAPI()
        app.include_router(make_workflow_router(ROOT, ANALYZERS, summarize_metadata, Path(directory.name) / "history.sqlite3"))
        self.client = TestClient(app)

    def start(self, payload):
        response = self.client.post("/api/workflow/runs", json=payload)
        self.assertEqual(response.status_code, 202, response.text)
        return response.json()["id"]

    def snapshot(self, run):
        response = self.client.get(f"/api/workflow/runs/{run}")
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()

    def wait(self, run):
        for _ in range(80):
            snapshot = self.snapshot(run)
            if snapshot["status"] in {"done", "error"}:
                return snapshot
            time.sleep(.035)
        self.fail("Workflow did not complete")

    def test_uploaded_fixture_root_and_wrapper(self):
        for prefix in ("", "alternate/"):
            with self.subTest(prefix=prefix):
                imported = self.client.post("/api/workflow/uploads", content=variant(prefix),
                                            headers={"X-Training-Project": "authorized"})
                self.assertEqual(imported.status_code, 201, imported.text)
                payload = graph()
                payload["uploadId"] = imported.json()["uploadId"]
                payload["nodes"][-3].update(metric="count", minimum=99)
                result = self.wait(self.start(payload))
                self.assertEqual(result["status"], "done")
                self.assertEqual(result["nodes"]["ai"]["status"], "skipped")
                self.assertEqual(result["nodes"]["webhook"]["status"], "skipped")
                findings = result["report"]["findings"]
                self.assertEqual(len(findings), 3)
                self.assertEqual({item["category"] for item in findings}, {"SECRET", "SCA", "SAST"})
                self.assertTrue(any(item["path"].endswith("alternate.properties") for item in findings))
                self.assertNotIn("synthetic-key-for-fixture-only", json.dumps(findings))

    def test_unsafe_archive_paths(self):
        for name in ("../outside.txt", "/outside.txt", "C:/outside.txt", "folder\\..\\outside.txt", "NUL.txt"):
            with self.subTest(name=name):
                raw = BytesIO()
                with ZipFile(raw, "w") as archive:
                    archive.writestr("build.gradle.kts", "")
                    archive.writestr(name, "test")
                result = self.client.post("/api/workflow/uploads", content=raw.getvalue(),
                                          headers={"X-Training-Project": "authorized"})
                self.assertEqual(result.status_code, 422)

    def test_visitor_archive_is_scanned_and_unlisted_in_public_demo(self):
        with TemporaryDirectory() as directory, patch.dict("os.environ", {
            "WORKFLOW_PUBLIC_DEMO": "1", "WORKFLOW_PUBLIC_TELEGRAM": "1",
            "TELEGRAM_BOT_TOKEN": "test-token", "TELEGRAM_CHAT_ID": "test-chat",
            "WORKFLOW_UI_URL": "https://public-demo.example",
        }):
            app = FastAPI()
            app.include_router(make_workflow_router(ROOT, ANALYZERS, summarize_metadata,
                                                    Path(directory) / "history.sqlite3"))
            self.client = TestClient(app)
            request = {"X-Training-Project": "authorized"}
            raw = BytesIO()
            with ZipFile(raw, "w") as archive:
                archive.writestr("commission/build.gradle.kts", "plugins {}")
                archive.writestr("commission/example.properties", "api-key=synthetic-commission-fixture")
            denied = self.client.post("/api/workflow/uploads", content=raw.getvalue())
            self.assertEqual(denied.status_code, 403)
            imported = self.client.post("/api/workflow/uploads", content=raw.getvalue(), headers=request)
            self.assertEqual(imported.status_code, 201, imported.text)
            payload = scan_graph(imported.json()["uploadId"]).model_dump(mode="json", exclude_none=True)
            with patch("backend.notifications.httpx.post", return_value=httpx.Response(200, json={"ok": True})) as send:
                run = self.start(payload)
                result = self.wait(run)
            send.assert_called_once()
            message = send.call_args.kwargs
            self.assertEqual(message["data"]["chat_id"], "test-chat")
            self.assertIn("Проект: Загруженный учебный ZIP", message["data"]["caption"])
            self.assertIn(f"https://public-demo.example/?run={run}#results", message["data"]["caption"])
            self.assertEqual(json.loads(message["files"]["document"][1]), result["report"])
            self.assertEqual(result["status"], "done")
            self.assertEqual(len(result["report"]["findings"]), 1)
            self.assertNotIn("synthetic-commission-fixture", json.dumps(result["report"]))
            self.assertEqual(result["telegramDelivery"], {"status": "delivered", "httpStatus": 200})
            with TestClient(app) as another_browser:
                saved = another_browser.get(f"/api/workflow/history/{run}").json()
                self.assertEqual(saved["report"], result["report"])
                self.assertEqual(saved["source"], "Загруженный учебный ZIP")
                self.assertNotIn(run, {item["id"] for item in another_browser.get("/api/workflow/history").json()})

    def test_graph_validation(self):
        value = graph()
        value["edges"].append({"source": "report", "target": "source"})
        self.assertEqual(self.client.post("/api/workflow/runs", json=value).status_code, 422)
        value = graph()
        value["nodes"][0]["kind"] = "unexpected"
        self.assertEqual(self.client.post("/api/workflow/runs", json=value).status_code, 422)
        value = graph()
        value["nodes"][-3].update(metric="path", pattern="[")
        with self.assertRaisesRegex(ValueError, "выражение"):
            ordered_steps(Workflow.model_validate(value))

    def test_schedule_runs_once_and_regex_selects_branch(self):
        payload = graph(schedule=True)
        payload["nodes"][0]["at"] = (datetime.now(timezone.utc) + timedelta(seconds=.7)).isoformat()
        payload["nodes"][-3].update(metric="path", pattern="non-matching-suffix$")
        run = self.start(payload)
        self.assertEqual(self.snapshot(run)["status"], "scheduled")
        denied = self.client.post("/api/workflow/runs", json=payload)
        self.assertEqual(denied.status_code, 409)
        result = self.wait(run)
        self.assertEqual(result["status"], "done")
        self.assertEqual(result["nodes"]["condition"]["detail"], "Ветка «Нет»")
        self.assertEqual(len(result["report"]["findings"]), 15)
        self.assertEqual(self.snapshot(run), result)

    def test_regex_checks_findings_after_position_100(self):
        paths = [SimpleNamespace(path=f"file-{index}.kt") for index in range(100)]
        paths.append(SimpleNamespace(path="match.kt"))
        condition = Step(id="condition", kind="condition", metric="path", pattern="^match")
        self.assertTrue(condition_matches(condition, paths))

    def test_empty_builtin_project_cannot_produce_a_clean_report(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            empty = root / "empty"
            empty.mkdir()
            app = FastAPI()
            app.include_router(make_workflow_router(empty, ANALYZERS, summarize_metadata,
                                                    root / "history.sqlite3"))
            with TestClient(app) as client:
                self.client = client
                run = self.start(graph())
                result = self.wait(run)
                saved = client.get(f"/api/workflow/history/{run}").json()
            self.assertEqual(result["status"], "error")
            self.assertEqual(result["nodes"]["source"]["status"], "error")
            self.assertNotIn("report", result)
            self.assertFalse(saved["comparable"])

    def test_demo_webhook_acknowledges_actual_workflow_delivery(self):
        def local_delivery(_url, *, json, headers, **_options):
            return self.client.post("/api/workflow/demo-webhook", json=json, headers=headers)

        with (
            patch.dict("os.environ", {"WORKFLOW_WEBHOOK_URL": "http://127.0.0.1:8000/api/workflow/demo-webhook"}),
            patch("backend.workflow.get_summary_provider", return_value=None),
            patch("backend.workflow.httpx.post", side_effect=local_delivery),
        ):
            run = self.start(graph())
            result = self.wait(run)
        self.assertEqual(result["nodes"]["webhook"]["output"]["httpStatus"], 202)
        self.assertEqual(result["delivery"]["runId"], run)

    def test_webhook_labels_an_incomplete_report(self):
        payload = graph()
        payload["nodes"][-3].update(severity="HIGH")
        response = httpx.Response(202, json={"accepted": True}, request=httpx.Request("POST", "http://127.0.0.1/"))
        with patch.object(ANALYZERS["sca"], "scan", side_effect=OSError), \
             patch("backend.workflow.get_summary_provider", return_value=None), \
             patch("backend.workflow.httpx.post", return_value=response) as delivery:
            run = self.start(payload)
            result = self.wait(run)
        self.assertEqual(result["status"], "error")
        self.assertEqual(len(result["report"]["findings"]), 10)
        self.assertEqual(result["nodes"]["webhook"]["status"], "done")
        sent = delivery.call_args.kwargs["json"]
        self.assertFalse(sent["reportComplete"])
        self.assertEqual(sent["failedAnalyzers"], ["sca"])

    def test_link_is_already_resolvable_at_delivery_and_summary_persists(self):
        captured = []

        def delivery(_url, *, json, **_options):
            stored = self.client.get(f"/api/workflow/history/{json['runId']}").json()
            captured.append((json, stored))
            return httpx.Response(202, json={"accepted": True}, request=httpx.Request("POST", "http://127.0.0.1/"))

        with patch.dict("os.environ", {"WORKFLOW_UI_URL": "https://example.test"}), \
             patch("backend.workflow.get_summary_provider", return_value=None), \
             patch("backend.workflow.httpx.post", side_effect=delivery):
            run = self.start(graph())
            state = self.wait(run)
        self.assertEqual(state["status"], "done")
        self.assertEqual(state["nodes"]["condition"]["input"]["severity"], "CRITICAL")
        self.assertEqual(state["nodes"]["condition"]["output"]["branch"], "yes")
        self.assertEqual(state["nodes"]["webhook"]["output"]["httpStatus"], 202)
        payload, at_delivery = captured[0]
        self.assertEqual(payload["reportUrl"], f"https://example.test/?run={run}#results")
        self.assertEqual(at_delivery["count"], 15)
        final = self.client.get(f"/api/workflow/history/{run}").json()
        self.assertEqual(final["summary"], state["summary"])
        self.assertEqual(final["status"], "done")

    def test_history_failure_explains_missing_report_link(self):
        response = httpx.Response(202, json={"accepted": True}, request=httpx.Request("POST", "http://127.0.0.1/"))
        with patch.dict("os.environ", {"WORKFLOW_UI_URL": "https://example.test"}), \
             patch("backend.workflow.RunHistory.save", side_effect=OSError), \
             patch("backend.workflow.httpx.post", return_value=response) as delivery:
            result = self.wait(self.start(graph()))
        self.assertIn("historyError", result)
        payload = delivery.call_args.kwargs["json"]
        self.assertNotIn("reportUrl", payload)
        self.assertIn("История недоступна", payload["reportUrlUnavailable"])

    def test_telegram_delivery_uses_only_a_preconfigured_test_chat(self):
        payload = graph()
        payload["nodes"][-1]["kind"] = "telegram"
        response = httpx.Response(200, json={"ok": True}, request=httpx.Request("POST", "https://api.telegram.org/"))
        with patch.dict("os.environ", {"TELEGRAM_BOT_TOKEN": "test-token", "TELEGRAM_CHAT_ID": "test-chat"}), \
             patch("backend.notifications.httpx.post", return_value=response) as delivery:
            result = self.wait(self.start(payload))
        self.assertEqual(result["nodes"]["webhook"]["output"]["httpStatus"], 200)
        request = delivery.call_args.kwargs["json"]
        self.assertEqual(request["chat_id"], "test-chat")
        self.assertIn("SECRET: 5", request["text"])
        self.assertNotIn("src/main", request["text"])

    def test_public_telegram_uses_saved_report_and_dedicated_chat(self):
        with TemporaryDirectory() as directory, patch.dict("os.environ", {
            "WORKFLOW_PUBLIC_DEMO": "1", "WORKFLOW_PUBLIC_TELEGRAM": "1",
            "TELEGRAM_BOT_TOKEN": "test-token", "TELEGRAM_CHAT_ID": "test-chat",
            "WORKFLOW_UI_URL": "https://public-demo.example",
        }):
            app = FastAPI()
            app.include_router(make_workflow_router(ROOT, ANALYZERS, summarize_metadata,
                                                    Path(directory) / "history.sqlite3"))
            self.client = TestClient(app)
            graph_data = scan_graph().model_dump(mode="json", exclude_none=True)

            def deliver(url, *, data, files, **_options):
                self.assertTrue(url.endswith("/sendDocument"))
                self.assertEqual(data["chat_id"], "test-chat")
                link = data["caption"].splitlines()[-1]
                self.assertTrue(link.startswith("https://public-demo.example/?run="))
                run_id = link.split("=", 1)[1].split("#", 1)[0]
                saved = self.client.get(f"/api/workflow/history/{run_id}").json()
                self.assertEqual(saved["status"], "done")
                self.assertEqual(saved["count"], 15)
                self.assertEqual(json.loads(files["document"][1]), saved["report"])
                return httpx.Response(200, json={"ok": True})

            with patch("backend.notifications.httpx.post", side_effect=deliver) as sender:
                for _ in range(5):
                    result = self.wait(self.start(graph_data))
                    self.assertEqual(result["telegramDelivery"], {"status": "delivered", "httpStatus": 200})
                limited = self.wait(self.start(graph_data))
                self.assertEqual(limited["status"], "done")
                self.assertEqual(limited["telegramDelivery"], {"status": "rate_limited"})
                self.assertEqual(sender.call_count, 5)

            with (
                patch("backend.workflow.RunHistory.reserve_telegram_notification", return_value=True),
                patch("backend.notifications.httpx.post", side_effect=httpx.ConnectError("offline")),
            ):
                failed = self.wait(self.start(graph_data))
                self.assertEqual(failed["status"], "done")
                self.assertEqual(len(failed["report"]["findings"]), 15)
                self.assertEqual(failed["telegramDelivery"], {"status": "failed"})

    def test_report_available_during_ai_and_webhook_failure(self):
        entered = Event()
        release = Event()

        class OfflineProvider:
            def summarize(self, metadata):
                entered.set()
                release.wait(2)
                raise httpx.ConnectError("test offline")

        response = httpx.Response(503, request=httpx.Request("POST", "http://127.0.0.1/"))
        with patch("backend.workflow.get_summary_provider", return_value=OfflineProvider()), \
             patch("backend.workflow.httpx.post", return_value=response) as delivery:
            run = self.start(graph())
            try:
                self.assertTrue(entered.wait(2))
                state = self.snapshot(run)
                self.assertEqual(state["nodes"]["ai"]["status"], "running")
                self.assertEqual(len(state["report"]["findings"]), 15)
            finally:
                release.set()
            result = self.wait(run)
            self.assertEqual(result["status"], "error")
            self.assertEqual(result["summary"]["mode"], "rules")
            self.assertEqual(
                [event["status"] for event in result["events"] if event["nodeId"] == "ai"],
                ["waiting", "running", "done"],
            )
            self.assertIn("503", result["nodes"]["webhook"]["detail"])
            self.assertEqual(result["report"], state["report"])
            sent = delivery.call_args.kwargs["json"]
            self.assertEqual(sent["counts"], {"SECRET": 5, "SCA": 5, "SAST": 5})
            self.assertEqual(sent["maxSeverity"], "CRITICAL")
            self.assertTrue(sent["reportComplete"])
            self.assertEqual(sent["failedAnalyzers"], [])
            self.assertIn("recommendations", sent)

    def test_rejects_invented_advisory_in_free_text(self):
        metadata = [{"id": 1, "category": "SCA", "severity": "HIGH", "group": "g", "artifact": "a",
                     "advisoryId": "GHSA-1111-2222-3333"}]

        class Provider:
            def summarize(self, _):
                return json.dumps({
                    "summary": "Исправить CVE-2026-9999.",
                    "priorities": [{"action": "Обновить", "reason": "Высокий риск", "findingIds": [1]}],
                })

        self.assertEqual(summarize_metadata(metadata, Provider()).mode, "rules")
