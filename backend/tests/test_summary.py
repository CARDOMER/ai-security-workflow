import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import Mock, patch

import httpx
from fastapi.testclient import TestClient

from backend.history import RunHistory
from backend.main import app
from backend.summary import GigaChatProvider, YandexProvider, REPORT_SIGNATURE_HEADER, get_summary_provider


class SummaryTests(unittest.TestCase):
    client = TestClient(app)

    def test_gigachat_freemium_oauth_and_structured_request(self):
        requests = []

        def respond(request):
            requests.append(request)
            if len(requests) == 1:
                return httpx.Response(200, json={"access_token": "test-token"})
            return httpx.Response(200, json={"choices": [
                {"finish_reason": "stop", "message": {"content": "{}"}},
            ]})

        with patch.dict("os.environ", {
            "AI_SUMMARY_PROVIDER": "gigachat", "AI_SUMMARY_MODEL": "GigaChat-2-Max",
            "GIGACHAT_CREDENTIALS": "test-key", "GIGACHAT_CA_FILE": "",
        }):
            provider = get_summary_provider()
        self.assertIsInstance(provider, GigaChatProvider)
        with patch("backend.summary.httpx.Client", return_value=httpx.Client(transport=httpx.MockTransport(respond))):
            self.assertEqual(provider.summarize([{"id": 1}]), "{}")

        auth, completion = requests
        self.assertEqual(str(auth.url), "https://ngw.devices.sberbank.ru:9443/api/v2/oauth")
        self.assertEqual(auth.headers["Authorization"], "Basic test-key")
        self.assertIn("rquid", auth.headers)
        self.assertEqual(auth.content, b"scope=GIGACHAT_API_PERS")
        self.assertEqual(str(completion.url), "https://api.giga.chat/v1/chat/completions")
        self.assertEqual(completion.headers["Authorization"], "Bearer test-token")
        payload = json.loads(completion.content)
        self.assertEqual(payload["model"], "GigaChat-2-Max")
        self.assertTrue(payload["response_format"]["strict"])
        self.assertEqual(json.loads(payload["messages"][1]["content"]), [{"id": 1}])
        self.assertNotIn("test-key", completion.content.decode())

    def report(self, analyzers=None):
        response = self.client.post("/api/scan", json={"analyzers": analyzers} if analyzers else None)
        self.assertEqual(response.status_code, 200)
        return response.json(), {REPORT_SIGNATURE_HEADER: response.headers[REPORT_SIGNATURE_HEADER]}

    def submit(self, provider, report, headers):
        app.dependency_overrides[get_summary_provider] = lambda: provider
        self.addCleanup(app.dependency_overrides.pop, get_summary_provider, None)
        return self.client.post("/api/report/summary", json=report, headers=headers)

    def test_sends_only_signed_metadata_and_accepts_valid_references(self):
        report, headers = self.report()
        report["findings"][0]["description"] = "marker-never-forward"
        provider = Mock()
        provider.summarize.return_value = json.dumps({
            "summary": "Сначала исправьте находки высокой критичности.",
            "priorities": [{"action": "Замените секрет", "reason": "Снизит риск доступа", "findingIds": [1]}],
        })
        response = self.submit(provider, report, headers)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["mode"], "llm")
        self.assertEqual(response.json()["priorities"][0]["findingIds"], [1])
        metadata = provider.summarize.call_args.args[0]
        self.assertEqual(len(metadata), 15)
        self.assertEqual(set(metadata[0]), {"id", "class", "path", "category", "severity", "line"})
        sca = next(item for item in metadata if item["category"] == "SCA")
        self.assertEqual(set(sca), {"id", "category", "path", "severity", "group", "artifact", "version", "advisoryId"})
        self.assertTrue(all("description" not in item and "remediation" not in item for item in metadata))
        self.assertNotIn("marker-never-forward", json.dumps(metadata))

    def test_rejects_reference_outside_current_report(self):
        report, headers = self.report(["sca"])
        provider = Mock()
        provider.summarize.return_value = json.dumps({
            "summary": "Сводка",
            "priorities": [{"action": "Действие", "reason": "Причина", "findingIds": [6]}],
        })
        result = self.submit(provider, report, headers)
        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.json()["mode"], "rules")
        self.assertTrue(all(1 <= n <= 5 for item in result.json()["priorities"] for n in item["findingIds"]))

    def test_timeout_is_reported_separately(self):
        report, headers = self.report(["sca"])
        provider = Mock()
        provider.summarize.side_effect = httpx.ReadTimeout("private provider details")
        response = self.submit(provider, report, headers)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["mode"], "rules")
        self.assertIn("вовремя", response.json()["fallbackReason"])
        self.assertNotIn("private provider details", response.text)

    def test_missing_configuration(self):
        report, headers = self.report(["sca"])
        with patch.dict("os.environ", {"AI_SUMMARY_PROVIDER": "yandex", "YANDEX_API_KEY": "", "YANDEX_FOLDER_ID": "test-folder"}):
            response = self.client.post("/api/report/summary", json=report, headers=headers)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["mode"], "rules")
        self.assertEqual(len(data["priorities"]), 3)
        first = data["priorities"][0]["findingIds"][0]
        self.assertEqual(report["findings"][first - 1]["severity"], "CRITICAL")

    def test_connection_failure_uses_rules(self):
        report, headers = self.report()
        provider = Mock()
        provider.summarize.side_effect = httpx.ConnectError("offline")
        response = self.submit(provider, report, headers)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["mode"], "rules")
        self.assertIn("15", response.json()["summary"])

    def test_manual_summary_is_saved_with_the_workflow_report(self):
        report, _ = self.report(["sca"])
        with TemporaryDirectory() as directory:
            database = Path(directory) / "history.sqlite3"
            history = RunHistory(database)
            entry = {"id": "training-run", "status": "running", "completedAt": "2026-01-01",
                     "report": report, "summary": None}
            history.save(entry)
            endpoint = "/api/workflow/history/training-run/summary"
            with (
                patch("backend.main.HISTORY_PATH", database),
                patch.dict("os.environ", {"WORKFLOW_PUBLIC_DEMO": "1"}),
            ):
                self.assertEqual(self.client.post(endpoint).status_code, 409)
                history.save(dict(entry, status="done"))
                response = self.client.post(endpoint)
            self.assertEqual(response.status_code, 200, response.text)
            saved = RunHistory(database).find(entry["id"])
            self.assertEqual(saved["summary"], response.json())
            self.assertEqual(saved["report"], report)

    def test_legacy_openai_configuration_cannot_activate_cloud(self):
        with patch.dict("os.environ", {"AI_SUMMARY_PROVIDER": "openai", "OPENAI_API_KEY": "test", "YANDEX_API_KEY": "test"}):
            self.assertIsNone(get_summary_provider())

    def test_tampered_metadata_never_reaches_provider(self):
        report, headers = self.report(["sca"])
        report["findings"][0]["path"] = "unexpected/path"
        provider = Mock()
        self.assertEqual(self.submit(provider, report, headers).status_code, 422)
        provider.summarize.assert_not_called()

    def test_yandex_adapter_builds_structured_request(self):
        with patch.dict("os.environ", {
            "AI_SUMMARY_PROVIDER": "yandex", "AI_SUMMARY_MODEL": "yandexgpt-5.1",
            "YANDEX_FOLDER_ID": "test-folder", "YANDEX_API_KEY": "test-key",
        }):
            provider = get_summary_provider()
        self.assertIsInstance(provider, YandexProvider)
        choice = {"finish_reason": "stop", "message": {"content": "{}"}}
        endpoint = "https://ai.api.cloud.yandex.net/v1/chat/completions"
        response = httpx.Response(200, json={"choices": [choice]}, request=httpx.Request("POST", endpoint))
        with patch("backend.summary.httpx.post", return_value=response) as post:
            self.assertEqual(provider.summarize([{"id": 1, "category": "SCA"}]), "{}")
        args, kwargs = post.call_args
        self.assertEqual(args[0], endpoint)
        self.assertEqual(kwargs["headers"]["Authorization"], "Api-Key test-key")
        self.assertEqual(kwargs["headers"]["OpenAI-Project"], "test-folder")
        self.assertEqual(kwargs["headers"]["x-data-logging-enabled"], "false")
        payload = kwargs["json"]
        self.assertEqual(payload["model"], "gpt://test-folder/yandexgpt-5.1")
        self.assertNotIn("test-key", json.dumps(payload))
        self.assertFalse(payload["store"])
        self.assertTrue(payload["response_format"]["json_schema"]["strict"])
        self.assertEqual(json.loads(payload["messages"][1]["content"]), [{"id": 1, "category": "SCA"}])
