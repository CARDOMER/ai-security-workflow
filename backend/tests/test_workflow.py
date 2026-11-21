import unittest
from collections import Counter
from unittest.mock import patch

from fastapi.testclient import TestClient

from backend.main import ANALYZERS, ROOT, app


class WorkflowTests(unittest.TestCase):
    client = TestClient(app)

    def test_selected_analyzer_only(self):
        with (
            patch.object(ANALYZERS["secret"], "scan") as secret,
            patch.object(ANALYZERS["sca"], "scan", wraps=ANALYZERS["sca"].scan) as sca,
            patch.object(ANALYZERS["sast"], "scan") as sast,
        ):
            response = self.client.post("/api/scan", json={"analyzers": ["sca"]})
            secret.assert_not_called()
            sca.assert_called_once_with(ROOT)
            sast.assert_not_called()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(Counter(item["category"] for item in response.json()["findings"]), {"SCA": 5})

    def test_all_analyzers_and_legacy_request(self):
        response = self.client.post("/api/scan", json={"analyzers": ["secret", "sca", "sast"]})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), self.client.post("/api/scan").json())
        self.assertEqual(
            Counter(item["category"] for item in response.json()["findings"]),
            {"SECRET": 5, "SCA": 5, "SAST": 5},
        )

    def test_unknown_analyzer_rejects_entire_request(self):
        with patch.object(ANALYZERS["sca"], "scan") as sca:
            response = self.client.post("/api/scan", json={"analyzers": ["sca", "unknown"]})
            self.assertEqual(response.status_code, 422)
            sca.assert_not_called()

    def test_empty_selection_is_rejected(self):
        self.assertEqual(self.client.post("/api/scan", json={"analyzers": []}).status_code, 422)
