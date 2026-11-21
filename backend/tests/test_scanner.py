import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from fastapi.testclient import TestClient

from backend.main import ROOT, app


def identity(item):
    return item["category"], item["path"], item["class"], item["line"], item.get("endLine", item["line"])


class ScannerTests(unittest.TestCase):
    client = TestClient(app)

    def test_training_dataset_matches_reference(self):
        reference = ROOT.parent / "ground-truth" / "training-findings.json"
        expected = json.loads(reference.read_text(encoding="utf-8"))
        response = self.client.post("/api/scan")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(set(response.json()), {"findings"})
        findings = [item for item in response.json()["findings"] if item["category"] == "SECRET"]
        self.assertCountEqual(
            [identity(item) for item in findings],
            [identity(item) for item in expected["findings"] if item["category"] == "SECRET"],
        )
        self.assertTrue(all("••••••••" in item["description"] for item in findings))
        self.assertTrue(all(item["severity"] in {"MEDIUM", "HIGH"} for item in findings))

    def test_new_files_are_scanned_and_controls_are_ignored(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "build.gradle.kts").touch()
            file = root / "custom.yml"
            value = "completely-new-fixture-value"
            file.write_text(
                f"api-key: {value}\n" "token: ${SAFE_TOKEN}\npassword: changeme\n",
                encoding="utf-8",
            )
            with patch("backend.main.ROOT", root):
                response = self.client.post("/api/scan")
                self.assertEqual(response.status_code, 200)
                self.assertNotIn(value, response.text)
                self.assertEqual(
                    [identity(item) for item in response.json()["findings"]],
                    [("SECRET", "custom.yml", "api-key", 1, 1)],
                )
                file.write_text("token: ${SAFE_TOKEN}\n", encoding="utf-8")
                self.assertEqual(self.client.post("/api/scan").json(), {"findings": []})

    def test_composition_requires_authorization_context(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "build.gradle.kts").touch()
            source = root / "Fixture.kt"
            code = '\n'.join([
                'val first = "synthetic-first"',
                'val second = "synthetic-second"',
                'val combined = first + second',
            ])
            source.write_text(code, encoding="utf-8")
            with patch("backend.main.ROOT", root):
                self.assertEqual(self.client.post("/api/scan").json(), {"findings": []})
                source.write_text(code + "\nheaders.setBearerAuth(combined)", encoding="utf-8")
                response = self.client.post("/api/scan")
                self.assertNotIn("synthetic-first", response.text)
                self.assertNotIn("synthetic-second", response.text)
                self.assertEqual(
                    [identity(item) for item in response.json()["findings"]],
                    [("SECRET", "Fixture.kt", "recoverable-token", 1, 4)],
                )

    def test_missing_dataset_returns_service_unavailable(self):
        with TemporaryDirectory() as directory:
            with patch("backend.main.ROOT", Path(directory) / "missing"):
                self.assertEqual(self.client.post("/api/scan").status_code, 503)
