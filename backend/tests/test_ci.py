import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from backend.ci import run_gate
from backend.main import ANALYZERS, ROOT


class SecurityGateTests(unittest.TestCase):
    def test_project_path_is_scanned_instead_of_the_default_fixture(self):
        with TemporaryDirectory() as directory:
            base = Path(directory)
            output, project = base / "artifacts", base / "source"
            project.mkdir()
            self.assertEqual(run_gate(project, output)[0], 2)
            self.assertEqual(run_gate(ROOT, output)[0], 1)
            (project / "build.gradle.kts").write_text("dependencies {}\n", encoding="utf-8")
            self.assertEqual(run_gate(project, output)[0], 0)
            report = json.loads((output / "security-report.json").read_text("utf-8"))
            self.assertEqual(report["findings"], [])

    def test_training_fixtures_produce_real_gate_outcomes(self):
        for fixture, expected_exit, expected_count in (("clean-training", 0, 0), ("repair-desk", 1, 15)):
            with self.subTest(fixture=fixture), TemporaryDirectory() as directory:
                output = Path(directory)
                code, _ = run_gate(fixture, output)
                self.assertEqual(code, expected_exit)
                self.assertEqual(len(json.loads((output / "security-report.json").read_text("utf-8"))["findings"]),
                                 expected_count)

    def test_analyzer_failure_is_reported_with_partial_artifact(self):
        with TemporaryDirectory() as directory, patch.object(ANALYZERS["sca"], "scan", side_effect=OSError):
            output = Path(directory)
            code, reason = run_gate("repair-desk", output)
            self.assertEqual(code, 2)
            self.assertIn("sca", reason)
            artifact = json.loads((output / "security-gate.json").read_text("utf-8"))
            self.assertEqual(artifact["exitCode"], 2)
            self.assertEqual(len(json.loads((output / "security-report.json").read_text("utf-8"))["findings"]), 10)
