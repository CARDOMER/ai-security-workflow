import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from fastapi.testclient import TestClient

from backend.main import app
from backend.quality import evaluate


class QualityTests(unittest.TestCase):
    finding = {"category": "SECRET", "path": "sample.properties", "class": "api-key", "line": 2}
    control = dict(finding, id="control", line=3, expectedFinding=False)
    reference = {"findings": [dict(finding, id="expected")], "controls": [control]}

    def test_exact_match(self):
        result = evaluate(self.reference, [self.finding])
        self.assertEqual(result["total"], {"expected": 1, "matched": 1, "missed": 0, "unexpected": 0})
        self.assertEqual(result["byCategory"]["SECRET"], result["total"])

    def test_missed_finding(self):
        result = evaluate(self.reference, [])
        self.assertEqual(result["total"]["missed"], 1)
        self.assertEqual(result["missed"], self.reference["findings"])

    def test_duplicate_finding_is_unexpected(self):
        result = evaluate(self.reference, [self.finding, self.finding])
        self.assertEqual(result["total"]["matched"], 1)
        self.assertEqual(result["total"]["unexpected"], 1)
        self.assertEqual(result["unexpected"], [self.finding])

    def test_control_hit_must_match_its_own_location(self):
        result = evaluate(self.reference, [dict(self.finding, endLine=3), dict(self.finding, line=3)])
        self.assertEqual(result["total"]["unexpected"], 1)
        self.assertEqual([item["id"] for item in result["controls"]["hits"]], ["control"])
        self.assertEqual(evaluate(self.reference, [dict(self.finding, endLine=3)])["controls"]["hits"], [])

    def test_alternate_location_and_advisory_alias(self):
        sca = {"category": "SCA", "path": "build.gradle.kts", "group": "sample", "artifact": "lib", "version": "1"}
        reference = {"findings": [
            dict(self.finding, alternateLocations=[{"path": "alternate.kt", "line": 4, "endLine": 5}]),
            dict(sca, advisoryIds=["GHSA-example", "CVE-example"]),
        ], "controls": []}
        actual = [dict(self.finding, path="alternate.kt", line=5), dict(sca, advisoryId="CVE-example")]
        self.assertEqual(evaluate(reference, actual)["total"]["matched"], 2)

    def test_full_repair_desk_and_advisory(self):
        with TestClient(app) as client:
            response = client.post("/api/quality")
            self.assertEqual(response.status_code, 200, response.text)
            result = response.json()
            self.assertEqual(result["total"], {"expected": 15, "matched": 15, "missed": 0, "unexpected": 0})
            self.assertEqual(result["controls"], {"total": 6, "hits": []})

            response = client.get("/api/sca/advisory", params={
                "group": "org.apache.commons", "artifact": "commons-text", "advisoryId": "CVE-2022-42889",
            })
            self.assertEqual(response.status_code, 200)
            self.assertIn("1.10.0", response.json()["fixedVersions"])
            self.assertTrue(response.json()["ranges"])

    def test_sca_control_matches_equivalent_ghsa_and_cve(self):
        dependency = {"category": "SCA", "path": "build.gradle.kts", "group": "sample", "artifact": "lib", "version": "1"}
        control = dict(dependency, id="sca-control", advisoryIds=["CVE-example"], expectedFinding=False)
        advisory = {"group": "sample", "artifact": "lib", "id": "GHSA-example", "aliases": ["CVE-example"]}
        result = evaluate({"findings": [], "controls": [control]}, [dict(dependency, advisoryId="GHSA-example")], [advisory])
        self.assertEqual([item["id"] for item in result["controls"]["hits"]], ["sca-control"])

    def test_missing_reference_has_clear_error_and_keeps_scan_available(self):
        with TemporaryDirectory() as directory, patch("backend.main.REFERENCE", Path(directory) / "missing.json"):
            with TestClient(app) as client:
                quality = client.post("/api/quality")
                self.assertEqual(quality.status_code, 503)
                self.assertIn("Эталон Repair Desk", quality.json()["detail"])
                self.assertEqual(len(client.post("/api/scan").json()["findings"]), 15)
