import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from fastapi.testclient import TestClient

from backend.main import ROOT, app
from backend.sca_scanner import MavenScaScanner, declared_versions, in_range


class MavenScaTests(unittest.TestCase):
    def test_range_boundaries_and_numeric_comparison(self):
        interval = {"lower": "1.9", "upper": "1.10", "lowerInclusive": True, "upperInclusive": False}
        self.assertTrue(in_range("1.9.0", interval))
        self.assertFalse(in_range("1.8.99", interval))
        self.assertFalse(in_range("1.10.0", interval))
        self.assertFalse(in_range("1.9-RC1", interval))
        interval.update(lowerInclusive=False, upperInclusive=True)
        self.assertFalse(in_range("1.9.0", interval))
        self.assertTrue(in_range("1.10.0", interval))
        interval.update(lower=None, upper="20230227")
        self.assertTrue(in_range("20230227", interval))

    def test_literal_variable_property_and_multiline_add(self):
        build = '''
            val local = "1.09"
            val fromProperty = providers.gradleProperty("revision").get()
            dependencies {
                implementation("sample:literal:2.0")
                implementation("sample:local:$local")
                add(
                    "runtimeOnly",
                    "sample:property:${fromProperty}",
                )
                // implementation("sample:comment:1.0")
                constraints { implementation("sample:constraint:1.0") }
                implementation("sample:unknown:1.$unknown")
            }
        '''
        self.assertEqual(
            declared_versions(build, "revision=20230227", ""),
            {("sample", "literal", "2.0"), ("sample", "local", "1.09"), ("sample", "property", "20230227")},
        )

    def test_lockfile_overrides_declared_version_and_ignores_transitive_entries(self):
        build = '''
            dependencies {
                implementation("sample:overridden:1.0")
                implementation("sample:versionless")
            }
        '''
        locks = "sample:overridden:2.00=runtimeClasspath\nsample:versionless:3.0=runtimeClasspath\nsample:transitive:1.0=runtimeClasspath"
        self.assertEqual(
            declared_versions(build, "", locks),
            {("sample", "overridden", "2.00"), ("sample", "versionless", "3.0")},
        )

    def test_variables_respect_their_dependency_block_scope(self):
        build = '''
            val revision = "1.0"
            fun unrelated() {
                val revision = "2.0"
            }
            dependencies {
                val revision = "3.0"
                implementation("sample:local:$revision")
            }
            dependencies {
                implementation("sample:global:$revision")
            }
        '''
        self.assertEqual(declared_versions(build, "", ""), {
            ("sample", "local", "3.0"), ("sample", "global", "1.0"),
        })

    def test_each_advisory_is_reported_once(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "build.gradle.kts").write_text(
                'dependencies { implementation("sample:artifact:1.0"); testImplementation("sample:artifact:1.0") }',
                encoding="utf-8",
            )
            db = root / "vulnerabilities.json"
            affected = {"lower": None, "lowerInclusive": False, "upper": "2", "upperInclusive": False}
            entry = {
                "group": "sample", "artifact": "artifact", "ranges": [affected, affected],
                "aliases": ["CVE-2026-0001"], "severity": "HIGH",
            }
            db.write_text(json.dumps({"vulnerabilities": [
                dict(entry, id="GHSA-a"), dict(entry, id="GHSA-b", aliases=["CVE-2026-0002"]),
            ]}), encoding="utf-8")
            self.assertEqual([item.advisoryId for item in MavenScaScanner(db).scan(root)], ["GHSA-a", "GHSA-b"])

    def test_combined_report_matches_sca_reference(self):
        reference = ROOT.parent / "ground-truth" / "training-findings.json"
        expected = json.loads(reference.read_text(encoding="utf-8"))
        response = TestClient(app).post("/api/scan")
        self.assertEqual(response.status_code, 200)
        findings = response.json()["findings"]
        self.assertEqual(sum(item["category"] in {"SECRET", "SCA"} for item in findings), 10)
        sca = [item for item in findings if item["category"] == "SCA"]
        target = [item for item in expected["findings"] if item["category"] == "SCA"]
        fields = ("path", "group", "artifact", "version")
        self.assertCountEqual(
            [tuple(item[key] for key in fields) for item in sca],
            [tuple(item[key] for key in fields) for item in target],
        )
        for item in sca:
            record = next(row for row in target if all(row[key] == item[key] for key in fields))
            self.assertIn(item["advisoryId"], record["advisoryIds"])
            self.assertNotIn("line", item)
            self.assertNotIn("class", item)
            self.assertIn(item["severity"], {"LOW", "MEDIUM", "HIGH", "CRITICAL"})
        for control in expected["controls"]:
            if control["category"] == "SCA":
                self.assertFalse(any(all(row[key] == control[key] for key in fields) for row in sca))
