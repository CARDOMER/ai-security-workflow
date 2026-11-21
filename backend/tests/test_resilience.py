import tempfile
import unittest
from pathlib import Path

from backend.main import DATABASE
from backend.sast_scanner import KotlinSastScanner
from backend.sca_scanner import MavenScaScanner
from backend.secrets_scanner import SecretsScanner


class AnalyzerResilienceTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)

    def write(self, path, content):
        file = self.root / path
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_text(content, encoding="utf-8")

    def test_secret_formatting_and_comments(self):
        self.write("module/demo/Headers.kt", '''
/*
val migrationApiKey = "documentation-only-example"
*/
val session = System . getenv ( "DEMO_SESSION" ) ?: "synthetic-fallback-value"
request.header("Authorization", "Bearer ${session}")
val localPassword = "synthetic-other-value" // inline comment
val serviceUrl = "https://example.test" // ordinary URL
''')
        self.write("module/conf/alternate.properties",
                   "service.api-key=${SET_AT_RUNTIME}\nservice.authorization=Bearer synthetic-demo-token\n")
        findings = SecretsScanner().scan(self.root)
        self.assertCountEqual([item.kind for item in findings], ["secret-fallback", "password", "configuration-token"])
        self.assertTrue(all("synthetic-" not in item.description for item in findings))

    def test_sast_annotated_parameter_spacing_and_safe_sql(self):
        self.write("different/layout/Lookup.kt", '''
@RestController
class Lookup(private val directory: JdbcTemplate) {
    fun find(@RequestParam ( value = "ref" ) ref: String) =
        directory.queryForList("SELECT label FROM records WHERE label = '$ref'")

    fun safe(@RequestParam ref: String) =
        directory.queryForList("SELECT label FROM records WHERE label = ?", ref)
}
''')
        report = KotlinSastScanner().scan(self.root)
        self.assertEqual([(item.kind, item.path) for item in report],
                         [("sql-injection", "different/layout/Lookup.kt")])

    def test_catalog_scans_used_aliases_and_honors_lock(self):
        self.write("build.gradle.kts", '''
dependencies {
    implementation(
        libs.apache.text,
    )
    add("runtimeOnly", libs.json.core)
    implementation(libs.missing.reference)
    // implementation(libs.unused)
}
''')
        self.write("gradle/libs.versions.toml", '''
[versions]
text-version = "1.9"

[libraries]
apache-text = { module = "org.apache.commons:commons-text", version.ref = "text-version" }
json_core = { group = "org.json", name = "json", version = "20250107" }
missing-reference = { module = "org.jsoup:jsoup", version.ref = "not-defined" }
unused = "org.jsoup:jsoup:1.14.1"
''')
        scanner = MavenScaScanner(DATABASE)
        self.assertEqual([(item.artifact, item.version) for item in scanner.scan(self.root)], [("commons-text", "1.9")])
        self.write("gradle.lockfile", "org.apache.commons:commons-text:1.13.0=runtimeClasspath\n")
        self.assertEqual(scanner.scan(self.root), [])
