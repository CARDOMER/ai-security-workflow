import json
import unittest
from collections import Counter
from pathlib import Path
from tempfile import TemporaryDirectory

from fastapi.testclient import TestClient

from backend.main import ROOT, app
from backend.sast_scanner import KotlinSastScanner


class KotlinSastTests(unittest.TestCase):
    def scan_sources(self, **sources):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            for name, source in sources.items():
                (root / f"{name}.kt").write_text(source, encoding="utf-8")
            return {finding.kind for finding in KotlinSastScanner().scan(root)}

    def test_sql_requires_interpolation_of_an_http_parameter(self):
        controller = '''
            @RestController
            class Lookup(private val storage: JdbcTemplate) {
                fun locate(@RequestParam reference: String) =
                    storage.queryForList("SELECT label FROM records WHERE label = '$reference'")
            }
        '''
        self.assertEqual(self.scan_sources(AlternateLookup=controller), {"sql-injection"})
        safe = controller.replace("'$reference'", "?").replace('label = ?")', 'label = ?", reference)')
        self.assertEqual(self.scan_sources(AlternateLookup=safe), set())

    def test_tls_flags_only_the_unconditional_override(self):
        source = '''
            fun open(): HttpsURLConnection = connection.apply {
                hostnameVerifier = HostnameVerifier { name, session -> true }
            }
        '''
        self.assertEqual(self.scan_sources(AlternateHttps=source), {"tls-verification"})
        safe = source.replace("hostnameVerifier =", "// hostnameVerifier =")
        self.assertEqual(self.scan_sources(AlternateHttps=safe), set())

    def test_cors_requires_both_settings_in_the_same_block(self):
        source = '''
            val cfg = CorsConfiguration().apply {
                allowedOrigins = listOf("*")
                allowCredentials = true
            }
        '''
        self.assertEqual(self.scan_sources(AlternateCors=source), {"credentialed-cors"})
        safe = source.replace('allowCredentials = true', 'allowCredentials = false')
        other = 'val other = CorsConfiguration().apply { allowCredentials = true }'
        self.assertEqual(self.scan_sources(AlternateCors=safe + other), set())

    def test_route_requires_a_sensitive_handler_and_shadowed_protection(self):
        controller = '''
            @RestController
            class Directory(private val store: JdbcTemplate) {
                @GetMapping("/operations/list")
                fun listing() = store.queryForList("SELECT owner_id FROM objects")
            }
        '''
        rules = '''
            fun chain(security: HttpSecurity) = security.authorizeHttpRequests { routes ->
                routes.requestMatchers(GET, "/operations/list").permitAll()
                routes.requestMatchers("/operations/**").hasRole("STAFF")
            }
        '''
        self.assertEqual(
            self.scan_sources(AlternateController=controller, AlternateRules=rules), {"route-authorization"},
        )
        self.assertEqual(
            self.scan_sources(AlternateController=controller.replace("owner_id", "label"), AlternateRules=rules),
            set(),
        )
        self.assertEqual(
            self.scan_sources(AlternateController=controller, AlternateRules=rules.replace("permitAll()", 'hasRole("STAFF")')),
            set(),
        )

    def test_object_access_joins_controller_and_repository(self):
        controller = '''
            @RestController
            class Objects(private val adapter: ObjectStore) {
                @GetMapping("/objects/{ref}")
                fun details(@PathVariable ref: Long) = adapter.fetch(ref)
            }
        '''
        repository = '''
            @Repository
            class ObjectStore(private val db: JdbcTemplate) {
                fun fetch(identifier: Long) = db.queryForList(
                    "SELECT owner_id, label FROM stored_object WHERE object_id = ?",
                    identifier,
                )
            }
        '''
        self.assertEqual(
            self.scan_sources(AlternateHandler=controller, AlternateStore=repository), {"object-authorization"},
        )
        scoped_controller = controller.replace("ref: Long)", "ref: Long, principal: Principal)").replace(
            "fetch(ref)", "fetch(ref, principal.name)",
        )
        scoped_repository = repository.replace("identifier: Long)", "identifier: Long, owner: String)").replace(
            'object_id = ?",', 'object_id = ? AND owner_id = ?",',
        ).replace("identifier,\n", "identifier, owner,\n")
        self.assertEqual(self.scan_sources(AlternateHandler=scoped_controller, AlternateStore=scoped_repository), set())

    def test_training_report_matches_reference(self):
        def identity(item):
            return item["class"], item["path"], item["line"], item.get("endLine", item["line"])

        reference = ROOT.parent / "ground-truth" / "training-findings.json"
        expected = json.loads(reference.read_text(encoding="utf-8"))
        response = TestClient(app).post("/api/scan")
        self.assertEqual(response.status_code, 200)
        findings = response.json()["findings"]
        self.assertEqual(Counter(item["category"] for item in findings), {"SECRET": 5, "SCA": 5, "SAST": 5})
        actual = [identity(item) for item in findings if item["category"] == "SAST"]
        self.assertCountEqual(actual, [identity(item) for item in expected["findings"] if item["category"] == "SAST"])
        for control in expected["controls"]:
            if control["category"] == "SAST":
                self.assertNotIn(identity(control), actual)
