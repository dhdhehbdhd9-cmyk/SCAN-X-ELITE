import tempfile
import unittest
from pathlib import Path

from scanx_app.core.models import ScanRequest, Finding, ScanResult
from scanx_app.core.orchestrator import ScanOrchestrator
from scanx_app.core.security import redact, safe_html, safe_relative_path, fingerprint_secret
from scanx_app.core.settings import load_settings
from scanx_app.core.exceptions import TargetError, ConfigurationError

class FoundationTests(unittest.TestCase):
    def test_prepare_local_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            request = ScanRequest(directory, "local_directory")
            prepared = ScanOrchestrator().prepare(request)
            self.assertEqual(prepared.target_kind, "local_directory")

    def test_reject_missing_directory(self):
        request = ScanRequest("/definitely/not/a/real/path", "local_directory")
        with self.assertRaises(TargetError):
            ScanOrchestrator().prepare(request)

    def test_github_url_name(self):
        request = ScanRequest("https://github.com/OWASP/NodeGoat.git",
                              "github_url", deep_history=True)
        prepared = ScanOrchestrator().prepare(request)
        self.assertEqual(prepared.project_name, "NodeGoat")
        self.assertTrue(prepared.deep_history)

    def test_redaction(self):
        self.assertEqual(redact("super-secret"), "[REDACTED]")

    def test_html_escaping(self):
        self.assertEqual(safe_html('<script>"x"</script>'),
                         '&lt;script&gt;&quot;x&quot;&lt;/script&gt;')

    def test_path_traversal_rejected(self):
        with self.assertRaises(ValueError):
            safe_relative_path("../../etc/passwd")

    def test_fingerprint_is_deterministic_with_same_salt(self):
        salt = b"test-only-salt"
        self.assertEqual(fingerprint_secret("dummy", salt=salt),
                         fingerprint_secret("dummy", salt=salt))
        self.assertNotEqual(fingerprint_secret("dummy", salt=salt),
                            fingerprint_secret("other", salt=salt))

    def test_default_security_settings(self):
        settings = load_settings()
        self.assertFalse(settings["security"]["persist_secret_values"])
        self.assertFalse(settings["security"]["network_validation"])
        self.assertEqual(settings["scan"]["git_history"], "complete")

    def test_reject_secret_persistence_config(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "unsafe.yaml"
            path.write_text(
                "security:\n  persist_secret_values: true\n",
                encoding="utf-8",
            )
            with self.assertRaises(ConfigurationError):
                load_settings(path)

if __name__ == "__main__":
    unittest.main()
