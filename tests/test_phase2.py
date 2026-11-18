import io, tempfile, unittest, zipfile
from pathlib import Path
from scanx_app.core.models import ScanRequest
from scanx_app.core.orchestrator import ScanOrchestrator
from scanx_app.core.settings import load_settings
from scanx_app.engines.filesystem import FilesystemEngine
from scanx_app.engines.patterns import PatternEngine, load_rules
from scanx_app.engines.archive import ArchiveEngine

class Phase2Tests(unittest.TestCase):
    def setUp(self):
        self.settings = load_settings()
        self.settings['engines']['gitleaks'] = False
    def test_pattern_detection_is_redacted(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d); secret='ghp_' + 'A'*30
            (root/'.env').write_text('TOKEN='+secret+'\n')
            result=ScanOrchestrator().scan(ScanRequest(str(root),'local_directory',use_gitleaks=False))
            self.assertTrue(result.findings)
            self.assertTrue(all(f.masked_value == '[REDACTED]' for f in result.findings))
            self.assertTrue(all(secret not in repr(f) for f in result.findings))
    def test_excluded_directory_and_binary(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d); (root/'node_modules').mkdir(); (root/'node_modules'/'x.txt').write_text('ghp_'+'B'*30)
            (root/'binary.bin').write_bytes(b'ghp_'+b'C'*30+b'\0')
            fs=FilesystemEngine(self.settings); candidates=list(fs.discover(root))
            self.assertEqual([c.relative_path for c in candidates], ['binary.bin'])
            self.assertTrue(candidates[0].is_binary)
    def test_archive_scan_without_extraction(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d); archive=root/'secrets.zip'
            with zipfile.ZipFile(archive,'w') as z: z.writestr('inside.env','TOKEN=ghp_'+'D'*30)
            settings=dict(self.settings); settings['scan']['scan_archives']=True
            result=ScanOrchestrator().scan(ScanRequest(str(root),'local_directory',use_gitleaks=False,scan_archives=True))
            self.assertTrue(any('!/' in f.file for f in result.findings))
            self.assertEqual(list(root.glob('inside.env')), [])
    def test_no_network_for_github(self):
        with self.assertRaises(Exception):
            ScanOrchestrator().scan(ScanRequest('https://github.com/a/b.git','github_url'))
    def test_rules_load(self):
        self.assertGreaterEqual(len(load_rules('rules')), 10)

if __name__ == '__main__': unittest.main()
