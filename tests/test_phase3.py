import os, subprocess, tempfile, unittest
from pathlib import Path
from scanx_app.core.models import ScanRequest
from scanx_app.core.orchestrator import ScanOrchestrator
from scanx_app.engines.git_history import GitHistoryEngine
from scanx_app.notify.telegram import load_telegram_config, format_report

class Phase3Tests(unittest.TestCase):
    def make_repo(self):
        d = tempfile.TemporaryDirectory(); root = Path(d.name)
        subprocess.run(['git','init','-q'], cwd=root, check=True)
        subprocess.run(['git','config','user.email','test@example.invalid'], cwd=root, check=True)
        subprocess.run(['git','config','user.name','Test'], cwd=root, check=True)
        return d, root
    def test_history_finding_has_real_line_number(self):
        holder, root = self.make_repo()
        try:
            (root/'old.env').write_text('first=1\nTOKEN=ghp_'+'A'*30+'\n')
            subprocess.run(['git','add','.'], cwd=root, check=True); subprocess.run(['git','commit','-qm','add'], cwd=root, check=True)
            (root/'old.env').unlink(); subprocess.run(['git','add','-A'], cwd=root, check=True); subprocess.run(['git','commit','-qm','remove'], cwd=root, check=True)
            result = ScanOrchestrator().scan(ScanRequest(str(root),'local_directory',deep_history=True,use_gitleaks=False))
            history = [f for f in result.findings if 'history' in f.tags]
            self.assertTrue(history); self.assertEqual(history[0].line, 2); self.assertIsNotNone(history[0].commit)
        finally: holder.cleanup()
    def test_patterns_can_be_disabled(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d); (root/'.env').write_text('TOKEN=ghp_'+'B'*30)
            old=os.environ.get('SCANX_CONFIG')
            cfg=root/'settings.yaml'; cfg.write_text('engines:\n  patterns: false\n  gitleaks: false\n')
            os.environ['SCANX_CONFIG']=str(cfg)
            try:
                result=ScanOrchestrator().scan(ScanRequest(str(root),'local_directory',use_gitleaks=False))
                self.assertEqual(result.engine_status['patterns'],'disabled'); self.assertEqual(result.findings, [])
            finally:
                if old is None: os.environ.pop('SCANX_CONFIG',None)
                else: os.environ['SCANX_CONFIG']=old
    def test_bad_telegram_yaml_is_ignored(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'telegram.yaml'; path.write_text('- invalid\n- shape\n'); path.chmod(0o600)
            self.assertIsNone(load_telegram_config(path))
    def test_telegram_report_sanitizes_newlines(self):
        class F: rule_name='rule\nspoof'; rule_id='r'; file='x\nfile'; line=1; commit='abc\n123'
        class R: findings=[F()]
        text=format_report('target\nname',R())
        self.assertNotIn('rule\nspoof', text); self.assertNotIn('x\nfile', text)
    def test_missing_git_is_reported(self):
        with tempfile.TemporaryDirectory() as d:
            engine=GitHistoryEngine({'scan':{}})
            # A non-repository must be explicitly skipped, never reported clean.
            findings,status,warning=engine.scan(Path(d), object())
            self.assertEqual(status,'skipped'); self.assertTrue(warning)

if __name__ == '__main__': unittest.main()
