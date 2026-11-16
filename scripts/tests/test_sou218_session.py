# SPDX-License-Identifier: Apache-2.0
"""Offline only: synthetic credentials, mock build, no provider or native token read."""
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("memory_session", Path(__file__).resolve().parents[1] / "sou218-session.py")
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)


class SessionTests(unittest.TestCase):
    def test_hidden_paste_wrappers_and_invalid_input(self):
        fake = "synthetic_paste_only_1234567890"
        self.assertEqual(M.normalize_key(" "+fake+"\n"), fake)
        self.assertEqual(M.normalize_key("\x1b[200~"+fake+"\x1b[201~"), fake)
        for value in ["short", "\x1b[200~"+fake, fake+"\x00", '"'+fake+'"', fake+" invalid"]:
            with self.assertRaises(ValueError): M.normalize_key(value)

    def test_budget_never_refunds_or_resets_on_failure_and_expiry(self):
        b = M.Budget(3, 200)
        b.reserve(2, 100)
        self.assertEqual(b.remaining, 1)
        for amount, now in [(2, 101), (0, 101), (-1, 101), (True, 101), (1, 200)]:
            with self.assertRaises(ValueError): b.reserve(amount, now)
        self.assertEqual(b.remaining, 1)
        b.reserve(1, 199)
        with self.assertRaises(ValueError): b.reserve(1, 199)

    def fixture(self, directory):
        root = Path(directory); repo = root / "repo"; repo.mkdir()
        (repo / "crates/agentfw").mkdir(parents=True)
        (repo / "crates/agentfw/Cargo.toml").write_text('[features]\nsou218-gemini25-flash-test = []\n')
        state = root / "state"; state.mkdir(mode=0o700)
        session = state / "session"; session.mkdir(mode=0o700)
        token = root / "native-token"; M.write_private(token, {"synthetic": "unused"})
        evidence = state / "evidence.json"; M.write_private(evidence, {"public": True})
        cfg = state / "config.json"
        config = {"model": M.MODEL, "project": "test-project", "ledger": str(state / "journal"),
                  "evidence_file": str(evidence), "native_token_file": str(token), "row_ceiling": 30}
        M.write_private(cfg, config)
        request = {"action": "submit", "config": str(cfg), "feature": "sou218-gemini25-flash-test", "max_new_rows": 1}
        return repo, state, session, token, cfg, config, request

    def test_scope_permissions_and_unknown_recovery_refuse(self):
        with tempfile.TemporaryDirectory() as d:
            repo, state, session, token, cfg, config, req = self.fixture(d)
            features = {req["feature"]: []}
            result, _ = M.validate_job(req, "test-project", state, features, token)
            self.assertTrue(result["non_billed_free_tier"])
            for field, value in [("model", "other"), ("project", "other"), ("row_ceiling", 31),
                                 ("resume_count_unknown", {}), ("parent_attempt", {}), ("metadata_recovery_started_sha256", "a"*64),
                                 ("native_token_file", str(cfg)), ("ledger", str(Path(d)/"outside"))]:
                bad = dict(config); bad[field] = value; cfg.write_text(json.dumps(bad))
                with self.assertRaises(ValueError): M.validate_job(req, "test-project", state, features, token)
            cfg.write_text(json.dumps(config)); cfg.chmod(0o644)
            with self.assertRaises(ValueError): M.validate_job(req, "test-project", state, features, token)
            cfg.chmod(0o600)
            link = state / "link"; link.symlink_to(cfg)
            with self.assertRaises(ValueError): M.validate_job(dict(req, config=str(link)), "test-project", state, features, token)

    def test_pipe_only_delivery_budget_busy_and_secret_absent_from_files(self):
        with tempfile.TemporaryDirectory() as d:
            repo, state, session, token, cfg, config, req = self.fixture(d)
            synthetic = "synthetic_session_key_1234567890"
            fake = Path(d)/"offline-worker"
            fake.write_text("#!/usr/bin/python3\nimport os,json,hashlib\ng=json.load(os.fdopen(int(os.environ['SOUP_WALL_GEMINI_SESSION_FD'])))\nassert len(g['key'])>20\nassert g['parent_pid']==os.getppid()\nassert g['max_new_rows']==1\nassert g['config_sha256']==hashlib.sha256(open(os.environ['SOUP_WALL_GEMINI_MANUAL_CONFIG'],'rb').read()).hexdigest()\nassert all(g['key'] not in v for v in os.environ.values())\nprint('OFFLINE_PIPE_PASS')\n")
            fake.chmod(0o700)
            sup = M.Supervisor(session, repo, state, "test-project", M.Budget(2, int(time.time())+120), synthetic, token)
            with patch.object(M, "build", return_value=str(fake)):
                worker = threading.Thread(target=sup.work); worker.start()
                first = sup.dispatch(req)
                with self.assertRaises(ValueError): sup.dispatch(req)
                sup.pending.join()
                status = sup.dispatch({"action":"status"})
                self.assertEqual(status["remaining_reserved_budget"], 1)
                self.assertEqual(status["jobs"][0]["exit_code"], 0)
                second = sup.dispatch(req); sup.pending.join()
                self.assertNotEqual(first["id"], second["id"])
                with self.assertRaises(ValueError): sup.dispatch(req)
                sup.dispatch({"action":"stop"}); worker.join(timeout=3)
                self.assertFalse(worker.is_alive())
            for p in session.rglob('*'):
                if p.is_file(): self.assertNotIn(synthetic.encode(), p.read_bytes())
            events = [json.loads(p.read_text()) for p in sorted(session.glob('event-*.json'))]
            self.assertEqual([v['event'] for v in events], ['reserved','key_used','finished']*2)

    def test_provider_quota_stop_blocks_further_jobs(self):
        with tempfile.TemporaryDirectory() as d:
            repo, state, session, token, cfg, config, req = self.fixture(d)
            fake=Path(d)/"quota-worker"
            fake.write_text("#!/usr/bin/python3\nimport os,json\nfrom pathlib import Path\ng=json.load(os.fdopen(int(os.environ['SOUP_WALL_GEMINI_SESSION_FD'])))\nc=json.load(open(os.environ['SOUP_WALL_GEMINI_MANUAL_CONFIG']))\np=Path(c['ledger'])/'report-offline.json'\np.write_text(json.dumps({'rows':[{'state':'quota_stop'}]}))\np.chmod(0o600)\n")
            fake.chmod(0o700)
            sup=M.Supervisor(session,repo,state,"test-project",M.Budget(3,int(time.time())+60),"synthetic_session_key_1234567890",token)
            with patch.object(M,"build",return_value=str(fake)):
                worker=threading.Thread(target=sup.work);worker.start()
                sup.dispatch(req);sup.pending.join()
                self.assertTrue(sup.stopping)
                self.assertEqual(sup.budget.remaining,2)
                with self.assertRaises(ValueError):sup.dispatch(req)
                worker.join(timeout=3);self.assertFalse(worker.is_alive())

    def test_reservation_survives_worker_spawn_failure(self):
        with tempfile.TemporaryDirectory() as d:
            repo, state, session, token, cfg, config, req = self.fixture(d)
            sup = M.Supervisor(session, repo, state, "test-project", M.Budget(1,int(time.time())+60), "synthetic_session_key_1234567890", token)
            with patch.object(M, "build", return_value='/missing/offline-worker'):
                worker = threading.Thread(target=sup.work); worker.start()
                sup.dispatch(req); sup.pending.join()
                self.assertEqual(sup.budget.remaining, 0)
                with self.assertRaises(ValueError): sup.dispatch(req)
                sup.dispatch({"action":"stop"}); worker.join(timeout=3)

    def test_real_terminal_hidden_entry_status_stop_without_provider(self):
        import pty, select, signal, socket, sys
        with tempfile.TemporaryDirectory() as d:
            repo, state, unused_session, token, cfg, config, req = self.fixture(d)
            live = state / "live"
            synthetic = "synthetic_terminal_key_1234567890"
            pid, fd = pty.fork()
            if pid == 0:
                os.execv(sys.executable, [sys.executable, str(SPEC.origin), "serve", "--session", str(live),
                    "--repo", str(repo), "--allowed-root", str(state), "--template-config", str(cfg),
                    "--project", "test-project", "--rows", "2", "--minutes", "1"])
            transcript = bytearray()
            def until(marker):
                deadline = time.time()+10
                while marker not in transcript:
                    if time.time() > deadline: self.fail("terminal phase timeout")
                    if select.select([fd],[],[],0.2)[0]:
                        try: transcript.extend(os.read(fd,4096))
                        except OSError: self.fail("synthetic terminal closed: " + transcript.decode(errors="replace"))
            try:
                until(b"Type SESSION")
                os.write(fd, b"SESSION test-project gemini-2.5-flash 2 USD0\n")
                until(b"Gemini API key (hidden):")
                os.write(fd, synthetic.encode()+b"\n")
                until(b"Session armed.")
                self.assertNotIn(synthetic.encode(), transcript)
                def command(action):
                    with socket.socket(socket.AF_UNIX) as client:
                        client.settimeout(3);client.connect(str(live/'control.sock'))
                        client.sendall(json.dumps({"action":action}).encode());client.shutdown(socket.SHUT_WR)
                        return json.loads(client.recv(65536))
                status=command("status")
                self.assertEqual(status["remaining_reserved_budget"],2)
                self.assertEqual(status["jobs"],[])
                command("stop")
                deadline=time.time()+5
                while time.time()<deadline:
                    done,status=os.waitpid(pid,os.WNOHANG)
                    if done:
                        pid=None;self.assertEqual(os.waitstatus_to_exitcode(status),0);break
                    time.sleep(0.1)
                self.assertIsNone(pid)
                for file in live.glob('*.json'): self.assertNotIn(synthetic.encode(),file.read_bytes())
            finally:
                if pid is not None:
                    os.kill(pid,signal.SIGKILL);os.waitpid(pid,0)
                os.close(fd)


if __name__ == '__main__': unittest.main()
