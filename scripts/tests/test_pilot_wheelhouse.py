# SPDX-License-Identifier: Apache-2.0
"""Exact graph, bounded transfer and offline pip bootstrap regressions."""
import copy
from email.message import Message
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import pilot_wheelhouse as W


class Response(io.BytesIO):
    def __init__(self, data, wheel, **headers):
        super().__init__(data)
        self.status = 200
        self.url = wheel["url"]
        self.headers = Message()
        for name, value in {"Content-Length": str(wheel["size"]), **headers}.items():
            self.headers[name] = value

    def geturl(self):
        return self.url


class Wheelhouse(unittest.TestCase):
    @unittest.skipUnless(hasattr(os, "mkfifo"), "requires POSIX FIFO")
    def test_fifo_is_refused_without_waiting_for_a_writer(self):
        with tempfile.TemporaryDirectory() as temp:
            fifo = Path(temp) / "wheel.whl"
            os.mkfifo(fifo)
            with self.assertRaisesRegex(ValueError, "regular_file_required"):
                W.regular(fifo)

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.requirements = self.root / "requirements.lock"
        self.manifest = self.root / "wheels.lock.json"
        self.source = self.root / "source"
        self.source.mkdir()
        self.destination = self.root / "cache"
        self.wheels = []
        self.payloads = {}
        lines = []
        for name in ("alpha", "beta"):
            data = ("owned synthetic wheel " + name).encode()
            digest = hashlib.sha256(data).hexdigest()
            filename = name + "-1.0-py3-none-any.whl"
            self.wheels.append({"name": name, "version": "1.0", "filename": filename,
                "url": "https://files.pythonhosted.org/packages/aa/bb/" + filename,
                "size": len(data), "sha256": digest})
            self.payloads[filename] = data
            (self.source / filename).write_bytes(data)
            lines.append(f"{name}==1.0 --hash=sha256:{digest}\n")
        self.requirements.write_bytes("".join(lines).encode())
        self.document = {"format": W.FORMAT, "target": W.TARGET,
            "requirements_sha256": hashlib.sha256(self.requirements.read_bytes()).hexdigest(), "wheels": self.wheels}
        self.write_manifest()

    def write_manifest(self, document=None):
        self.manifest.write_text(json.dumps(self.document if document is None else document), encoding="utf-8")

    def prepare(self, **kwargs):
        return W.prepare_wheelhouse(self.manifest, self.requirements, self.destination, **kwargs)

    def test_exact_offline_copy_and_reuse_never_open_network(self):
        with patch.object(W.urllib.request, "build_opener", side_effect=AssertionError("network forbidden")):
            self.assertEqual(self.prepare(source=self.source), self.destination)
            self.assertEqual(self.prepare(), self.destination)
        self.assertEqual({p.name for p in self.destination.iterdir()}, set(self.payloads))
        self.assertEqual([p.read_bytes() for p in sorted(self.destination.iterdir())],
                         [self.payloads[name] for name in sorted(self.payloads)])
        if os.name == "posix":
            self.assertEqual(self.destination.stat().st_mode & 0o777, 0o700)

    def test_shipped_manifest_matches_every_name_version_and_lock_digest(self):
        assets = ROOT / "profiles/mcp/git-readonly-v1"
        wheels = W.load_manifest(assets / "wheels.lock.json", assets / "requirements.lock")
        self.assertEqual(len(wheels), 34)
        self.assertEqual(len({(row["name"], row["version"]) for row in wheels}), 34)
        self.assertIn(("pip", "26.3"), {(row["name"], row["version"]) for row in wheels})

    def test_unknown_missing_and_duplicate_names_fail_even_with_same_count(self):
        for key, value in (("name", "gamma"), ("name", "beta"), ("version", "2.0"), ("sha256", "0" * 64)):
            bad = copy.deepcopy(self.document)
            bad["wheels"][0][key] = value
            self.write_manifest(bad)
            with self.subTest(key=key, value=value), self.assertRaisesRegex(ValueError, "graph"):
                self.prepare(source=self.source)
            self.assertFalse(self.destination.exists())
        for wheels in (self.wheels[:-1], self.wheels + [self.wheels[0]], []):
            self.write_manifest({**self.document, "wheels": wheels})
            with self.assertRaises(ValueError):
                self.prepare(source=self.source)

    def test_duplicate_json_keys_and_requirements_aliases_refuse(self):
        self.manifest.write_text('{"format":"a","format":"b"}')
        with self.assertRaisesRegex(ValueError, "duplicate"):
            self.prepare()
        self.requirements.write_bytes(self.requirements.read_bytes() + self.requirements.read_bytes())
        self.write_manifest()
        with self.assertRaisesRegex(ValueError, "duplicate_requirement"):
            self.prepare()

    def test_raw_lock_identity_changes_fail_before_effects(self):
        self.requirements.write_bytes(self.requirements.read_bytes().replace(b"\n", b"\r\n"))
        with self.assertRaisesRegex(ValueError, "identity_mismatch"):
            self.prepare()
        self.assertFalse(self.destination.exists())

    def test_hostile_filenames_and_bounds_refuse_before_network(self):
        for value in ("../alpha.whl", "/alpha.whl", "a\\alpha.whl", "alpha.whl:stream", "alpha.whl.",
                      "alpha-1.0-py3-none-any.tar.gz", "ALPHA-2.0-py3-none-any.whl", "x" * 241):
            bad = copy.deepcopy(self.document)
            bad["wheels"][0]["filename"] = value
            self.write_manifest(bad)
            with self.subTest(filename=value), self.assertRaises(ValueError):
                self.prepare(allow_download=True)
        for size in (0, -1, W.MAX_WHEEL + 1, True, "20"):
            bad = copy.deepcopy(self.document)
            bad["wheels"][0]["size"] = size
            self.write_manifest(bad)
            with self.subTest(size=size), self.assertRaises(ValueError):
                self.prepare(allow_download=True)
        self.write_manifest()
        with patch.object(W, "MAX_TOTAL", 1), self.assertRaisesRegex(ValueError, "total"):
            self.prepare()

    def test_unreviewed_urls_and_redirects_refuse(self):
        filename = self.wheels[0]["filename"]
        for url in ("http://files.pythonhosted.org/packages/aa/" + filename,
                    "file:///etc/passwd", "ftp://files.pythonhosted.org/file",
                    "https://evil.example/packages/aa/" + filename,
                    "https://files.pythonhosted.org.evil.example/packages/aa/" + filename,
                    "https://user@files.pythonhosted.org/packages/aa/" + filename,
                    "https://files.pythonhosted.org:443/packages/aa/" + filename,
                    "https://files.pythonhosted.org/packages/%2e%2e/" + filename,
                    "https://files.pythonhosted.org/packages/../" + filename,
                    "https://files.pythonhosted.org/packages/aa/" + filename + "?download=true"):
            with self.subTest(url=url):
                bad = copy.deepcopy(self.document)
                bad["wheels"][0]["url"] = url
                self.write_manifest(bad)
                with self.assertRaises(ValueError):
                    self.prepare(allow_download=True)
                request = W.urllib.request.Request(self.wheels[0]["url"])
                with self.assertRaises(ValueError):
                    W.ReviewedRedirects().redirect_request(request, None, 302, "Found", {}, url)
        request = W.urllib.request.Request(self.wheels[0]["url"])
        with self.assertRaisesRegex(ValueError, "redirect_refused"):
            W.ReviewedRedirects().redirect_request(request, None, 302, "Found", {}, self.wheels[1]["url"])

    def test_redirect_response_body_is_closed_without_draining(self):
        class UnboundedBody(io.BytesIO):
            def read(self, *args, **kwargs):
                raise AssertionError("redirect body must never be drained")
        for code in (301, 302, 303, 307, 308):
            body = UnboundedBody(b"body")
            headers = Message()
            headers["Location"] = self.wheels[1]["url"]
            headers["Transfer-Encoding"] = "chunked"
            request = W.urllib.request.Request(self.wheels[0]["url"])
            request.timeout = 1
            with self.subTest(status=code), self.assertRaisesRegex(ValueError, "redirect_refused"):
                getattr(W.ReviewedRedirects(), "http_error_" + str(code))(
                    request, body, code, "Redirect", headers)
            self.assertTrue(body.closed)

    def test_missing_tampered_extra_and_symlink_source_never_fall_back(self):
        first = self.source / self.wheels[0]["filename"]
        for change in (lambda: first.unlink(), lambda: first.write_bytes(b"x" * self.wheels[0]["size"]),
                       lambda: (self.source / "unreviewed.whl").write_bytes(b"extra")):
            with self.subTest(change=change):
                for path in self.source.iterdir():
                    path.unlink()
                for filename, data in self.payloads.items():
                    (self.source / filename).write_bytes(data)
                change()
                with patch.object(W.urllib.request, "build_opener", side_effect=AssertionError("no fallback")):
                    with self.assertRaises(ValueError):
                        self.prepare(source=self.source, allow_download=True)
                self.assertFalse(self.destination.exists())

    def test_no_download_permission_refuses_without_network(self):
        with patch.object(W.urllib.request, "build_opener", side_effect=AssertionError("network forbidden")):
            with self.assertRaisesRegex(ValueError, "without_explicit_downloads"):
                self.prepare()

    def test_existing_cache_tamper_is_not_replaced_even_with_download_permission(self):
        self.prepare(source=self.source)
        path = self.destination / self.wheels[0]["filename"]
        bad = b"x" * self.wheels[0]["size"]
        path.write_bytes(bad)
        with patch.object(W.urllib.request, "build_opener", side_effect=AssertionError("network forbidden")):
            with self.assertRaisesRegex(ValueError, "digest"):
                self.prepare(allow_download=True)
        self.assertEqual(path.read_bytes(), bad)

    def test_symlink_and_hardlink_entries_refuse(self):
        first = self.source / self.wheels[0]["filename"]
        target = self.root / "target"
        first.replace(target)
        try:
            first.symlink_to(target)
        except OSError:
            self.skipTest("symlink creation requires unavailable host privilege")
        with self.assertRaisesRegex(ValueError, "symlink"):
            self.prepare(source=self.source)
        first.unlink()
        os.link(target, first)
        with self.assertRaisesRegex(ValueError, "regular_file"):
            self.prepare(source=self.source)

    def test_destination_symlink_parent_refuses_before_creating_cache(self):
        alias = self.root / "alias"
        actual = self.root / "actual"
        actual.mkdir()
        try:
            alias.symlink_to(actual, target_is_directory=True)
        except OSError:
            self.skipTest("symlink creation requires unavailable host privilege")
        self.destination = alias / "cache"
        with self.assertRaisesRegex(ValueError, "symlink"):
            self.prepare(source=self.source)
        self.assertEqual(list(actual.iterdir()), [])

    def test_download_is_bounded_and_checks_every_response(self):
        wheel = self.wheels[0]
        data = self.payloads[wheel["filename"]]
        cases = [(data, {}), (data[:-1], {}), (data + b"extra", {}),
                 (b"x" * len(data), {}), (data, {"Content-Encoding": "gzip"}),
                 (data, {"Transfer-Encoding": "chunked"}), (data, {"Content-Length": str(len(data) + 1)})]
        for index, (body, headers) in enumerate(cases):
            with self.subTest(index=index):
                response = Response(body, wheel, **headers)
                with patch.object(W.urllib.request, "build_opener") as build:
                    build.return_value.open.return_value = response
                    if index == 0:
                        output = io.BytesIO()
                        W.download(wheel, output, time.monotonic() + 10)
                        self.assertEqual(output.getvalue(), data)
                        request = build.return_value.open.call_args.args[0]
                        self.assertEqual(request.get_header("Accept-encoding"), "identity")
                        self.assertLessEqual(build.return_value.open.call_args.kwargs["timeout"], W.TIMEOUT)
                    else:
                        with self.assertRaises(ValueError):
                            W.download(wheel, io.BytesIO(), time.monotonic() + 10)
        with patch.object(W.urllib.request, "build_opener", side_effect=AssertionError("expired")):
            with self.assertRaisesRegex(ValueError, "deadline"):
                W.download(wheel, io.BytesIO(), time.monotonic() - 1)

    def test_failed_download_never_publishes_partial_wheel(self):
        def fail(wheel, output, deadline):
            output.write(b"partial")
            raise ValueError("transfer refused")
        with patch.object(W, "download", side_effect=fail):
            with self.assertRaisesRegex(ValueError, "transfer refused"):
                self.prepare(allow_download=True)
        self.assertEqual(list(self.destination.iterdir()), [])

    def test_installer_refuses_bad_wheels_before_pip_and_uses_only_local_pip(self):
        spec = importlib.util.spec_from_file_location("wheelhouse_test_installer", ROOT / "scripts/install-sou68-git-profile.py")
        installer = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(installer)
        workspace = self.root / "workspace"
        (workspace / ".git").mkdir(parents=True)
        assets = self.root / "assets"
        assets.mkdir()
        (assets / "requirements.lock").write_bytes(self.requirements.read_bytes())
        (assets / "wheels.lock.json").write_bytes(self.manifest.read_bytes())
        git, bwrap, launcher, archive = [self.root / name for name in ("git", "bwrap", "launcher", "python.tar.gz")]
        for path in (git, bwrap, launcher, archive):
            path.write_bytes(b"owned fixture")
        digest = hashlib.sha256(git.read_bytes()).hexdigest()
        identity = {"files": {}, "git_version": "1.0", "python": {"version": "3.11.0", "sha256": digest}}
        (assets / "upstream-identity.json").write_text(json.dumps(identity))

        def extract(archive, package):
            (package / "python/bin").mkdir(parents=True)
            (package / "python/bin/python3.11").write_bytes(b"never executed")

        for mode in ("bad", "missing", "offline", "download", "explicit-allow", "timeout"):
            valid = mode not in ("bad", "missing")
            destination = self.root / ("install-" + mode)
            first = self.source / self.wheels[0]["filename"]
            first.write_bytes(self.payloads[first.name] if valid else b"bad")
            if mode == "missing":
                first.unlink()
            def download(wheel, output, deadline):
                output.write(self.payloads[wheel["filename"]])
            def invoke(words, **kwargs):
                if words[2].endswith("pilot_wheelhouse.py"):
                    self.assertLessEqual(kwargs["timeout"], 300)
                    if mode == "timeout":
                        raise subprocess.TimeoutExpired(words, kwargs["timeout"])
                    W.prepare_wheelhouse(assets / "wheels.lock.json", assets / "requirements.lock",
                                         destination / "wheelhouse", allow_download=True)
                    return subprocess.CompletedProcess(words, 0)
                self.assertLessEqual(kwargs["timeout"], 300)
                raise RuntimeError("pip boundary")
            with self.subTest(mode=mode), patch.object(installer, "ASSETS", assets), \
                    patch.object(installer.platform, "system", return_value="Linux"), \
                    patch.object(installer.platform, "machine", return_value="x86_64"), \
                    patch.object(installer, "verify_python_notices"), \
                    patch.object(installer, "verify_runtime_license_notices"), \
                    patch.object(installer, "extract_python", side_effect=extract), \
                    patch.object(installer.subprocess, "check_output", side_effect=["git version 1.0", "--ro-bind-fd", "Python 3.11.0"]), \
                    patch.object(installer.subprocess, "run", side_effect=invoke) as run, \
                    patch.object(W, "download", side_effect=download) as fetch, \
                    patch.object(W.urllib.request, "build_opener", side_effect=AssertionError("network forbidden")):
                error = subprocess.TimeoutExpired if mode == "timeout" else RuntimeError if valid else ValueError
                pattern = "timed out" if mode == "timeout" else "pip boundary" if valid else "missing_or_unreviewed" if mode == "missing" else "size_mismatch"
                with self.assertRaisesRegex(error, pattern):
                    installer.install(destination, workspace, git, digest, bwrap, launcher,
                        python_archive=archive, wheelhouse=None if mode in ("download", "timeout") else self.source,
                        allow_download=mode in ("download", "explicit-allow", "timeout"))
                self.assertEqual(fetch.call_count, len(self.wheels) if mode == "download" else 0)
                if mode == "timeout":
                    self.assertEqual(run.call_count, 1)
                elif not valid:
                    run.assert_not_called()
                else:
                    words = run.call_args.args[0]
                    for flag in ("-I", "--isolated", "--require-hashes", "--only-binary=:all:", "--no-compile",
                                 "--no-cache-dir", "--disable-pip-version-check", "--no-index"):
                        self.assertIn(flag, words)
                    self.assertEqual(words[words.index("--find-links") + 1], str(destination / "wheelhouse"))
                    self.assertFalse(any(word.startswith(("https:", "http:")) for word in words))

    def test_ci_executes_only_accepted_helper_and_retains_admission(self):
        spec = importlib.util.spec_from_file_location("wheelhouse_test_ci", ROOT / "scripts/ci/native-prepared-host-inputs.py")
        ci = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(ci)
        self.assertEqual(ci.ACCEPTED, '37dd43e268573be3eab92e3b211e9cec224025af')
        names = ["wheels.lock.json", "requirements.lock"]
        data = {name: (self.root / name).read_bytes() for name in names}
        def git(*words):
            self.assertEqual(words[0], "show")
            self.assertTrue(words[1].startswith(ci.ACCEPTED + ":"))
            return data[words[1].split(":", 1)[1]]
        accepted = ci.accepted_inputs(self.root, names, git)
        self.assertEqual(accepted, data)
        self.requirements.write_bytes(b"candidate change")
        accepted['scripts/pilot_wheelhouse.py'] = b"# accepted helper"
        accepted['profiles/mcp/git-readonly-v1/wheels.lock.json'] = accepted.pop('wheels.lock.json')
        accepted['profiles/mcp/git-readonly-v1/requirements.lock'] = accepted.pop('requirements.lock')
        staged = ci.stage_wheel_inputs(accepted, self.root)
        self.assertEqual(staged['requirements'].read_bytes(), data['requirements.lock'])
        self.assertEqual(staged['manifest'].read_bytes(), data['wheels.lock.json'])
        self.assertEqual(staged['helper'].read_bytes(), b"# accepted helper")
        with self.assertRaisesRegex(RuntimeError, "accepted_setup_input_changed"):
            ci.accepted_inputs(self.root, names, git)
        # The explicitly reviewed snapshot supplies the helper; equality still gates setup.
        def actual_git(*words):
            return subprocess.check_output(["git", *words], cwd=ROOT, stderr=subprocess.DEVNULL, timeout=20)
        self.assertEqual(ci.accepted_inputs(ROOT, ["scripts/pilot_wheelhouse.py"], actual_git),
                         {"scripts/pilot_wheelhouse.py": (ROOT / "scripts/pilot_wheelhouse.py").read_bytes()})
        actual_git("merge-base", "--is-ancestor", ci.ACCEPTED, "HEAD")


if __name__ == "__main__":
    unittest.main()
