# SPDX-License-Identifier: Apache-2.0
"""Prepared/installed selection boundaries, with the reviewed original assets."""
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import pilot_git_profiles as G


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / file)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


PREP = load("profile_test_preparation", "prepare-installed-pilot.py")
DOOR = load("profile_test_door", "pilot.py")
BUILD = load("profile_test_builder", "build-pilot-front-door.py")


class Selection(unittest.TestCase):
    def test_only_one_reviewed_declaration_and_exact_original_schemas(self):
        upstream = json.loads((ROOT / G.ASSETS / "upstream-tools-list.json").read_bytes())["result"]["tools"]
        original = G.registry(G.DEFAULT)
        for name in G.PROFILES:
            with self.subTest(name=name):
                bound = G.binding(name)
                self.assertEqual(G.from_selection({"format": G.SELECTION_V3, "git_selection": bound}), name)
                registry = G.registry(name)
                self.assertEqual([t["name"] for t in registry["tools"]], [t["name"] for t in upstream])
                self.assertEqual([(t["schema_sha256"], t["action_class"], t["egress"]) for t in registry["tools"]],
                                 [(t["schema_sha256"], t["action_class"], t["egress"]) for t in original["tools"]])
                self.assertTrue(all(t.get("mcp_result_profile", bound["profile_format"]) == bound["profile_format"]
                                    for t in registry["tools"]))
        for union in (list(G.PROFILES), "git-readonly-file-revisions-v1+git-tracked-symlinks-readonly-v1",
                      "file-revisions", "", None):
            with self.subTest(union=union), self.assertRaisesRegex(ValueError, "select_one_reviewed_variant"):
                G.binding(union)

    def test_manifest_versions_never_upgrade_legacy_authority(self):
        self.assertEqual(G.from_selection({"format": G.SELECTION_V2}), G.DEFAULT)
        for name in G.PROFILES:
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, "legacy_selection"):
                G.from_selection({"format": G.SELECTION_V2, "git_selection": G.binding(name)})
        for version in (G.SELECTION_V3, "sw-installed-pilot-selection/4"):
            with self.assertRaises(ValueError):
                G.from_selection({"format": version})
        value = G.binding("git-readonly-file-revisions-v1")
        for key in ("profile_format", "registry_id", "registry_sha256", "policy_sha256", "classifier_sha256", "files"):
            bad = copy.deepcopy(value)
            bad[key] = {} if key == "files" else "changed"
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, "binding_changed"):
                G.from_selection({"format": G.SELECTION_V3, "git_selection": bad})

    def test_reviewed_classifier_follows_selected_grammar_only(self):
        schema = next(t["inputSchema"] for t in json.loads((ROOT / G.ASSETS / "upstream-tools-list.json").read_bytes())
                      ["result"]["tools"] if t["name"] == "git_show")
        for name in G.PROFILES:
            spec = importlib.util.spec_from_file_location("selected_test_classifier", G.classifier_path(name))
            classifier = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(classifier)
            for revision, accepted in (("HEAD:tracked.txt", name == "git-readonly-file-revisions-v1"),
                                       ("refs/heads/main", name == "git-readonly-local-refs-v1")):
                with self.subTest(name=name, revision=revision):
                    self.assertEqual(classifier._bounded_git_read("git_show", {"repo_path": "/workspace",
                        "revision": revision}, {"tool_schema": schema, "pinned_schema": schema}), accepted)

    def test_repeated_cli_selection_refuses_without_effects(self):
        for script, words in (("pilot.py", ["preview", "--prefix", "/tmp/uncreated-sou162"]),
                              ("prepare-installed-pilot.py", [])):
            result = subprocess.run([sys.executable, "-B", str(ROOT / "scripts" / script), *words,
                "--git-profile", G.DEFAULT, "--git-profile", "git-readonly-file-revisions-v1"],
                capture_output=True, timeout=30)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(b"exactly one reviewed variant", result.stderr)

    def test_policy_identity_and_source_changes_fail_before_selection(self):
        name = "git-tracked-symlinks-readonly-v1"
        selection = {"format": G.SELECTION_V3, "git_selection": G.binding(name)}
        with patch.object(G, "sha", return_value="0" * 64), self.assertRaises(ValueError):
            G.from_selection(selection)


class InstalledClosure(unittest.TestCase):
    def test_every_variant_previews_from_component_without_checkout_or_selected_execution(self):
        source = {"commit": "a" * 40, "tree": "b" * 40, "dirty": False, "files_sha256": "c" * 64}
        archive, _ = BUILD.assemble(BUILD.contents(), source)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            tree = root / "installed"
            with tarfile.open(fileobj=io.BytesIO(archive)) as bundle:
                for member in bundle.getmembers()[1:]:
                    path = tree / member.name
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(bundle.extractfile(member).read())
            self.assertFalse((tree / ".git").exists())
            for name in G.PROFILES:
                with self.subTest(name=name):
                    prefix = root / name
                    result = subprocess.run([sys.executable, "-I", "-B", str(tree / "scripts/pilot.py"),
                        "preview", "--prefix", str(prefix), "--git-profile", name, "--json"],
                        cwd=root, env={"PATH": "/usr/bin:/bin", "HOME": str(root)}, capture_output=True, timeout=60)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    report = json.loads(result.stdout.splitlines()[-1])
                    self.assertEqual(report["git_selection"], G.binding(name))
                    self.assertFalse(report["executed"])
                    self.assertFalse(prefix.exists())
                    self.assertEqual(report["source"]["commit"], source["commit"])
            # Alter a selected reviewed helper while retaining its old identity.
            path = tree / "scripts/install-sou107-git-profile.py"
            path.write_bytes(path.read_bytes() + b"\n# altered\n")
            result = subprocess.run([sys.executable, "-I", "-B", str(tree / "scripts/pilot.py"), "preview",
                "--prefix", str(root / "tamper"), "--git-profile", "git-tracked-symlinks-readonly-v1", "--json"],
                cwd=root, env={"PATH": "/usr/bin:/bin", "HOME": str(root)}, capture_output=True, timeout=60)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((root / "tamper").exists())


class ProfileBytes(unittest.TestCase):
    def fixture(self, root, name):
        package = root / "package"
        (package / "python/bin").mkdir(parents=True)
        runtime = package / "python/bin/python3.11"
        runtime.write_bytes(b"owned runtime fixture")
        for file in ("git", "git_launcher", "bwrap"):
            (root / file).write_bytes(file.encode())
        paths = {key: root / key for key in ("git", "git_launcher", "bwrap")}
        workspace = root / "repository"
        workspace.mkdir()
        profile = {"format": G.selected(name)[0], "workspace": str(workspace), "runtimePath": str(runtime),
            "runtimeSha256": G.sha(runtime), "packageRoot": str(package), "packageTreeSha256": PREP.FS.tree_sha(package),
            "bwrapPath": str(paths["bwrap"]), "bwrapSha256": G.sha(paths["bwrap"]), "libraries": [],
            "git": {"path": str(paths["git"]), "sha256": G.sha(paths["git"])},
            "gitLauncher": {"path": str(paths["git_launcher"]), "sha256": G.sha(paths["git_launcher"])}}
        receipt = {"format": "sou68-profile-installation/1", "profile": profile,
                   "upstream_identity": json.loads((ROOT / G.ASSETS / "upstream-identity.json").read_bytes())}
        identity = G.selected(name)[2]
        if identity:
            receipt.update(format="sou150-profile-installation/1" if "tracked" in name else "sou107-profile-installation/1",
                           selection_identity=json.loads((ROOT / identity).read_bytes()))
        for file, value in (("profile.json", profile), ("registry.json", G.registry(name))):
            (root / file).write_text(json.dumps(value))
        (root / "policy.yaml").write_bytes(G.policy_path(name).read_bytes())
        for label in ("profile", "registry", "policy"):
            receipt[label + "_sha256"] = G.sha(root / (label + (".yaml" if label == "policy" else ".json")))
        (root / "installation.json").write_text(json.dumps(receipt))
        return paths, workspace, receipt

    def test_selected_bytes_verify_and_receipt_rehash_cannot_broaden_registry_or_profile(self):
        for name in G.PROFILES:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                root.chmod(0o700)
                paths, workspace, receipt = self.fixture(root, name)
                verified = PREP.verify_profile("git", root, paths, workspace, name, versioned=True)
                self.assertEqual(verified["format"], G.selected(name)[0])
                original = (root / "registry.json").read_bytes()
                registry = json.loads(original)
                registry["tools"][0]["egress"] = ["https://outside.invalid"]
                (root / "registry.json").write_text(json.dumps(registry))
                receipt["registry_sha256"] = G.sha(root / "registry.json")
                (root / "installation.json").write_text(json.dumps(receipt))
                with self.assertRaisesRegex(ValueError, "profile_registry_changed"):
                    PREP.verify_profile("git", root, paths, workspace, name)
                (root / "registry.json").write_bytes(original)
                receipt["registry_sha256"] = G.sha(root / "registry.json")
                profile = receipt["profile"]
                profile["format"] = "sw-mcp/git-readonly-file-revisions/1" if name == G.DEFAULT else "sw-mcp/git-readonly/1"
                (root / "profile.json").write_text(json.dumps(profile))
                receipt["profile_sha256"] = G.sha(root / "profile.json")
                (root / "installation.json").write_text(json.dumps(receipt))
                with self.assertRaisesRegex(ValueError, "profile_format_changed"):
                    PREP.verify_profile("git", root, paths, workspace, name)


if __name__ == "__main__":
    unittest.main()
