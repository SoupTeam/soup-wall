# SPDX-License-Identifier: Apache-2.0
"""Check actual extracted release layouts using owned inert binary fixtures."""

import io
import gzip
import json
from pathlib import Path
import subprocess
import struct
import sys
import tarfile
import tempfile
import unittest
import zipfile


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import release_docs as docs


class ReleaseDocumentation(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="release-doc-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.commit = "a" * 40
        self.target = docs.TARGETS[0]

    def stage(self, target=None):
        target = target or self.target
        stage = self.root / ("soup-wall-test-" + target)
        stage.mkdir()
        for name in docs.required_files(target) | {"README.md"}:
            path = stage / name
            path.parent.mkdir(parents=True, exist_ok=True)
            if name in {"agentfw", "soup-wall-bench", "llm-firewall", "soup-wall-gateway"} or name.endswith(".exe"):
                # Inert owned bytes. They are never executed and prove no native behavior.
                path.write_bytes(b"owned supplied binary fixture; not executable code\n")
                path.chmod(0o755)
            else:
                source = "vendor/kryptering/LICENSE" if name == "third-party/kryptering/LICENSE" else name
                path.write_bytes((ROOT / source).read_bytes())
        docs.stage(ROOT, stage, self.commit, target)
        return stage

    def archive(self, stage, target=None, entries=None):
        target = target or self.target
        windows = target.endswith("windows-msvc")
        archive = self.root / (stage.name + (".zip" if windows else ".tar.gz"))
        if windows:
            with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as package:
                for path in sorted(stage.rglob("*")):
                    if path.is_file():
                        package.write(path, stage.name + "/" + path.relative_to(stage).as_posix())
                for name, data in entries or []:
                    package.writestr(name, data)
        else:
            with tarfile.open(archive, "w:gz") as package:
                def modes(member):
                    # Windows filesystems do not carry Unix execute bits. The
                    # controlled tar fixture explicitly models Unix staging.
                    if member.name.rsplit("/", 1)[-1] in {"agentfw", "soup-wall-bench", "llm-firewall", "soup-wall-gateway"}:
                        member.mode = 0o755
                    return member
                package.add(stage, arcname=stage.name, filter=modes)
                for name, data in entries or []:
                    member = tarfile.TarInfo(name)
                    member.size = len(data)
                    package.addfile(member, io.BytesIO(data))
        return archive

    def check(self, archive, stage, target=None):
        return docs.check_archive(ROOT, archive, self.commit, target or self.target, stage.name)

    def test_all_four_real_archive_formats_preserve_complete_operator_closure(self):
        for target in docs.TARGETS:
            with self.subTest(target=target):
                stage = self.stage(target)
                record = self.check(self.archive(stage, target), stage, target)
                self.assertEqual(record["status"], "passed")
                self.assertEqual(record["native_execution"], "not performed")
                self.assertGreaterEqual(record["documents"], 140)
                self.assertIn("Binary archive copy", (stage / "README.md").read_text())
                self.assertIn("docs/RELEASE_ARCHIVE.md", (stage / "README.md").read_text())
                self.assertTrue((stage / "docs/img/soup-wall-mark.svg").is_file())
                self.assertEqual((stage / "firewall.yaml").read_bytes(), (ROOT / "firewall.yaml").read_bytes())
                self.assertEqual((stage / "third-party/kryptering/LICENSE").read_bytes(), (ROOT / "vendor/kryptering/LICENSE").read_bytes())
                self.assertNotIn(".checkpoint", "\n".join(docs.inventory(stage)))

    def test_extracted_omitted_asset_refuses(self):
        stage = self.stage()
        (stage / "docs/img/soup-wall-mark.svg").unlink()
        (stage / "docs/img").rmdir()
        with self.assertRaisesRegex(ValueError, "membership/hash"):
            self.check(self.archive(stage), stage)

    def test_unlisted_empty_archive_directories_refuse(self):
        stage = self.stage()
        (stage / "unlisted-empty").mkdir()
        with self.assertRaisesRegex(ValueError, "undeclared empty archive directory"):
            self.check(self.archive(stage), stage)

    def test_extracted_changed_asset_refuses(self):
        stage = self.stage()
        (stage / "docs/SELF_HOSTING.md").write_text("changed")
        with self.assertRaisesRegex(ValueError, "membership/hash"):
            self.check(self.archive(stage), stage)

    def test_forged_self_manifest_does_not_hide_document_corruption(self):
        stage = self.stage()
        (stage / "README.md").write_text("[broken](docs/absent.md)")
        record = json.loads((stage / docs.MANIFEST).read_text())
        record["files"]["README.md"] = {"sha256": docs.digest((stage / "README.md").read_bytes()), "size": (stage / "README.md").stat().st_size}
        (stage / docs.MANIFEST).write_text(json.dumps(record))
        with self.assertRaisesRegex(ValueError, "canonical rendering"):
            self.check(self.archive(stage), stage)

    def test_wrong_source_and_target_refuse(self):
        stage = self.stage()
        archive = self.archive(stage)
        with self.assertRaisesRegex(ValueError, "source documentation identity"):
            docs.check_archive(ROOT, archive, "b" * 40, self.target, stage.name)
        with self.assertRaises((ValueError, zipfile.BadZipFile)):
            docs.check_archive(ROOT, archive, self.commit, docs.TARGETS[-1], stage.name)

    def test_duplicate_case_colliding_and_escaping_members_refuse(self):
        stage = self.stage()
        for name in (stage.name + "/README.md", stage.name + "/Readme.md", "../escape.txt", stage.name + "/../escape.txt", stage.name + "/bad\\name", stage.name + "/CON.txt"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.check(self.archive(stage, entries=[(name, b"x")]), stage)

    def test_zip_duplicate_and_link_entry_refuse(self):
        stage = self.stage(docs.TARGETS[-1])
        archive = self.archive(stage, docs.TARGETS[-1])
        with zipfile.ZipFile(archive, "a") as package:
            member = zipfile.ZipInfo(stage.name + "/linked")
            member.create_system = 3
            member.external_attr = (0o120777 << 16)
            package.writestr(member, "README.md")
        with self.assertRaisesRegex(ValueError, "linked ZIP"):
            self.check(archive, stage, docs.TARGETS[-1])

    def test_zip_implicit_parent_case_aliases_refuse_before_extraction(self):
        target = docs.TARGETS[-1]
        stage = self.stage(target)
        for original, alias in (("docs/SELF_HOSTING.md", "DOCS/SELF_HOSTING.md"),
                                ("docs/operations/SANDBOX.md", "docs/OPERATIONS/SANDBOX.md"),
                                ("docs/img/soup-wall-mark.svg", "docs/IMG/soup-wall-mark.svg")):
            # Omit explicit directory entries. Every full filename remains
            # unique even under casefold; unrelated children share the parent.
            archive = self.root / "parent-case-alias.zip"
            with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as package:
                for path in sorted(stage.rglob("*")):
                    if path.is_file():
                        relative = path.relative_to(stage).as_posix()
                        package.write(path, stage.name + "/" + (alias if relative == original else relative))
            with self.subTest(alias=alias), self.assertRaisesRegex(ValueError, "archive path casing"):
                self.check(archive, stage, target)

    def test_oversized_parser_metadata_is_rejected_before_archive_loading(self):
        archive = self.root / "huge-header.tar.gz"
        member = tarfile.TarInfo("metadata")
        member.type = tarfile.XHDTYPE
        member.size = 65537
        with gzip.open(archive, "wb") as output:
            output.write(member.tobuf())
        with self.assertRaisesRegex(ValueError, "metadata budget"):
            docs.bound_archive_headers(archive, False)
        archive = self.root / "huge-directory.zip"
        archive.write_bytes(struct.pack("<4s4H2IH", b"PK\x05\x06", 0, 0, 65534, 65534, 0, 0, 0))
        with self.assertRaisesRegex(ValueError, "oversized ZIP directory"):
            docs.bound_archive_headers(archive, True)

    def test_tar_links_and_missing_executable_mode_refuse(self):
        stage = self.stage()
        archive = self.archive(stage)
        with tarfile.open(archive, "r:gz") as package:
            contents = [(member, package.extractfile(member).read() if member.isfile() else None) for member in package]
        for link in (True, False):
            with tarfile.open(archive, "w:gz") as package:
                for member, data in contents:
                    if member.name.endswith("/agentfw") and not link:
                        member.mode = 0o644
                    package.addfile(member, io.BytesIO(data) if data is not None else None)
                if link:
                    member = tarfile.TarInfo(stage.name + "/linked")
                    member.type = tarfile.SYMTYPE
                    member.linkname = "README.md"
                    package.addfile(member)
            with self.assertRaises(ValueError):
                self.check(archive, stage)

    def test_group_only_execute_mode_does_not_qualify_unix_binary(self):
        stage = self.stage()
        archive = self.archive(stage)
        with tarfile.open(archive, "r:gz") as package:
            contents = [(member, package.extractfile(member).read() if member.isfile() else None) for member in package]
        for mode in (0o0010, 0o0410):
            with tarfile.open(archive, "w:gz") as package:
                for member, data in contents:
                    if member.name.endswith("/agentfw"):
                        # An extracted file is owned by the extracting user;
                        # group execute cannot substitute for owner execute.
                        member.mode = mode
                    package.addfile(member, io.BytesIO(data) if data is not None else None)
            with self.subTest(mode=oct(mode)), self.assertRaisesRegex(ValueError, "owner"):
                self.check(archive, stage)

    def test_tar_owner_read_and_directory_traversal_are_required(self):
        stage = self.stage()
        archive = self.archive(stage)
        with tarfile.open(archive, "r:gz") as package:
            contents = [(member, member.mode, package.extractfile(member).read() if member.isfile() else None) for member in package]
        for relative, mode in (("", 0o400), ("docs", 0), ("docs", 0o100),
                               ("docs/SELF_HOSTING.md", 0o040), ("agentfw", 0o100)):
            changed = stage.name + ("/" + relative if relative else "")
            with tarfile.open(archive, "w:gz") as package:
                for member, original_mode, data in contents:
                    member.mode = mode if member.name == changed else original_mode
                    package.addfile(member, io.BytesIO(data) if data is not None else None)
            with self.subTest(path=relative, mode=oct(mode)), self.assertRaisesRegex(ValueError, "owner"):
                self.check(archive, stage)

    def test_archive_verifies_from_both_clean_lf_and_crlf_git_checkouts(self):
        source = self.root / "lf-source"
        source.mkdir()
        files = {"README.md": b"# Fixture\n\n[Guide](docs/RELEASE_ARCHIVE.md)\n",
                 docs.INDEX: b"# Archive guide\n\n[README](../README.md)\n",
                 "docs/img/fixture.svg": b"<svg>\n</svg>\n"}
        contract = {"format": docs.FORMAT, "documents": {name: docs.digest(data) for name, data in files.items()}, "source_only": []}
        files[docs.CONTRACT] = (json.dumps(contract, indent=2) + "\n").encode()
        for name in docs.BASE:
            path = "vendor/kryptering/LICENSE" if name == "third-party/kryptering/LICENSE" else name
            files[path] = b"owned source fixture\n"
        for name, data in files.items():
            path = source / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        def git(*args):
            return subprocess.check_output(["git", *args], stderr=subprocess.PIPE).decode().strip()
        git("init", "--quiet", str(source))
        git("-C", str(source), "config", "core.autocrlf", "false")
        git("-C", str(source), "add", ".")
        git("-C", str(source), "-c", "user.name=Archive fixture", "-c", "user.email=fixture@example.invalid", "commit", "--quiet", "-m", "owned fixture")
        commit = git("-C", str(source), "rev-parse", "HEAD")
        other = self.root / "crlf-source"
        git("clone", "--quiet", "--no-checkout", str(source), str(other))
        git("-C", str(other), "config", "core.autocrlf", "true")
        git("-C", str(other), "checkout", "--quiet", commit)
        self.assertEqual(git("-C", str(other), "status", "--porcelain"), "")
        self.assertIn(b"\r\n", (other / docs.CONTRACT).read_bytes())
        self.assertNotIn(b"\r\n", (source / docs.CONTRACT).read_bytes())
        target = docs.TARGETS[-1]
        stage = self.root / "cross-checkout-archive"
        stage.mkdir()
        for name in docs.required_files(target) | {"README.md"}:
            path = stage / name
            path.parent.mkdir(parents=True, exist_ok=True)
            if name.endswith(".exe"):
                path.write_bytes(b"owned inert fixture")
            else:
                path.write_bytes((source / ("vendor/kryptering/LICENSE" if name == "third-party/kryptering/LICENSE" else name)).read_bytes())
        docs.stage(source, stage, commit, target)
        archive = self.archive(stage, target)
        for checkout in (source, other):
            with self.subTest(checkout=checkout.name):
                self.assertEqual(docs.check_archive(checkout, archive, commit, target, stage.name)["status"], "passed")

    def test_canonical_operator_index_and_shipped_command_guides_stay_offline(self):
        names = docs.read_contract(ROOT)["documents"]
        index = (ROOT / "docs/README.md").read_text()
        operator_section = index.split("## Product and operator guides\n", 1)[1].split("\n## ", 1)[0]
        for _, line in docs.check_docs.markdown_lines(operator_section):
            for original in docs.check_docs.link_destinations(line):
                target = "docs/" + original.split("#", 1)[0]
                self.assertIn(target, names)
        for name in ("AGENT_DOCTOR.md", "AGENT_COMMAND_HELP.md", "MCP_PROFILE_LIFECYCLE.md",
                     "PILOT_CONFIGURATION_RECOVERY.md", "SCIM_DIRECTORY.md", "TLS_ROTATION.md"):
            self.assertIn("docs/operations/" + name, names)

    def test_source_only_links_are_exact_commit_and_original_commands_labelled(self):
        stage = self.stage()
        readme = (stage / "README.md").read_text()
        self.assertIn(f"{docs.REPOSITORY}/blob/{self.commit}/CONTRIBUTING.md", readme)
        self.assertIn("Canonical source-build examples remain unchanged", readme)
        self.assertIn("./target/release/agentfw install", readme)
        self.assertNotIn("operations/evidence/", "\n".join(docs.inventory(stage)))

    def test_broken_heading_and_case_refuse_at_extracted_boundary(self):
        stage = self.stage()
        cases = ("[bad](docs/SELF_HOSTING.md#missing)", "[bad](docs/self_hosting.md)", "[bad](../escape.md)", "[bad](file:///tmp/foo)", "[bad](docs\\SELF_HOSTING.md)")
        for content in cases:
            (stage / "probe.md").write_text(content)
            with self.subTest(content=content), self.assertRaises(ValueError):
                docs.validate_links(stage, set(docs.inventory(stage)))

    def test_source_hash_and_declared_omission_controls(self):
        with tempfile.TemporaryDirectory(prefix="release-doc-source-") as temporary:
            source = Path(temporary)
            files = {"README.md": b"# Fixture\n", docs.INDEX: b"# Index\n"}
            contract = {"format": docs.FORMAT, "documents": {name: docs.digest(data) for name, data in files.items()}, "source_only": []}
            files[docs.CONTRACT] = json.dumps(contract).encode()
            for name, data in files.items():
                path = source / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
            subprocess.run(["git", "init", "--quiet", str(source)], check=True, capture_output=True)
            subprocess.run(["git", "-C", str(source), "add", "."], check=True, capture_output=True)
            (source / "README.md").write_bytes(b"changed")
            with self.assertRaisesRegex(ValueError, "stale documentation source hash"):
                docs.rendered_documents(source, self.commit)
        tracked = docs.source_names(ROOT)
        with self.assertRaisesRegex(ValueError, "undeclared offline omission"):
            docs.render(ROOT, "README.md", b"[implementation](CONTRIBUTING.md)\n", {"README.md"}, [], tracked, self.commit)
        with self.assertRaisesRegex(ValueError, "broken source anchor"):
            docs.render(ROOT, "README.md", b"[implementation](CONTRIBUTING.md#missing)\n", {"README.md"}, ["CONTRIBUTING.md"], tracked, self.commit)
        with self.assertRaises(ValueError):
            docs.render(ROOT, "README.md", b"![logo](docs/img/soup-wall-mark.svg)\n", {"README.md"}, ["docs/img/soup-wall-mark.svg"], tracked, self.commit)

    def test_local_source_manifest_does_not_copy_private_or_historical_inputs(self):
        names = docs.read_contract(ROOT)["documents"]
        self.assertFalse(any("evidence" in Path(name).parts or name.startswith((".git", ".codex", ".checkpoint")) or name == "AGENTS.md" for name in names))
        self.assertLessEqual(len(names), 192)

    def test_both_workflow_stages_check_final_archives_without_changing_publish_gates(self):
        workflow = (ROOT / ".github/workflows/release.yml").read_text()
        for title, extension in (("Stage (unix)", ".tar.gz"), ("Stage (windows)", ".zip")):
            block = workflow.split("      - name: " + title + "\n", 1)[1].split("\n      - ", 1)[0]
            self.assertIn("scripts/release_docs.py stage", block)
            self.assertIn("scripts/release_docs.py check-archive", block)
            self.assertIn("${{ needs.verify.outputs.sha }}", block)
            self.assertIn(extension, block)
        self.assertIn("bash promotion-admission.sh", workflow)
        self.assertIn("bash ../promotion-admission.sh", workflow)


if __name__ == "__main__":
    unittest.main()
