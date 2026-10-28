# SPDX-License-Identifier: Apache-2.0
"""Portable custody controls; fake ELF fixtures are never executed."""
import copy
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import ci_qualification_build as B


def elf(marker):
    header = bytearray(64)
    header[:6] = b"\x7fELF\x02\x01"
    header[18:20] = b"\x3e\x00"
    return bytes(header) + marker.encode()


class Custody(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.expected = {
            "source": {"commit": "a" * 40, "tree": "b" * 40, "cargo_lock_sha256": "c" * 64},
            "runtime": {"image": "20261026.1", "rust": "1.99.1", "libc_sha256": "d" * 64},
            "producer": {"run_id": "123", "run_attempt": 1, "repository": "SoupTeam/soup-wall",
                         "workflow_ref": "SoupTeam/soup-wall/.github/workflows/ci.yml@refs/pull/1/merge",
                         "workflow_sha": "e" * 40, "producer_job": "ci-builds--agent-default-ubuntu2404"},
        }
        self.payload = {role: elf(role) for role in B.ROLES}
        self.manifest = {"format": B.FORMAT, "tuple": B.TUPLE, **copy.deepcopy(self.expected),
                         "commands": B.COMMANDS, "files": {
                             role: {"path": path, "mode": 0o555, "size": len(self.payload[role]),
                                    "sha256": B.sha(self.payload[role]), "target": B.TARGETS[role]}
                             for role, path in B.ROLES.items()},
                         "metrics": {"stages": [{"stage": name, "compiled_artifacts": 2, "execution_seconds": 0.5}
                                                for name in ("binary", "tests")],
                                     "compiled_artifacts": 4, "execution_seconds": 1.5}}
        self.archive = self.root / "build.tar.gz"

    def write_archive(self, *, manifest=None, raw=None, change=None, extra=False, omit=False, trailer=b""):
        value = self.manifest if manifest is None else manifest
        raw = B.canonical(value) if raw is None else raw
        with self.archive.open("wb") as output:
            with gzip.GzipFile(fileobj=output, mode="wb", mtime=0) as zipped:
                with tarfile.open(fileobj=zipped, mode="w|", format=tarfile.USTAR_FORMAT) as bundle:
                    bundle.addfile(B.member_info("manifest.json", len(raw), 0o444), io.BytesIO(raw))
                    for index, (role, path) in enumerate(B.ROLES.items()):
                        if omit and index == 3:
                            continue
                        data = self.payload[role]
                        member = B.member_info(path, len(data), 0o555)
                        if change and index == 0:
                            data = change(member, data)
                        bundle.addfile(member, io.BytesIO(data))
                    if extra:
                        bundle.addfile(B.member_info("extra", 1, 0o444), io.BytesIO(b"x"))
            output.write(trailer)
        self.archive.chmod(0o600)
        return B.sha(self.archive.read_bytes()), B.sha(raw)

    def unpack(self, digests, destination=None, expected=None):
        return B.unpack(self.archive, destination or self.root / "selected", expected or self.expected,
                        "456", *digests)

    def unpublished(self, path=None):
        self.assertFalse(((path or self.root / "selected") / "custody.json").exists())

    def test_complete_finite_archive_preserves_every_byte_mode_and_custody(self):
        files = {}
        for role, data in self.payload.items():
            path = self.root / role
            path.write_bytes(data)
            path.chmod(0o555)
            files[role] = path
        digests = B.pack(self.manifest, files, self.archive)
        result = self.unpack((digests["archive_sha256"], digests["manifest_sha256"]))
        self.assertEqual(result["artifact_id"], "456")
        self.assertEqual(json.loads((self.root / "selected/custody.json").read_text()), result)
        for role, path in B.ROLES.items():
            selected = self.root / "selected" / path
            self.assertEqual(selected.read_bytes(), self.payload[role])
            self.assertEqual(selected.stat().st_mode & 0o777, 0o555)

    def test_source_image_abi_workflow_run_and_superseded_attempt_refuse(self):
        digests = self.write_archive()
        for section, field, value in (("source", "commit", "f" * 40), ("source", "tree", "f" * 40),
                                      ("source", "cargo_lock_sha256", "f" * 64),
                                      ("runtime", "image", "different"), ("runtime", "rust", "1.94.1"),
                                      ("runtime", "libc_sha256", "f" * 64),
                                      ("producer", "run_id", "999"), ("producer", "run_attempt", 2),
                                      ("producer", "workflow_sha", "f" * 40),
                                      ("producer", "workflow_ref", "unrelated.yml"),
                                      ("producer", "producer_job", "unrelated-job")):
            with self.subTest(section=section, field=field):
                changed = copy.deepcopy(self.expected)
                changed[section][field] = value
                destination = self.root / (section + "-" + field)
                with self.assertRaisesRegex(ValueError, section + "_identity_mismatch"):
                    self.unpack(digests, destination, changed)
                self.unpublished(destination)
        # A consumer-only rerun retains the same authenticated producer context.
        self.assertEqual(self.unpack(digests)["expected"], self.expected)

    def test_missing_extra_roles_and_role_substitution_refuse_even_rehashed_archive(self):
        for fault in ("missing", "extra", "substitution", "boolean-size"):
            with self.subTest(fault=fault):
                changed = copy.deepcopy(self.manifest)
                if fault == "missing":
                    del changed["files"]["agentfw"]
                elif fault == "extra":
                    changed["files"]["unreviewed"] = changed["files"]["agentfw"]
                elif fault == "substitution":
                    changed["files"]["agentfw"]["target"] = B.TARGETS["library"]
                else:
                    changed["files"]["agentfw"]["size"] = True
                with self.assertRaises(ValueError):
                    self.unpack(self.write_archive(manifest=changed), self.root / fault)
                self.unpublished(self.root / fault)

    def test_tampering_does_not_rebind_protected_producer_hashes(self):
        expected = self.write_archive()
        raw = self.archive.read_bytes()
        self.archive.write_bytes(raw[:-1] + bytes([raw[-1] ^ 1]))
        with self.assertRaisesRegex(ValueError, "artifact_digest_mismatch"):
            self.unpack(expected)
        self.assertFalse((self.root / "selected").exists())

    def test_missing_extra_traversal_links_and_executable_modes_refuse_without_outside_effect(self):
        outside = self.root / "outside"
        outside.write_bytes(b"owned outside sentinel")
        faults = {
            "traversal": lambda info, data: (setattr(info, "name", "../outside") or data),
            "absolute": lambda info, data: (setattr(info, "name", str(outside)) or data),
            "symlink": lambda info, data: (setattr(info, "type", tarfile.SYMTYPE) or
                                           setattr(info, "linkname", str(outside)) or data),
            "hardlink": lambda info, data: (setattr(info, "type", tarfile.LNKTYPE) or
                                            setattr(info, "linkname", str(outside)) or data),
            "mode": lambda info, data: (setattr(info, "mode", 0o4755) or data),
            "corrupt-payload": lambda info, data: data[:-1] + b"!",
        }
        for fault, change in faults.items():
            with self.subTest(fault=fault):
                with self.assertRaises(ValueError):
                    self.unpack(self.write_archive(change=change), self.root / fault)
                self.unpublished(self.root / fault)
                self.assertEqual(outside.read_bytes(), b"owned outside sentinel")
        for fault in ("missing", "extra"):
            with self.subTest(fault=fault), self.assertRaises(ValueError):
                self.unpack(self.write_archive(extra=fault == "extra", omit=fault == "missing"),
                            self.root / fault)
            self.unpublished(self.root / fault)

    def test_duplicate_json_key_refuses(self):
        raw = B.canonical(self.manifest)
        raw = b'{"format":"unreviewed",' + raw[1:]
        with self.assertRaisesRegex(ValueError, "manifest_duplicate_key"):
            self.unpack(self.write_archive(raw=raw))
        self.unpublished()

    def test_extension_and_oversized_headers_refuse_before_reading_declared_body(self):
        for label, kind, size in (("pax", tarfile.XHDTYPE, 2**40),
                                  ("gnu", tarfile.GNUTYPE_LONGNAME, 2**40),
                                  ("large", tarfile.REGTYPE, B.MAX_MANIFEST + 1)):
            with self.subTest(label=label):
                member = B.member_info("manifest.json", size, 0o444)
                member.type = kind
                with gzip.open(self.archive, "wb") as output:
                    output.write(member.tobuf(format=tarfile.GNU_FORMAT))
                self.archive.chmod(0o600)
                digests = B.sha(self.archive.read_bytes()), B.sha(B.canonical(self.manifest))
                with self.assertRaises(ValueError):
                    self.unpack(digests, self.root / label)
                self.unpublished(self.root / label)

    def test_archive_path_replacement_race_never_publishes_custody_or_touches_target(self):
        digests = self.write_archive()
        outside = self.root / "outside"
        outside.write_bytes(b"owned outside sentinel")
        validate = B.validate_manifest
        def race(value, expected):
            result = validate(value, expected)
            self.archive.unlink()
            self.archive.symlink_to(outside)
            return result
        with patch.object(B, "validate_manifest", side_effect=race), \
                self.assertRaisesRegex(ValueError, "archive_changed_during_validation"):
            self.unpack(digests)
        self.unpublished()
        self.assertEqual(outside.read_bytes(), b"owned outside sentinel")

    def test_existing_linked_output_and_hardlinked_input_are_not_repaired(self):
        digests = self.write_archive()
        outside = self.root / "outside"
        outside.mkdir()
        (outside / "sentinel").write_bytes(b"owned")
        selected = self.root / "selected"
        selected.symlink_to(outside)
        with self.assertRaises(FileExistsError):
            self.unpack(digests)
        self.assertTrue(selected.is_symlink())
        self.assertEqual((outside / "sentinel").read_bytes(), b"owned")
        selected.unlink()
        os.link(self.archive, self.root / "other-link")
        with self.assertRaisesRegex(ValueError, "owned_regular_file_required"):
            self.unpack(digests)
        self.assertFalse(selected.exists())

    def test_every_installed_byte_mode_layout_and_receipt_is_rechecked_before_use(self):
        digests = self.write_archive()
        context = {"expected": self.expected, "artifact_id": "456", "archive_sha256": digests[0], "manifest_sha256": digests[1]}
        for fault in ("none", "bytes", "mode", "extra", "missing-marker", "marker", "link", "root-link"):
            with self.subTest(fault=fault):
                destination = self.root / fault
                self.unpack(digests, destination)
                path = destination / B.ROLES["library"]
                if fault == "bytes":
                    path.chmod(0o755);path.write_bytes(elf("tampered"));path.chmod(0o555)
                elif fault == "mode": path.chmod(0o755)
                elif fault in {"extra", "missing-marker", "marker", "link"}:
                    destination.chmod(0o755)
                    if fault == "extra": (destination / "extra").write_bytes(b"extra")
                    elif fault == "missing-marker": (destination / "custody.json").unlink()
                    elif fault == "marker":
                        marker = destination / "custody.json";marker.chmod(0o644);marker.write_text('{}');marker.chmod(0o444)
                    else:
                        (destination / "tests").chmod(0o755);path.unlink();path.symlink_to(self.root / "outside")
                        (destination / "tests").chmod(0o555)
                    destination.chmod(0o555)
                elif fault == "root-link":
                    destination.chmod(0o755);destination.rename(self.root / "real-root")
                    (self.root / "real-root").chmod(0o555);destination.symlink_to(self.root / "real-root")
                with patch.object(B, "source_builder") as builder, patch.object(B, "runtime_identity", return_value=self.expected["runtime"]):
                    builder.return_value.source_identity.return_value = self.expected["source"]
                    if fault == "none":
                        fd = B.verified_role(destination, context, "library")
                        self.assertEqual(os.read(fd, 1024), self.payload["library"]);os.close(fd)
                    else:
                        with self.assertRaises((ValueError, OSError)):
                            B.verified_role(destination, context, "library")


class Dependency(unittest.TestCase):
    def setUp(self):
        self.env = {"GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "2", "GITHUB_REPOSITORY": "SoupTeam/soup-wall",
                    "GITHUB_WORKFLOW_REF": "SoupTeam/soup-wall/.github/workflows/ci.yml@refs/pull/3/merge",
                    "GITHUB_WORKFLOW_SHA": "a" * 40, "SOU166_PRODUCER_RESULT": "success",
                    "SOU166_PRODUCER_ATTEMPT": "1", "SOU166_ARCHIVE_NAME": "build-r123-a1.tar.gz",
                    "SOU166_ARTIFACT_ID": "456", "SOU166_ARCHIVE_SHA256": "b" * 64, "SOU166_MANIFEST_SHA256": "c" * 64}

    def test_retained_producer_and_actual_rerun_have_distinct_immutable_custody(self):
        old = B.dependency_context(self.env)
        self.assertEqual(B.producer_identity(self.env, "1")["run_attempt"], 1)
        rerun = dict(self.env, SOU166_PRODUCER_ATTEMPT="2", SOU166_ARCHIVE_NAME="build-r123-a2.tar.gz", SOU166_ARTIFACT_ID="789")
        self.assertNotEqual(old, B.dependency_context(rerun))

    def test_missing_failed_skipped_future_and_unbound_producer_cannot_download(self):
        faults = {"SOU166_PRODUCER_RESULT": ["", "failure", "skipped", "cancelled"],
                  "SOU166_PRODUCER_ATTEMPT": ["", "0", "3", "-1", "latest", 1],
                  "SOU166_ARTIFACT_ID": ["", "latest", "456,789", "0", "../456"],
                  "SOU166_ARCHIVE_SHA256": ["", "x" * 64], "SOU166_MANIFEST_SHA256": [""],
                  "SOU166_ARCHIVE_NAME": ["build-r123-a2.tar.gz", "../build.tar.gz"],
                  "GITHUB_WORKFLOW_REF": ["SoupTeam/soup-wall/.github/workflows/unrelated.yml@refs/heads/main"],
                  "GITHUB_WORKFLOW_SHA": [""], "GITHUB_REPOSITORY": ["unrelated/repository"]}
        for key, values in faults.items():
            for value in values:
                with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                    B.dependency_context(dict(self.env, **{key: value}))

    def test_only_reviewed_original_commands_can_select_a_role(self):
        valid = ["test", "--locked", "--offline", "-p", "agentfw", "--lib", "create_file", "--", "--nocapture"]
        self.assertEqual(B.parse_cargo(valid), ("library", "create_file"))
        for changed in (valid + ["--ignored"], valid[:5] + ["--all-features"] + valid[5:],
                        valid[:6] + ["nonexistent_filter"] + valid[7:], ["build", "--release"],
                        ["test", "--locked", "--offline", "-p", "agentfw", "--test", "unreviewed", "--", "--nocapture"]):
            with self.subTest(command=changed), self.assertRaises(ValueError): B.parse_cargo(changed)

    def test_zero_test_success_is_failure_and_retains_actual_record(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(B, "source_builder") as builder, \
                patch.dict(os.environ, {"SOU166_MODE": "source", "CARGO_TARGET_DIR": temporary + "/target"}):
            output = Path(temporary) / "result.json"
            def fake(*args, **kwargs): kwargs["log"].write_text("test result: ok. 0 passed; 0 failed; 0 ignored;\n")
            builder.return_value.bounded_cargo.side_effect = fake
            with self.assertRaisesRegex(ValueError, "nonempty_passed"):
                B.cargo(["test", "--locked", "--offline", "-p", "agentfw", "--lib", "create_file", "--", "--nocapture"], output)
            self.assertEqual(json.loads(output.read_text())["status"], "failed")

    def test_fresh_source_target_exists_before_accepted_bounded_runner_checks_it(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(B, "source_builder") as builder, \
                patch.dict(os.environ, {"SOU166_MODE": "source", "CARGO_TARGET_DIR": temporary + "/fresh-target"}):
            output = Path(temporary) / "result.json"
            def inspect(command, **kwargs):
                self.assertTrue(kwargs["target"].is_dir())
                self.assertFalse(kwargs["target"].is_symlink())
                self.assertEqual(command, ["cargo", "build", "--message-format=json", "--locked", "--offline", "-p", "agentfw", "--bin", "agentfw"])
                kwargs["log"].write_text('{"reason":"compiler-artifact","fresh":false}\n')
            builder.return_value.bounded_cargo.side_effect = inspect
            result = B.cargo(["build", "--locked", "--offline", "-p", "agentfw", "--bin", "agentfw"], output)
            self.assertEqual(result["compiled_artifacts"], 1)
            self.assertEqual(result["status"], "passed")


if __name__ == "__main__":
    unittest.main()
