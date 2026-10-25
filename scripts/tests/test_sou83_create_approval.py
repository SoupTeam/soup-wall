# SPDX-License-Identifier: Apache-2.0
"""Independent checks for the original-create effect and operator witness."""
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

spec = importlib.util.spec_from_file_location("sou83_create_approval", Path(__file__).resolve().parents[1] / "verify-sou83-create-approval.py")
M = importlib.util.module_from_spec(spec)
spec.loader.exec_module(M)


class EffectWitness(unittest.TestCase):
    def test_success_requires_actual_private_exact_file_not_receipt(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.assertRaises(FileNotFoundError): M.verify_publication(root, "write.txt")
            target = root / "write.txt"
            target.write_text("wrong"); target.chmod(0o600)
            with self.assertRaises(ValueError): M.verify_publication(root, "write.txt")
            target.write_text(M.CONTENT); target.chmod(0o644)
            with self.assertRaises(ValueError): M.verify_publication(root, "write.txt")
            target.chmod(0o600)
            self.assertEqual(M.verify_publication(root, "write.txt")["sha256"], hashlib.sha256(M.CONTENT.encode()).hexdigest())
            alias = root / "alias.txt"; alias.symlink_to(target)
            with self.assertRaises(ValueError): M.verify_publication(root, "alias.txt")
            alias.unlink(); alias.hardlink_to(target)
            with self.assertRaises(ValueError): M.verify_publication(root, "write.txt")

    def test_resource_witness_rejects_wrong_root_target_content_or_host_frame(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            args = SimpleNamespace()
            rig = SimpleNamespace(workspace=root, args=args, env={})
            request = M.frame(50, "approved.txt")
            raw = json.dumps(request).encode() + b"\n"
            selected = {"host_call_id": 50, "request_sha256": hashlib.sha256(raw).hexdigest()}
            info = root.stat()
            resource = {"contract_version":"sw-mcp/original-create-resource/1", "workspace":str(root),
                        "device":info.st_dev, "inode":info.st_ino, "target":"/workspace/approved.txt",
                        "content_sha256":hashlib.sha256(M.CONTENT.encode()).hexdigest(),
                        "content_bytes":len(M.CONTENT.encode()), "must_be_absent":True}
            selected["original_create"] = resource
            record = {"args":request["params"]["arguments"], "selected_invocation":selected, "resource_details":resource}
            waiting = {"pending_id":"owned", "binding_sha256":"a" * 64}
            client = SimpleNamespace(sent=[raw])
            with patch.object(M.S, "command", return_value="private inspected record"), patch.object(M.S, "inspected_output", return_value=record):
                self.assertEqual(M.inspect_pending(rig, waiting, request, client), record)
                for field, value in [("inode", info.st_ino + 1), ("target", "/workspace/other.txt"),
                                     ("content_bytes", 0), ("content_sha256", "0" * 64), ("must_be_absent", False)]:
                    saved = resource[field]; resource[field] = value
                    with self.subTest(field=field), self.assertRaises(ValueError): M.inspect_pending(rig, waiting, request, client)
                    resource[field] = saved
                client.sent = [b"different request"]
                with self.assertRaises(ValueError): M.inspect_pending(rig, waiting, request, client)

    def test_allowed_looking_response_cannot_satisfy_refusal_witness(self):
        client = Mock()
        client.receive.return_value = ({"id":50, "result":{"content":[]}}, b"")
        with self.assertRaises(ValueError): M.assert_refused(client)
        client.receive.return_value = ({"id":51, "error":{"code":-1}}, b"")
        with self.assertRaises(ValueError): M.assert_refused(client)
        client.receive.return_value = ({"id":50, "error":{"code":-1}}, b"")
        M.assert_refused(client)
