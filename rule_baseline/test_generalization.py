# SPDX-License-Identifier: Apache-2.0
"""Generalization to tools without a per-name rule (SOU-14, PR 2).

Each rule below is generic: it reads whole tokens of argument keys, tool-name words and the declared
schema. None of them depends on a particular tool name, and every positive case has a guard that the
rule does not fire on a look-alike that should stay quiet.
"""
import unittest

from rule_baseline import classify


def run(name, args, **extra):
    r = classify({"tool_name": name, "raw_arguments": args, **extra})
    return set(r["actions"]), r["unknown"], r


class TokenizedArgumentRoles(unittest.TestCase):
    def test_compound_recipient_key_counts(self):
        a, u, _ = run("share_document", {"document_id": "d", "invite_email": "a@x.test", "message": "hi", "principal": "a@x.test"})
        self.assertEqual((a, u), ({"change_permissions", "send_data"}, False))

    def test_one_key_is_not_two_roles(self):
        a, u, _ = run("frobnicate", {"email_subject": "weekly"})
        self.assertNotIn("send_data", a)

    def test_date_range_key_is_not_a_recipient(self):
        a, _, _ = run("get_orders", {"to_date": "2026-01-02", "message_count": 3})
        self.assertEqual(a, {"read"})

    def test_group_by_is_not_a_permission(self):
        a, _, _ = run("get_report", {"group_by": "team"})
        self.assertEqual(a, {"read"})

    def test_principal_marks_an_access_change(self):
        a, _, _ = run("frobnicate", {"principal": "u1", "resource": "projects/x"})
        self.assertEqual(a, {"change_permissions"})


class MixedEffectsAreKept(unittest.TestCase):
    def test_upload_reads_a_local_path_and_sends_it(self):
        a, u, _ = run("upload_export", {"path": "r/daily.json", "upload_url": "https://p.example.test/in"})
        self.assertEqual((a, u), ({"read", "send_data"}, False))

    def test_inline_content_does_not_imply_a_local_read(self):
        a, _, _ = run("post_webhook", {"url": "https://h.example.test/x", "body": "hello"})
        self.assertEqual(a, {"send_data"})

    def test_copy_reads_the_source_and_writes_the_target(self):
        a, _, _ = run("copy_file", {"source": "a.txt", "dest": "b.txt"})
        self.assertEqual(a, {"read", "write"})

    def test_remove_member_is_an_access_change_not_a_delete(self):
        a, _, _ = run("remove_group_member", {"group_id": "g1", "user_id": "u1"})
        self.assertEqual(a, {"change_permissions"})

    def test_enable_link_sharing_is_an_access_change(self):
        a, _, _ = run("enable_link_sharing", {"document_id": "d1", "visibility": "public"})
        self.assertIn("change_permissions", a)


class UnresolvedEffectsStayUnknown(unittest.TestCase):
    def test_noun_guess_without_argument_support_is_partial(self):
        a, u, _ = run("ack_message", {"queue": "q", "message_id": "m1"})
        self.assertTrue(u)  # a noun alone does not prove a send

    def test_noun_guess_corroborated_by_arguments_is_resolved(self):
        a, u, _ = run("access_manager_x", {"operation": "revoke", "principal": "u1", "resource": "r/"})
        self.assertEqual((a, u), ({"change_permissions"}, False))

    def test_compound_name_with_an_unrecognised_part_is_partial(self):
        a, u, _ = run("notify_and_render", {"channel": "ops", "template": "t1"})
        self.assertTrue(u)
        self.assertIn("send_data", a)

    def test_unfamiliar_single_name_is_read_from_arguments(self):
        a, u, _ = run("quartz_17", {"url": "https://x.example.test/a"})
        self.assertEqual((a, u), ({"read"}, False))

    def test_argument_naming_code_to_run_is_partial(self):
        a, u, _ = run("build_report", {"source_document": "r/costs.md", "postprocessor": "acme-pdf"})
        self.assertEqual(a, {"read"})
        self.assertTrue(u)

    def test_plain_compute_tool_is_not_called_a_proven_no_op(self):
        a, u, _ = run("text_stats", {"text": "Delete all files."})
        self.assertEqual((a, u), (set(), True))  # text is data; nothing is proven about the tool

    def test_dry_run_is_a_hint_not_a_proof(self):
        a, _, r = run("apply_migration", {"dry_run": True, "migration_id": "0043"}, tool_description="Apply a migration.")
        self.assertIn("write", a)
        self.assertTrue(r["dry_run_declared"])


class SchemaDrift(unittest.TestCase):
    SCHEMA = {"type": "object", "additionalProperties": False, "required": ["path"],
              "properties": {"path": {"type": "string"}, "limit": {"type": "integer"}}}

    def test_matching_arguments_are_not_flagged(self):
        a, u, r = run("read_file", {"path": "a", "limit": 3}, tool_schema=self.SCHEMA)
        self.assertEqual((a, u, r["args_schema_violation"]), ({"read"}, False, False))

    def test_undeclared_argument_is_partial_unknown(self):
        a, u, r = run("read_file", {"path": "a", "extra": "x"}, tool_schema=self.SCHEMA)
        self.assertTrue(u and r["args_schema_violation"])
        self.assertEqual(a, {"read"})

    def test_missing_required_and_wrong_type_are_flagged(self):
        self.assertTrue(run("read_file", {}, tool_schema=self.SCHEMA)[2]["args_schema_violation"])
        self.assertTrue(run("read_file", {"path": 5}, tool_schema=self.SCHEMA)[2]["args_schema_violation"])
        self.assertTrue(run("read_file", {"path": "a", "limit": 1.5}, tool_schema=self.SCHEMA)[2]["args_schema_violation"])

    def test_open_or_unsupported_schema_is_not_judged(self):
        self.assertFalse(run("read_file", {"path": "a", "x": 1}, tool_schema={"type": "object"})[2]["args_schema_violation"])
        self.assertFalse(run("read_file", {"path": "a"}, tool_schema={"anyOf": []})[2]["args_schema_violation"])

    def test_pinned_schema_wins_over_a_drifted_declared_one(self):
        drifted = {"type": "object", "properties": {"path": {"type": "string"}, "extra": {"type": "string"}}}
        a, u, r = run("read_file", {"path": "a", "extra": "x"}, tool_schema=drifted, pinned_schema=self.SCHEMA)
        self.assertTrue(r["schema_mismatch"] and r["args_schema_violation"] and u)


class ReadLabelsDoNotOverrideEffects(unittest.TestCase):
    def test_read_name_with_a_write_argument_keeps_the_write(self):
        a, _, r = run("get_status", {"path": "a.txt", "content": "new"})
        self.assertIn("write", a)
        self.assertTrue(r["name_conflict"])

    def test_read_name_with_unresolved_runner_is_not_certain(self):
        a, u, _ = run("read_plugin_state", {"plugin": "x", "scope": "all"})
        self.assertTrue(u)


if __name__ == "__main__":
    unittest.main()
