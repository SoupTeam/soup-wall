# SPDX-License-Identifier: Apache-2.0
"""Retain original, bounded inputs of the owned installed qualification privately."""
from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path

from roadmap_support import MAX_REPORT, clean_source, digest, exact, load_json, parse_json, require, safe_file, write_private

RECEIPT_LIMIT = 32 * 1024
SELECTION_LIMIT = 64 * 1024
BUILD_ROLES = ("agentfw", "git_launcher", "sandbox_tests")
TOOL_ROLES = {"ar", "c++", "cargo", "cc", "cmake", "git", "ld", "make", "pkg-config",
              "python", "ranlib", "readelf", "rustc", "rustup"}
TOOL_ENV = {"RUSTC": "rustc", "CC": "cc", "CXX": "c++", "AR": "ar", "RANLIB": "ranlib", "CMAKE": "cmake"}
BUILD_ENV = {"RUSTUP_AUTO_INSTALL": "0", "CARGO_BUILD_JOBS": "2", "SOURCE_DATE_EPOCH": "0",
             "CARGO_PROFILE_DEV_DEBUG": "0", "CARGO_PROFILE_TEST_DEBUG": "0"}
BUILD_COMMANDS = [
    ["cargo", "build", "--locked", "-p", "agentfw", "--bins", "--message-format=json"],
    ["cargo", "test", "--locked", "-p", "agentfw", "--lib", "--no-run", "--message-format=json"],
]
SELECTION_ROLES = {*BUILD_ROLES, "bwrap", "claude", "git", "python", "npm", "node",
                   "filesystem_classifier", "git_classifier", "policy"}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def path_field(value):
    require(type(value) is str and len(value) <= 1024 and value.startswith("/") and
            all(part not in ("", ".", "..") for part in value[1:].split("/")) and
            not any(ord(char) < 32 or ord(char) == 127 for char in value),
            "unsafe custody input path")


def verify_receipt(raw, source, inputs):
    require(len(raw) <= RECEIPT_LIMIT, "source-build receipt byte limit")
    receipt = exact(parse_json(raw), {"format", "status", "source", "tools", "toolchain",
                                     "commands", "environment", "binaries", "build_seconds",
                                     "generation_tree_sha256"}, "source-build receipt")
    require(receipt["format"] == "sw-native-pilot-agent-source-build/1" and
            receipt["status"] == "built-not-qualified" and receipt["toolchain"] == "1.94.1" and
            receipt["commands"] == BUILD_COMMANDS, "source-build receipt contract mismatch")
    clean_source(receipt["source"], "build source", source["commit"], source["tree"],
                 ("files_sha256", "cargo_lock_sha256", "rust_toolchain_sha256"))
    digest(receipt["generation_tree_sha256"], "build generation")
    seconds = receipt["build_seconds"]
    require(type(seconds) in (int, float) and 0 <= seconds <= 1200, "source-build time invalid")
    tools = exact(receipt["tools"], TOOL_ROLES, "build tools")
    for name, item in tools.items():
        exact(item, {"path", "sha256"}, "build tool " + name)
        path_field(item["path"])
        digest(item["sha256"], "build tool " + name)
    expected_env = {**BUILD_ENV, "RUSTUP_TOOLCHAIN": receipt["toolchain"],
                    **{key: tools[role]["path"] for key, role in TOOL_ENV.items()}}
    require(receipt["environment"] == expected_env, "source-build environment mismatch")
    for role, item in exact(receipt["binaries"], set(BUILD_ROLES), "built binaries").items():
        exact(item, {"path", "sha256", "size"}, "built " + role)
        path_field(item["path"])
        require(digest(item["sha256"], "built " + role) == inputs[role],
                "source-build binary mismatch: " + role)
        require(type(item["size"]) is int and 0 < item["size"] <= 512 * 1024 * 1024,
                "source-build binary size invalid")
    return receipt


def verify_selection(raw, source, inputs, build_source):
    require(len(raw) <= SELECTION_LIMIT, "selection byte limit")
    selected = parse_json(raw)
    require(selected.get("format") in ("sw-installed-pilot-selection/2", "sw-installed-pilot-selection/3"),
            "unsupported runtime selection")
    clean_source(selected["source"], "selection source", source["commit"], source["tree"], ("files_sha256",))
    require(selected["source"]["files_sha256"] == build_source["files_sha256"],
            "selection source inventory mismatch")
    files = exact(selected["files"], SELECTION_ROLES, "selection files")
    for role, item in files.items():
        exact(item, {"path", "sha256"}, "selection " + role)
        path_field(item["path"])
        digest(item["sha256"], "selection " + role)
        # Launch preparation stages some roles on different paths.
        if role in inputs:
            require(item["sha256"] == inputs[role], "selection binary mismatch: " + role)
    profiles = exact(selected["prepared_profiles"], {"filesystem", "git"}, "prepared profiles")
    for name, profile in profiles.items():
        digest(profile["registry_sha256"], name + " registry")
        digest(profile["package_tree_sha256"], name + " package")
    return selected


def selected_identities(selected):
    profiles = selected["prepared_profiles"]

    def combined(field):
        return sha((profiles["filesystem"][field] + "\n" + profiles["git"][field] + "\n").encode("ascii"))

    return {"registry": combined("registry_sha256"), "server": combined("package_tree_sha256")}


def retain(output, name, raw):
    """Write the already validated bytes under the producer's private directory."""
    directory = output / "custody"
    directory.mkdir(mode=0o700, exist_ok=True)
    info = directory.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
            and info.st_mode & 0o777 == 0o700, "custody directory must be private")
    write_private(directory, name, raw)
    return {"file": name, "sha256": sha(raw)}


def capture_receipt(output, path, source, inputs, source_root=None):
    raw = safe_file(path, RECEIPT_LIMIT)
    receipt = verify_receipt(raw, source, inputs)
    if source_root is not None:
        verify_receipt_source_files(receipt, source_root)
    return receipt, retain(output, "source-build-receipt.json", raw)


def capture_selection(output, name, path, source, inputs, build):
    raw = safe_file(path, SELECTION_LIMIT)
    verify_selection(raw, source, inputs, build)
    return retain(output, name + "-selection.json", raw)


def verify_cleanup(value):
    row = exact(value, {"observed", "descendant_count", "all_stopped", "remaining"}, "cleanup")
    observed = row["observed"]
    require(type(observed) is list and 1 <= len(observed) <= 512, "cleanup process inventory invalid")
    identities = set()
    parents = 0
    for fact in observed:
        exact(fact, {"pid", "start_time_ticks", "parent_process"}, "observed process")
        require(type(fact["pid"]) is int and 0 < fact["pid"] < 2**31 and
                type(fact["start_time_ticks"]) is int and 0 < fact["start_time_ticks"] < 2**63 and
                type(fact["parent_process"]) is bool, "cleanup process identity invalid")
        key = (fact["pid"], fact["start_time_ticks"])
        require(key not in identities, "duplicate cleanup process identity")
        identities.add(key)
        parents += fact["parent_process"]
    require(parents == 1 and row["remaining"] == [] and row["all_stopped"] is True and
            type(row["descendant_count"]) is int and row["descendant_count"] == len(observed) - parents,
            "cleanup observer incomplete")


def private_json(output, name, value):
    return retain(output, name, (json.dumps(value, sort_keys=True, allow_nan=False) + "\n").encode())


def verify_ref(path, ref, name, limit):
    exact(ref, {"file", "sha256"}, "custody reference")
    require(ref["file"] == name, "unexpected custody filename")
    raw = safe_file(path / name, limit)
    require(sha(raw) == digest(ref["sha256"], "custody file"), "custody bytes changed: " + name)
    return raw


OBSERVER_SOURCES = {
    "procfs": "verify-sou62-real-mcp.py",
    "receiver": "qualify-project-isolation.py",
    "dispatch": "qualify-pilot-launcher.py",
}


def capture_observer_sources(output, source_root, names):
    captured = {}
    for name in names:
        filename = OBSERVER_SOURCES[name]
        raw = safe_file(source_root / "scripts" / filename, 128 * 1024)
        captured[name] = retain(output, filename, raw)
    return captured


def capture_front_door(output, report, receiver_positive, receiver_effects, useful, cancel, file_positive):
    for cleanup in (useful, cancel):
        verify_cleanup(cleanup)
    return private_json(output, "front-door-observer.json", {
        "format": "sw-installed-front-door-observer/1",
        "selection_sha256": report["selection_sha256"],
        "component": report["component"]["component"],
        "source": report["source_before"],
        "receiver_positive": receiver_positive,
        "receiver_effects": receiver_effects,
        "file_positive": file_positive,
        "cases": {"useful": useful, "cancel": cancel},
    })


def read_custody(path, obj, source, inputs):
    binding = exact(obj["custody"], {"format", "receipt", "selections", "observers", "observer_sources"}, "custody")
    require(binding["format"] == "sw-installed-pilot-custody/1", "unsupported custody format")
    raw = verify_ref(path, binding["receipt"], "source-build-receipt.json", RECEIPT_LIMIT)
    receipt = verify_receipt(raw, source, inputs)
    require(sha(raw) == obj["source_build_receipt_sha256"] and receipt["source"] == obj["build_source"] and
            receipt["tools"] == obj["compiler_inputs"], "original build receipt differs from the report")
    return receipt, binding


def check_observer_sources(path, refs, names, source_reader):
    exact(refs, set(names), "observer sources")
    for name in names:
        filename = OBSERVER_SOURCES[name]
        raw = verify_ref(path, refs[name], filename, 128 * 1024)
        require(raw == source_reader(filename, 128 * 1024), "observer source differs from the verifier source")


def verify_front_door(path, obj, source, inputs, companions, source_reader, parent_sha):
    _, binding = read_custody(path, obj, source, inputs)
    selections = exact(binding["selections"], {"primary", "demo"}, "front-door selections")
    selected = {}
    for name, field in (("primary", "selection_sha256"), ("demo", "demo_selection_sha256")):
        ref = selections[name]
        raw = verify_ref(path, ref, name + "-selection.json", SELECTION_LIMIT)
        require(ref["sha256"] == obj[field], name + " selection differs from parent")
        selected[name] = verify_selection(raw, source, inputs, obj["build_source"])
    require(selections["primary"]["sha256"] != selections["demo"]["sha256"] and
            "prepared_workspaces" in selected["primary"] and "prepared_workspaces" not in selected["demo"],
            "primary and demo selections are not distinct workspaces")
    require(selected["primary"]["files"]["policy"]["sha256"] == selected["demo"]["files"]["policy"]["sha256"],
            "selected policies differ")
    for role in ("demo", "installed-pilot"):
        child = companions[role][0]
        require(child.get("parent_report_sha256") == parent_sha, role + " belongs to a different parent")
        require(child.get("selection_sha256") == selections["demo"]["sha256"],
                role + " selected a different generation")
        require(child.get("selected_sha256") == {key: value["sha256"] for key, value in selected["demo"]["files"].items()},
                role + " selected different runtime bytes")
    check_observer_sources(path, binding["observer_sources"], ("procfs", "receiver"), source_reader)
    observer = exact(binding["observers"], {"front-door"}, "front-door observers")
    raw = verify_ref(path, observer["front-door"], "front-door-observer.json", 128 * 1024)
    witness = exact(parse_json(raw), {"format", "selection_sha256", "component", "source",
                                     "receiver_positive", "receiver_effects", "file_positive", "cases"},
                    "front-door observer")
    require(witness["format"] == "sw-installed-front-door-observer/1" and witness["source"] == source and
            witness["selection_sha256"] == obj["selection_sha256"] and
            witness["component"] == obj["component"]["component"], "foreign front-door observer")
    require(type(witness["receiver_positive"]) is int and witness["receiver_positive"] == 1 and
            witness["file_positive"] is True, "observer calibration missing")
    require(type(witness["receiver_effects"]) is int and witness["receiver_effects"] == 0, "receiver effects observed")
    for name, cleanup in exact(witness["cases"], {"useful", "cancel"}, "cleanup cases").items():
        verify_cleanup(cleanup)
        row = next(row for row in obj["cases"] if row["case"] == name)
        require(row["process_cleanup"] == {"all_stopped": True, "descendants": cleanup["descendant_count"]},
                "cleanup observer differs from original case")
    pilot, demo = (companions[name][0] for name in ("installed-pilot", "demo"))
    pilot_cases = {case["id"]: case["evidence"] for case in pilot["cases"]}
    calibration = pilot_cases["witness-calibration"]
    require(calibration["receiver_positive_observed"] is True and calibration["original_write_observed"] is True and
            type(calibration["git_original_opens"]) is int and calibration["git_original_opens"] > 0 and
            calibration["fifo"]["forbidden.fifo"]["reader_seen"] is True,
            "installed-pilot observer calibration missing")
    refusal = pilot_cases["untrusted-input-refusal"]
    require(refusal["fifo"]["reader_seen"] is False and refusal["fifo"]["bytes_written"] == 0 and
            refusal["opens_during_refused_mutator"] == 0 and refusal["receiver_deliveries"] == 0,
            "installed-pilot refusal witnesses incomplete")
    cleanup = pilot_cases["final-cleanup"]
    require(cleanup["all_owned_processes_stopped"] is True and cleanup["private_installation_removed"] is True and
            cleanup["source_and_inputs_unchanged"] is True and cleanup["forced_cleanup"] is False,
            "installed-pilot cleanup witness incomplete")
    verify_cleanup(refusal["host"]["process_cleanup"])
    demo_case = next(case for case in demo["cases"] if case["case"] == "useful-refusal")
    require(demo_case["dispatch_counts"] == [1, 1, 0] and demo_case["exact_once_kernel_read"] is True,
            "demo execution/refusal witnesses incomplete")
    verify_cleanup(demo_case["process_cleanup"])
    identities = selected_identities(selected["primary"])
    return binding, combine_identities([identities, selected_identities(selected["demo"])])


def read_child(path):
    return load_json(path, MAX_REPORT)


def capture_clean_user_observer(output, name, selection, source, receiver_positive,
                                receiver_effects, dispatch, cleanup):
    verify_cleanup(cleanup)
    return private_json(output, name + "-observer.json", {
        "format": "sw-clean-user-observer/1",
        "selection_sha256": selection, "source": source, "receiver_positive": receiver_positive,
        "receiver_effects": receiver_effects, "discoveries": dispatch["discoveries"],
        "calls": dispatch["calls"], "cleanup": cleanup,
    })


def verify_clean_user(path, obj, source, inputs, companions, source_reader, _parent_sha):
    _, binding = read_custody(path, obj, source, inputs)
    names = ("catalog-service", "release-ledger")
    selections = exact(binding["selections"], {*names, "walkthrough"}, "clean-user selections")
    require(len({r["sha256"] for r in selections.values()}) == 3, "duplicate clean-user selection")
    check_observer_sources(path, binding["observer_sources"], ("procfs", "receiver", "dispatch"), source_reader)
    observers = exact(binding["observers"], set(names), "clean-user observers")
    measured = []
    for name in (*names, "walkthrough"):
        ref = selections[name]
        raw = verify_ref(path, ref, name + "-selection.json", SELECTION_LIMIT)
        selected = verify_selection(raw, source, inputs, obj["build_source"])
        measured.append(selected_identities(selected))
        selected_files = {key: value["sha256"] for key, value in selected["files"].items()}
        if name == "walkthrough":
            demo, ask = companions["walkthrough"][0], companions["ask"][0]
            require(ref["sha256"] == obj["walkthrough_selection_sha256"] == demo.get("selection_sha256") ==
                    obj["ask_selection_sha256"], "walkthrough or Ask selection differs from parent")
            require(demo["selected_sha256"] == selected_files, "walkthrough selected different runtime bytes")
            for role in ("agentfw", "git_launcher", "claude", "node", "npm", "bwrap", "git"):
                require(ask["selected_sha256"][role] == selected_files[role], "Ask selected different runtime bytes")
            continue
        project = obj["projects"][name]
        require(ref["sha256"] == project["selection_sha256"] and selected_files == project["selected_sha256"] and
                selected["source"] == project["selected_source"] and
                selected["prepared_profiles"] == project["profiles"], name + " selection differs from parent")
        raw = verify_ref(path, observers[name], name + "-observer.json", 128 * 1024)
        witness = exact(parse_json(raw), {"format", "selection_sha256", "source", "receiver_positive",
                                         "receiver_effects", "discoveries", "calls", "cleanup"}, "clean-user observer")
        require(witness["format"] == "sw-clean-user-observer/1" and witness["source"] == source and
                witness["selection_sha256"] == ref["sha256"], "foreign clean-user observer")
        require(type(witness["receiver_positive"]) is int and witness["receiver_positive"] == 1 and
                type(witness["discoveries"]) is int and 2 <= witness["discoveries"] <= 64,
                "observer calibration missing")
        require(type(witness["receiver_effects"]) is int and witness["receiver_effects"] == 0, "receiver effects observed")
        require(type(witness["calls"]) is list and 1 <= len(witness["calls"]) <= 64, "dispatch inventory invalid")
        for call in witness["calls"]:
            exact(call, {"pid", "fd", "id", "tool", "args_sha256"}, "observed dispatch")
            digest(call["args_sha256"], "observed dispatch arguments")
            require(call["tool"] == "read_text_file", "unexpected original dispatch")
        verify_cleanup(witness["cleanup"])
        row = next(row for row in obj["clean_user"]["cases"] if row["id"] == name + ":denied-calls")
        require(row["process_cleanup"] == {"all_stopped": True, "descendants": witness["cleanup"]["descendant_count"]},
                "cleanup observer differs from original case")
    return binding, combine_identities(measured)


def verify_parent(path, selection_sha, source):
    parent, parent_sha = read_child(path)
    require(parent.get("format") == "sw-installed-front-door-qualification/1" and
            parent.get("status") == "passed" and parent.get("provider") == "owned-scripted-loopback" and
            parent.get("source_before") == parent.get("source_after") ==
            {key: source[key] for key in ("commit", "tree", "dirty")} and
            parent.get("demo_selection_sha256") == selection_sha,
            "companion selection differs from the original parent")
    return parent_sha


def combine_identities(measured):
    return {name: sha("".join(item[name] + "\n" for item in measured).encode("ascii"))
            for name in ("registry", "server")}


def verify_receipt_source_files(receipt, source_root):
    for key, filename in (("cargo_lock_sha256", "Cargo.lock"), ("rust_toolchain_sha256", "rust-toolchain.toml")):
        require(sha(safe_file(source_root / filename, 1024 * 1024)) == receipt["source"][key],
                "source-build receipt input mismatch: " + filename)
