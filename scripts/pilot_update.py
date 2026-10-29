from __future__ import annotations

import argparse
from contextlib import contextmanager, ExitStack
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import selectors
import stat
import subprocess
import sys
import tarfile
import time
import uuid

sys.dont_write_bytecode = True
FORMAT = "sw-pilot-update/1"
INVENTORY = "sw-pilot-update-inventory/1"
STATE = "sw-pilot-update-state/1"
JOURNAL = "sw-pilot-update-journal/1"
LIMIT = 65536
MAX_BINARY = 512 * 1024 * 1024
MAX_ARCHIVE = 32 * 1024 * 1024
RESERVE = 1024 * 1024 * 1024
ROOT = Path(__file__).resolve().parents[1]


class DispatchInterrupted(ValueError):
    dispatch_started = True


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def decode(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "duplicate_json_field")
            result[key] = value
        return result
    def invalid(_):
        raise ValueError("nonfinite_json")
    require(len(raw) <= LIMIT, "record_limit")
    try:
        return json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid)
    except RecursionError:
        raise ValueError("json_depth_limit") from None


def hex_value(value, size):
    return type(value) is str and re.fullmatch("[0-9a-f]{" + str(size) + "}", value) is not None


def open_directory(path):
    path = Path(path)
    require(path.is_absolute() and ".." not in path.parts and len(str(path)) <= 4096
            and len(path.parts) <= 64, "canonical_absolute_directory_required")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for name in path.parts[1:]:
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            os.close(fd)
            fd = child
            info = os.fstat(fd)
            require(info.st_uid in (0, os.getuid()) and
                    (not info.st_mode & 0o022 or info.st_uid == 0 and info.st_mode & stat.S_ISVTX),
                    "untrusted_parent")
        return fd
    except BaseException:
        os.close(fd)
        raise


def identity(info):
    return info.st_dev, info.st_ino


class Directory:
    def __init__(self, path):
        self.path = Path(path)
        self.fd = open_directory(self.path)
        info = os.fstat(self.fd)
        try:
            require(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700,
                    "private_directory_required")
        except BaseException:
            os.close(self.fd)
            raise
        self.identity = identity(info)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        os.close(self.fd)

    def check(self):
        latest = open_directory(self.path)
        try:
            require(identity(os.fstat(latest)) == self.identity, "directory_replaced")
        finally:
            os.close(latest)

    def read(self, name, default=None):
        self.check()
        require("/" not in name and name not in (".", ".."), "invalid_record_name")
        try:
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=self.fd)
        except FileNotFoundError:
            return default
        try:
            info = os.fstat(fd)
            require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
                    and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1
                    and info.st_size <= LIMIT, "owned_bounded_record_required")
            raw = bytearray()
            while len(raw) <= LIMIT:
                block = os.read(fd, min(8192, LIMIT + 1 - len(raw)))
                if not block:
                    break
                raw.extend(block)
            after = os.stat(name, dir_fd=self.fd, follow_symlinks=False)
            require((identity(info), info.st_size, info.st_mtime_ns) ==
                    (identity(after), after.st_size, after.st_mtime_ns), "record_changed")
            self.check()
            return decode(raw)
        finally:
            os.close(fd)

    def write(self, name, value):
        self.check()
        require("/" not in name and name not in (".", ".."), "invalid_record_name")
        raw = canonical(value) + b"\n"
        require(len(raw) <= LIMIT, "record_limit")
        self.read(name)
        temporary = ".update-" + uuid.uuid4().hex
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=self.fd)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(os.dup(fd), "wb") as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            self.check()
            os.replace(temporary, name, src_dir_fd=self.fd, dst_dir_fd=self.fd)
            os.fsync(self.fd)
            self.check()
        finally:
            os.close(fd)
            try:
                os.unlink(temporary, dir_fd=self.fd)
            except FileNotFoundError:
                pass

    @contextmanager
    def lock(self, exclusive):
        import fcntl
        self.check()
        fd = os.open(".update.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=self.fd)
        try:
            info = os.fstat(fd)
            require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
                    and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1,
                    "owned_lock_required")
            try:
                fcntl.flock(fd, (fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH) | fcntl.LOCK_NB)
            except BlockingIOError:
                raise ValueError("active_or_concurrent_operation") from None
            self.check()
            yield
        finally:
            os.close(fd)


def read_file(path, limit):
    path = Path(path)
    parent = open_directory(path.parent)
    try:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                     dir_fd=parent)
    finally:
        os.close(parent)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_uid in (0, os.getuid())
                and before.st_nlink == 1 and not before.st_mode & 0o022
                and 0 <= before.st_size <= limit, "untrusted_or_oversized_input")
        h = hashlib.sha256()
        raw = bytearray() if limit <= MAX_ARCHIVE else None
        count = 0
        while block := os.read(fd, 1024 * 1024):
            count += len(block)
            require(count <= limit, "input_grew")
            h.update(block)
            if raw is not None:
                raw.extend(block)
        after = os.fstat(fd)
        require((before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
                (after.st_size, after.st_mtime_ns, after.st_ctime_ns), "input_changed")
        return {"path": str(path), "sha256": h.hexdigest(), "size": count,
                "mode": f"{stat.S_IMODE(before.st_mode):04o}"}, bytes(raw) if raw is not None else None
    finally:
        os.close(fd)


def checked_file(record, limit=MAX_BINARY):
    require(type(record) is dict and set(record) == {"path", "sha256", "size", "mode"}
            and type(record["path"]) is str and hex_value(record["sha256"], 64)
            and type(record["size"]) is int and 0 < record["size"] <= limit
            and record["mode"] in ("0400", "0500", "0600", "0644", "0700", "0755"),
            "invalid_file_inventory")
    actual, raw = read_file(record["path"], limit)
    require(actual == record, "input_identity_changed")
    return raw


def compatible(source, helper, selection):
    require(type(source) is dict and set(source) == {"commit", "tree", "dirty", "files_sha256"}
            and hex_value(source["commit"], 40) and hex_value(source["tree"], 40)
            and hex_value(source["files_sha256"], 64) and source["dirty"] is False,
            "invalid_source_identity")
    require(helper == {key: source[key] for key in ("commit", "tree")}
            and selection.get("source") == source, "mixed_source")


def tree_entries(root):
    root = Path(root)
    pending = [root]
    count = 0
    while pending:
        path = pending.pop()
        with Directory(path) as directory, os.scandir(directory.fd) as entries:
            for entry in entries:
                count += 1
                require(count <= 512, "generation_entry_limit")
                info = entry.stat(follow_symlinks=False)
                item = path / entry.name
                if stat.S_ISDIR(info.st_mode):
                    pending.append(item)
                    yield str(item.relative_to(root)), "directory"
                else:
                    require(stat.S_ISREG(info.st_mode), "linked_or_special_generation_entry")
                    yield str(item.relative_to(root)), "file"
            directory.check()


def component(record, source):
    raw = checked_file(record, MAX_ARCHIVE)
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
        members = archive.getmembers()
        require(2 <= len(members) <= 129 and all(member.isfile() and not member.pax_headers for member in members)
                and members[0].name == "manifest.json", "unsupported_component")
        manifest_raw = archive.extractfile(members[0]).read(LIMIT + 1)
        manifest = decode(manifest_raw)
        require(canonical(manifest) == manifest_raw and set(manifest) == {"schema", "entry", "python", "source", "files"}
                and manifest["schema"] == "sw-pilot-front-door-component/1"
                and manifest["entry"] == "scripts/pilot.py"
                and manifest["python"] == "cpython>=3.11,<3.14", "unsupported_component")
        compatible(source, manifest["source"], {"source": source})
        entries = manifest["files"]
        require(type(entries) is list and len(entries) == len(members) - 1, "component_files_mismatch")
        names = [entry["path"] for entry in entries]
        require(names == sorted(set(names)) and {"scripts/pilot.py", "source-identity.json",
                "scripts/prepare-installed-pilot.py", "scripts/pilot-run.py"} <= set(names),
                "incomplete_component")
        for member, entry in zip(members[1:], entries):
            require(set(entry) == {"mode", "path", "sha256", "size"}
                    and member.name == entry["path"] and len(member.name) <= 100
                    and all(re.fullmatch(r"[A-Za-z0-9_.-]+", part) and part not in (".", "..")
                            for part in member.name.split("/"))
                    and type(entry["size"]) is int and 0 <= entry["size"] <= 1024 * 1024
                    and member.size == entry["size"] and entry["mode"] in ("0400", "0500"),
                    "invalid_component_member")
            data = archive.extractfile(member).read(1024 * 1024 + 1)
            require(hashlib.sha256(data).hexdigest() == entry["sha256"], "component_hash_mismatch")
            if member.name == "source-identity.json":
                require(decode(data) == {"format": "sw-pilot-source-identity/1", "source": source},
                        "component_source_mismatch")
        return hashlib.sha256(manifest_raw).hexdigest()


def inventory(value):
    require(type(value) is dict and set(value) == {"format", "source", "version", "component", "interpreter",
            "prefix", "selection", "front_door", "runtime"} and value["format"] == INVENTORY,
            "unsupported_inventory")
    require(type(value["version"]) is str and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", value["version"]),
            "invalid_version")
    prefix = Path(value["prefix"])
    with Directory(prefix):
        pass
    selection = decode(checked_file(value["selection"], LIMIT))
    door = decode(checked_file(value["front_door"], LIMIT))
    require(type(selection) is dict and type(door) is dict, "invalid_preparation_records")
    path = Path(value["selection"]["path"])
    require(path.name == "selection.json" and hex_value(path.parent.name, 32)
            and path.parent.parent.parent == prefix / "preparation"
            and value["front_door"]["path"] == str(prefix / "front-door.json")
            and door.get("format") == "sw-pilot-front-door/1"
            and door.get("selection") == str(path)
            and door.get("selection_sha256") == value["selection"]["sha256"]
            and door.get("commit") == value["source"]["commit"]
            and door.get("tree") == value["source"]["tree"], "prepared_prefix_mismatch")
    with Directory(prefix / "preparation") as preparation:
        marker = preparation.read("current.json")
    require(marker == {"format": "sw-pilot-preparation/1", "generation": path.parent.name,
            "selection_sha256": value["selection"]["sha256"], "status": "prepared-not-active"},
            "prepared_marker_changed")
    runtime = value["runtime"]
    require(type(runtime) is dict and set(runtime) == set(selection.get("files", {}))
            and {"agentfw", "git_launcher", "sandbox_tests", "python", "git", "claude", "bwrap", "node", "npm"}
            <= set(runtime) and len(runtime) <= 32, "runtime_inventory_incomplete")
    for name, record in runtime.items():
        checked_file(record)
        selected = selection["files"][name]
        require(selected == {key: record[key] for key in ("path", "sha256")}, "runtime_selection_mismatch")
    checked_file(value["interpreter"])
    require(value["interpreter"] == runtime["python"], "interpreter_identity_mismatch")
    identifier = component(value["component"], value["source"])
    compatible(value["source"], {key: value["source"][key] for key in ("commit", "tree")}, selection)
    return {"inventory_sha256": digest(value), "component": identifier,
            "source": value["source"], "prefix": str(prefix)}


def make_inventory(prefix, archive, archive_sha256, expected_commit, version):
    prefix = Path(prefix)
    with Directory(prefix) as directory:
        door = directory.read("front-door.json")
    require(type(door) is dict and hex_value(expected_commit, 40) and door.get("commit") == expected_commit,
            "reviewed_commit_required")
    selection_path = Path(door["selection"])
    selection_record, raw = read_file(selection_path, LIMIT)
    selected = decode(raw)
    runtime = {role: read_file(entry["path"], MAX_BINARY)[0] for role, entry in selected["files"].items()}
    component_record, _ = read_file(archive, MAX_ARCHIVE)
    require(component_record["sha256"] == archive_sha256, "reviewed_component_digest_required")
    value = {"format": INVENTORY, "source": selected["source"], "version": version,
             "component": component_record, "interpreter": runtime["python"], "prefix": str(prefix),
             "selection": selection_record, "front_door": read_file(prefix / "front-door.json", LIMIT)[0],
             "runtime": runtime}
    inventory(value)
    return value


def state(root):
    root = Path(root)
    if not root.exists() and not root.is_symlink():
        fd = open_directory(root.parent)
        os.close(fd)
        return {"format": STATE, "current": None, "previous": None}
    with Directory(root) as directory:
        value = directory.read("current.json", {"format": STATE, "current": None, "previous": None})
    return validate_state(value)


def validate_state(value):
    require(type(value) is dict and set(value) == {"format", "current", "previous"} and value["format"] == STATE,
            "invalid_coordinator_state")
    for key in ("current", "previous"):
        binding = value[key]
        require(binding is None or type(binding) is dict and set(binding) == {"generation", "inventory_sha256"}
                and hex_value(binding["generation"], 32) and hex_value(binding["inventory_sha256"], 64),
                "invalid_generation_binding")
    return value


def read_journal(directory):
    value = directory.read("journal.json")
    if value is None:
        return None
    fields = {"format", "phase", "before", "after", "plan_sha256"}
    require(type(value) is dict and set(value) in (fields, fields | {"recovery"})
            and value["format"] == JOURNAL and value["phase"] in ("staging", "selecting", "complete")
            and hex_value(value["plan_sha256"], 64), "invalid_update_journal")
    validate_state(value["before"])
    validate_state(value["after"])
    require(value["after"]["current"] is not None
            and value["after"]["previous"] == value["before"]["current"], "invalid_update_journal")
    if "recovery" in value:
        require(value["phase"] == "complete" and value["recovery"] in ("before_selection", "after_selection"),
                "invalid_update_journal")
    return value


def plan(root, candidate):
    root = Path(root)
    require(root.is_absolute() and not root.is_relative_to(ROOT) and not ROOT.is_relative_to(root),
            "external_coordinator_required")
    reviewed = inventory(candidate)
    parent = open_directory(root.parent)
    try:
        destination = {"parent": list(identity(os.fstat(parent))), "root": None}
    finally:
        os.close(parent)
    if root.exists() or root.is_symlink():
        with Directory(root) as directory:
            destination["root"] = list(directory.identity)
    current = state(root)
    require(not root.is_relative_to(candidate["prefix"]) and not Path(candidate["prefix"]).is_relative_to(root),
            "coordinator_prefix_overlap")
    if root.exists():
        with Directory(root) as directory:
            record = read_journal(directory)
            require(not record or record.get("phase") == "complete", "recover_pending_update")
        if current["current"]:
            verify_binding(root, current["current"])
    report = {"format": FORMAT, "action": "preview", "writes": False, "protection": "not_observed",
              "root": str(root), "destination": destination, "before": current, "target": reviewed,
              "accepted_validation": "required_before_selection", "reserve_bytes": RESERVE}
    report["plan_sha256"] = digest(report)
    return report


def confirm_current_plan(directory, candidate, reviewed):
    fresh = plan(directory.path, candidate)
    require(fresh["destination"]["parent"] == reviewed["destination"]["parent"]
            and fresh["destination"]["root"] == list(directory.identity), "directory_replaced")
    if reviewed["destination"]["root"] is None:
        fresh["destination"]["root"] = None
        fresh.pop("plan_sha256")
        fresh["plan_sha256"] = digest(fresh)
    require(fresh["plan_sha256"] == reviewed["plan_sha256"], "plan_confirmation_changed")


def load_helper(name, root, filename):
    spec = importlib.util.spec_from_file_location(name, Path(root) / "scripts" / filename)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@contextmanager
def selection_leases(values):
    lock = load_helper("update_selection_lock", ROOT, "pilot-selection-lock.py")
    with ExitStack() as stack:
        for prefix in sorted({value["prefix"] for value in values}):
            stack.enter_context(lock.hold(Path(prefix) / "preparation", exclusive=True))
        transition = load_helper("update_transition", ROOT, "switch-prepared-pilot.py")
        summaries = [{"agent_path": value["runtime"]["agentfw"]["path"],
                      "claude_path": value["runtime"]["claude"]["path"]} for value in values]
        transition.require_inactive(*summaries)
        yield


def generation_dir(root, binding):
    require(type(binding) is dict and hex_value(binding.get("generation"), 32)
            and hex_value(binding.get("inventory_sha256"), 64), "invalid_generation_binding")
    return Path(root) / ("generation-" + binding["generation"])


def stored_inventory(root, binding):
    with Directory(generation_dir(root, binding)) as directory:
        value = directory.read("inventory.json")
    require(digest(value) == binding["inventory_sha256"], "stored_inventory_changed")
    return value


def environment(home):
    return {"HOME": str(home.parent if home.name == ".agentfw" else home), "LANG": "C.UTF-8",
            "PYTHONDONTWRITEBYTECODE": "1", "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null"}


def command(words, home):
    with subprocess.Popen([str(word) for word in words], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, cwd=home, env=environment(home)) as process:
        streams = {process.stdout: bytearray(), process.stderr: bytearray()}
        try:
            deadline = time.monotonic() + 180
            with selectors.DefaultSelector() as selector:
                for stream in streams:
                    selector.register(stream, selectors.EVENT_READ)
                while selector.get_map():
                    require(time.monotonic() < deadline, "component_command_timeout")
                    for key, _ in selector.select(timeout=0.2):
                        block = os.read(key.fd, 8192)
                        if not block:
                            selector.unregister(key.fileobj)
                            continue
                        streams[key.fileobj].extend(block)
                        require(len(streams[key.fileobj]) <= LIMIT, "component_command_output_limit")
            process.wait(timeout=max(0.1, deadline - time.monotonic()))
            require(process.returncode == 0, "accepted_component_operation_failed")
            return bytes(streams[process.stdout])
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=10)


def stage(root, binding, value, directory, guard):
    destination = generation_dir(root, binding)
    os.mkdir(destination.name, mode=0o700, dir_fd=directory.fd)
    os.fsync(directory.fd)
    guard.bind(destination)
    with Directory(destination) as staged:
        staged.write("inventory.json", value)
        staged.write("owner.json", {"format": FORMAT, "generation": binding["generation"],
                     "device": staged.identity[0], "inode": staged.identity[1]})
        operator = destination / "agent-home"
        os.mkdir("agent-home", mode=0o700, dir_fd=staged.fd)
        with Directory(operator) as user_home:
            os.mkdir(".agentfw", mode=0o700, dir_fd=user_home.fd)
        home = operator / ".agentfw"
        agent = value["runtime"]["agentfw"]
        guard.recheck("before_agent_install")
        command([agent["path"], "lifecycle", "install", value["version"], agent["path"],
                 "--sha256", agent["sha256"]], home)
        staged.check()
        archive = value["component"]
        guard.recheck("before_component_install")
        command([agent["path"], "pilot-component", "--home", home, "install", archive["path"],
                 "--sha256", archive["sha256"], "--python", value["interpreter"]["path"]], home)
        staged.check()
        directory.check()


def verify_binding(root, binding):
    value = stored_inventory(root, binding)
    reviewed = inventory(value)
    directory = generation_dir(root, binding)
    home = directory / "agent-home" / ".agentfw"
    with Directory(directory) as stage_dir:
        owner = stage_dir.read("owner.json")
        require(owner == {"format": FORMAT, "generation": binding["generation"],
                         "device": stage_dir.identity[0], "inode": stage_dir.identity[1]}, "generation_replaced")
    with Directory(home / "versions") as versions:
        lifecycle = versions.read("lifecycle.json")
    require(type(lifecycle) is dict, "invalid_managed_receipt")
    active = lifecycle.get("active")
    require(lifecycle.get("process") is None and lifecycle.get("operation") is None
            and lifecycle.get("pending_stage") is None and active is not None
            and lifecycle.get("owned") == [active] and lifecycle.get("previous") is None
            and active["digest"] == value["runtime"]["agentfw"]["sha256"]
            and active["version"] == value["version"] and active["binary"] == "agentfw-" + value["version"],
            "managed_binary_binding_changed")
    binary = home / "versions" / active["binary"]
    record = {**value["runtime"]["agentfw"], "path": str(binary), "mode": "0700"}
    checked_file(record)
    with Directory(home / "pilot-front-door") as component_dir:
        pointer = component_dir.read("current.json")
        require(component_dir.read("journal.json") is None, "component_install_interrupted")
    require(type(pointer) is dict and type(pointer.get("python")) is dict
            and pointer["schema"] == "sw-pilot-front-door-current/1" and pointer["component"] == reviewed["component"]
            and pointer["python"]["path"] == value["interpreter"]["path"]
            and pointer["python"]["sha256"] == value["interpreter"]["sha256"], "component_binding_changed")
    installed = home / "pilot-front-door" / "components" / reviewed["component"]
    archive_raw = checked_file(value["component"], MAX_ARCHIVE)
    with tarfile.open(fileobj=io.BytesIO(archive_raw), mode="r:") as archive:
        manifest_raw = archive.extractfile("manifest.json").read(LIMIT + 1)
        manifest_record, manifest_bytes = read_file(installed / "manifest.json", LIMIT)
        require(manifest_record["mode"] == "0400" and manifest_bytes == manifest_raw,
                "installed_manifest_changed")
        entries = decode(manifest_raw)["files"]
        names = {"manifest.json"} | {"tree/" + entry["path"] for entry in entries}
        directories = {str(parent) for name in names for parent in Path(name).parents if str(parent) != "."}
        observed = set()
        for name, kind in tree_entries(installed):
            require(name in (names if kind == "file" else directories), "unlisted_component_entry")
            if kind == "file":
                observed.add(name)
        require(observed == names, "incomplete_installed_component")
        for entry in entries:
            actual, _ = read_file(installed / "tree" / entry["path"], 1024 * 1024)
            require(all(actual[key] == entry[key] for key in ("mode", "size", "sha256")),
                    "installed_helper_changed")
    return {"inventory": value, "home": home, "binary": binary, "component": reviewed["component"]}


def accepted_validation(verified):
    value, home, binary = verified["inventory"], verified["home"], verified["binary"]
    checked = decode(command([binary, "pilot-component", "--home", home, "verify"], home))
    require(checked.get("ok") is True and checked.get("component") == verified["component"],
            "installed_component_not_verified")
    tree = home / "pilot-front-door" / "components" / verified["component"] / "tree"
    program = ('import importlib.util,sys;from pathlib import Path;'
               'r=Path(sys.argv[1]);s=importlib.util.spec_from_file_location("v",r/"scripts/pilot.py");'
               'm=importlib.util.module_from_spec(s);s.loader.exec_module(m);'
               'm.verified_state(Path(sys.argv[2]));'
               'm.PREP.verify_generation(Path(sys.argv[3]).parent,sys.argv[4],probe_native=False)')
    command([value["interpreter"]["path"], "-I", "-B", "-c", program, tree, value["prefix"],
             value["selection"]["path"], value["source"]["commit"]], home)


def cleanup_plan(root, binding):
    selected = state(root)
    require(binding not in (selected["current"], selected["previous"]), "generation_still_retained")
    with Directory(root) as directory:
        journal = read_journal(directory)
        require(not journal or journal.get("phase") == "complete", "recover_pending_update")
    verified = verify_binding(root, binding)
    destination = generation_dir(root, binding)
    profile = "agent-home/.agentfw"
    component_dir = profile + "/pilot-front-door/components/" + verified["component"]
    expected = {"inventory.json", "owner.json", profile + "/versions/.lock", profile + "/versions/lifecycle.json",
                profile + "/versions/agentfw-" + verified["inventory"]["version"],
                profile + "/pilot-front-door/current.json", component_dir + "/manifest.json"}
    with tarfile.open(fileobj=io.BytesIO(checked_file(verified["inventory"]["component"], MAX_ARCHIVE)), mode="r:") as archive:
        manifest = decode(archive.extractfile("manifest.json").read(LIMIT + 1))
    expected.update(component_dir + "/tree/" + entry["path"] for entry in manifest["files"])
    expected_dirs = {str(parent) for name in expected for parent in Path(name).parents if str(parent) != "."}
    observed = {}
    for name, kind in tree_entries(destination):
        require(name in (expected if kind == "file" else expected_dirs), "unrelated_generation_state_preserved")
        if kind == "file":
            observed[name] = read_file(destination / name, MAX_BINARY)[0]
    require(set(observed) == expected, "incomplete_cleanup_inventory")
    report = {"format": FORMAT, "action": "cleanup", "writes": False,
              "binding": binding, "before": selected, "files": observed}
    report["plan_sha256"] = digest(report)
    return report


def cleanup(root, binding, confirmation):
    with Directory(root) as directory, directory.lock(exclusive=True):
        review = cleanup_plan(root, binding)
        require(review["plan_sha256"] == confirmation, "plan_confirmation_changed")
        verified = verify_binding(root, binding)
        with selection_leases([verified["inventory"]]):
            require(cleanup_plan(root, binding) == review, "cleanup_inputs_changed")
            home = verified["home"]
            agent = verified["inventory"]["runtime"]["agentfw"]["path"]
            command([agent, "pilot-component", "--home", home, "remove", "--all"], home)
            directory.check()
            command([agent, "lifecycle", "remove"], home)
            directory.check()
    return {"format": FORMAT, "status": "owned_components_removed", "generation": binding["generation"],
            "retained": ["inventory.json", "owner.json", "agent-home/.agentfw/versions/.lock"],
            "prepared_inputs": "unchanged", "protection": "not_observed"}


def publish(directory, before, after, confirmation):
    directory.write("journal.json", {"format": JOURNAL, "phase": "selecting", "before": before,
                                    "after": after, "plan_sha256": confirmation})
    actual = directory.read("current.json", {"format": STATE, "current": None, "previous": None})
    require(actual == before, "coordinator_state_changed")
    directory.write("current.json", after)
    directory.write("journal.json", {"format": JOURNAL, "phase": "complete", "before": before,
                                    "after": after, "plan_sha256": confirmation})


def apply(root, candidate, confirmation):
    root = Path(root)
    reviewed = plan(root, candidate)
    require(reviewed["plan_sha256"] == confirmation, "plan_confirmation_changed")
    parent = open_directory(root.parent)
    try:
        require(list(identity(os.fstat(parent))) == reviewed["destination"]["parent"], "directory_replaced")
        if reviewed["destination"]["root"] is None:
            os.mkdir(root.name, mode=0o700, dir_fd=parent)
            os.fsync(parent)
    finally:
        os.close(parent)
    with Directory(root) as directory, directory.lock(exclusive=True):
        confirm_current_plan(directory, candidate, reviewed)
        before = state(root)
        values = [candidate]
        if before["current"]:
            values.append(stored_inventory(root, before["current"]))
        with selection_leases(values):
            confirm_current_plan(directory, candidate, reviewed)
            capacity = load_helper("update_capacity", ROOT, "pilot_capacity.py")
            required = candidate["runtime"]["agentfw"]["size"] + candidate["component"]["size"]
            try:
                with capacity.Guard([capacity.Demand("coordinated_generation", root, required)], RESERVE) as guard:
                    binding = {"generation": uuid.uuid4().hex, "inventory_sha256": digest(candidate)}
                    after = {"format": STATE, "current": binding, "previous": before["current"]}
                    directory.write("journal.json", {"format": JOURNAL, "phase": "staging", "before": before,
                                                    "after": after, "plan_sha256": confirmation})
                    stage(root, binding, candidate, directory, guard)
                    accepted_validation(verify_binding(root, binding))
                    require(inventory(candidate) == reviewed["target"], "candidate_changed_after_stage")
                    guard.recheck("before_coordinated_selection")
                    directory.check()
                    publish(directory, before, after, confirmation)
            except capacity.Refusal:
                raise ValueError("insufficient_or_unknown_stage_capacity") from None
    return {"format": FORMAT, "status": "selected", "current": binding,
            "source": candidate["source"], "protection": "not_observed"}


def rollback_plan(root):
    before = state(root)
    require(before["current"] is not None and before["previous"] is not None, "no_previous_generation")
    with Directory(root) as directory:
        journal = read_journal(directory)
        require(not journal or journal.get("phase") == "complete", "recover_pending_update")
    for binding in (before["current"], before["previous"]):
        verify_binding(root, binding)
    result = {"format": FORMAT, "action": "rollback", "writes": False, "before": before,
              "after": {"format": STATE, "current": before["previous"], "previous": before["current"]}}
    result["plan_sha256"] = digest(result)
    return result


def rollback(root, confirmation):
    with Directory(root) as directory, directory.lock(exclusive=True):
        review = rollback_plan(root)
        require(review["plan_sha256"] == confirmation, "plan_confirmation_changed")
        bindings = [review["before"][key] for key in ("current", "previous")]
        with selection_leases([stored_inventory(root, binding) for binding in bindings]):
            for binding in bindings:
                accepted_validation(verify_binding(root, binding))
            require(rollback_plan(root) == review, "rollback_inputs_changed")
            publish(directory, review["before"], review["after"], confirmation)
    return {"format": FORMAT, "status": "rolled_back", "current": review["after"]["current"],
            "protection": "not_observed", "authority": "fresh_run_required"}


def recovery_plan(root):
    current = state(root)
    with Directory(root) as directory:
        journal = read_journal(directory)
    if not journal or journal.get("phase") == "complete":
        outcome = "nothing_pending"
    else:
        require(journal.get("format") == JOURNAL and journal.get("phase") in ("staging", "selecting"),
                "invalid_update_journal")
        outcome = ("before_selection" if current == journal.get("before") else
                   "after_selection" if current == journal.get("after") else "conflicting_state")
    report = {"format": FORMAT, "action": "recover", "writes": False,
              "outcome": outcome, "current": current, "journal": journal}
    report["plan_sha256"] = digest(report)
    return report


def recover(root, confirmation):
    with Directory(root) as directory, directory.lock(exclusive=True):
        report = recovery_plan(root)
        require(report["plan_sha256"] == confirmation, "plan_confirmation_changed")
        require(report["outcome"] != "conflicting_state", "operator_state_preserved")
        binding = report["current"]["current"]
        if binding:
            verify_binding(root, binding)
        if report["outcome"] != "nothing_pending":
            directory.write("journal.json", {**report["journal"], "phase": "complete",
                                             "recovery": report["outcome"]})
    return {"format": FORMAT, "status": "recovered", "outcome": report["outcome"],
            "protection": "not_observed", "authority": "fresh_run_required"}


def selected_command(root, args):
    with Directory(root) as directory, directory.lock(exclusive=False):
        journal = read_journal(directory)
        require(not journal or journal.get("phase") == "complete", "recover_pending_update")
        binding = state(root)["current"]
        require(binding is not None, "no_coordinated_generation")
        verified = verify_binding(root, binding)
        require(args and args[0] in ("run", "status"), "coordinated_run_or_status_required")
        require(not any(word == "--prefix" or word.startswith("--prefix=") for word in args[1:]),
                "coordinated_prefix_override_refused")
        env = environment(verified["home"])
        if args[0] == "run":
            provider = load_helper("update_provider", ROOT, "pilot_provider.py")
            env.update(provider.selected(os.environ))
        try:
            result = subprocess.run([str(verified["binary"]), "pilot", "--home", str(verified["home"]),
                                     args[0], "--prefix", verified["inventory"]["prefix"], *args[1:]],
                                    cwd=Path.home(), env=env, timeout=3700)
        except subprocess.TimeoutExpired:
            raise DispatchInterrupted("coordinated_dispatch_timeout") from None
        try:
            directory.check()
        except (OSError, ValueError):
            raise DispatchInterrupted("coordinator_changed_after_dispatch") from None
        return result.returncode


def main(argv=None):
    parser = argparse.ArgumentParser(description="Coordinate exact local pilot generations; preview is read-only.")
    parser.add_argument("operation", choices=("inventory", "preview", "apply", "rollback", "recover", "inspect", "cleanup"))
    parser.add_argument("--prefix", type=Path, required=True)
    parser.add_argument("--inventory", type=Path)
    parser.add_argument("--confirm")
    parser.add_argument("--generation")
    parser.add_argument("--inventory-sha256")
    parser.add_argument("--component", type=Path)
    parser.add_argument("--component-sha256")
    parser.add_argument("--expected-commit")
    parser.add_argument("--version")
    args = parser.parse_args(argv)
    try:
        require(sys.platform == "linux" and os.geteuid() != 0, "non_root_linux_required")
        if args.operation in ("apply", "rollback", "recover", "cleanup") and (args.confirm or args.operation == "apply"):
            preparation = load_helper("update_platform", ROOT, "prepare-installed-pilot.py")
            preparation.supported_platform()
        if args.operation == "inventory":
            require(args.component is not None, "local_component_required")
            result = make_inventory(args.prefix, args.component, args.component_sha256, args.expected_commit, args.version)
        elif args.operation in ("preview", "apply"):
            require(args.inventory is not None, "local_inventory_required")
            _, raw = read_file(args.inventory, LIMIT)
            value = decode(raw)
            result = plan(args.prefix, value) if args.operation == "preview" else apply(args.prefix, value, args.confirm)
        elif args.operation == "rollback":
            result = rollback(args.prefix, args.confirm) if args.confirm else rollback_plan(args.prefix)
        elif args.operation == "recover":
            result = recover(args.prefix, args.confirm) if args.confirm else recovery_plan(args.prefix)
        elif args.operation == "cleanup":
            binding = {"generation": args.generation, "inventory_sha256": args.inventory_sha256}
            result = cleanup(args.prefix, binding, args.confirm) if args.confirm else cleanup_plan(args.prefix, binding)
        else:
            result = {"format": FORMAT, "state": state(args.prefix), "protection": "not_observed"}
        print(json.dumps(result, sort_keys=True))
        return 0
    except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError, tarfile.TarError) as error:
        reason = str(error) if isinstance(error, ValueError) and re.fullmatch(r"[a-z_]{1,80}", str(error)) else "update_refused"
        print(json.dumps({"format": FORMAT, "status": "refused", "reason": reason,
                          "protection": "not_observed", "action": "inspect or recover before retrying"}, sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
