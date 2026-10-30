# SPDX-License-Identifier: Apache-2.0
"""Private, explicitly selected provider profiles for the installed pilot.

This is local configuration, not an authority or a credential broker.  The
accepted sealed provider carrier remains the only prepared-host handoff.
"""
from __future__ import annotations

import fcntl
from contextlib import contextmanager
import getpass
import hashlib
import ipaddress
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys
import time
from urllib.parse import urlsplit
import uuid

_provider_spec = importlib.util.spec_from_file_location(
    "provider_profiles_boundary", Path(__file__).with_name("pilot_provider.py"))
PROVIDER = importlib.util.module_from_spec(_provider_spec)
_provider_spec.loader.exec_module(PROVIDER)

FORMAT = "sw-pilot-provider-profile/1"
SELECTED_FORMAT = "sw-pilot-provider-selection/1"
DIRECTORY = "pilot-providers"
NAME = re.compile(r"[a-z][a-z0-9_-]{0,31}\Z")
MODEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,99}\Z")
SHA = re.compile(r"[0-9a-f]{64}\Z")
SECRET_KEYS = frozenset(("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN"))
PUBLIC_KEYS = frozenset(PROVIDER.KEYS) - SECRET_KEYS
MAX_PROFILES = 16
MAX_FILE = PROVIDER.MAX_BYTES


class Refusal(ValueError):
    """Only finite reason codes may cross the CLI boundary."""


def require(condition, reason):
    if not condition:
        raise Refusal(reason)


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def pairs(items):
    result = {}
    for key, value in items:
        require(key not in result, "provider_profile_invalid")
        result[key] = value
    return result


def strict(raw):
    require(len(raw) <= MAX_FILE, "provider_profile_invalid")
    try:
        value = json.loads(raw, object_pairs_hook=pairs,
                           parse_constant=lambda _: require(False, "provider_profile_invalid"))
    except (ValueError, UnicodeError, RecursionError):
        raise Refusal("provider_profile_invalid") from None
    require(type(value) is dict, "provider_profile_invalid")
    return value


def name(value):
    require(type(value) is str and NAME.fullmatch(value) and value != "selected",
            "provider_name_invalid")
    return value


def _url(value, *, endpoint):
    require(type(value) is str and 0 < len(value) <= 512
            and all(33 <= ord(c) < 127 for c in value) and "%" not in value and "\\" not in value,
            "provider_transport_invalid")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        raise Refusal("provider_transport_invalid") from None
    require(parsed.hostname is not None and parsed.username is None and parsed.password is None
            and parsed.query == "" and parsed.fragment == "" and port != 0,
            "provider_transport_invalid")
    host = parsed.hostname
    require(parsed.scheme in ("https", "http") and host.isascii(), "provider_transport_invalid")
    if ":" in host:
        try:
            ipaddress.IPv6Address(host)
        except ValueError:
            raise Refusal("provider_transport_invalid") from None
    else:
        require(len(host) <= 253 and all(re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", part)
                                         for part in host.rstrip(".").split(".")), "provider_transport_invalid")
    if parsed.scheme == "http":
        require(host in ("127.0.0.1", "::1"), "provider_transport_invalid")
    if endpoint:
        require(not any(part in (".", "..") for part in parsed.path.split("/")),
                "provider_transport_invalid")
    else:
        require(parsed.path in ("", "/"), "provider_transport_invalid")


def validate_public(public):
    require(type(public) is dict and set(public) <= PUBLIC_KEYS | {"model"}
            and type(public.get("model")) is str and MODEL.fullmatch(public["model"]),
            "provider_profile_invalid")
    for key, value in public.items():
        require(type(value) is str and "\0" not in value, "provider_profile_invalid")
        if key == "ANTHROPIC_BASE_URL":
            _url(value, endpoint=True)
        elif key in ("HTTP_PROXY", "HTTPS_PROXY"):
            _url(value, endpoint=False)
        elif key == "NO_PROXY":
            require(len(value) <= 512 and all(re.fullmatch(r"[A-Za-z0-9.*_:\[\]-]{1,128}", part)
                                                  for part in value.split(",")), "provider_transport_invalid")
        elif key == "SSL_CERT_FILE":
            path = Path(value)
            require(path.is_absolute() and path.resolve(strict=True) == path,
                    "provider_transport_invalid")
            info = path.stat()
            require(stat.S_ISREG(info.st_mode) and info.st_uid in (0, os.getuid())
                    and not info.st_mode & 0o022 and info.st_size <= 2 * 1024 * 1024,
                    "provider_transport_invalid")


def validate_profile(value, expected=None):
    require(set(value) == {"format", "name", "public", "secrets"} and value["format"] == FORMAT,
            "provider_profile_invalid")
    name(value["name"])
    require(expected is None or value["name"] == expected, "provider_profile_invalid")
    validate_public(value["public"])
    secrets = value["secrets"]
    require(type(secrets) is dict and len(secrets) == 1 and set(secrets) <= SECRET_KEYS
            and all(type(v) is str and v and "\0" not in v for v in secrets.values()),
            "provider_profile_invalid")
    require(len(encoded(value)) <= MAX_FILE, "provider_profile_invalid")
    PROVIDER.require_access(secrets)
    return value


def secret_input(args):
    if args.secret_fd is not None:
        require(args.secret_fd >= 3, "provider_secret_input_invalid")
        try:
            fd = os.dup(args.secret_fd)
            with os.fdopen(fd, "rb", closefd=True) as stream:
                info = os.fstat(stream.fileno())
                try:
                    seals = fcntl.fcntl(stream.fileno(), fcntl.F_GET_SEALS)
                except OSError:
                    seals = 0
                sealed = info.st_nlink == 0 and (seals & (
                    fcntl.F_SEAL_SEAL | fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK)) == (
                    fcntl.F_SEAL_SEAL | fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK)
                require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
                        and (sealed or stat.S_IMODE(info.st_mode) == 0o600)
                        and info.st_size <= MAX_FILE,
                        "provider_secret_input_invalid")
                stream.seek(0)
                raw = stream.read(MAX_FILE + 1)
                require(len(raw) <= MAX_FILE and _same(os.fstat(stream.fileno()), info),
                        "provider_secret_input_invalid")
            value = strict(raw)
            require(len(value) == 1 and set(value) <= SECRET_KEYS, "provider_secret_input_invalid")
            return value
        except (OSError, ValueError):
            raise Refusal("provider_secret_input_invalid") from None
    require(sys.stdin.isatty(), "provider_terminal_required")
    key = "ANTHROPIC_API_KEY" if args.prompt_api_key else "ANTHROPIC_AUTH_TOKEN"
    return {key: getpass.getpass("Provider secret (hidden): ")}


def _same(left, right):
    return (left.st_dev, left.st_ino, left.st_uid, left.st_mode, left.st_nlink,
            left.st_size, left.st_mtime_ns, left.st_ctime_ns) == (
            right.st_dev, right.st_ino, right.st_uid, right.st_mode, right.st_nlink,
            right.st_size, right.st_mtime_ns, right.st_ctime_ns)


def _open_absolute_directory(path):
    current = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        for part in path.parts[1:]:
            following = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                dir_fd=current)
            os.close(current)
            current = following
        return current
    except BaseException:
        os.close(current)
        raise


class Store:
    def __init__(self, home, *, create=False):
        self.home = Path(home)
        require(self.home.is_absolute() and ".." not in self.home.parts,
                "provider_home_invalid")
        self.home_fd = self.fd = None
        try:
            try:
                self.home_fd = _open_absolute_directory(self.home)
            except FileNotFoundError:
                if not create:
                    return
                raise
            self._private(self.home_fd)
            try:
                self.fd = os.open(DIRECTORY, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                  dir_fd=self.home_fd)
            except FileNotFoundError:
                if create:
                    os.mkdir(DIRECTORY, 0o700, dir_fd=self.home_fd)
                    self.fd = os.open(DIRECTORY, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                      dir_fd=self.home_fd)
            if self.fd is not None:
                self._private(self.fd)
        except (OSError, ValueError):
            self.close()
            raise Refusal("provider_home_invalid") from None

    @staticmethod
    def _private(fd):
        info = os.fstat(fd)
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
                and stat.S_IMODE(info.st_mode) == 0o700, "provider_home_invalid")

    def close(self):
        for key in ("fd", "home_fd"):
            fd = getattr(self, key, None)
            if fd is not None:
                os.close(fd)
                setattr(self, key, None)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def _check(self):
        if self.home_fd is None:
            return
        self._private(self.home_fd)
        reopened = _open_absolute_directory(self.home)
        try:
            require(_same(os.fstat(reopened), os.fstat(self.home_fd)), "provider_home_changed")
        finally:
            os.close(reopened)
        if self.fd is not None:
            self._private(self.fd)
            named = os.stat(DIRECTORY, dir_fd=self.home_fd, follow_symlinks=False)
            require(_same(os.fstat(self.fd), named), "provider_home_changed")

    @contextmanager
    def locked(self):
        require(self.fd is not None, "provider_home_invalid")
        self._check()
        lock = os.open(".lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC,
                       0o600, dir_fd=self.fd)
        try:
            info = os.fstat(lock)
            require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
                    and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1,
                    "provider_private_file_required")
            deadline = time.monotonic() + 5
            while True:
                try:
                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    require(time.monotonic() < deadline, "provider_store_busy")
                    time.sleep(.05)
            require(_same(os.stat(".lock", dir_fd=self.fd, follow_symlinks=False), info),
                    "provider_file_changed")
            self._check()
            # A killed writer can leave only its unpublished create-new file.
            # The lock proves no current writer owns it; never follow or adopt it.
            for entry in os.listdir(self.fd):
                if not re.fullmatch(r"\.next-[0-9a-f]{32}", entry):
                    continue
                temporary = os.stat(entry, dir_fd=self.fd, follow_symlinks=False)
                require(stat.S_ISREG(temporary.st_mode) and temporary.st_uid == os.getuid()
                        and stat.S_IMODE(temporary.st_mode) == 0o600 and temporary.st_nlink == 1
                        and temporary.st_size <= MAX_FILE, "provider_store_invalid")
                os.unlink(entry, dir_fd=self.fd)
            os.fsync(self.fd)
            yield
        finally:
            os.close(lock)

    def read(self, filename):
        if self.fd is None:
            return None
        self._check()
        try:
            before = os.stat(filename, dir_fd=self.fd, follow_symlinks=False)
        except FileNotFoundError:
            return None
        require(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid()
                and stat.S_IMODE(before.st_mode) == 0o600 and before.st_nlink == 1
                and before.st_size <= MAX_FILE, "provider_private_file_required")
        descriptor = os.open(filename, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                             dir_fd=self.fd)
        try:
            opened = os.fstat(descriptor)
            require(_same(opened, before), "provider_file_changed")
            raw = b""
            while len(raw) <= MAX_FILE:
                part = os.read(descriptor, min(4096, MAX_FILE + 1 - len(raw)))
                if not part:
                    break
                raw += part
            require(len(raw) == opened.st_size and _same(os.fstat(descriptor), opened),
                    "provider_file_changed")
            require(_same(os.stat(filename, dir_fd=self.fd, follow_symlinks=False), opened),
                    "provider_file_changed")
            self._check()
            return raw
        finally:
            os.close(descriptor)

    def _write(self, filename, raw, *, replace=False):
        require(self.fd is not None and len(raw) <= MAX_FILE, "provider_profile_invalid")
        self._check()
        old = self.read(filename)
        require(replace or old is None, "provider_profile_exists")
        temporary = ".next-" + uuid.uuid4().hex
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                             0o600, dir_fd=self.fd)
        try:
            with os.fdopen(descriptor, "wb", closefd=True) as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            require(self.read(filename) == old, "provider_file_changed")
            self._check()
            if replace:
                os.replace(temporary, filename, src_dir_fd=self.fd, dst_dir_fd=self.fd)
            else:
                os.link(temporary, filename, src_dir_fd=self.fd, dst_dir_fd=self.fd,
                        follow_symlinks=False)
                os.unlink(temporary, dir_fd=self.fd)
            os.fsync(self.fd)
        finally:
            try:
                os.unlink(temporary, dir_fd=self.fd)
            except FileNotFoundError:
                pass

    def profile(self, profile_name):
        raw = self.read(name(profile_name) + ".json")
        require(raw is not None, "provider_profile_missing")
        return validate_profile(strict(raw), profile_name), digest(raw)

    def names(self):
        if self.fd is None:
            return []
        self._check()
        entries = os.listdir(self.fd)
        require(len(entries) <= MAX_PROFILES + 32, "provider_profile_limit")
        names = []
        for entry in entries:
            if entry.endswith(".json") and entry != "selected.json":
                names.append(name(entry[:-5]))
            elif entry == "selected.json":
                continue
            elif entry == ".lock" or re.fullmatch(r"\.next-[0-9a-f]{32}", entry):
                info = os.stat(entry, dir_fd=self.fd, follow_symlinks=False)
                require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
                        and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1
                        and info.st_size <= MAX_FILE, "provider_store_invalid")
            else:
                raise Refusal("provider_store_invalid")
        require(len(names) <= MAX_PROFILES, "provider_profile_limit")
        return sorted(names)

    def selected(self):
        raw = self.read("selected.json")
        if raw is None:
            return None
        value = strict(raw)
        require(set(value) == {"format", "name", "profile_sha256"}
                and value["format"] == SELECTED_FORMAT
                and type(value["profile_sha256"]) is str and SHA.fullmatch(value["profile_sha256"]),
                "provider_selection_invalid")
        name(value["name"])
        return value

    def inspect(self):
        names = self.names()
        selected = self.selected()
        profiles = []
        identities = {}
        for item in names:
            value, identity = self.profile(item)
            identities[item] = identity
            public = value["public"]
            profiles.append({"name": item, "public_sha256": digest(encoded(public)), "model": public["model"],
                             "endpoint_sha256": digest(public.get("ANTHROPIC_BASE_URL", "").encode()),
                             "transport_fields": sorted(set(public) - {"model", "ANTHROPIC_BASE_URL"})})
        return {"format": SELECTED_FORMAT, "profiles": profiles,
                "selected": selected["name"] if selected else None,
                "selection_valid": selected is None or identities.get(selected["name"]) == selected["profile_sha256"]}

    def create(self, profile_name, public, secrets, *, replace=False):
        profile_name = name(profile_name)
        value = validate_profile({"format": FORMAT, "name": profile_name,
                                  "public": public, "secrets": secrets}, profile_name)
        with self.locked():
            names = self.names()
            require(profile_name in names or len(names) < MAX_PROFILES, "provider_profile_limit")
            self._write(profile_name + ".json", encoded(value), replace=replace)
        return {"name": profile_name, "public_sha256": digest(encoded(public)), "selected": False}

    def select(self, profile_name):
        with self.locked():
            value, identity = self.profile(profile_name)
            self._write("selected.json", encoded({"format": SELECTED_FORMAT, "name": value["name"],
                        "profile_sha256": identity}), replace=True)
        return {"name": value["name"], "public_sha256": digest(encoded(value["public"]))}

    def environment(self):
        if self.fd is not None:
            with self.locked():
                if self.read("selected.json") is not None:
                    os.unlink("selected.json", dir_fd=self.fd)
                    os.fsync(self.fd)
        return {"selection": "explicit-environment"}

    def remove(self, profile_name):
        with self.locked():
            self.profile(profile_name)
            self._check()
            os.unlink(name(profile_name) + ".json", dir_fd=self.fd)
            os.fsync(self.fd)
        return {"removed": profile_name, "selection": "stale-if-selected"}


def chosen(home, environment):
    """Read the exact selected profile; ambient provider fields cannot combine."""
    with Store(home) as store:
        selected = store.selected()
        if selected is None:
            values = PROVIDER.selected(environment)
            PROVIDER.require_access(values)
            return values, None, None, None
        require(not PROVIDER.selected(environment), "provider_source_conflict")
        profile, identity = store.profile(selected["name"])
        require(identity == selected["profile_sha256"], "provider_selection_stale")
        values = dict(profile["public"])
        model = values.pop("model")
        values.update(profile["secrets"])
        return values, model, selected["name"], identity


def unchanged(home, profile_name, identity):
    if profile_name is None:
        return
    with Store(home) as store:
        selected = store.selected()
        require(selected is not None and selected["name"] == profile_name
                and selected["profile_sha256"] == identity
                and store.profile(profile_name)[1] == identity, "provider_selection_stale")
