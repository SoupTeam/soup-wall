"""Handle-verified local NTFS I/O for the existing offline audit exporter.

This module is imported only on Windows. It does not repair existing ACLs.
"""

import ctypes as C
from ctypes import wintypes as W
import io
import msvcrt
import os
from pathlib import Path


KERNEL = C.WinDLL("kernel32", use_last_error=True)
ADVAPI = C.WinDLL("advapi32", use_last_error=True)
INVALID = W.HANDLE(-1).value
READ = 0x80000000
WRITE = 0x40000000
READ_CONTROL = 0x00020000
SHARE_READ = 1
SHARE_WRITE = 2
CREATE_NEW = 1
OPEN_EXISTING = 3
OPEN_REPARSE = 0x00200000
BACKUP_SEMANTICS = 0x02000000
ATTR_REPARSE = 0x400
ATTR_OFFLINE = 0x1000
ATTR_DIRECTORY = 0x10
PROTECTED_DACL = 0x1000
OWNER_DACL = 5
SE_FILE_OBJECT = 1
TOKEN_QUERY = 8


class WinStoreError(Exception):
    pass


class FileInfo(C.Structure):
    _fields_ = [("attributes", W.DWORD), ("created", W.FILETIME),
                ("accessed", W.FILETIME), ("written", W.FILETIME),
                ("volume", W.DWORD), ("size_high", W.DWORD),
                ("size_low", W.DWORD), ("links", W.DWORD),
                ("index_high", W.DWORD), ("index_low", W.DWORD)]


class AclSize(C.Structure):
    _fields_ = [("count", W.DWORD), ("in_use", W.DWORD), ("free", W.DWORD)]


class SecurityAttributes(C.Structure):
    _fields_ = [("length", W.DWORD), ("descriptor", W.LPVOID), ("inherit", W.BOOL)]


def _call(name, result, args, *values):
    fn = getattr(KERNEL if name in {"CreateFileW", "CloseHandle", "GetFileInformationByHandle",
                                        "GetVolumeInformationW", "GetDriveTypeW", "QueryDosDeviceW",
                                        "CreateDirectoryW", "FlushFileBuffers", "GetCurrentProcess"}
                 else ADVAPI, name)
    fn.restype = result
    fn.argtypes = args
    return fn(*values)


def _fail(message):
    raise WinStoreError(f"{message} (Windows error {C.get_last_error()})")


def _close(handle):
    if handle not in (None, INVALID):
        _call("CloseHandle", W.BOOL, [W.HANDLE], handle)


def _local_free(pointer):
    fn = KERNEL.LocalFree
    fn.restype = W.HANDLE
    fn.argtypes = [W.HANDLE]
    fn(pointer)


def _sid_string(sid):
    result = W.LPWSTR()
    if not _call("ConvertSidToStringSidW", W.BOOL, [W.LPVOID, C.POINTER(W.LPWSTR)], sid, C.byref(result)):
        _fail("audit SID unavailable")
    try:
        return result.value
    finally:
        _local_free(result)


def _current_sid():
    token = W.HANDLE()
    process = _call("GetCurrentProcess", W.HANDLE, [])
    if not _call("OpenProcessToken", W.BOOL, [W.HANDLE, W.DWORD, C.POINTER(W.HANDLE)],
                 process, TOKEN_QUERY, C.byref(token)):
        _fail("audit account unavailable")
    try:
        needed = W.DWORD()
        _call("GetTokenInformation", W.BOOL, [W.HANDLE, W.DWORD, W.LPVOID, W.DWORD, C.POINTER(W.DWORD)],
              token, 1, None, 0, C.byref(needed))
        buf = C.create_string_buffer(needed.value)
        if not _call("GetTokenInformation", W.BOOL, [W.HANDLE, W.DWORD, W.LPVOID, W.DWORD, C.POINTER(W.DWORD)],
                     token, 1, buf, needed, C.byref(needed)):
            _fail("audit account unavailable")
        sid = C.cast(buf, C.POINTER(W.LPVOID))[0]
        return _sid_string(sid)
    finally:
        _close(token)


def _private_acl(handle, directory):
    owner = W.LPVOID()
    dacl = W.LPVOID()
    descriptor = W.LPVOID()
    code = _call("GetSecurityInfo", W.DWORD,
                 [W.HANDLE, W.DWORD, W.DWORD, C.POINTER(W.LPVOID), W.LPVOID,
                  C.POINTER(W.LPVOID), W.LPVOID, C.POINTER(W.LPVOID)],
                 handle, SE_FILE_OBJECT, OWNER_DACL, C.byref(owner), None,
                 C.byref(dacl), None, C.byref(descriptor))
    if code:
        raise WinStoreError("audit ACL unavailable")
    try:
        if (not owner or not dacl or not _call("IsValidAcl", W.BOOL, [W.LPVOID], dacl)
                or _sid_string(owner) != _current_sid()):
            raise WinStoreError("audit object has unsafe owner or DACL")
        control = W.WORD()
        revision = W.DWORD()
        if not _call("GetSecurityDescriptorControl", W.BOOL,
                     [W.LPVOID, C.POINTER(W.WORD), C.POINTER(W.DWORD)],
                     descriptor, C.byref(control), C.byref(revision)) or not control.value & PROTECTED_DACL:
            raise WinStoreError("audit DACL is not protected")
        info = AclSize()
        if not _call("GetAclInformation", W.BOOL,
                     [W.LPVOID, W.LPVOID, W.DWORD, W.DWORD],
                     dacl, C.byref(info), C.sizeof(info), 2) or info.count != 2:
            raise WinStoreError("audit DACL has unexpected entries")
        trustees = set()
        for index in range(2):
            ace = W.LPVOID()
            if not _call("GetAce", W.BOOL, [W.LPVOID, W.DWORD, C.POINTER(W.LPVOID)],
                         dacl, index, C.byref(ace)):
                _fail("audit ACE unavailable")
            if (C.c_ubyte.from_address(ace.value).value != 0 or
                    C.c_ushort.from_address(ace.value + 2).value < 12):
                raise WinStoreError("audit DACL contains an invalid allow ACE")
            trustees.add(_sid_string(ace.value + 8))
        if trustees != {_current_sid(), "S-1-5-18"}:
            raise WinStoreError("audit DACL contains a foreign trustee")
    finally:
        _local_free(descriptor)


def _metadata(handle, directory, private):
    data = FileInfo()
    if not _call("GetFileInformationByHandle", W.BOOL, [W.HANDLE, C.POINTER(FileInfo)],
                 handle, C.byref(data)):
        _fail("audit object identity unavailable")
    if data.attributes & (ATTR_REPARSE | ATTR_OFFLINE) or bool(data.attributes & ATTR_DIRECTORY) != directory:
        raise WinStoreError("audit path has unsupported type or reparse/offline attribute")
    if not directory and data.links != 1:
        raise WinStoreError("audit file has a hard link")
    if private:
        _private_acl(handle, directory)
    return (data.volume, data.index_high, data.index_low), data.size_high * 2**32 + data.size_low


def _open(path, directory=False, create=False, descriptor=None):
    attributes = None
    security = None
    if descriptor is not None:
        security = SecurityAttributes(C.sizeof(SecurityAttributes), descriptor, 0)
        attributes = C.byref(security)
    handle = _call("CreateFileW", W.HANDLE,
                   [W.LPCWSTR, W.DWORD, W.DWORD, W.LPVOID, W.DWORD, W.DWORD, W.HANDLE],
                   str(path), READ_CONTROL | (WRITE if create else READ),
                   SHARE_READ | SHARE_WRITE, attributes,
                   CREATE_NEW if create else OPEN_EXISTING,
                   OPEN_REPARSE | (BACKUP_SEMANTICS if directory else 0), None)
    if handle == INVALID:
        _fail("audit path could not be opened")
    return handle


def _local_root(path):
    if not path.is_absolute() or not path.drive or path.drive.startswith("\\"):
        raise WinStoreError("audit export requires an absolute local drive path")
    if any(part in (".", "..") or part.rstrip(" .") != part or ":" in part or "\0" in part
           for part in path.parts[1:]):
        raise WinStoreError("audit path contains an unsafe component")
    root = path.anchor
    if _call("GetDriveTypeW", W.DWORD, [W.LPCWSTR], root) != 3:
        raise WinStoreError("audit export requires a fixed local drive")
    mapping = C.create_unicode_buffer(4096)
    if not _call("QueryDosDeviceW", W.DWORD, [W.LPCWSTR, W.LPWSTR, W.DWORD],
                 path.drive, mapping, len(mapping)) or mapping.value.startswith("\\??\\"):
        raise WinStoreError("audit export refuses a redirected drive")
    filesystem = C.create_unicode_buffer(64)
    if not _call("GetVolumeInformationW", W.BOOL,
                 [W.LPCWSTR, W.LPWSTR, W.DWORD, W.LPVOID, W.LPVOID, W.LPVOID, W.LPWSTR, W.DWORD],
                 root, None, 0, None, None, None, filesystem, len(filesystem)) or filesystem.value != "NTFS":
        raise WinStoreError("audit export requires local NTFS")


def _descriptor():
    sid = _current_sid()
    sddl = f"O:{sid}D:P(A;;GA;;;{sid})(A;;GA;;;SY)"
    result = W.LPVOID()
    if not _call("ConvertStringSecurityDescriptorToSecurityDescriptorW", W.BOOL,
                 [W.LPCWSTR, W.DWORD, C.POINTER(W.LPVOID), W.LPVOID],
                 sddl, 1, C.byref(result), None):
        _fail("audit private DACL unavailable")
    return result


class Reader:
    def __init__(self, directory, private=True):
        self.directory = directory.absolute()
        _local_root(self.directory)
        self.handles = []
        try:
            root = Path(self.directory.anchor)
            for path in (root, *reversed(self.directory.parents[:-1]), self.directory):
                handle = _open(path, directory=True)
                try:
                    _metadata(handle, True, private and path == self.directory)
                except BaseException:
                    _close(handle)
                    raise
                self.handles.append(handle)
            self.identity, _ = _metadata(self.handles[-1], True, private)
        except BaseException:
            self.close()
            raise

    def close(self):
        for handle in self.handles:
            _close(handle)
        self.handles = []

    def read(self, name, limit):
        if (not name or name in (".", "..") or "\\" in name or "/" in name or
                ":" in name or name.rstrip(" .") != name):
            raise WinStoreError("unsafe audit file name")
        path = self.directory / name
        try:
            handle = _open(path)
        except WinStoreError:
            if C.get_last_error() in (2, 3):
                return None
            raise
        try:
            identity, size = _metadata(handle, False, True)
            if size > limit:
                raise WinStoreError("audit file exceeds configured limit")
            if _metadata(self.handles[-1], True, True)[0] != self.identity:
                raise WinStoreError("audit directory changed")
            fd = msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
            handle = None
            with os.fdopen(fd, "rb") as stream:
                body = stream.read(limit + 1)
                if os.fstat(stream.fileno()).st_size != size:
                    raise WinStoreError("audit file changed during export; retry")
            if len(body) > limit:
                raise WinStoreError("audit file exceeds configured limit")
            return body
        finally:
            _close(handle)


def private_output(path, body):
    path = path.absolute()
    _local_root(path)
    parent = path.parent
    if not parent.exists():
        ancestor = Reader(parent.parent, private=False)
        try:
            acl = _descriptor()
            try:
                security = SecurityAttributes(C.sizeof(SecurityAttributes), acl, 0)
                if not _call("CreateDirectoryW", W.BOOL, [W.LPCWSTR, W.LPVOID], str(parent), C.byref(security)):
                    _fail("private output directory could not be created")
            finally:
                _local_free(acl)
        finally:
            ancestor.close()
    reader = Reader(parent)
    try:
        acl = _descriptor()
        try:
            handle = _open(path, create=True, descriptor=acl)
        finally:
            _local_free(acl)
        try:
            _metadata(handle, False, True)
            fd = msvcrt.open_osfhandle(handle, os.O_WRONLY | os.O_BINARY)
            handle = None
            with os.fdopen(fd, "wb") as stream:
                stream.write(body)
                stream.flush()
                os.fsync(stream.fileno())
        finally:
            _close(handle)
    finally:
        reader.close()
