#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""SOU-204 execution-level side-effect trace for `agentfw mcp-schema-upgrade` (Windows x64).

Runs each command under the Win32 debugging API (no administrator rights, no
installed tools, no host setting changes) and records, for the whole process
tree:

* every process creation (CREATE_PROCESS_DEBUG_EVENT with DEBUG_PROCESS, so
  child processes are reported as well as the analyzer itself);
* every DLL load;
* the first call of each Winsock / name-resolution entry point, observed with a
  one-shot software breakpoint written into each process's loaded ws2_32.dll.

Positive controls run the same instrumentation on commands that do create a
socket and a child process, to show the instrumentation detects them.

Scope: user-mode Winsock entry points of ws2_32.dll and process creation in the
traced tree. It does not observe kernel-level or raw AFD I/O, other networking
DLLs except by their load event, or traffic of unrelated processes.

Usage: python scripts/schema-upgrade-trace-windows.py --agentfw target/debug/agentfw.exe --out trace.json
"""
from __future__ import annotations

import argparse
import ctypes
import ctypes.wintypes as w
import hashlib
import json
import os
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIX = "crates/agentfw/tests/fixtures/schema_upgrade"
FS = "profiles/mcp/filesystem-readonly-v1"
GIT = "profiles/mcp/git-readonly-v1"
TRAPPED = ["WSAStartup", "socket", "WSASocketW", "WSASocketA", "connect", "WSAConnect",
           "WSAConnectByNameW", "getaddrinfo", "GetAddrInfoW", "GetAddrInfoExW", "gethostbyname",
           "sendto", "WSASendTo", "WSAIoctl"]
NETWORK_DLLS = {"mswsock.dll", "dnsapi.dll", "winhttp.dll", "wininet.dll", "webio.dll",
                "wshqos.dll", "wship6.dll", "rasadhlp.dll", "fwpuclnt.dll", "napinsp.dll"}

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
DEBUG_PROCESS = 0x1
DETACHED_PROCESS = 0x00000008  # no console, so no OS-created conhost.exe
DBG_CONTINUE = 0x00010002
DBG_EXCEPTION_NOT_HANDLED = 0x80010001
EXCEPTION_BREAKPOINT = 0x80000003
STATUS_WX86_BREAKPOINT = 0x4000001F


class EXCEPTION_RECORD(ctypes.Structure):
    _fields_ = [("ExceptionCode", w.DWORD), ("ExceptionFlags", w.DWORD),
                ("ExceptionRecord", ctypes.c_void_p), ("ExceptionAddress", ctypes.c_void_p),
                ("NumberParameters", w.DWORD), ("ExceptionInformation", ctypes.c_uint64 * 15)]


class EXCEPTION_DEBUG_INFO(ctypes.Structure):
    _fields_ = [("ExceptionRecord", EXCEPTION_RECORD), ("dwFirstChance", w.DWORD)]


class CREATE_PROCESS_DEBUG_INFO(ctypes.Structure):
    _fields_ = [("hFile", w.HANDLE), ("hProcess", w.HANDLE), ("hThread", w.HANDLE),
                ("lpBaseOfImage", ctypes.c_void_p), ("dwDebugInfoFileOffset", w.DWORD),
                ("nDebugInfoSize", w.DWORD), ("lpThreadLocalBase", ctypes.c_void_p),
                ("lpStartAddress", ctypes.c_void_p), ("lpImageName", ctypes.c_void_p),
                ("fUnicode", w.WORD)]


class LOAD_DLL_DEBUG_INFO(ctypes.Structure):
    _fields_ = [("hFile", w.HANDLE), ("lpBaseOfDll", ctypes.c_void_p),
                ("dwDebugInfoFileOffset", w.DWORD), ("nDebugInfoSize", w.DWORD),
                ("lpImageName", ctypes.c_void_p), ("fUnicode", w.WORD)]


class _U(ctypes.Union):
    _fields_ = [("Exception", EXCEPTION_DEBUG_INFO), ("CreateProcessInfo", CREATE_PROCESS_DEBUG_INFO),
                ("LoadDll", LOAD_DLL_DEBUG_INFO), ("raw", ctypes.c_byte * 160)]


class DEBUG_EVENT(ctypes.Structure):
    _fields_ = [("dwDebugEventCode", w.DWORD), ("dwProcessId", w.DWORD),
                ("dwThreadId", w.DWORD), ("u", _U)]


class STARTUPINFO(ctypes.Structure):
    _fields_ = [("cb", w.DWORD), ("lpReserved", w.LPWSTR), ("lpDesktop", w.LPWSTR),
                ("lpTitle", w.LPWSTR), ("dwX", w.DWORD), ("dwY", w.DWORD), ("dwXSize", w.DWORD),
                ("dwYSize", w.DWORD), ("dwXCountChars", w.DWORD), ("dwYCountChars", w.DWORD),
                ("dwFillAttribute", w.DWORD), ("dwFlags", w.DWORD), ("wShowWindow", w.WORD),
                ("cbReserved2", w.WORD), ("lpReserved2", ctypes.c_void_p), ("hStdInput", w.HANDLE),
                ("hStdOutput", w.HANDLE), ("hStdError", w.HANDLE)]


class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [("hProcess", w.HANDLE), ("hThread", w.HANDLE),
                ("dwProcessId", w.DWORD), ("dwThreadId", w.DWORD)]


k32.WaitForDebugEvent.argtypes = [ctypes.POINTER(DEBUG_EVENT), w.DWORD]
k32.ContinueDebugEvent.argtypes = [w.DWORD, w.DWORD, w.DWORD]
k32.ReadProcessMemory.argtypes = [w.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t,
                                  ctypes.POINTER(ctypes.c_size_t)]
k32.WriteProcessMemory.argtypes = k32.ReadProcessMemory.argtypes
k32.FlushInstructionCache.argtypes = [w.HANDLE, ctypes.c_void_p, ctypes.c_size_t]
k32.GetFinalPathNameByHandleW.argtypes = [w.HANDLE, w.LPWSTR, w.DWORD, w.DWORD]
k32.OpenThread.restype = w.HANDLE
k32.OpenThread.argtypes = [w.DWORD, w.BOOL, w.DWORD]
k32.GetThreadContext.argtypes = [w.HANDLE, ctypes.c_void_p]
k32.SetThreadContext.argtypes = [w.HANDLE, ctypes.c_void_p]
k32.CloseHandle.argtypes = [w.HANDLE]
k32.GetExitCodeProcess.argtypes = [w.HANDLE, ctypes.POINTER(w.DWORD)]


def exports(dll_path: str) -> dict[str, int]:
    """Export RVAs of a PE file read from disk."""
    b = Path(dll_path).read_bytes()
    pe = struct.unpack_from("<I", b, 0x3C)[0]
    nsec = struct.unpack_from("<H", b, pe + 6)[0]
    opt = pe + 24
    dd = opt + (112 if struct.unpack_from("<H", b, opt)[0] == 0x20B else 96)
    erva = struct.unpack_from("<I", b, dd)[0]
    sections = [struct.unpack_from("<8sIIII", b, opt + struct.unpack_from("<H", b, pe + 20)[0] + i * 40)
                for i in range(nsec)]

    def off(rva):
        for _, vs, va, rs, ro in sections:
            if va <= rva < va + max(vs, rs):
                return rva - va + ro
        raise ValueError("rva")
    e = off(erva)
    nnames, faddr, fnames, fords = struct.unpack_from("<IIII", b, e + 24)
    out = {}
    for i in range(nnames):
        name_off = off(struct.unpack_from("<I", b, off(fnames) + 4 * i)[0])
        name = b[name_off:b.index(b"\0", name_off)].decode()
        ordinal = struct.unpack_from("<H", b, off(fords) + 2 * i)[0]
        out[name] = struct.unpack_from("<I", b, off(faddr) + 4 * ordinal)[0]
    return out


WS2 = os.path.join(os.environ["SystemRoot"], "System32", "ws2_32.dll")
WS2_EXPORTS = exports(WS2)


def path_of(handle) -> str:
    buf = ctypes.create_unicode_buffer(1024)
    n = k32.GetFinalPathNameByHandleW(handle, buf, 1024, 0)
    return buf.value if n else ""


def trace(argv: list[str], cwd: Path, env: dict[str, str], stdout: Path) -> dict:
    si = STARTUPINFO()
    si.cb = ctypes.sizeof(si)
    pi = PROCESS_INFORMATION()
    cmdline = subprocess.list2cmdline(argv)
    env_block = "".join(f"{k}={v}\0" for k, v in sorted(env.items())) + "\0"
    with open(stdout, "wb") as sink:
        import msvcrt
        handle = msvcrt.get_osfhandle(sink.fileno())
        os.set_handle_inheritable(handle, True)
        si.dwFlags = 0x100  # STARTF_USESTDHANDLES
        si.hStdOutput = si.hStdError = handle
        si.hStdInput = None
        ok = k32.CreateProcessW(None, ctypes.create_unicode_buffer(cmdline), None, None, True,
                                DEBUG_PROCESS | DETACHED_PROCESS | 0x400,  # CREATE_UNICODE_ENVIRONMENT
                                ctypes.create_unicode_buffer(env_block), str(cwd),
                                ctypes.byref(si), ctypes.byref(pi))
        if not ok:
            raise OSError(ctypes.get_last_error(), "CreateProcessW failed")
        processes, dlls, hits = [], {}, {}
        handles = {}
        breakpoints = {}  # (pid, address) -> (name, original byte)
        live = set()
        root_exit = None
        event = DEBUG_EVENT()
        while True:
            if not k32.WaitForDebugEvent(ctypes.byref(event), 120_000):
                raise TimeoutError("trace timed out")
            code, pid, tid = event.dwDebugEventCode, event.dwProcessId, event.dwThreadId
            status = DBG_CONTINUE
            if code == 3:  # CREATE_PROCESS
                info = event.u.CreateProcessInfo
                handles[pid] = info.hProcess
                live.add(pid)
                processes.append({"image": Path(path_of(info.hFile)).name, "root": pid == pi.dwProcessId})
                if info.hFile:
                    k32.CloseHandle(info.hFile)
            elif code == 6:  # LOAD_DLL
                info = event.u.LoadDll
                name = Path(path_of(info.hFile)).name.lower() if info.hFile else "<unknown>"
                if info.hFile:
                    k32.CloseHandle(info.hFile)
                dlls.setdefault(pid, []).append(name)
                if name == "ws2_32.dll":
                    for fn in TRAPPED:
                        if fn not in WS2_EXPORTS:
                            continue
                        address = info.lpBaseOfDll + WS2_EXPORTS[fn]
                        original = ctypes.c_ubyte()
                        k32.ReadProcessMemory(handles[pid], address, ctypes.byref(original), 1, None)
                        k32.WriteProcessMemory(handles[pid], address, ctypes.byref(ctypes.c_ubyte(0xCC)), 1, None)
                        k32.FlushInstructionCache(handles[pid], address, 1)
                        breakpoints[(pid, address)] = (fn, original.value)
            elif code == 1:  # EXCEPTION
                record = event.u.Exception.ExceptionRecord
                address = record.ExceptionAddress or 0
                if record.ExceptionCode == EXCEPTION_BREAKPOINT and (pid, address) in breakpoints:
                    fn, original = breakpoints.pop((pid, address))
                    hits[fn] = hits.get(fn, 0) + 1
                    k32.WriteProcessMemory(handles[pid], address, ctypes.byref(ctypes.c_ubyte(original)), 1, None)
                    k32.FlushInstructionCache(handles[pid], address, 1)
                    thread = k32.OpenThread(0x0018, False, tid)  # GET/SET_CONTEXT
                    context = (ctypes.c_byte * (1232 + 16))()
                    base = (ctypes.addressof(context) + 15) & ~15
                    struct.pack_into("<I", (ctypes.c_byte * 1232).from_address(base), 0x30, 0x100001)
                    k32.GetThreadContext(thread, base)
                    rip = ctypes.c_uint64.from_address(base + 0xF8)
                    rip.value = address
                    k32.SetThreadContext(thread, base)
                    k32.CloseHandle(thread)
                elif record.ExceptionCode in (EXCEPTION_BREAKPOINT, STATUS_WX86_BREAKPOINT):
                    pass  # loader's initial breakpoint
                else:
                    status = DBG_EXCEPTION_NOT_HANDLED
            elif code == 5:  # EXIT_PROCESS
                live.discard(pid)
                if pid == pi.dwProcessId:
                    exit_code = w.DWORD()
                    k32.GetExitCodeProcess(pi.hProcess, ctypes.byref(exit_code))
                    root_exit = exit_code.value
            elif code == 8:  # OUTPUT_DEBUG_STRING
                pass
            k32.ContinueDebugEvent(pid, tid, status)
            if code == 5 and not live:
                break
        k32.CloseHandle(pi.hThread)
        k32.CloseHandle(pi.hProcess)
    network_dlls = sorted({d for names in dlls.values() for d in names if d in NETWORK_DLLS})
    return {"exit": root_exit, "processes_created": len(processes),
            "child_processes": [p["image"] for p in processes if not p["root"]],
            "winsock_calls_observed": dict(sorted(hits.items())),
            "breakpoints_armed": len(TRAPPED) * sum("ws2_32.dll" in n for n in dlls.values()),
            "network_provider_dlls_loaded": network_dlls,
            "dll_loads": sum(len(n) for n in dlls.values())}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--agentfw", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    if sys.platform != "win32" or struct.calcsize("P") != 8:
        raise SystemExit("Windows x64 only")
    binary = args.agentfw.resolve()
    rel = lambda p: str(ROOT / p)
    runs = [
        ("valid-declared-destination", "valid", [binary, "mcp-schema-upgrade", "--before", rel(f"{FS}/upstream-tools-list.json"),
          "--after", rel(f"{FIX}/fs-destination-controls.json"), "--registry", rel(f"{FIX}/fs-control-current.registry.json"),
          "--proposed-registry", rel(f"{FIX}/fs-control-proposed.registry.json")], 5, ""),
        ("valid-git-semantic", "valid", [binary, "mcp-schema-upgrade", "--before", rel(f"{GIT}/upstream-tools-list.json"),
          "--after", rel(f"{FIX}/git-semantic.json"), "--before-identity", rel(f"{GIT}/upstream-identity.json"),
          "--registry", rel(f"{FIX}/git-readonly-v1.registry.json")], 5, ""),
        ("malicious-metadata", "valid", [binary, "mcp-schema-upgrade", "--before", rel(f"{FS}/upstream-tools-list.json"),
          "--after", rel(f"{FIX}/fs-malicious-metadata.json"), "--before-identity", rel(f"{FS}/upstream-identity.json"),
          "--registry", rel(f"{FIX}/filesystem-readonly-v1.registry.json")], 5, ""),
        ("refusal-duplicate-key", "refusal", [binary, "mcp-schema-upgrade", "--before", rel(f"{GIT}/upstream-tools-list.json"),
          "--after", rel(f"{FIX}/invalid-duplicate-key.json"), "--registry", rel(f"{FIX}/git-readonly-v1.registry.json")], 2,
          "duplicate_json_member"),
        ("refusal-identity-mismatch", "refusal", [binary, "mcp-schema-upgrade", "--before", rel(f"{FIX}/git-metadata-inert.json"),
          "--after", rel(f"{GIT}/upstream-tools-list.json"), "--before-identity", rel(f"{GIT}/upstream-identity.json"),
          "--snapshot-only"], 2, "identity_digest_mismatch"),
        ("refusal-missing-declarations", "refusal", [binary, "mcp-schema-upgrade", "--before", rel(f"{GIT}/upstream-tools-list.json"),
          "--after", rel(f"{FIX}/git-semantic.json")], 2, "missing_declarations"),
    ]
    controls = [
        ("control-python-socket", [sys.executable, "-I", "-c",
          "import socket\ns=socket.socket()\ntry: s.connect(('127.0.0.1', 9))\nexcept OSError: pass\ns.close()"]),
        ("control-python-child-process", [sys.executable, "-I", "-c",
          "import subprocess,sys; subprocess.run([sys.executable, '-I', '-c', 'pass'])"]),
    ]
    results = []
    with tempfile.TemporaryDirectory() as temp:
        tmp = Path(temp)
        env = {"HOME": str(tmp / "home"), "USERPROFILE": str(tmp / "home"),
               "SystemRoot": os.environ["SystemRoot"], "PATH": os.environ.get("PATH", "")}
        (tmp / "home").mkdir()
        (tmp / "cwd").mkdir()
        for name, path_kind, argv, expect, code in runs:
            argv = [str(a) for a in argv] + ["--out", str(tmp / "out" / name)]
            (tmp / "out").mkdir(exist_ok=True)
            observed = trace(argv, tmp / "cwd", env, tmp / f"{name}.log")
            clean = (observed["processes_created"] == 1 and not observed["child_processes"]
                     and not observed["winsock_calls_observed"] and not observed["network_provider_dlls_loaded"])
            log = (tmp / f"{name}.log").read_text(errors="replace")
            results.append({"run": name, "path": path_kind, "expect_exit": expect, "expect_refusal": code or None,
                            **observed, "stdout_stderr_head": log[:240],
                            "result": "PASS" if clean and observed["exit"] == expect and code in log else "FAIL"})
        for name, argv in controls:
            observed = trace([str(a) for a in argv], tmp / "cwd", env, tmp / f"{name}.log")
            detected = observed["winsock_calls_observed"] if "socket" in name else observed["child_processes"]
            results.append({"run": name, "path": "positive_control", **observed,
                            "result": "PASS" if detected else "FAIL"})
        home_written = any((tmp / "home").rglob("*"))
        cwd_written = any((tmp / "cwd").rglob("*"))
    record = {
        "format": "sw-evidence/sou204-windows-trace/1",
        "instrumentation": "Win32 debugging API from Python ctypes (DEBUG_PROCESS); one-shot int3 breakpoints "
                           "on ws2_32.dll exports; no administrator rights, installs or host setting changes",
        "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
        "ws2_32_sha256": hashlib.sha256(Path(WS2).read_bytes()).hexdigest(),
        "trapped_functions": TRAPPED,
        "network_provider_dlls_watched": sorted(NETWORK_DLLS),
        "scope_limits": [
            "observes user-mode Winsock entry points of ws2_32.dll and process creation in the traced tree only",
            "kernel-level or raw AFD/NtDeviceIoControl networking, other networking APIs (except by DLL load) and "
            "traffic of other processes are not observed; no packet capture was possible without elevation",
            "a statically imported ws2_32.dll is loaded in every run; its load alone is not a network event",
        ],
        "home_written": home_written, "cwd_written": cwd_written,
        "runs": results,
        "totals": {"pass": sum(r["result"] == "PASS" for r in results),
                   "fail": sum(r["result"] != "PASS" for r in results)},
    }
    args.out.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps(record["totals"]))
    return 0 if record["totals"]["fail"] == 0 and not home_written and not cwd_written else 1


if __name__ == "__main__":
    sys.exit(main())
