# SPDX-License-Identifier: Apache-2.0
"""Rule-based tool-call classifier (Task 1 baseline).

Input : {"tool_name", "raw_arguments", "server_id"?, "tool_description"?,
          "tool_schema"?, "pinned_schema"?}
Output: core   {"actions": [...], "unknown": bool}  (the approved contract's semantic result)
        extras {"status": ok|unknown|error, "confidence", "uncertainty", "reason", "reason_codes",
                "scores", "evidence": [{action, source, weight, detail}], flags...,
                "definition_estimate": {actions, unknown, sources}  # name + schema only, no arguments
                "definition_invocation_diff": bool                  # estimate vs actual-argument result
                "failure": null | {"code": classifier_invalid|classifier_timeout|classifier_internal_error}}
Technical failures use status "error" plus a `failure` code and are never a valid classification.
The module is a single stdlib-only file because the daemon executes it as one source snapshot.

Revision pilot_readonly_v1 (SOU-97) is git_readonly_v1 plus one exact-schema proof for three original
read-only filesystem tools (see _bounded_fs_read). It is selected only explicitly; it grants nothing.

Principles
- The tool description is UNTRUSTED. It never adds or removes a category. It is
  only inspected to raise flags (description_conflict, description_suspicious).
- Evidence comes from the tool name tokens, the ACTUAL arguments, and (weakly)
  the schema. Categories are multi-label; evidence is combined with noisy-OR.
- unknown is a flag, not an action: true when nothing was recognised (status
  "unknown"), on error, or when part of a shell command was not recognised
  (partial unknown, e.g. actions ["read"] + unknown true).
- No evidence -> actions [] with status "unknown". Bad input -> status "error".
  Neither is ever a permission: this module only describes the call.
- tool_schema from the server is untrusted: if it differs from pinned_schema it is
  ignored (pinned_schema is used) and confidence is capped (schema_mismatch).
"""
from __future__ import annotations

import json
import hashlib
import re
import sys
from typing import Any

CATEGORIES = ("read", "write", "delete", "send_data", "change_permissions")
UNKNOWN = "unknown"
THRESHOLD = 0.5
MAX_DEPTH, MAX_LEAVES, MAX_LEAF_CHARS, MAX_DESC_CHARS = 6, 200, 4096, 2000
# Output envelope bounds. The Rust bridge reads at most 16 KiB of reply and a reason of 1..1024 bytes.
REVISION = "pilot_readonly_v1"
INTERFACE = "sw-classifier-core/0.4"
MAX_NAME_CHARS, MAX_INPUT_BYTES, MAX_REASON_CHARS = 256, 1024 * 1024, 1000
MAX_EVIDENCE, MAX_CODES, MAX_REPLY_BYTES = 8, 24, 12 * 1024
FAILURE_CODES = ("classifier_invalid", "classifier_timeout", "classifier_internal_error")

# ---------------------------------------------------------------- name vocab
def _vocab(cat: str, words: str, weight: float = 0.7) -> dict[str, tuple[str, float]]:
    return {w: (cat, weight) for w in words.split()}

VERBS: dict[str, tuple[str, float]] = {}
VERBS.update(_vocab("read", "read get list ls cat head tail view show fetch find search lookup "
                    "query select count describe inspect preview display print load retrieve "
                    "browse stat grep glob scan open download check"))
VERBS.update(_vocab("write", "write create update edit append put set save insert add rename move "
                    "mv copy cp mkdir touch modify patch replace upsert store commit install import apply"))
VERBS.update(_vocab("delete", "delete remove rm rmdir unlink drop truncate erase purge destroy wipe "
                    "clear trash shred uninstall discard"))
VERBS.update(_vocab("send_data", "send post upload publish forward reply transmit push broadcast notify"))
VERBS.update(_vocab("send_data", "submit", 0.55))
VERBS.update(_vocab("send_data", "mailer emailer sender notifier uploader publisher poster", 0.7))  # agent nouns
VERBS.update(_vocab("change_permissions", "chmod chown chgrp grant revoke promote demote elevate sudo "
                    "setfacl icacls", 0.8))
VERBS.update(_vocab("change_permissions", "share unshare invite", 0.55))
VERBS.update(_vocab("write", "enable disable toggle", 0.55))
# Nouns: only count when the name has no verb at all.
SEND_NOUNS = set("email mail message sms slack discord webhook notification tweet".split())
# Nouns that retarget a mutation verb: set_permissions, remove_role, revoke_access.
PERM_NOUNS = set("permission permissions perm perms role roles acl privilege privileges access grants ownership sharing visibility member members".split())
GENERIC_WRITE = set("set update add modify edit create put save replace apply patch store enable disable toggle".split())
DELETE_VERBS = {w for w, (c, _) in VERBS.items() if c == "delete"}
READ_VERBS = {w for w, (c, _) in VERBS.items() if c == "read"}

BUILTIN = {**{n: "read" for n in "Read Grep Glob NotebookRead TodoRead WebFetch WebSearch".split()},
           **{n: "write" for n in "Write Edit MultiEdit NotebookEdit TodoWrite".split()}}
SHELL_TOKENS = set("bash shell sh zsh powershell pwsh cmd terminal exec eval".split())
SHELL_KEYS = {"command", "cmd", "argv", "script", "shell_command", "commandline", "command_line"}

# ---------------------------------------------------------------- shell rules
I = re.I
PIPE_TO_SHELL = re.compile(r"\|\s*(?:sudo\s+)?(?:ba|z)?sh\b", I)
NESTED = re.compile(r"""^(?:bash|sh|zsh)\s+-\w*c\s+(["'])(.*)\1\s*$""", I | re.S)
ENV_PREFIX = re.compile(r"^(?:\w+=\S*\s+)+")
# Ignore only complete descriptor/device targets, never filename prefixes.
NOISE_REDIRECT = re.compile(r"\d?>\s*&(?:\d+|-)(?=\s|$)|(?:\d?>>?|&>>?|>&)\s*/dev/null(?=\s|$)")
# Redirections, heredocs and process substitution are not analysed for no-op proofs.
UNSUPPORTED_SYNTAX = re.compile(r"[<>]")
REDIRECT = re.compile(r"(?<![<>\d&-])(?:&>>?|>>?&?)\s*[^\s&|>]")

DELETE_CMD = re.compile(
    r"^(?:rm|rmdir|unlink|shred|del|erase|rd|mkfs\S*|shutdown|reboot|remove-item)\b"
    r"|^git\s+(?:clean|rm)\b|^git\s+reset\s+--hard\b|^git\s+push\b.*(?:--force|\s-f\b)"
    r"|^dd\b.*\bof=/dev/|\bfind\b.*\s-delete\b|\s-exec\s+rm\b|\bxargs\s+(?:-\S+\s+)*rm\b"
    r"|\bdrop\s+(?:table|database|schema)\b|\bdelete\s+from\b|^truncate\b"
    r"|^docker\s+(?:rm|rmi|system\s+prune)\b|^kubectl\s+delete\b|^terraform\s+destroy\b", I)
PERM_CMD = re.compile(
    r"^(?:sudo|su\s+-|chmod|chown|chgrp|setfacl|icacls|takeown|usermod|passwd|visudo|setcap|chattr"
    r"|net\s+user|add-localgroupmember)\b", I)
SEND_CMD = re.compile(
    r"(?:^curl\b.*?(?:(?:--data\S*|--form\S*|--upload-file|-X\s*(?:POST|PUT|PATCH|DELETE))"
    r"|(?-i:\s-[a-zA-Z]*[dFT]\b)))"
    r"|^wget\b.*(?:--post-data|--post-file|--method\s*=\s*(?:POST|PUT))"
    r"|^(?:nc|ncat|scp|rsync|sftp|sendmail|mailx?)\b|^git\s+push\b"
    r"|^(?:npm|pip3?|cargo|gem|go|twine)\s+(?:publish|upload)\b"
    r"|^gh\s+(?:gist\s+create|issue\s+comment|pr\s+create|release\s+upload)\b"
    r"|^aws\s+s3api\s+put-object\b|^(?:xh|https?)\s+(?:POST|PUT|PATCH)\b"
    r"|^(?:invoke-webrequest|invoke-restmethod|iwr|irm)\b.*(?:-method\s+(?:post|put|patch)|-body\b)"
    r"|>\s*/dev/tcp/|^ssh\b.*<", I)
AWS_S3 = re.compile(r"^aws\s+s3\s+(?:cp|sync|mv)\b", I)  # direction is ambiguous
WRITE_CMD = re.compile(
    r"^(?:mkdir|touch|mv|cp|ln|tee|set-content|add-content|out-file|new-item|copy-item|move-item"
    r"|rename-item)\b|^sed\s+-i\b|^git\s+(?:commit|add|checkout|merge|rebase|stash|tag|init|restore"
    r"|switch|mv|pull)\b|^curl\b.*(?:\s-o\s|\s-O\b|--output\b)", I)
TEXT_CMDS = {"echo", "printf", "grep", "egrep", "fgrep", "rg", "ag", "select-string"}  # quoted words are data
NOOP_CMD = re.compile(r"^(?:echo|printf|true|false|:|sleep)(?:\s|$)", I)  # produce output only
INSTALL_CMD = re.compile(r"^(?:npm|pip3?|cargo|yarn|pnpm)\s+(?:install|add|i|update|ci)\b", I)
READ_CMD = re.compile(
    r"^(?:ls|dir|cat|head|tail|less|more|grep|egrep|rg|ag|find|pwd|wc|stat|tree|which"
    r"|where|whoami|date|env|printenv|file|du|df|ps|diff|sort|uniq|cut|cd|test|get-content|get-childitem"
    r"|gc|gci|select-string|test-path|curl|wget)\b|^git\s+(?:status|log|diff|show|fetch|clone|branch"
    r"|ls-files|grep|blame|ls-remote)\b|^npm\s+(?:ls|view|search)\b", I)


def _scan(text: str) -> tuple[list[str], list[str]]:
    """Split a shell string into segments OUTSIDE quotes; drop unquoted '#' comments.

    Returns (segments, command_substitutions). Not a full POSIX parser: it handles quotes,
    backslash escapes, ; & && || | newline, comments and $(...) / `...` substitutions.
    """
    segs: list[str] = []
    subs: list[str] = []
    buf: list[str] = []
    q = None
    i, n = 0, len(text)

    def flush() -> None:
        s = "".join(buf).strip()
        buf.clear()
        if s:
            segs.append(s)

    while i < n:
        c = text[i]
        if q == "'":
            buf.append(c)
            if c == "'":
                q = None
            i += 1
            continue
        if c == "\\" and i + 1 < n:
            buf.append(text[i:i + 2]); i += 2
            continue
        if text.startswith("$(", i):
            depth, j = 1, i + 2
            while j < n and depth:
                depth += (text[j] == "(") - (text[j] == ")")
                j += 1
            subs.append(text[i + 2:j - 1 if depth == 0 else j])
            buf.append(text[i:j]); i = j
            continue
        if c == "`":
            j = text.find("`", i + 1)
            j = n if j < 0 else j
            subs.append(text[i + 1:j]); buf.append(text[i:j + 1]); i = j + 1
            continue
        if q == '"':
            buf.append(c)
            if c == '"':
                q = None
            i += 1
            continue
        if c in "'\"":
            q = c; buf.append(c); i += 1
            continue
        if c == "#" and (not buf or buf[-1].isspace()):
            j = text.find("\n", i)
            i = n if j < 0 else j
            continue
        if c in ";\n":
            flush(); i += 1
        elif c == "|":
            flush(); i += 2 if text.startswith("||", i) else 1
        elif c == "&" and text.startswith("&&", i):
            flush(); i += 2
        elif c == "&" and not (buf and buf[-1] in "<>") and not text.startswith("&>", i):
            flush(); i += 1  # background job
        else:
            buf.append(c); i += 1
    flush()
    return segs, subs


def _mask(s: str) -> str:
    """Replace the contents of quoted strings with '_' so words inside quotes are never commands."""
    out, q, i = [], None, 0
    while i < len(s):
        c = s[i]
        if q:
            if c == q:
                q = None; out.append(c)
            elif c == "\\" and q == '"' and i + 1 < len(s):
                out.append("__"); i += 1
            else:
                out.append("_")
        else:
            if c in "'\"":
                q = c
            out.append(c)
        i += 1
    return "".join(out)


def _shell(text: str, ev, depth: int = 0) -> int:
    """Emit evidence; return the number of segments no rule recognised."""
    unmatched = 0
    if PIPE_TO_SHELL.search(_mask(text)):
        ev("delete", 0.85, "shell", "pipe to shell (code execution, treated as delete-class)")
    segs, subs = _scan(text)
    if depth < 3:
        for sub in subs:
            unmatched += _shell(sub, ev, depth + 1)
    else:
        unmatched += len(subs)  # substitutions beyond the depth limit were not examined
    for seg in segs:
        seg = ENV_PREFIX.sub("", seg.strip())
        if not seg:
            continue
        nested = NESTED.match(seg)
        if nested and depth < 2:
            unmatched += _shell(nested.group(2), ev, depth + 1)
            continue
        masked = _mask(seg)
        head = re.match(r"(?:sudo\s+)?(\S+)", seg, I)
        text_only = bool(head) and head.group(1).lower() in TEXT_CMDS
        rest = re.sub(r"^sudo\s+", "", masked if text_only else seg, flags=I)
        strong = False
        if rest != (masked if text_only else seg):
            ev("change_permissions", 0.85, "shell", "sudo")  # privilege escalation; the command itself is judged below
        for cat, rx, w, why in (("delete", DELETE_CMD, 0.85, "destructive command"),
                                ("change_permissions", PERM_CMD, 0.85, "permission command"),
                                ("send_data", SEND_CMD, 0.85, "outbound data command"),
                                ("write", WRITE_CMD, 0.85, "file/repo write command")):
            if rx.search(rest):
                ev(cat, w, "shell", why); strong = True
        if AWS_S3.search(rest):
            ev("send_data", 0.6, "shell", "aws s3 copy (direction ambiguous)"); strong = True
        if INSTALL_CMD.search(rest):
            ev("write", 0.6, "shell", "package install writes to disk"); strong = True
        redirect = bool(REDIRECT.search(NOISE_REDIRECT.sub(" ", masked)))
        if redirect:
            ev("write", 0.85, "shell", "output redirection")
        reads = bool(READ_CMD.search(rest)) and not strong
        if reads:
            ev("read", 0.8, "shell", "read-only command")
        if not (strong or redirect or reads):
            if NOOP_CMD.search(rest) and not UNSUPPORTED_SYNTAX.search(NOISE_REDIRECT.sub(" ", masked)):
                ev.noop.append(seg)  # recognised, proven to have no effect
            else:
                unmatched += 1
    return unmatched

# ---------------------------------------------------------------- argument rules
RECIPIENT_KEYS = set("to cc bcc recipient recipients email emails address channel chat_id phone".split())
CONTENT_KEYS = set("body message text content subject html attachment attachments data payload json form".split())
URL_KEYS = set("url uri endpoint webhook webhook_url href host".split())
PATH_KEYS = set("path file filename file_path filepath directory dir src dest destination".split())
EDIT_KEYS = set("content text data contents lines new_string old_string patch".split())
PERM_KEYS = set("permission permissions access_level role roles acl privilege privileges grant owner group".split())
ACTION_KEYS = {"action", "operation", "op", "verb"}
DATA_KEYS = CONTENT_KEYS | EDIT_KEYS
# Whole-token matching ("invite_email" -> email) uses only tokens that are unambiguous inside a key.
RECIPIENT_TOK = {"recipient", "recipients", "email", "emails", "address", "phone", "channel", "invitee"}
URL_TOK = {"url", "uri", "endpoint", "webhook", "href"}
PATH_TOK = {"path", "file", "filename", "filepath", "directory", "dir"}
CONTENT_TOK = {"body", "message", "text", "content", "subject", "html", "attachment", "attachments", "payload"}
EDIT_TOK = {"content", "contents", "text", "lines", "patch"}
PERM_TOK = {"permission", "permissions", "role", "roles", "acl", "privilege", "privileges",
            "principal", "grantee", "invitee", "assignee"}
INLINE_TOK = {"body", "content", "contents", "text", "data", "payload", "html", "lines"}
SOURCE_TOK = {"source", "src"}
OPAQUE_ARG_TOK = {"plugin", "callback", "hook", "handler", "middleware", "extension"}
ATTACH_PATH = re.compile(r"attachments?_(?:path|paths|file|files)")
MODE_KEYS = {"mode", "method"}  # may also carry an action word (e.g. mode="purge")
MODE_OCTAL = re.compile(r"^[0-7]{3,4}$|^[ugoa]*[+\-=][rwxXst]+$")
MODE_WORDS = {"private", "public", "shared", "readonly", "read-only", "restricted", "world-readable"}
# Name tokens that signal effects hidden behind another component (no shell text to inspect).
OPAQUE_TOKENS = set("callback hook plugin invoke exec execute eval macro handler".split())


class _Walk:
    def __init__(self) -> None:
        self.keys: set[str] = set()
        self.leaves: list[tuple[str, str]] = []
        self.scalars: dict[str, Any] = {}
        self.truncated = False
        self.unmatched = 0
        self.children: list[_Walk] = []  # independent workflow steps, classified separately

    def go(self, obj: Any, key: str = "", depth: int = 0) -> None:
        if depth > MAX_DEPTH:
            self.truncated = True
        elif isinstance(obj, dict):
            for k, v in obj.items():
                self.keys.add(str(k).lower())
                if str(k).lower() in DATA_KEYS and isinstance(v, (dict, list, tuple)):
                    continue  # structured payload/content is data, not a nested call
                self.go(v, str(k).lower(), depth + 1)
        elif isinstance(obj, (list, tuple)):
            if obj and all(isinstance(v, dict) and {str(k).lower() for k in v} & ACTION_KEYS for v in obj):
                for v in obj:  # a list of steps: each step is classified in its own context
                    child = _Walk()
                    child.go(v, key, depth + 1)
                    self.children.append(child)
            else:
                for v in obj:
                    self.go(v, key, depth + 1)
        elif isinstance(obj, str):
            if len(self.leaves) >= MAX_LEAVES:
                self.truncated = True
                return
            if len(obj) > MAX_LEAF_CHARS:
                self.truncated, obj = True, obj[:MAX_LEAF_CHARS]
            self.leaves.append((key, obj))
        else:
            self.scalars.setdefault(key, obj)


def _tokens(text: str) -> list[str]:
    text = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1 \2", text)
    text = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", text)
    return [t for t in re.split(r"[^A-Za-z0-9]+", text.lower()) if t]


def _kmatch(keys: set[str], exact: set[str], tokens: set[str]) -> set[str]:
    """Keys equal to a vocabulary entry or containing a vocabulary token (invite_email -> email)."""
    return {k for k in keys if k in exact or any(t in tokens for t in _tokens(k))}


def _distinct(a: set[str], b: set[str]) -> bool:
    """True when two roles are played by different keys (one key such as `email_subject` is not both)."""
    return any(x != y for x in a for y in b)


COMPOUND_TOKENS = {"and", "then"}
# Containers whose effects are defined by the (parsed) arguments rather than by the name.
# Names that say only "run something": the thing that runs is not in the arguments. Workflow-style
# names (batch, pipeline, ...) are different: their steps are read one by one.
BARE_RUNNERS = {"run", "call"}
KNOWN_RUNNERS = SHELL_TOKENS | OPAQUE_TOKENS | {"run", "call", "invoke", "workflow", "batch", "pipeline", "sequence"}


def _unresolved_compound(toks: list[str], runner_resolved: bool = False) -> bool:
    """True for a compound name (`notify_and_render`) in which some part has no recognised action word.

    Only compound names are judged this way: an unfamiliar single name such as `quartz_17` is legitimate
    and its effects are read from the arguments instead.
    """
    parts, cur = [], []
    for t in toks:
        if t in COMPOUND_TOKENS:
            parts.append(cur)
            cur = []
        else:
            cur.append(t)
    parts.append(cur)
    parts = [p for p in parts if p]
    # A runner clause (`run`, `call`, `workflow`, ...) is resolved only by invocation evidence: a visible shell
    # command or parsed steps. Recognising the word is not knowing what it runs.
    return len(parts) > 1 and any(
        not any(t in VERBS or (runner_resolved and t in KNOWN_RUNNERS) for t in part) for part in parts)


DATA_NOUNS = set(("file files folder folders directory directories dir document documents doc docs record records row rows "
                  "table tables database db bucket object objects message messages email emails ticket tickets issue issues "
                  "page pages repo repository branch key keys secret secrets backup backups log logs volume snapshot snapshots "
                  "entry entries item items data content text blob blobs asset assets image images note notes comment comments").split())


def _verb_object(toks: list[str], i: int) -> str:
    """What the verb at toks[i] is applied to: "permission", "ambiguous" or "other".

    The object is the run of tokens after the verb up to the next verb; when nothing follows it
    ("permission_delete"), the run of tokens before it is used. "delete_file_and_remove_member": the
    object of "delete" is a file and "member" belongs to "remove". "delete_member_file" names both an
    access noun and a data noun in one clause, so the target is ambiguous and nothing is dropped.
    """
    def span(rng):
        out = []
        for j in rng:
            if toks[j] in VERBS:
                break
            if toks[j] not in COMPOUND_TOKENS:
                out.append(toks[j])
        return out
    after = span(range(i + 1, len(toks)))
    obj = after or span(range(i - 1, -1, -1))
    has_perm = any(t in PERM_NOUNS for t in obj)
    if has_perm and any(t in DATA_NOUNS for t in obj):
        return "ambiguous"
    return "permission" if has_perm else "other"


def _name_evidence(tool_name: str, ev, runner_resolved: bool = False) -> tuple[set[str], bool]:
    """Emit name evidence. Returns (categories inferred from nouns alone, compound name not fully resolved)."""
    if tool_name in BUILTIN:
        ev(BUILTIN[tool_name], 0.95, "name", f"known built-in tool {tool_name}")
        return set(), False
    last = tool_name.split("__")[-1]
    toks = _tokens(last)
    verbs = [t for t in toks if t in VERBS]
    perm_noun = any(t in PERM_NOUNS for t in toks)
    retargeted = ambiguous = False
    for i, t in enumerate(toks):
        if t not in VERBS:
            continue
        cat, w = VERBS[t]
        if perm_noun and (t in GENERIC_WRITE or t in DELETE_VERBS):
            target = _verb_object(toks, i)
            if target == "permission":
                retargeted = True  # "remove user access" changes permissions; it does not delete a file
                continue
            if target == "ambiguous":
                retargeted = ambiguous = True  # keep the verb's own effect and add the access change
        ev(cat, w, "name", f"name token '{t}'")
    noun_cats: set[str] = set()
    if perm_noun:
        if retargeted:
            ev("change_permissions", 0.75, "name", "permission noun with a mutation verb")
        elif not verbs:
            ev("change_permissions", 0.55, "name", "permission noun")
            noun_cats.add("change_permissions")
    elif not verbs and any(t in SEND_NOUNS for t in toks):
        ev("send_data", 0.5, "name", "messaging noun without a verb")
        noun_cats.add("send_data")
    return noun_cats, ambiguous or _unresolved_compound(toks, runner_resolved)


def _arg_evidence(w: _Walk, ev) -> None:
    keys, sc = w.keys, w.scalars
    rec = _kmatch(keys, RECIPIENT_KEYS, RECIPIENT_TOK)
    con = _kmatch(keys, CONTENT_KEYS, CONTENT_TOK)
    urls = _kmatch(keys, URL_KEYS, URL_TOK)
    paths = _kmatch(keys, PATH_KEYS, PATH_TOK)
    edit = _kmatch(keys, EDIT_KEYS, EDIT_TOK)
    if _distinct(rec, con):
        ev("send_data", 0.7, "args", "recipient plus content arguments")
    method = str(sc.get("method", "")).upper()
    if urls:
        if _distinct(urls, con) or method in {"POST", "PUT", "PATCH"}:
            ev("send_data", 0.75, "args", "URL with body or write method")
        elif method == "DELETE":
            ev("delete", 0.7, "args", "HTTP DELETE")
        else:
            ev("read", 0.55, "args", "URL without a body")
    if _distinct(paths, edit):
        ev("write", 0.7, "args", "path plus content arguments")
    if _kmatch(keys, PERM_KEYS, PERM_TOK):
        ev("change_permissions", 0.65, "args", "permission/role argument")
    for k, v in sc.items():
        if v is True and any(t in DELETE_VERBS for t in _tokens(str(k))):
            ev("delete", 0.6, "args", f"flag {k}=true")  # e.g. {"delete": true} on a generic tool
    if _kmatch(keys, set(), SOURCE_TOK):
        ev("read", 0.55, "args", "source resource argument")
    if any(set(_tokens(k)) & OPAQUE_ARG_TOK or any(t.endswith("processor") for t in _tokens(k)) for k in keys):
        w.unmatched += 1  # an argument that names code to run: its effects are not visible here
    mode = sc.get("mode")
    for k, v in w.leaves:
        if k == "mode":
            mode = v
    if isinstance(mode, str):
        if MODE_OCTAL.match(mode):
            ev("change_permissions", 0.85, "args", "mode looks like chmod value")
        elif mode.lower() in MODE_WORDS:
            ev("change_permissions", 0.7, "args", "mode is an access level")
        elif mode in {"r", "rb"}:
            ev("read", 0.6, "args", "file mode read")
        elif mode in {"w", "wb", "a", "ab", "x", "w+", "a+"}:
            ev("write", 0.6, "args", "file mode write")
    for k, v in w.leaves:
        if k in ACTION_KEYS | MODE_KEYS:
            found = False
            for t in _tokens(v):
                if t in VERBS:
                    found = True
                    ev(VERBS[t][0], 0.65, "args", f"{k}='{t}'")
            if k in ACTION_KEYS and not found:
                w.unmatched += 1  # explicit action value we do not understand
    if any(ATTACH_PATH.fullmatch(k) for k in keys):
        ev("read", 0.7, "args", "local file attachment path")
    shell_keys = keys & SHELL_KEYS
    if shell_keys:
        text = " ".join(v for k, v in w.leaves if k in shell_keys)
        if text.strip():
            w.unmatched += _shell(text, ev)
        else:
            w.unmatched += 1  # A command key without inspectable text does not resolve a runner.
    for child in w.children:
        _arg_evidence(child, ev)
        w.unmatched += child.unmatched
        w.truncated = w.truncated or child.truncated


def _schema_evidence(schema: Any, ev) -> None:
    props: set[str] = set()
    if isinstance(schema, dict):
        inner = schema.get("inputSchema") or schema.get("input_schema") or schema
        p = inner.get("properties") if isinstance(inner, dict) else None
        if isinstance(p, dict):
            props = {str(k).lower() for k in list(p)[:100]}
    if props & RECIPIENT_KEYS and props & CONTENT_KEYS:
        ev("send_data", 0.25, "schema", "schema has recipient and content")
    if props & URL_KEYS and props & CONTENT_KEYS:
        ev("send_data", 0.25, "schema", "schema has URL and body")
    if props & PERM_KEYS or "mode" in props:
        ev("change_permissions", 0.25, "schema", "schema has permission fields")
    if props & PATH_KEYS and props & EDIT_KEYS:
        ev("write", 0.25, "schema", "schema has path and content")


RO_CLAIM = re.compile(r"\b(?:read[- ]?only|only reads?|does not (?:modify|write|delete|send|change)"
                      r"|no side[- ]effects?|harmless|safe|just (?:reads?|views?|lists?))\b", I)
INJECT = re.compile(r"ignore (?:all |any |previous |prior |the )*(?:security|instructions?|checks?|polic(?:y|ies)|rules?)"
                    r"|do not (?:ask|warn|confirm|log|report)|(?:already|pre-?)approved|bypass|disable (?:security|checks)"
                    r"|ignore (?:all |any |the )?restrictions?|override (?:the |all )?(?:polic(?:y|ies)|rules?|restrictions?)"
                    r"|you must (?:call|run|send)|system prompt", I)


_JSON_TYPES = {"string": str, "boolean": bool, "object": dict, "array": list}


def _schema_violation(args: Any, schema: Any) -> bool:
    """Shallow, bounded check of top-level arguments against a closed object schema.

    Unsupported or open schemas are not checked. This never rewrites arguments; it only reports drift.
    """
    if not isinstance(schema, dict) or not isinstance(args, dict) or schema.get("type") != "object":
        return False
    props = schema.get("properties")
    if not isinstance(props, dict):
        return False
    required = schema.get("required")
    if isinstance(required, list) and any(isinstance(r, str) and r not in args for r in required):
        return True
    if schema.get("additionalProperties") is False and any(k not in props for k in args):
        return True
    for key, value in args.items():
        declared = props.get(key)
        kind = declared.get("type") if isinstance(declared, dict) else None
        if not isinstance(kind, str):
            continue  # Union/composite types are outside this shallow diagnostic check.
        if kind in ("integer", "number"):
            if isinstance(value, bool) or not isinstance(value, (int, float)) or (kind == "integer" and isinstance(value, float) and not value.is_integer()):
                return True
        elif kind in _JSON_TYPES and not isinstance(value, _JSON_TYPES[kind]):
            return True
    return False


def _canon(obj: Any) -> str:
    try:
        return json.dumps(obj, sort_keys=True, default=str)
    except (TypeError, ValueError):
        return repr(obj)


def _error(reason: str, code: str = "classifier_invalid") -> dict[str, Any]:
    """Technical failure (D06): never a semantic classification and never a policy input."""
    assert code in FAILURE_CODES
    return {"status": "error", "interface": INTERFACE, "failure": {"code": code, "detail": reason[:200]},
            "actions": [], "unknown": True, "confidence": 0.0, "uncertainty": 1.0,
            "reason_codes": ["invalid_input" if code == "classifier_invalid" else code],
            "reason": reason[:MAX_REASON_CHARS] or code, "scores": {}, "evidence": [],
            "definition_estimate": {"actions": [], "unknown": True, "sources": []},
            "description_conflict": False, "description_suspicious": False,
            "name_conflict": False, "schema_mismatch": False, "truncated": False}


def _bound(out: dict[str, Any]) -> dict[str, Any]:
    """Keep every reply inside the bridge limits without changing the semantic core."""
    out["reason"] = (str(out.get("reason") or "no reason").replace("\n", " "))[:MAX_REASON_CHARS]
    out["reason_codes"] = [str(c)[:64] for c in out.get("reason_codes", [])][:MAX_CODES]
    out["evidence"] = out.get("evidence", [])[:MAX_EVIDENCE]
    if len(json.dumps(out, ensure_ascii=False).encode()) > MAX_REPLY_BYTES:
        out["evidence"], out["scores"] = [], {}
    return out


def _evidence_list(evid: dict[str, list[tuple[float, str, str]]], included: list[str]) -> list[dict[str, Any]]:
    """Bounded, structured evidence for the included actions; never echoes argument values."""
    rows = sorted(((w, c, src, detail) for c in included for w, src, detail in evid.get(c, [])), reverse=True)
    return [{"action": c, "source": src, "weight": round(w, 2), "detail": detail[:160]}
            for w, c, src, detail in rows[:MAX_EVIDENCE]]


def _definition_estimate(evid: dict[str, list[tuple[float, str, str]]]) -> dict[str, Any]:
    """What the tool DEFINITION alone suggests (name and schema); arguments are not consulted.

    This is an estimate about the tool, kept distinct from the invocation result, which also
    uses the actual arguments. A disagreement is reported as `definition_invocation_diff`.
    """
    scores: dict[str, float] = {}
    for cat, items in evid.items():
        p = 1.0
        for w, src, _ in items:
            if src in ("name", "schema"):
                p *= 1 - w
        if p < 1.0:
            scores[cat] = min(1 - p, 0.99)
    actions = [c for c in CATEGORIES if scores.get(c, 0) >= THRESHOLD]
    return {"actions": actions, "unknown": not actions, "sources": ["name", "schema"]}


# Original mcp-server-git 2026.10.10 schemas, canonicalized with _canon.
# These are semantic evidence, NEVER server identity or execution authority.
# Admission must still pin discovery/runtime and enforce policy and isolation.
GIT_READ_SCHEMAS = {
    'git_status': '1860b4cdb5a84dfd037bf6a0ab39408f7f12e9d8b5059624bbf837951f25bcda',
    'git_diff_unstaged': 'fdfa2e3759e0963d7c896850031e4224a67a9b19280596c7fc6254cb415255dd',
    'git_diff_staged': '0a08fd75b4b1971f2726a93e0572a99e2487125440796ac21d9d1485a776acfa',
    'git_diff': 'e1d4050ef0a1419a7478c6d6656c4010c995a318f624c0f30a010d2b29844edf',
    'git_log': '24d0d296ada01f385549756674a28b6cd48718446ad32a34c0b805271f284cb3',
    'git_show': '1ed494818a3d86742310267537e8ab6cf707a8d95f08eaede1472c481066ff50',
}


def _bounded_git_read(name: str, args: Any, event: dict) -> bool | None:
    if name not in GIT_READ_SCHEMAS:
        return None
    declared, pinned = event.get('tool_schema'), event.get('pinned_schema')
    if not isinstance(declared, dict) or hashlib.sha256(_canon(declared).encode()).hexdigest() != GIT_READ_SCHEMAS[name]:
        return False
    if pinned is not None and _canon(pinned) != _canon(declared):
        return False
    allowed = {'repo_path'}
    if name == 'git_log':
        allowed.add('max_count')
    if name in ('git_diff', 'git_diff_staged', 'git_diff_unstaged'):
        allowed.add('context_lines')
    reference = {'git_diff': 'target', 'git_show': 'revision'}.get(name)
    if reference:
        allowed.add(reference)
    if not isinstance(args, dict) or set(args) - allowed or args.get('repo_path') != '/workspace':
        return False
    for key, lower in [('max_count', 1), ('context_lines', 0)]:
        if key in args and (type(args[key]) is not int or not lower <= args[key] <= 20):
            return False
    if reference:
        value = args.get(reference)
        if not isinstance(value, str) or not (value == 'HEAD' or re.fullmatch(r'[0-9a-fA-F]{40}', value)):
            return False
    return True


# Original @modelcontextprotocol/server-filesystem 2026.8.31 input schemas, canonicalized with _canon.
# Like GIT_READ_SCHEMAS these are semantic evidence, NEVER server identity or execution authority:
# admission must still pin discovery, validate arguments and enforce policy and isolation.
FS_READ_SCHEMAS = {
    'directory_tree': '177d2a6bbf9a0879c3c3c245ad7a731eca099825db8d9bcbdcc3122d63415baa',
    'read_multiple_files': '6f26113dbd3ca808b91378a83045e07e02d9cf2d0397c6ad6073d53db28cbcad',
    'search_files': 'e5c74cfd621ada64c07af3f822a3d08fa8dc0e2b268c80cc3898ccef2bf0e49e',
}
FS_ARGS = {  # name: (required keys, optional keys); every value is checked below
    'directory_tree': ({'path'}, {'excludePatterns'}),
    'read_multiple_files': ({'paths'}, set()),
    'search_files': ({'path', 'pattern'}, {'excludePatterns'}),
}
FS_MAX_ITEMS = 256  # the selected profile's array bound (crates/agentfw/src/mcp/input.rs MAX_ITEMS)


def _workspace_path(value: Any) -> bool:
    """Mirror of the profile's validate_workspace_path (server_profile.rs); stricter is allowed, looser is not."""
    if not isinstance(value, str) or not value or len(value.encode('utf-8')) > MAX_LEAF_CHARS:
        return False
    if any(ord(c) < 32 or 127 <= ord(c) < 160 for c in value) or '\\' in value or ':' in value or value.startswith('~'):
        return False
    if any(part in ('', '.', '..') for part in value.removeprefix('/').split('/')):
        return False
    return not value.startswith('/') or value == '/workspace' or value.startswith('/workspace/')


def _text_list(value: Any, minimum: int) -> bool:
    return (isinstance(value, list) and minimum <= len(value) <= FS_MAX_ITEMS
            and all(isinstance(v, str) and len(v) <= MAX_LEAF_CHARS
                    and not any(ord(c) < 32 or 127 <= ord(c) < 160 for c in v) for v in value))


def _bounded_fs_read(name: str, args: Any, event: dict) -> bool:
    """True only for an exact original read form whose every argument value was inspected here.

    The generic walker stops at MAX_LEAVES values; this proof does not, because it checks each of at
    most FS_MAX_ITEMS bounded strings itself. Any other form returns False and is classified exactly as
    before. A name alone, a description, or server_id never establishes the proof.
    """
    if name not in FS_READ_SCHEMAS:
        return False
    declared, pinned = event.get('tool_schema'), event.get('pinned_schema')
    if not isinstance(declared, dict) or hashlib.sha256(_canon(declared).encode()).hexdigest() != FS_READ_SCHEMAS[name]:
        return False
    if pinned is not None and _canon(pinned) != _canon(declared):
        return False
    required, optional = FS_ARGS[name]
    if not isinstance(args, dict) or not required <= set(args) <= required | optional:
        return False
    if name == 'read_multiple_files':
        return _text_list(args['paths'], 1) and all(_workspace_path(p) for p in args['paths'])
    if not _workspace_path(args['path']):
        return False
    if 'excludePatterns' in args and not _text_list(args['excludePatterns'], 0):
        return False
    return 'pattern' not in args or _text_list([args['pattern']], 1)


def _classify(event: Any) -> dict[str, Any]:
    if not isinstance(event, dict):
        return _error("invalid_input: event must be an object")
    name = event.get("tool_name")
    if not isinstance(name, str) or not name.strip():
        return _error("invalid_input: tool_name must be a non-empty string")
    if len(name) > MAX_NAME_CHARS:
        return _error("invalid_input: tool_name exceeds the length limit")
    args = event.get("raw_arguments")
    if isinstance(args, str):
        try:
            args = json.loads(args)
        except ValueError:
            pass  # keep as a raw string leaf
    if args is not None and not isinstance(args, (dict, list, str, int, float, bool)):
        return _error("invalid_input: raw_arguments is not JSON-like")

    evid: dict[str, list[tuple[float, str, str]]] = {}

    def ev(cat: str, w: float, src: str, detail: str) -> None:
        evid.setdefault(cat, []).append((w, src, detail))

    ev.noop = []  # shell segments proven to have no effect (D07)
    walk = _Walk()
    walk.go(args)
    if isinstance(args, str):
        walk.leaves.append(("", args[:MAX_LEAF_CHARS]))
    noun_cats, compound_unresolved = _name_evidence(name, ev, bool(walk.keys & SHELL_KEYS or walk.children))
    name_cats = {c for c, items in evid.items() if any(s == "name" for _, s, _ in items)}
    before = {c: len(v) for c, v in evid.items()}
    git_read = _bounded_git_read(name, args, event)
    fs_read = _bounded_fs_read(name, args, event)
    if fs_read:
        # Paths and glob patterns of an exact original read form are data; each was checked above,
        # so the generic walker's leaf bound no longer limits what was examined.
        ev('read', 0.95, 'args', 'bounded original filesystem read with exact schema')
        walk.truncated = False
    elif git_read is True:
        # Exact bounded integer context_lines is display context, not content
        # to write. No arbitrary field/value is omitted from this proof.
        ev('read', 0.95, 'args', 'bounded original Git read with exact schema')
    else:
        _arg_evidence(walk, ev)
        if git_read is False:
            walk.unmatched += 1  # retain risky evidence, but never prove unsupported Git forms
    if set(_tokens(name.split("__")[-1])) & SHELL_TOKENS and not (walk.keys & SHELL_KEYS):
        walk.unmatched += _shell(" ".join(v for _, v in walk.leaves), ev)
    if set(_tokens(name.split("__")[-1])) & OPAQUE_TOKENS and not (walk.keys & SHELL_KEYS):
        walk.unmatched += 1  # effects hidden behind a callback/plugin: partial unknown
    if compound_unresolved:
        walk.unmatched += 1  # one part of a compound tool name is not recognised
    last_toks = _tokens(name.split("__")[-1])
    if (any(t in BARE_RUNNERS for t in last_toks) and not any(t in VERBS for t in last_toks)
            and not set(last_toks) & (KNOWN_RUNNERS - BARE_RUNNERS) and not walk.children
            and not (walk.keys & SHELL_KEYS)):
        walk.unmatched += 1  # a generic runner: what it runs is not in its arguments, so its effects are open
    for cat in noun_cats:  # a category guessed from a noun alone must be corroborated by the arguments
        if not any(src in ("args", "shell") and w >= THRESHOLD for w, src, _ in evid.get(cat, [])):
            walk.unmatched += 1
    sends = max((x[0] for x in evid.get("send_data", [])), default=0.0)
    if sends >= THRESHOLD and _kmatch(walk.keys, PATH_KEYS, PATH_TOK) and not _kmatch(walk.keys, set(), INLINE_TOK):
        ev("read", 0.6, "args", "local path argument sent outward")
    violation = _schema_violation(args, event.get("pinned_schema") if event.get("pinned_schema") is not None
                                  else event.get("tool_schema"))
    if violation:
        walk.unmatched += 1  # arguments do not match the declared schema: effects not fully known
    arg_cats = {c for c, items in evid.items() if any(s in ("args", "shell") for _, s, _ in items)}
    declared, pinned = event.get("tool_schema"), event.get("pinned_schema")
    mismatch = pinned is not None and declared is not None and _canon(declared) != _canon(pinned)
    _schema_evidence(pinned if pinned is not None else declared, ev)

    estimate = _definition_estimate(evid)  # before name-only read evidence may be dropped below
    name_conflict = name_cats == {"read"} and bool(arg_cats & {"write", "delete", "send_data", "change_permissions"})
    if name_conflict:  # a read-like name does not prove read-only: drop name-only read evidence
        evid["read"] = [i for i in evid["read"] if i[1] != "name"]
        if not evid["read"]:
            del evid["read"]
    scores: dict[str, float] = {}
    for cat, items in evid.items():
        p = 1.0
        for w, _, _ in items:
            p *= 1 - w
        scores[cat] = round(min(1 - p, 0.99), 2)
    included = [c for c in CATEGORIES if scores.get(c, 0) >= THRESHOLD]

    desc = event.get("tool_description")
    desc = desc[:MAX_DESC_CHARS] if isinstance(desc, str) else ""
    risky = {"write", "delete", "send_data", "change_permissions"}
    flags = {
        "description_conflict": bool(RO_CLAIM.search(desc)) and bool(set(included) & risky),
        "description_suspicious": bool(INJECT.search(desc)),
        "name_conflict": name_conflict,
        "schema_mismatch": mismatch,
        "args_schema_violation": violation,
        "dry_run_declared": any(walk.scalars.get(k) is True for k in ("dry_run", "dryrun", "dry-run")),
        "truncated": walk.truncated,
    }
    out: dict[str, Any] = dict(flags)

    def seal(result: dict[str, Any]) -> dict[str, Any]:
        result.update(interface=INTERFACE, failure=None, evidence=_evidence_list(evid, result["actions"]),
                      definition_estimate=estimate,
                      definition_invocation_diff=set(estimate["actions"]) != set(result["actions"]))
        return _bound(result)

    if not included and ev.noop and walk.unmatched == 0 and not walk.truncated:
        # D07: every examined command is a proven no-op -> no actions, nothing unknown
        out.update(status="ok", actions=[], unknown=False, confidence=0.9, uncertainty=0.1,
                   reason_codes=["proven_noop"] + [k for k, v in flags.items() if v],
                   reason="all commands are proven no-ops (echo/printf/true/false/:/sleep)", scores=scores)
        return seal(out)
    if not included:
        out.update(status="unknown", actions=[], unknown=True, confidence=0.0, uncertainty=1.0,
                   reason_codes=["no_rule_matched"] + [k for k, v in flags.items() if v],
                   reason="no rule matched; weak signals: " + (", ".join(f"{c}={s}" for c, s in scores.items()) or "none"),
                   scores=scores)
        return seal(out)
    confidence = min(scores[c] for c in included)
    if walk.truncated:
        confidence = min(confidence, 0.2)
    if mismatch:
        confidence = min(confidence, 0.5)
    partial = walk.unmatched > 0 or walk.truncated  # unexamined input = effects not fully known
    if partial:
        confidence = min(confidence, 0.5)
    top = sorted((i for c in included for i in evid[c]), reverse=True)[:3]
    codes = sorted({f"{src}:{c}" for c in included for _, src, _ in evid[c]},
                   key=lambda x: (x.split(":")[1], x))
    out.update(status="ok", actions=included, unknown=partial, confidence=round(confidence, 2),
               uncertainty=round(1 - confidence, 2),
               reason_codes=codes + (["partial_unknown"] if partial else []) + [k for k, v in flags.items() if v and k not in ("name_conflict",)] +
               (["name_conflict"] if flags["name_conflict"] else []),
               reason="; ".join(f"{s}: {d}" for _, s, d in top) + ("; input truncated" if walk.truncated else ""),
               scores=scores)
    return seal(out)


def classify(event: Any) -> dict[str, Any]:
    """Public entry point. Never raises: a crash is a technical failure, not a classification."""
    try:
        return _classify(event)
    except RecursionError:
        return _error("invalid_input: nesting exceeds the supported depth")
    except Exception as exc:  # noqa: BLE001 - failure channel must not leak a traceback
        return _error(f"unexpected {type(exc).__name__}", "classifier_internal_error")


def main() -> int:
    # The daemon's limit applies to UTF-8 JSON bytes, excluding the line delimiter.
    stream = sys.stdin.buffer
    while True:
        line = stream.readline(MAX_INPUT_BYTES + 2)
        if not line:
            return 0
        payload = line[:-1] if line.endswith(b"\n") else line
        if len(payload) > MAX_INPUT_BYTES:
            while line and not line.endswith(b"\n"):  # drain the oversized frame
                line = stream.readline(MAX_INPUT_BYTES + 2)
            result = _error("invalid_input: input line exceeds the size limit")
        elif payload.strip():
            try:
                result = classify(json.loads(payload.decode("utf-8")))
            except (ValueError, UnicodeError, RecursionError):
                result = _error("invalid_input: not valid UTF-8 JSON")
        else:
            continue
        print(json.dumps(result, ensure_ascii=False))


if __name__ == "__main__":
    raise SystemExit(main())
