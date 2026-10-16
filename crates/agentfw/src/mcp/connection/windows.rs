// SPDX-License-Identifier: Apache-2.0

use super::Options;
use crate::private_file_windows::{current_user_sid, sid_to_string, PrivateAcl};
use crate::windows_read::{checked_create_stage, CreateParent};
use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::ffi::c_void;
use std::fs::File;
use std::io::{Read, Write};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::ptr::{null, null_mut};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use windows_sys::Win32::Foundation::{LocalFree, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_FILE_OBJECT};
use windows_sys::Win32::Security::{
    AclSizeInformation, GetAce, GetAclInformation, GetSecurityDescriptorControl, IsValidAcl,
    ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, ACL_SIZE_INFORMATION, DACL_SECURITY_INFORMATION,
    OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SE_DACL_PROTECTED,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateDirectoryW, CreateFileW, GetFileInformationByHandle, MoveFileExW, ReplaceFileW,
    BY_HANDLE_FILE_INFORMATION, CREATE_NEW, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL,
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_READ_ATTRIBUTES, FILE_READ_DATA, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    FILE_WRITE_DATA, OPEN_EXISTING, READ_CONTROL,
};

const LIMIT: usize = 1024 * 1024;

fn sha(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn hash(value: &Value) -> String {
    sha(&serde_json::to_vec(value).expect("JSON value serializes"))
}

fn parse(bytes: &[u8]) -> Result<Value> {
    ensure!(bytes.len() <= LIMIT, "file exceeds 1 MiB");
    let crate::mcp::admission::Strict(value) = serde_json::from_slice(bytes)
        .map_err(|_| anyhow::anyhow!("invalid or duplicate JSON fields"))?;
    Ok(value)
}

fn parent(path: &Path) -> Result<CreateParent> {
    let text = path.to_str().context("path must be Unicode")?;
    ensure!(
        !text.starts_with(r"\\") && !text.contains('/') && !text.contains('\0'),
        "path namespace is unsupported"
    );
    let dir = path.parent().context("missing parent directory")?;
    let (_, name) = CreateParent::prepare(dir, dir, text, text)?;
    ensure!(
        path.file_name().and_then(|v| v.to_str()) == Some(name.as_str()),
        "path alias refused"
    );
    let pinned = CreateParent::prepare_connection(dir, dir)?;
    let wide: Vec<_> = dir.as_os_str().encode_wide().chain(Some(0)).collect();
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            READ_CONTROL | FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            null_mut(),
        )
    };
    ensure!(
        handle != INVALID_HANDLE_VALUE,
        "cannot inspect config directory ACL"
    );
    let security = unsafe { File::from_raw_handle(handle) };
    identity(&security, true)?;
    Ok(pinned)
}

fn verify_acl(file: &File) -> Result<()> {
    let mut owner: PSID = null_mut();
    let mut dacl: *mut ACL = null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
    let code = unsafe {
        GetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            null_mut(),
            &mut dacl,
            null_mut(),
            &mut descriptor,
        )
    };
    ensure!(code == 0, "cannot inspect Windows file security");
    struct Descriptor(PSECURITY_DESCRIPTOR);
    impl Drop for Descriptor {
        fn drop(&mut self) {
            unsafe {
                LocalFree(self.0);
            }
        }
    }
    let _memory = Descriptor(descriptor);
    ensure!(
        !descriptor.is_null() && !owner.is_null() && !dacl.is_null(),
        "missing owner or DACL"
    );
    let sid = current_user_sid()?;
    ensure!(
        sid_to_string(owner)? == sid,
        "file or directory is not owned by the current user"
    );
    ensure!(unsafe { IsValidAcl(dacl) } != 0, "invalid Windows DACL");
    let mut control = 0u16;
    let mut revision = 0;
    ensure!(
        unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) } != 0
            && control & SE_DACL_PROTECTED != 0,
        "a protected private DACL is required"
    );
    let mut size = ACL_SIZE_INFORMATION {
        AceCount: 0,
        AclBytesInUse: 0,
        AclBytesFree: 0,
    };
    ensure!(
        unsafe {
            GetAclInformation(
                dacl,
                (&mut size as *mut ACL_SIZE_INFORMATION).cast(),
                std::mem::size_of_val(&size) as u32,
                AclSizeInformation,
            )
        } != 0,
        "cannot inspect DACL entries"
    );
    let mut offset = 0usize;
    for index in 0..size.AceCount {
        let mut raw: *mut c_void = null_mut();
        ensure!(
            unsafe { GetAce(dacl, index, &mut raw) } != 0 && !raw.is_null(),
            "invalid DACL entry"
        );
        ensure!(
            offset + std::mem::size_of::<ACE_HEADER>() <= size.AclBytesInUse as usize,
            "DACL entry exceeds ACL bounds"
        );
        let header = unsafe { std::ptr::read_unaligned(raw.cast::<ACE_HEADER>()) };
        ensure!(
            header.AceType == 0
                && header.AceSize as usize >= std::mem::size_of::<ACCESS_ALLOWED_ACE>()
                && header.AceSize as usize <= size.AclBytesInUse as usize - offset,
            "unsupported DACL entry"
        );
        let ace = unsafe { &*raw.cast::<ACCESS_ALLOWED_ACE>() };
        let trustee = sid_to_string(std::ptr::addr_of!(ace.SidStart).cast_mut().cast())?;
        ensure!(
            trustee == sid || trustee == "S-1-5-18",
            "DACL grants another account access"
        );
        offset += header.AceSize as usize;
    }
    Ok(())
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug)]
struct Identity {
    volume: u32,
    high: u32,
    low: u32,
}

fn identity(file: &File, directory: bool) -> Result<Identity> {
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    ensure!(
        unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } != 0,
        "cannot inspect Windows handle"
    );
    ensure!(
        info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT == 0
            && (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0) == directory,
        "reparse or wrong file type refused"
    );
    ensure!(
        directory || info.nNumberOfLinks == 1,
        "hard-linked file refused"
    );
    verify_acl(file)?;
    Ok(Identity {
        volume: info.dwVolumeSerialNumber,
        high: info.nFileIndexHigh,
        low: info.nFileIndexLow,
    })
}

fn open(path: &Path, create: bool, exclusive: bool) -> Result<File> {
    let _parent = parent(path)?;
    let wide: Vec<_> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let acl = PrivateAcl::new()?;
    let attributes = acl.attributes();
    let access = FILE_READ_DATA
        | FILE_READ_ATTRIBUTES
        | READ_CONTROL
        | if create {
            windows_sys::Win32::Storage::FileSystem::WRITE_DAC
        } else {
            0
        }
        | if create || exclusive {
            FILE_WRITE_DATA
        } else {
            0
        };
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            access,
            if exclusive {
                0
            } else {
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE
            },
            if create { &attributes } else { null() },
            if create { CREATE_NEW } else { OPEN_EXISTING },
            FILE_FLAG_OPEN_REPARSE_POINT | FILE_ATTRIBUTE_NORMAL,
            null_mut(),
        )
    };
    ensure!(
        handle != INVALID_HANDLE_VALUE,
        "cannot open private Windows file: {}",
        std::io::Error::last_os_error()
    );
    let file = unsafe { File::from_raw_handle(handle) };
    if create {
        acl.apply(file.as_raw_handle())?;
    }
    identity(&file, false)?;
    checked_create_stage(
        &file,
        path.to_str().context("path must be Unicode")?,
        file.metadata()?.len() as usize,
    )?;
    Ok(file)
}

fn read_file(path: &Path, limit: usize) -> Result<(Vec<u8>, Identity)> {
    let _parent = parent(path)?;
    let mut file = open(path, false, false)?;
    let id = identity(&file, false)?;
    ensure!(
        file.metadata()?.len() <= limit as u64,
        "file exceeds read limit"
    );
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= limit && id == identity(&file, false)?,
        "file changed or exceeds limit"
    );
    Ok((bytes, id))
}

fn read_private(path: &Path) -> Result<Vec<u8>> {
    Ok(read_file(path, LIMIT)?.0)
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<Identity> {
    ensure!(bytes.len() <= LIMIT, "new private file exceeds limit");
    let mut file = open(path, true, false)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    identity(&file, false)
}

fn private_directory(path: &Path) -> Result<()> {
    let _parent = parent(path)?;
    let acl = PrivateAcl::new()?;
    let attributes = acl.attributes();
    let wide: Vec<_> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    ensure!(
        unsafe { CreateDirectoryW(wide.as_ptr(), &attributes) } != 0,
        "cannot create private archive"
    );
    Ok(())
}

fn exists(path: &Path) -> Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e.into()),
    }
}

fn executable(path: &Path) -> Result<String> {
    ensure!(
        path.extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("exe")),
        "a native .exe is required"
    );
    Ok(sha(&read_file(path, 512 * 1024 * 1024)?.0))
}

fn system_root() -> Result<PathBuf> {
    let value = std::env::var_os("SystemRoot").context("SystemRoot unavailable")?;
    let path = PathBuf::from(value);
    ensure!(path.is_absolute(), "SystemRoot must be absolute");
    Ok(path)
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Runtime {
    workspace: PathBuf,
    classifier_script: PathBuf,
    classifier_python: PathBuf,
}

fn runtime_selection(path: &Path) -> Result<(Runtime, String)> {
    let bytes = read_private(path)?;
    let selection: Runtime = serde_json::from_value(parse(&bytes)?)?;
    let _workspace = CreateParent::prepare_workspace(&selection.workspace, &selection.workspace)?;
    let script = read_private(&selection.classifier_script)?;
    let python = executable(&selection.classifier_python)?;
    let identity = hash(&json!({"runtime":sha(&bytes),"script":sha(&script),"python":python}));
    Ok((selection, identity))
}

pub(super) fn collector(
    home: &Path,
    id: &str,
    runtime: Option<&Path>,
    expected: Option<&str>,
    command: &[String],
) -> Result<()> {
    ensure!(
        home.file_name().is_some_and(|n| n == ".agentfw"),
        "explicit .agentfw required"
    );
    let _home = parent(&home.join("config.yaml"))?;
    read_private(&home.join("config.yaml"))?;
    read_private(&home.join("token"))?;
    read_private(&home.join("native-token"))?;
    ensure!(
        !id.is_empty() && id.len() <= 128 && command.len() <= 256,
        "invalid collector arguments"
    );
    let current = std::env::current_exe()?;
    executable(&current)?;
    let selected = runtime.map(runtime_selection).transpose()?;
    ensure!(
        selected.as_ref().map(|(_, id)| id.as_str()) == expected,
        "collector runtime identity changed"
    );
    let o = Options {
        path: home.join("unused.json"),
        server: id.into(),
        home: home.into(),
        agent: current.clone(),
        probe_tool: None,
        probe_args: None,
        runtime: runtime.map(Path::to_path_buf),
    };
    let executor = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    executor.block_on(preflight(&o))?;
    executable(Path::new(
        command.first().context("missing original executable")?,
    ))?;
    let mut child = std::process::Command::new(current);
    child
        .args(["mcp", "--id", id, "--native-admission", "--"])
        .args(command)
        .env_clear()
        .env(
            "USERPROFILE",
            home.parent().context("profile parent missing")?,
        )
        .env("SystemRoot", system_root()?)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    if let Some((selection, _)) = selected {
        child
            .env("AGENTFW_CLASSIFIER", "rule-baseline")
            .env("AGENTFW_RULE_BASELINE", selection.classifier_script)
            .env("AGENTFW_CLASSIFIER_PYTHON", selection.classifier_python)
            .env("AGENTFW_WORKSPACE", &selection.workspace)
            .current_dir(selection.workspace);
    }
    let status = child.status()?;
    ensure!(status.success(), "enforcing collector failed");
    Ok(())
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Publication {
    version: u8,
    path: PathBuf,
    archive: String,
    before: String,
    proposed: String,
    before_id: Identity,
    proposed_id: Identity,
}

fn journal_path(path: &Path) -> Result<PathBuf> {
    Ok(path.parent().context("missing parent")?.join(format!(
        ".soup-wall-publication-{}.json",
        sha(path.to_str().context("path must be Unicode")?.as_bytes())
    )))
}

fn finish(record: &Publication) -> Result<()> {
    ensure!(
        record.version == 1
            && record.archive.starts_with(".soup-wall-version-")
            && record.archive.len() < 128
            && record
                .archive
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"-_.".contains(&c)),
        "invalid publication record"
    );
    let dir = record
        .path
        .parent()
        .context("missing parent")?
        .join(&record.archive);
    let backup = dir.join("displaced.json");
    let stage = dir.join("stage.json");
    let current = read_file(&record.path, LIMIT)?;
    let before = read_private(&dir.join("snapshot.json"))?;
    let proposed = read_private(&dir.join("proposed.json"))?;
    ensure!(
        sha(&before) == record.before && sha(&proposed) == record.proposed,
        "publication snapshots changed"
    );
    if exists(&backup)? {
        let displaced = read_file(&backup, LIMIT)?;
        ensure!(
            current.1 == record.proposed_id
                && sha(&current.0) == record.proposed
                && displaced.1 == record.before_id
                && sha(&displaced.0) == record.before
                && !exists(&stage)?,
            "publication conflict; retain all versions and journal"
        );
    } else {
        let staged = read_file(&stage, LIMIT)?;
        ensure!(
            current.1 == record.before_id
                && sha(&current.0) == record.before
                && staged.1 == record.proposed_id
                && sha(&staged.0) == record.proposed,
            "interrupted publication is ambiguous; retain all versions and journal"
        );
    }
    std::fs::remove_file(journal_path(&record.path)?)?;
    Ok(())
}

fn recover(path: &Path, mutating: bool) -> Result<()> {
    let journal = journal_path(path)?;
    if exists(&journal)? {
        ensure!(
            mutating,
            "unfinished publication; repeat connect or disconnect"
        );
        let record: Publication = serde_json::from_value(parse(&read_private(&journal)?)?)?;
        ensure!(record.path == path, "publication path mismatch");
        finish(&record)?;
    }
    Ok(())
}

fn publish(path: &Path, expected: Option<(&[u8], Identity)>, bytes: &[u8]) -> Result<()> {
    let _parent = parent(path)?;
    ensure!(!exists(&journal_path(path)?)?, "unfinished publication");
    let Some((before, before_id)) = expected else {
        let stage = path
            .parent()
            .context("missing parent")?
            .join(format!(".soup-wall-stage-{}", crate::token::generate()));
        write_new(&stage, bytes)?;
        let source: Vec<_> = stage.as_os_str().encode_wide().chain(Some(0)).collect();
        let target: Vec<_> = path.as_os_str().encode_wide().chain(Some(0)).collect();
        ensure!(
            unsafe { MoveFileExW(source.as_ptr(), target.as_ptr(), 0) } != 0,
            "cannot publish new ownership record; staged bytes retained"
        );
        return Ok(());
    };
    let record = stage_publication(path, before, before_id, bytes)?;
    replace_record(&record)?;
    finish(&record)
}

fn stage_publication(
    path: &Path,
    before: &[u8],
    before_id: Identity,
    bytes: &[u8],
) -> Result<Publication> {
    ensure!(
        read_file(path, LIMIT)? == (before.to_vec(), before_id),
        "file changed before publication"
    );
    let name = format!(".soup-wall-version-{}", crate::token::generate());
    let archive = path.parent().context("missing parent")?.join(&name);
    private_directory(&archive)?;
    write_new(&archive.join("snapshot.json"), before)?;
    write_new(&archive.join("proposed.json"), bytes)?;
    let stage = archive.join("stage.json");
    let proposed_id = write_new(&stage, bytes)?;
    let record = Publication {
        version: 1,
        path: path.into(),
        archive: name,
        before: sha(before),
        proposed: sha(bytes),
        before_id,
        proposed_id,
    };
    write_new(&journal_path(path)?, &serde_json::to_vec(&record)?)?;
    Ok(record)
}

fn replace_record(record: &Publication) -> Result<()> {
    let path = &record.path;
    let archive = path
        .parent()
        .context("missing parent")?
        .join(&record.archive);
    let stage = archive.join("stage.json");
    let dest: Vec<_> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let staged: Vec<_> = stage.as_os_str().encode_wide().chain(Some(0)).collect();
    let backup = archive.join("displaced.json");
    let saved: Vec<_> = backup.as_os_str().encode_wide().chain(Some(0)).collect();
    ensure!(
        unsafe {
            ReplaceFileW(
                dest.as_ptr(),
                staged.as_ptr(),
                saved.as_ptr(),
                0,
                null_mut(),
                null_mut(),
            )
        } != 0,
        "Windows publication incomplete; retain journal and versions: {}",
        std::io::Error::last_os_error()
    );
    Ok(())
}

fn lock(path: &Path) -> Result<File> {
    let lock_path = path
        .parent()
        .context("missing parent")?
        .join(".soup-wall-mcp.lock");
    if !exists(&lock_path)? {
        match open(&lock_path, true, true) {
            Ok(file) => return Ok(file),
            Err(e) if !exists(&lock_path)? => return Err(e),
            Err(_) => (),
        }
    }
    open(&lock_path, false, true)
        .context("another connection operation is active or lock is unsafe")
}

struct ConfigFile {
    path: PathBuf,
    bytes: Vec<u8>,
    id: Identity,
    value: Value,
}

impl ConfigFile {
    fn read(path: &Path) -> Result<Self> {
        let (bytes, id) = read_file(path, LIMIT)?;
        let value = parse(&bytes)?;
        Ok(Self {
            path: path.into(),
            bytes,
            id,
            value,
        })
    }
    fn sibling(&self, name: &str) -> Result<PathBuf> {
        Ok(self.path.parent().context("missing parent")?.join(name))
    }
    fn entry(&self, name: &str) -> Result<Value> {
        ensure!(
            !name.is_empty()
                && name.len() <= 128
                && name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_-.".contains(&b)),
            "invalid server name"
        );
        let servers = self.value["mcpServers"]
            .as_object()
            .context("mcpServers must be an object")?;
        ensure!(servers.len() <= 256, "too many servers");
        let value = servers.get(name).context("selected server not found")?;
        validate_entry(value)?;
        Ok(value.clone())
    }
    fn replacement(&self, name: &str, entry: &Value) -> Result<Vec<u8>> {
        validate_entry(entry)?;
        let mut value = self.value.clone();
        value["mcpServers"][name] = entry.clone();
        let bytes = serde_json::to_vec_pretty(&value)?;
        ensure!(bytes.len() <= LIMIT, "updated config exceeds limit");
        Ok(bytes)
    }
    fn unchanged(&self) -> Result<()> {
        ensure!(
            read_file(&self.path, LIMIT)? == (self.bytes.clone(), self.id),
            "configuration changed during operation"
        );
        Ok(())
    }
    fn snapshot_unchanged(&self, name: &str, owner: &Option<Owner>) -> Result<()> {
        self.unchanged()?;
        ensure!(self.state(name)? == *owner, "ownership changed");
        Ok(())
    }
    fn state_name(&self, name: &str) -> String {
        format!(
            ".soup-wall-{}.json",
            sha(format!("{}\0{name}", self.path.display()).as_bytes())
        )
    }
    fn state(&self, name: &str) -> Result<Option<Owner>> {
        let path = self.sibling(&self.state_name(name))?;
        if !exists(&path)? {
            return Ok(None);
        }
        let owner: Owner = serde_json::from_value(parse(&read_private(&path)?)?)
            .context("invalid ownership metadata")?;
        ensure!(
            owner.version == 1
                && owner.path == self.path
                && owner.server == name
                && owner.original_sha256 == hash(&owner.original)
                && owner.wrapped_sha256 == hash(&owner.wrapped)
                && [
                    "pending_connect",
                    "pending_disconnect",
                    "connected",
                    "disconnected"
                ]
                .contains(&owner.phase.as_str()),
            "ownership metadata mismatch"
        );
        Ok(Some(owner))
    }
    fn validate_transaction(&self, owner: &Owner) -> Result<()> {
        self.replacement(&owner.server, &owner.original)?;
        self.replacement(&owner.server, &owner.wrapped)?;
        ensure!(
            serde_json::to_vec(owner)?.len() <= LIMIT,
            "ownership exceeds limit"
        );
        Ok(())
    }
    fn save(&self, owner: &Owner) -> Result<()> {
        self.unchanged()?;
        let path = self.sibling(&self.state_name(&owner.server))?;
        let prior = if exists(&path)? {
            Some(read_file(&path, LIMIT)?)
        } else {
            None
        };
        publish(
            &path,
            prior.as_ref().map(|(b, i)| (b.as_slice(), *i)),
            &serde_json::to_vec(owner)?,
        )?;
        Ok(())
    }
    fn replace(&mut self, name: &str, entry: &Value) -> Result<()> {
        self.unchanged()?;
        publish(
            &self.path,
            Some((&self.bytes, self.id)),
            &self.replacement(name, entry)?,
        )?;
        *self = Self::read(&self.path)?;
        Ok(())
    }
}

fn validate_entry(entry: &Value) -> Result<()> {
    let map = entry.as_object().context("server must be an object")?;
    ensure!(
        map.keys()
            .all(|k| ["command", "args", "type", "env"].contains(&k.as_str())),
        "unsupported selected server field"
    );
    ensure!(
        map.get("type").is_none_or(|v| v == "stdio"),
        "only stdio is supported"
    );
    ensure!(
        map.get("env")
            .is_none_or(|v| v.as_object().is_some_and(|m| m.is_empty())),
        "selected server environment must be empty; credentials cannot enter child environments"
    );
    let command = map
        .get("command")
        .and_then(Value::as_str)
        .context("command must be a string")?;
    ensure!(
        !command.is_empty()
            && command.len() <= 4096
            && !command.contains('\0')
            && Path::new(command).is_absolute(),
        "command must be a bounded absolute executable path"
    );
    if let Some(args) = map.get("args") {
        let args = args.as_array().context("args must be an array")?;
        ensure!(
            args.len() <= 256
                && args.iter().all(|a| a
                    .as_str()
                    .is_some_and(|s| s.len() <= 16384 && !s.contains('\0'))),
            "invalid or excessive arguments"
        );
    }
    Ok(())
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Owner {
    version: u8,
    path: PathBuf,
    server: String,
    phase: String,
    original: Value,
    wrapped: Value,
    original_sha256: String,
    wrapped_sha256: String,
    agent: PathBuf,
    home: PathBuf,
    agent_sha256: String,
    registry_sha256: String,
    native_config_sha256: String,
}

#[derive(Serialize)]
pub(super) struct Report {
    pub status: &'static str,
    operation: String,
    config_sha256: String,
    selected_sha256: String,
    server_id: String,
    agent_sha256: Option<String>,
    registry_sha256: Option<String>,
    probe_result_sha256: Option<String>,
    elapsed_ms: u128,
    detail: &'static str,
}

struct Native {
    binary: String,
    registry: String,
    config: String,
}

async fn preflight(o: &Options) -> Result<Native> {
    let binary = executable(&o.agent)?;
    ensure!(
        o.home.file_name().is_some_and(|v| v == ".agentfw"),
        "home must be the explicit .agentfw directory"
    );
    let bytes = read_private(&o.home.join("config.yaml"))?;
    let cfg =
        crate::Config::from_yaml(std::str::from_utf8(&bytes).context("invalid native config")?)
            .map_err(|_| anyhow::anyhow!("invalid native configuration"))?;
    ensure!(
        cfg.enforce && !cfg.judge.enabled,
        "enforcing native configuration required"
    );
    let installed = cfg
        .native
        .as_ref()
        .context("pinned native registry required")?;
    let registry_bytes = read_private(&installed.registry_path)?;
    ensure!(
        sha(&registry_bytes) == installed.registry_sha256,
        "native registry digest mismatch"
    );
    let native_token = read_private(&o.home.join("native-token"))?;
    let token = read_private(&o.home.join("token"))?;
    let native_token = std::str::from_utf8(&native_token)?.trim().to_owned();
    ensure!(!native_token.is_empty(), "native token is empty");
    let native = crate::native::NativeState::load(installed, native_token)
        .map_err(|_| anyhow::anyhow!("native registry unavailable or invalid"))?;
    let selected = o.runtime.as_deref().map(runtime_selection).transpose()?;
    for policy in native
        .registry
        .tools
        .iter()
        .filter_map(|tool| tool.resource_policy.as_ref())
        .filter(|policy| policy.is_windows_handles())
    {
        let (selection, _) = selected
            .as_ref()
            .context("Windows resource profiles require an explicit runtime selection")?;
        ensure!(
            selection.workspace == policy.workspace
                && sha(&read_private(&selection.classifier_script)?) == policy.classifier_sha256,
            "runtime does not match the reviewed Windows resource policy"
        );
    }
    let expected = crate::protection_status::Expectations {
        config_sha256: Some(crate::protection_status::config_digest(&cfg)),
        binary_sha256: Some(binary.clone()),
        registry_sha256: Some(installed.registry_sha256.clone()),
        ..Default::default()
    };
    let snapshot = crate::protection_status::query(
        &cfg,
        std::str::from_utf8(&token)?.trim(),
        &expected,
        Duration::from_secs(2),
    )
    .await
    .map_err(|_| anyhow::anyhow!("enforcing Agent preflight unavailable or identity mismatch"))?;
    ensure!(
        snapshot.mode == crate::protection_status::Mode::Enforcing,
        "Agent is not enforcing"
    );
    ensure!(
        read_private(&o.home.join("config.yaml"))? == bytes
            && read_private(&installed.registry_path)? == registry_bytes
            && executable(&o.agent)? == binary,
        "native identities changed during preflight"
    );
    ensure!(
        selected.as_ref().map(|(_, id)| id)
            == o.runtime
                .as_deref()
                .map(runtime_selection)
                .transpose()?
                .as_ref()
                .map(|(_, id)| id),
        "runtime changed during preflight"
    );
    Ok(Native {
        binary,
        registry: installed.registry_sha256.clone(),
        config: hash(
            &json!({"config":sha(&bytes),"runtime":o.runtime.as_deref().map(runtime_selection).transpose()?.map(|(_,id)|id)}),
        ),
    })
}

fn wrapped(entry: &Value, o: &Options, id: &str) -> Result<Value> {
    executable(Path::new(
        entry["command"].as_str().context("missing command")?,
    ))?;
    ensure!(
        !entry["args"].as_array().is_some_and(|a| a
            .iter()
            .any(|v| v == "--native-admission" || v == "collector")),
        "entry is already wrapped without matching ownership"
    );
    let mut result = entry.clone();
    result["command"] = json!(o.agent);
    let mut args = vec![
        json!("mcp-connection"),
        json!("collector"),
        json!("--home"),
        json!(o.home),
        json!("--id"),
        json!(id),
    ];
    if let Some(path) = &o.runtime {
        let (_, digest) = runtime_selection(path)?;
        args.extend([
            json!("--runtime"),
            json!(path),
            json!("--runtime-sha256"),
            json!(digest),
        ]);
    }
    args.extend([json!("--"), entry["command"].clone()]);
    args.extend(entry["args"].as_array().into_iter().flatten().cloned());
    result["args"] = Value::Array(args);
    validate_entry(&result)?;
    Ok(result)
}

async fn probe(entry: &Value, tool: &str, args: &str) -> Result<String> {
    ensure!(tool.len() <= 128 && !tool.is_empty(), "invalid probe tool");
    let arguments = parse(args.as_bytes())?;
    ensure!(arguments.is_object(), "probe arguments must be an object");
    let mut child =
        tokio::process::Command::new(entry["command"].as_str().context("missing command")?)
            .args(
                entry["args"]
                    .as_array()
                    .context("missing arguments")?
                    .iter()
                    .map(|v| v.as_str().unwrap_or_default()),
            )
            .env_clear()
            .env("SystemRoot", system_root()?)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()?;
    let outcome = tokio::time::timeout(Duration::from_secs(8), async {
        let mut input = child.stdin.take().context("missing stdin")?;
        let mut output = BufReader::new(child.stdout.take().context("missing stdout")?);
        let init = json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"soup-wall-connection","version":"1"}}});
        let frames = [
            init,
            json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
            json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}),
            json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":tool,"arguments":arguments}}),
        ];
        let mut last = Value::Null;
        for frame in frames {
            input.write_all(format!("{}\n", frame).as_bytes()).await?;
            input.flush().await?;
            if frame.get("id").is_some() {
                let mut bytes = Vec::new();
                loop {
                    ensure!(bytes.len() < LIMIT, "probe response exceeds limit");
                    let byte = output.read_u8().await?;
                    if byte == b'\n' { break; }
                    bytes.push(byte);
                }
                let reply = parse(&bytes)?;
                ensure!(reply["id"] == frame["id"] && reply.get("error").is_none() && reply.get("result").is_some(), "probe refused or invalid response");
                last = reply;
            }
        }
        ensure!(last["result"]["isError"] != true, "probe call was refused");
        Ok::<_, anyhow::Error>(hash(&last["result"]))
    }).await;
    let _ = child.kill().await;
    let _ = child.wait().await;
    outcome.context("probe timed out")?
}

pub(super) async fn run(operation: &str, o: &Options) -> Result<Report> {
    let start = Instant::now();
    ensure!(
        o.probe_tool.is_none() || operation == "inspect",
        "controlled requests are only supported by inspect"
    );
    let _parents = parent(&o.path)?;
    let _lock = if ["connect", "disconnect"].contains(&operation) {
        Some(lock(&o.path)?)
    } else {
        None
    };
    recover(&o.path, _lock.is_some())?;
    let mut config = ConfigFile::read(&o.path)?;
    let state_path = config.sibling(&config.state_name(&o.server))?;
    recover(&state_path, _lock.is_some())?;
    let entry = config.entry(&o.server)?;
    let mut owner = config.state(&o.server)?;
    let id = format!(
        "claude-{}",
        &sha(format!("{}\0{}", o.path.display(), o.server).as_bytes())[..24]
    );
    let mut report = Report {
        status: "unknown",
        operation: operation.to_owned(),
        config_sha256: sha(&config.bytes),
        selected_sha256: hash(&entry),
        server_id: id.clone(),
        agent_sha256: None,
        registry_sha256: None,
        probe_result_sha256: None,
        elapsed_ms: 0,
        detail: "connection identity is unknown",
    };
    if operation == "disconnect" {
        let Some(mut state) = owner.clone() else {
            ensure!(
                !entry["args"].as_array().is_some_and(|args| args
                    .iter()
                    .any(|v| v == "--native-admission" || v == "collector")),
                "wrapped entry has no matching ownership; state is unknown"
            );
            report.status = "disconnected";
            report.detail = "no owned change to restore";
            config.snapshot_unchanged(&o.server, &owner)?;
            report.elapsed_ms = start.elapsed().as_millis();
            return Ok(report);
        };
        config.snapshot_unchanged(&o.server, &owner)?;
        config.validate_transaction(&state)?;
        if hash(&entry) != state.original_sha256 {
            ensure!(
                hash(&entry) == state.wrapped_sha256,
                "selected entry changed; conflict preserved"
            );
            state.phase = "pending_disconnect".into();
            config.save(&state)?;
            config.replace(&o.server, &state.original)?;
        }
        state.phase = "disconnected".into();
        config.save(&state)?;
        owner = Some(state);
        report.status = "disconnected";
        report.detail = "original entry restored; unrelated settings preserved";
    } else if operation == "preview" {
        if let Some(state) = &owner {
            ensure!(
                hash(&entry) == state.wrapped_sha256 || hash(&entry) == state.original_sha256,
                "selected entry changed; conflict preserved"
            );
            config.validate_transaction(state)?;
        } else {
            let next = wrapped(&entry, o, &id)?;
            config.replacement(&o.server, &next)?;
        }
        report.status = "preview";
        report.detail = "selected stdio command will use the native collector; original arguments retained; child environment cleared";
    } else {
        let native = preflight(o).await;
        let snapshot = config.snapshot_unchanged(&o.server, &owner);
        if operation == "inspect" && snapshot.is_err() {
            report.detail = "configuration or ownership changed during inspection";
            report.elapsed_ms = start.elapsed().as_millis();
            return Ok(report);
        }
        snapshot?;
        if operation == "inspect" && native.is_err() {
            report.status = "unavailable";
            report.detail = "Agent preflight unavailable or identity mismatch";
        } else {
            let native = native?;
            report.agent_sha256 = Some(native.binary.clone());
            report.registry_sha256 = Some(native.registry.clone());
            if operation == "connect" {
                if let Some(state) = &owner {
                    ensure!(
                        state.agent == o.agent
                            && state.home == o.home
                            && state.agent_sha256 == native.binary
                            && state.registry_sha256 == native.registry
                            && state.native_config_sha256 == native.config,
                        "selected Agent or native configuration changed"
                    );
                    ensure!(
                        hash(&entry) == state.wrapped_sha256
                            || hash(&entry) == state.original_sha256,
                        "selected entry changed; conflict preserved"
                    );
                } else {
                    let next = wrapped(&entry, o, &id)?;
                    config.snapshot_unchanged(&o.server, &owner)?;
                    owner = Some(Owner {
                        version: 1,
                        path: o.path.clone(),
                        server: o.server.clone(),
                        phase: "pending_connect".into(),
                        original_sha256: hash(&entry),
                        wrapped_sha256: hash(&next),
                        original: entry.clone(),
                        wrapped: next,
                        agent: o.agent.clone(),
                        home: o.home.clone(),
                        agent_sha256: native.binary,
                        registry_sha256: native.registry,
                        native_config_sha256: native.config,
                    });
                }
                let state = owner.as_mut().unwrap();
                config.validate_transaction(state)?;
                state.phase = "pending_connect".into();
                config.save(state)?;
                if hash(&entry) != state.wrapped_sha256 {
                    config.replace(&o.server, &state.wrapped)?;
                }
                state.phase = "connected".into();
                config.save(state)?;
                report.status = "configured";
                report.detail = "native wrapper configured; execution is not inferred";
            } else if let Some(state) = &owner {
                if state.phase == "connected"
                    && hash(&entry) == state.wrapped_sha256
                    && state.agent == o.agent
                    && state.home == o.home
                    && state.agent_sha256 == native.binary
                    && state.registry_sha256 == native.registry
                    && state.native_config_sha256 == native.config
                {
                    report.status = "configured";
                    report.detail = "owned configuration and Agent identities match";
                    if let Some(tool) = &o.probe_tool {
                        match probe(&entry, tool, o.probe_args.as_deref().unwrap_or("{}")).await {
                            Ok(hash) => {
                                report.status = "verified_for_this_probe";
                                report.probe_result_sha256 = Some(hash);
                                report.detail = "controlled request returned a permitted result";
                            }
                            Err(_) => {
                                report.status = "unavailable";
                                report.detail = "controlled request failed or was refused";
                            }
                        }
                    }
                }
            }
        }
    }
    let snapshot = config.snapshot_unchanged(&o.server, &owner);
    if operation == "inspect" && snapshot.is_err() {
        report.status = "unknown";
        report.probe_result_sha256 = None;
        report.detail = "configuration or ownership changed during inspection";
    } else {
        snapshot?;
    }
    report.config_sha256 = sha(&config.bytes);
    report.selected_sha256 = hash(&config.entry(&o.server)?);
    report.elapsed_ms = start.elapsed().as_millis();
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::windows::fs::OpenOptionsExt;

    fn fixture() -> (tempfile::TempDir, PathBuf) {
        let root = tempfile::tempdir().unwrap();
        let profile = root.path().to_path_buf();
        fs::remove_dir(&profile).unwrap();
        crate::private_file_windows::ensure_private_directory(&profile).unwrap();
        let path = profile.join("profile with spaces.json");
        let value = json!({"mcpServers":{"notes":{"type":"stdio","command":r"C:\Fixture\server.exe","args":["a b","\u{65e5}\u{672c}\u{8a9e}"]},"other":{"command":"untouched","env":{"TOKEN":"fixture-only"}}},"settings":{"theme":"light"}});
        write_new(&path, &serde_json::to_vec(&value).unwrap()).unwrap();
        (root, path)
    }

    fn before(path: &Path) -> (Vec<u8>, Identity) {
        read_file(path, LIMIT).unwrap()
    }

    #[test]
    fn strict_entry_and_json_validation() {
        for value in [
            json!({"command":"relative"}),
            json!({"command":r"C:\bin\server.exe","args":[2]}),
            json!({"command":r"C:\bin\server.exe","env":{"TOKEN":"no"}}),
            json!({"command":r"C:\bin\server.exe","type":"http"}),
            json!({"command":r"C:\bin\server.exe","url":"no"}),
        ] {
            assert!(validate_entry(&value).is_err());
        }
        assert!(parse(br#"{"x":1,"x":2}"#).is_err());
        assert!(parse(&vec![b' '; LIMIT + 1]).is_err());
    }

    #[test]
    fn selected_change_retains_other_entries_and_original_fields() {
        let (_root, path) = fixture();
        let mut config = ConfigFile::read(&path).unwrap();
        let original = config.entry("notes").unwrap();
        let mut changed = original.clone();
        changed["args"] = json!(["changed"]);
        config.replace("notes", &changed).unwrap();
        assert_eq!(config.value["settings"], json!({"theme":"light"}));
        assert_eq!(
            config.value["mcpServers"]["other"]["env"]["TOKEN"],
            "fixture-only"
        );
        config.replace("notes", &original).unwrap();
        assert_eq!(config.entry("notes").unwrap(), original);
        assert!(!exists(&journal_path(&path).unwrap()).unwrap());
    }

    #[test]
    fn stale_snapshot_refuses_before_publication() {
        let (_root, path) = fixture();
        let mut config = ConfigFile::read(&path).unwrap();
        let external = b"{\"external\":true}";
        fs::write(&path, external).unwrap();
        assert!(config
            .replace("notes", &json!({"command":r"C:\a.exe"}))
            .is_err());
        assert_eq!(fs::read(path).unwrap(), external);
    }

    #[test]
    fn boundary_write_retains_external_bytes_and_refuses_success() {
        let (_root, path) = fixture();
        let (bytes, id) = before(&path);
        let record = stage_publication(&path, &bytes, id, b"{\"proposed\":true}").unwrap();
        let external = b"{\"external\":true}";
        fs::write(&path, external).unwrap();
        replace_record(&record).unwrap();
        assert!(finish(&record).is_err());
        let displaced = path
            .parent()
            .unwrap()
            .join(&record.archive)
            .join("displaced.json");
        assert_eq!(fs::read(displaced).unwrap(), external);
        assert!(recover(&path, true).is_err());
        assert!(journal_path(&path).unwrap().is_file());
    }

    #[test]
    fn boundary_replacement_retains_external_inode() {
        let (root, path) = fixture();
        let (bytes, id) = before(&path);
        let record = stage_publication(&path, &bytes, id, b"{\"proposed\":true}").unwrap();
        let external = root.path().join("editor.json");
        write_new(&external, b"{\"editor\":true}").unwrap();
        let destination: Vec<_> = path.as_os_str().encode_wide().chain(Some(0)).collect();
        let source: Vec<_> = external.as_os_str().encode_wide().chain(Some(0)).collect();
        assert_ne!(
            unsafe { MoveFileExW(source.as_ptr(), destination.as_ptr(), 1) },
            0
        );
        replace_record(&record).unwrap();
        assert!(finish(&record).is_err());
        assert_eq!(
            read_private(&root.path().join(&record.archive).join("displaced.json")).unwrap(),
            b"{\"editor\":true}"
        );
    }

    #[test]
    fn writes_through_old_descriptor_survive_success() {
        let (root, path) = fixture();
        let (bytes, id) = before(&path);
        let mut writer = fs::OpenOptions::new()
            .write(true)
            .share_mode(7)
            .open(&path)
            .unwrap();
        let record = stage_publication(&path, &bytes, id, b"{\"proposed\":true}").unwrap();
        replace_record(&record).unwrap();
        finish(&record).unwrap();
        writer.write_all(b"late external write").unwrap();
        writer.sync_all().unwrap();
        let displaced =
            read_private(&root.path().join(&record.archive).join("displaced.json")).unwrap();
        assert!(displaced.starts_with(b"late external write"));
    }

    #[test]
    fn post_publication_edit_retains_journal_and_live_bytes() {
        let (_root, path) = fixture();
        let (bytes, id) = before(&path);
        let record = stage_publication(&path, &bytes, id, b"{\"proposed\":true}").unwrap();
        replace_record(&record).unwrap();
        fs::write(&path, b"{\"later\":true}").unwrap();
        assert!(finish(&record).is_err());
        assert_eq!(fs::read(path).unwrap(), b"{\"later\":true}");
    }

    #[test]
    fn failed_native_replacement_keeps_recovery_versions() {
        let (root, path) = fixture();
        let (bytes, id) = before(&path);
        let record = stage_publication(&path, &bytes, id, b"{\"proposed\":true}").unwrap();
        let held = fs::OpenOptions::new()
            .read(true)
            .share_mode(1)
            .open(&path)
            .unwrap();
        assert!(replace_record(&record).is_err());
        assert!(journal_path(&path).unwrap().is_file());
        assert_eq!(
            read_private(&root.path().join(&record.archive).join("snapshot.json")).unwrap(),
            bytes
        );
        drop(held);
        recover(&path, true).unwrap();
        assert_eq!(read_private(&path).unwrap(), bytes);
    }

    #[test]
    fn hardlink_and_nonregular_input_are_refused() {
        let (root, path) = fixture();
        fs::hard_link(&path, root.path().join("alias.json")).unwrap();
        assert!(ConfigFile::read(&path).is_err());
        assert!(ConfigFile::read(root.path()).is_err());
    }

    #[test]
    fn unsafe_acl_is_refused_without_repair() {
        let (_root, path) = fixture();
        let result =
            std::process::Command::new(system_root().unwrap().join("System32").join("icacls.exe"))
                .arg(&path)
                .args(["/grant", "*S-1-1-0:R"])
                .output()
                .unwrap();
        assert!(result.status.success());
        assert!(ConfigFile::read(&path).is_err());
        let after =
            std::process::Command::new(system_root().unwrap().join("System32").join("icacls.exe"))
                .arg(path)
                .output()
                .unwrap();
        assert!(String::from_utf8_lossy(&after.stdout).contains("(R)"));
    }

    #[test]
    fn ancestor_junction_and_path_aliases_are_refused() {
        let (root, path) = fixture();
        for text in [
            "relative.json",
            r"\\localhost\share\file",
            r"C:relative",
            r"C:\path\..\file",
            r"C:\NUL",
            r"C:\file:stream",
        ] {
            assert!(parent(Path::new(text)).is_err());
        }
        let alias = root.path().join("junction");
        let result =
            std::process::Command::new(system_root().unwrap().join("System32").join("cmd.exe"))
                .args(["/d", "/c", "mklink", "/J"])
                .arg(&alias)
                .arg(root.path())
                .output()
                .unwrap();
        assert!(result.status.success());
        assert!(ConfigFile::read(&alias.join(path.file_name().unwrap())).is_err());
        fs::remove_dir(alias).unwrap();
    }

    #[test]
    fn concurrent_operations_are_refused_and_lock_releases() {
        let (_root, path) = fixture();
        let first = lock(&path).unwrap();
        assert!(lock(&path).is_err());
        drop(first);
        assert!(lock(&path).is_ok());
    }

    #[test]
    fn crash_child() {
        let Ok(path) = std::env::var("SOUP_CONNECTION_CRASH_PATH") else {
            return;
        };
        let path = PathBuf::from(path);
        let (bytes, id) = before(&path);
        let record = stage_publication(&path, &bytes, id, b"{\"proposed\":true}").unwrap();
        if std::env::var("SOUP_CONNECTION_CRASH_PHASE").as_deref() == Ok("after") {
            replace_record(&record).unwrap();
        }
        std::process::exit(86);
    }

    #[test]
    fn process_interruption_recovers_only_exact_states() {
        for phase in ["before", "after"] {
            let (_root, path) = fixture();
            let initial = read_private(&path).unwrap();
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "mcp::connection::windows::tests::crash_child",
                    "--nocapture",
                ])
                .env("SOUP_CONNECTION_CRASH_PATH", &path)
                .env("SOUP_CONNECTION_CRASH_PHASE", phase)
                .output()
                .unwrap();
            assert_eq!(output.status.code(), Some(86), "{:?}", output);
            assert!(recover(&path, false).is_err());
            recover(&path, true).unwrap();
            assert_eq!(
                read_private(&path).unwrap(),
                if phase == "before" {
                    initial
                } else {
                    b"{\"proposed\":true}".to_vec()
                }
            );
            assert!(!journal_path(&path).unwrap().exists());
        }
    }
}
