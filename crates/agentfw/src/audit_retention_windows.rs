// SPDX-License-Identifier: Apache-2.0
//! Native Windows retained audit store. Scope is a directly mapped local NTFS
//! volume, an owner-created protected DACL, and one exclusive writer.

use super::RetentionConfig;
use crate::private_file_windows::{verify_retention_security, PrivateAcl};
use crate::windows_read::CreateParent;
use anyhow::{anyhow, bail, ensure, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::path::Path;
use std::ptr::null_mut;
use windows_sys::Win32::Foundation::{
    ERROR_ALREADY_EXISTS, ERROR_FILE_EXISTS, ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND,
    GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateDirectoryW, CreateFileW, FileBasicInfo, FileDispositionInfo, FileIdInfo,
    FileStandardInfo, GetFileInformationByHandleEx, SetFileInformationByHandle, CREATE_NEW, DELETE,
    FILE_ATTRIBUTE_NORMAL, FILE_BASIC_INFO, FILE_FLAG_BACKUP_SEMANTICS,
    FILE_FLAG_OPEN_REPARSE_POINT, FILE_ID_INFO, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE,
    FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_STANDARD_INFO, FILE_TRAVERSE, OPEN_EXISTING,
    READ_CONTROL,
};

const MANIFEST: &str = "manifest.json";
const PENDING: &str = "manifest.pending";
const LOCK: &str = "writer.lock";
const MAX_MANIFEST: usize = 64 * 1024;

#[repr(C)]
#[derive(Default)]
struct IoStatusBlock {
    status_or_pointer: usize,
    information: usize,
}

#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtSetInformationFile(
        handle: HANDLE,
        status: *mut IoStatusBlock,
        information: *const std::ffi::c_void,
        length: u32,
        class: u32,
    ) -> i32;
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Segment {
    id: u64,
    closed: bool,
    bytes: u64,
    sha256: Option<String>,
    partial_tail: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    version: u8,
    limits: ManifestLimits,
    generation: u64,
    next_id: u64,
    pruned_through: u64,
    pending_prune: Option<u64>,
    segments: Vec<Segment>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestLimits {
    segment_size_bytes: u64,
    segment_count: usize,
    total_disk_bytes: u64,
    max_record_bytes: usize,
}

impl From<&RetentionConfig> for ManifestLimits {
    fn from(c: &RetentionConfig) -> Self {
        Self {
            segment_size_bytes: c.segment_size_bytes,
            segment_count: c.segment_count,
            total_disk_bytes: c.total_disk_bytes,
            max_record_bytes: c.max_record_bytes,
        }
    }
}

impl Manifest {
    fn validate(&self, c: &RetentionConfig) -> Result<()> {
        ensure!(
            self.version == 1 && self.generation > 0,
            "audit manifest is corrupt"
        );
        ensure!(
            self.limits.segment_size_bytes == c.segment_size_bytes
                && self.limits.segment_count == c.segment_count
                && self.limits.total_disk_bytes == c.total_disk_bytes
                && self.limits.max_record_bytes == c.max_record_bytes,
            "audit retention limits differ from the owned manifest"
        );
        ensure!(
            !self.segments.is_empty() && self.segments.len() <= c.segment_count,
            "audit manifest is corrupt"
        );
        let mut previous = self.pruned_through;
        for (index, segment) in self.segments.iter().enumerate() {
            ensure!(
                segment.id
                    == previous
                        .checked_add(1)
                        .ok_or_else(|| anyhow!("audit id overflow"))?
                    && segment.id < self.next_id
                    && segment.bytes <= c.segment_size_bytes,
                "audit segment order or size is corrupt"
            );
            ensure!(
                segment.closed == segment.sha256.is_some(),
                "audit manifest is corrupt"
            );
            ensure!(
                segment.closed || (!segment.partial_tail && index + 1 == self.segments.len()),
                "audit manifest is corrupt"
            );
            if let Some(hash) = &segment.sha256 {
                ensure!(
                    hash.len() == 64
                        && hash
                            .bytes()
                            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
                    "audit manifest is corrupt"
                );
            }
            previous = segment.id;
        }
        ensure!(
            self.next_id
                == previous
                    .checked_add(1)
                    .ok_or_else(|| anyhow!("audit id overflow"))?,
            "audit manifest is corrupt"
        );
        if let Some(id) = self.pending_prune {
            ensure!(
                self.segments.len() == c.segment_count
                    && self.segments[0].id == id
                    && self.segments[0].closed,
                "audit manifest is corrupt"
            );
        }
        Ok(())
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct Identity(u64, [u8; 16]);

fn identity(file: &File, directory: bool) -> Result<Identity> {
    let handle = file.as_raw_handle() as HANDLE;
    verify_retention_security(handle, directory)?;
    let mut id = FILE_ID_INFO::default();
    let mut standard = FILE_STANDARD_INFO::default();
    ensure!(
        unsafe {
            GetFileInformationByHandleEx(
                handle,
                FileIdInfo,
                (&mut id as *mut FILE_ID_INFO).cast(),
                std::mem::size_of::<FILE_ID_INFO>() as u32,
            )
        } != 0,
        "audit file identity unavailable"
    );
    ensure!(
        unsafe {
            GetFileInformationByHandleEx(
                handle,
                FileStandardInfo,
                (&mut standard as *mut FILE_STANDARD_INFO).cast(),
                std::mem::size_of::<FILE_STANDARD_INFO>() as u32,
            )
        } != 0,
        "audit file metadata unavailable"
    );
    ensure!(
        directory || standard.NumberOfLinks == 1,
        "audit owned file has a hard link"
    );
    ensure!(
        !standard.DeletePending,
        "audit owned object is pending deletion"
    );
    Ok(Identity(id.VolumeSerialNumber, id.FileId.Identifier))
}

fn wide(path: &Path) -> Result<Vec<u16>> {
    let units: Vec<u16> = path.as_os_str().encode_wide().collect();
    ensure!(!units.contains(&0), "audit path contains NUL");
    Ok(units.into_iter().chain(Some(0)).collect())
}

fn open_file_with(path: &Path, create: bool, access: u32, share: u32) -> Result<Option<File>> {
    let name = wide(path)?;
    let acl = PrivateAcl::new()?;
    let attrs = acl.attributes();
    let raw = unsafe {
        CreateFileW(
            name.as_ptr(),
            access,
            share,
            if create { &attrs } else { null_mut() },
            if create { CREATE_NEW } else { OPEN_EXISTING },
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
            null_mut(),
        )
    };
    if raw == INVALID_HANDLE_VALUE {
        let error = std::io::Error::last_os_error();
        if !create
            && matches!(error.raw_os_error(), Some(code) if code == ERROR_FILE_NOT_FOUND as i32 || code == ERROR_PATH_NOT_FOUND as i32)
        {
            return Ok(None);
        }
        if create
            && matches!(error.raw_os_error(), Some(code) if code == ERROR_ALREADY_EXISTS as i32 || code == ERROR_FILE_EXISTS as i32)
        {
            bail!("audit owned file already exists");
        }
        return Err(error).context("audit owned file could not be opened");
    }
    // SAFETY: CreateFileW returned a new owned handle.
    let file = unsafe { File::from_raw_handle(raw) };
    identity(&file, false)?;
    Ok(Some(file))
}

fn open_file(path: &Path, create: bool, exclusive: bool) -> Result<Option<File>> {
    open_file_with(
        path,
        create,
        GENERIC_READ | GENERIC_WRITE | DELETE | READ_CONTROL,
        if exclusive {
            0
        } else {
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE
        },
    )
}

struct OwnedDir {
    parent: CreateParent,
    store: CreateParent,
    directory: File,
    path: std::path::PathBuf,
    id: Identity,
}

impl OwnedDir {
    fn open(path: &Path) -> Result<Self> {
        ensure!(path.is_absolute(), "audit directory must be absolute");
        let parent_path = path.parent().context("audit directory needs a parent")?;
        let parent = CreateParent::prepare_connection(parent_path, parent_path)
            .context("audit parent traversal failed")?;
        parent
            .revalidate()
            .context("audit parent revalidation failed")?;
        if !path.exists() {
            let acl = PrivateAcl::for_directory()?;
            let attributes = acl.attributes();
            let units = wide(path)?;
            ensure!(
                unsafe { CreateDirectoryW(units.as_ptr(), &attributes) } != 0,
                "audit private directory could not be created"
            );
        }
        let store =
            CreateParent::prepare_connection(path, path).context("audit store traversal failed")?;
        store
            .revalidate()
            .context("audit store revalidation failed")?;
        let units = wide(path)?;
        let raw = unsafe {
            CreateFileW(
                units.as_ptr(),
                READ_CONTROL | FILE_READ_ATTRIBUTES | FILE_TRAVERSE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                null_mut(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                null_mut(),
            )
        };
        ensure!(
            raw != INVALID_HANDLE_VALUE,
            "audit store security handle unavailable"
        );
        let directory = unsafe { File::from_raw_handle(raw) };
        let id = identity(&directory, true).context("audit store private ACL validation failed")?;
        ensure!(
            (id.0, id.1) == store.identity(),
            "audit directory identity changed"
        );
        let owned = Self {
            parent,
            store,
            directory,
            path: path.to_owned(),
            id,
        };
        owned.check()?;
        Ok(owned)
    }

    fn check(&self) -> Result<()> {
        self.parent.revalidate()?;
        self.store.revalidate()?;
        ensure!(
            identity(&self.directory, true)? == self.id,
            "audit directory was replaced"
        );
        Ok(())
    }

    fn path(&self, name: &str) -> std::path::PathBuf {
        self.path.join(name)
    }

    fn existing(&self, name: &str) -> Result<Option<File>> {
        self.check()?;
        let file = open_file(&self.path(name), false, false)?;
        if let Some(file) = &file {
            self.check_named(name, file)?;
        }
        Ok(file)
    }

    fn read_existing(&self, name: &str) -> Result<Option<File>> {
        self.check()?;
        let file = open_file_with(
            &self.path(name),
            false,
            GENERIC_READ | READ_CONTROL,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        )?;
        if let Some(file) = &file {
            self.check_named(name, file)?;
        }
        Ok(file)
    }

    fn create_active(&self, name: &str) -> Result<File> {
        self.check()?;
        let file = open_file_with(
            &self.path(name),
            true,
            GENERIC_READ | GENERIC_WRITE | READ_CONTROL,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
        )?
        .context("audit active segment create returned no file")?;
        self.check_named(name, &file)?;
        Ok(file)
    }

    fn create(&self, name: &str) -> Result<File> {
        self.check()?;
        let file =
            open_file(&self.path(name), true, false)?.context("audit create returned no file")?;
        self.check_named(name, &file)?;
        Ok(file)
    }

    fn create_for_rename(&self, name: &str) -> Result<File> {
        self.check()?;
        let file = open_file_with(
            &self.path(name),
            true,
            GENERIC_READ | GENERIC_WRITE | DELETE | READ_CONTROL,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
        )?
        .context("audit pending file create returned no file")?;
        self.check_named(name, &file)?;
        Ok(file)
    }

    fn pin_delete(&self, name: &str, provisional: File) -> Result<File> {
        let original = identity(&provisional, false)?;
        let pinned = open_file_with(
            &self.path(name),
            false,
            GENERIC_READ | GENERIC_WRITE | DELETE | READ_CONTROL,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
        )?
        .context("audit owned file disappeared before mutation")?;
        ensure!(
            identity(&pinned, false)? == original,
            "audit owned file was replaced before mutation"
        );
        drop(provisional);
        Ok(pinned)
    }

    fn delete_owned(&self, name: &str) -> Result<Option<File>> {
        self.read_existing(name)?
            .map(|file| self.pin_delete(name, file))
            .transpose()
    }

    fn check_named(&self, name: &str, held: &File) -> Result<()> {
        self.check()?;
        let held_id = identity(held, false)?;
        let named = open_file_with(
            &self.path(name),
            false,
            GENERIC_READ | READ_CONTROL,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        )?
        .context("audit owned file disappeared")?;
        ensure!(
            identity(&named, false)? == held_id,
            "audit owned file was replaced"
        );
        Ok(())
    }

    fn pin_active(&self, name: &str, provisional: File) -> Result<File> {
        let original = identity(&provisional, false)?;
        let pinned = open_file_with(
            &self.path(name),
            false,
            GENERIC_READ | GENERIC_WRITE | READ_CONTROL,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
        )?
        .context("audit active segment disappeared")?;
        ensure!(
            identity(&pinned, false)? == original,
            "audit active segment was replaced"
        );
        drop(provisional);
        Ok(pinned)
    }

    fn prune(&self, name: &str, file: &File) -> Result<()> {
        self.check_named(name, file)?;
        let disposition =
            windows_sys::Win32::Storage::FileSystem::FILE_DISPOSITION_INFO { DeleteFile: true };
        ensure!(
            unsafe {
                SetFileInformationByHandle(
                    file.as_raw_handle() as HANDLE,
                    FileDispositionInfo,
                    (&disposition
                        as *const windows_sys::Win32::Storage::FileSystem::FILE_DISPOSITION_INFO)
                        .cast(),
                    std::mem::size_of_val(&disposition) as u32,
                )
            } != 0,
            "audit owned segment could not be pruned"
        );
        Ok(())
    }

    fn rename_pending(&self, pending: &File) -> Result<()> {
        self.check_named(PENDING, pending)?;
        let target: Vec<u16> = MANIFEST.encode_utf16().collect();
        let length =
            std::mem::size_of::<windows_sys::Win32::Storage::FileSystem::FILE_RENAME_INFO>()
                + 2 * target.len();
        let mut storage = vec![0usize; length.div_ceil(std::mem::size_of::<usize>())];
        let info = storage
            .as_mut_ptr()
            .cast::<windows_sys::Win32::Storage::FileSystem::FILE_RENAME_INFO>();
        let mut status = IoStatusBlock::default();
        // SAFETY: the aligned allocation has room for the header and UTF-16 target.
        unsafe {
            (*info).Anonymous.ReplaceIfExists = true;
            (*info).RootDirectory = self.directory.as_raw_handle() as HANDLE;
            (*info).FileNameLength = (target.len() * 2) as u32;
            std::ptr::copy_nonoverlapping(
                target.as_ptr(),
                (*info).FileName.as_mut_ptr(),
                target.len(),
            );
            // The Win32 wrapper rejects a relative name with RootDirectory on
            // some supported Windows releases. NtSetInformationFile retains the
            // destination directory handle as the actual namespace authority.
            let code = NtSetInformationFile(
                pending.as_raw_handle() as HANDLE,
                &mut status,
                info.cast(),
                length as u32,
                10,
            );
            ensure!(
                code >= 0,
                "audit manifest publication failed (NTSTATUS {code:#x})"
            );
        }
        self.check_named(MANIFEST, pending)?;
        Ok(())
    }
}

fn segment_name(id: u64) -> String {
    format!("segment-{id:020}.jsonl")
}

fn read_manifest(dir: &OwnedDir, name: &str) -> Result<Option<Manifest>> {
    let Some(mut file) = dir.existing(name)? else {
        return Ok(None);
    };
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take((MAX_MANIFEST + 1) as u64)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= MAX_MANIFEST, "audit manifest exceeds limit");
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|_| anyhow!("audit manifest is corrupt"))
}

fn publish(dir: &OwnedDir, manifest: &mut Manifest) -> Result<()> {
    ensure!(
        dir.existing(PENDING)?.is_none(),
        "audit pending manifest requires recovery"
    );
    manifest.generation = manifest
        .generation
        .checked_add(1)
        .context("audit generation exhausted")?;
    let bytes = serde_json::to_vec(manifest)?;
    ensure!(bytes.len() <= MAX_MANIFEST, "audit manifest exceeds limit");
    let mut pending = dir.create_for_rename(PENDING)?;
    pending
        .write_all(&bytes)
        .context("audit manifest write failed")?;
    pending.sync_all().context("audit manifest flush failed")?;
    dir.rename_pending(&pending)?;
    Ok(())
}

fn load_or_create(dir: &OwnedDir, c: &RetentionConfig) -> Result<Manifest> {
    let mut current = read_manifest(dir, MANIFEST)?;
    if let Some(pending) = read_manifest(dir, PENDING)? {
        pending.validate(c)?;
        let expected = current
            .as_ref()
            .map(|m| {
                m.generation
                    .checked_add(1)
                    .ok_or_else(|| anyhow!("audit generation exhausted"))
            })
            .transpose()?
            .unwrap_or(1);
        ensure!(
            pending.generation == expected,
            "audit pending manifest order is corrupt"
        );
        let file = dir
            .delete_owned(PENDING)?
            .context("audit pending manifest disappeared")?;
        dir.rename_pending(&file)?;
        current = Some(pending);
    }
    let manifest = if let Some(current) = current {
        current
    } else {
        ensure!(
            dir.read_existing(&segment_name(1))?.is_none(),
            "unowned initial audit segment name already exists"
        );
        let initial = Manifest {
            version: 1,
            limits: ManifestLimits::from(c),
            generation: 1,
            next_id: 2,
            pruned_through: 0,
            pending_prune: None,
            segments: vec![Segment {
                id: 1,
                closed: false,
                bytes: 0,
                sha256: None,
                partial_tail: false,
            }],
        };
        let mut file = dir.create(MANIFEST)?;
        file.write_all(&serde_json::to_vec(&initial)?)?;
        file.sync_all()?;
        initial
    };
    manifest.validate(c)?;
    Ok(manifest)
}

fn scan(file: &mut File, max: u64, line_max: usize) -> Result<(u64, String, bool)> {
    file.seek(SeekFrom::Start(0))?;
    let mut bytes = Vec::new();
    file.take(max + 1)
        .read_to_end(&mut bytes)
        .context("audit segment unreadable")?;
    ensure!(
        bytes.len() as u64 <= max,
        "audit segment exceeds configured limit"
    );
    let mut start = 0;
    for (index, byte) in bytes.iter().enumerate() {
        if *byte == b'\n' {
            ensure!(
                index + 1 - start <= line_max,
                "audit record exceeds configured limit"
            );
            serde_json::from_slice::<serde_json::Value>(&bytes[start..index])
                .map_err(|_| anyhow!("audit segment contains a corrupt record"))?;
            start = index + 1;
        }
    }
    let partial = start < bytes.len();
    if partial {
        ensure!(
            bytes.len() - start <= line_max,
            "audit partial record exceeds configured limit"
        );
    }
    Ok((
        bytes.len() as u64,
        format!("{:x}", Sha256::digest(&bytes)),
        partial,
    ))
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct ClosedIdentity {
    id: Identity,
    last_write_time: i64,
    change_time: i64,
}

fn closed_identity(file: &File) -> Result<ClosedIdentity> {
    let id = identity(file, false)?;
    let mut basic = FILE_BASIC_INFO::default();
    ensure!(
        unsafe {
            GetFileInformationByHandleEx(
                file.as_raw_handle() as HANDLE,
                FileBasicInfo,
                (&mut basic as *mut FILE_BASIC_INFO).cast(),
                std::mem::size_of::<FILE_BASIC_INFO>() as u32,
            )
        } != 0,
        "audit closed segment metadata unavailable"
    );
    Ok(ClosedIdentity {
        id,
        last_write_time: basic.LastWriteTime,
        change_time: basic.ChangeTime,
    })
}

fn closed_inventory(dir: &OwnedDir, manifest: &Manifest) -> Result<Vec<(u64, ClosedIdentity)>> {
    let mut inventory = Vec::with_capacity(manifest.segments.len());
    for segment in &manifest.segments {
        if segment.closed {
            let file = dir
                .read_existing(&segment_name(segment.id))?
                .context("audit closed segment is missing")?;
            ensure!(
                file.metadata()?.len() == segment.bytes,
                "audit closed segment size changed"
            );
            inventory.push((segment.id, closed_identity(&file)?));
        }
    }
    Ok(inventory)
}

struct LimitedWriter {
    bytes: Vec<u8>,
    max: usize,
}

impl Write for LimitedWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > self.max.saturating_sub(self.bytes.len()) {
            return Err(std::io::Error::other(
                "audit record exceeds configured limit",
            ));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

pub(super) struct RetainedSink {
    dir: OwnedDir,
    config: RetentionConfig,
    manifest: Manifest,
    lock: File,
    active: File,
    active_bytes: u64,
    manifest_identity: Identity,
    closed_identities: Vec<(u64, ClosedIdentity)>,
    failed: bool,
    #[cfg(test)]
    fail_after_bytes: Option<usize>,
    #[cfg(test)]
    fail_errno: Option<i32>,
}

impl RetainedSink {
    pub(super) fn open(config: &RetentionConfig, recover: bool) -> Result<Self> {
        config.validate()?;
        let dir = OwnedDir::open(&config.directory)?;
        // The lock handle permits no sharing. A second writer fails before it can
        // inspect or modify the manifest. Creation is CREATE_NEW with a private ACL.
        let lock = if dir.existing(LOCK)?.is_some() {
            open_file(&dir.path(LOCK), false, true)?.context("audit writer lock disappeared")?
        } else {
            open_file(&dir.path(LOCK), true, true)?.context("audit writer lock create failed")?
        };
        identity(&lock, false)?;
        ensure!(lock.metadata()?.len() == 0, "audit writer lock is unsafe");
        let mut manifest = load_or_create(&dir, config)?;
        if let Some(id) = manifest.pending_prune {
            let name = segment_name(id);
            if let Some(mut file) = dir.delete_owned(&name)? {
                let segment = &manifest.segments[0];
                let (bytes, digest, partial) = scan(
                    &mut file,
                    config.segment_size_bytes,
                    config.max_record_bytes,
                )?;
                ensure!(
                    bytes == segment.bytes
                        && Some(&digest) == segment.sha256.as_ref()
                        && partial == segment.partial_tail,
                    "audit segment changed before prune"
                );
                dir.prune(&name, &file)?;
            }
            manifest.segments.remove(0);
            manifest.pruned_through = id;
            manifest.pending_prune = None;
            publish(&dir, &mut manifest)?;
        }
        for segment in &manifest.segments {
            let name = segment_name(segment.id);
            let mut file = match dir.existing(&name)? {
                Some(file) => file,
                None if !segment.closed && segment.bytes == 0 => dir.create(&name)?,
                None => bail!("audit retained segment is missing"),
            };
            let (bytes, digest, partial) = scan(
                &mut file,
                config.segment_size_bytes,
                config.max_record_bytes,
            )?;
            if segment.closed {
                ensure!(
                    bytes == segment.bytes
                        && Some(&digest) == segment.sha256.as_ref()
                        && partial == segment.partial_tail,
                    "audit closed segment is corrupt"
                );
            } else if partial && !recover {
                bail!("audit active segment has an incomplete tail; run audit-retention recover");
            }
        }
        let last = manifest
            .segments
            .last()
            .context("audit manifest is empty")?;
        let active = if last.closed {
            Self::reserve_next(&dir, config, &mut manifest)?
        } else {
            let name = segment_name(last.id);
            let file = dir
                .read_existing(&name)?
                .context("audit active segment missing")?;
            dir.pin_active(&name, file)?
        };
        let active_bytes = active.metadata()?.len();
        let manifest_file = dir.existing(MANIFEST)?.context("audit manifest missing")?;
        let manifest_identity = identity(&manifest_file, false)?;
        drop(manifest_file);
        let closed_identities = closed_inventory(&dir, &manifest)?;
        let mut sink = Self {
            dir,
            config: config.clone(),
            manifest,
            lock,
            active,
            active_bytes,
            manifest_identity,
            closed_identities,
            failed: false,
            #[cfg(test)]
            fail_after_bytes: None,
            #[cfg(test)]
            fail_errno: None,
        };
        if recover {
            let mut checked = sink.active.try_clone()?;
            let (_, _, partial) = scan(
                &mut checked,
                config.segment_size_bytes,
                config.max_record_bytes,
            )?;
            if partial {
                sink.rotate(true)?;
            }
        }
        sink.check_active()?;
        Ok(sink)
    }

    fn reserve_next(
        dir: &OwnedDir,
        config: &RetentionConfig,
        manifest: &mut Manifest,
    ) -> Result<File> {
        let name = segment_name(manifest.next_id);
        ensure!(
            dir.read_existing(&name)?.is_none(),
            "unowned next audit segment name already exists"
        );
        if manifest.segments.len() == config.segment_count {
            let first = &manifest.segments[0];
            ensure!(
                first.closed,
                "audit retention has no closed segment to prune"
            );
            let id = first.id;
            let name = segment_name(id);
            let mut file = dir
                .delete_owned(&name)?
                .context("audit prune segment missing")?;
            let (bytes, digest, partial) = scan(
                &mut file,
                config.segment_size_bytes,
                config.max_record_bytes,
            )?;
            ensure!(
                bytes == first.bytes
                    && Some(&digest) == first.sha256.as_ref()
                    && partial == first.partial_tail,
                "audit segment changed before prune"
            );
            manifest.pending_prune = Some(id);
            publish(dir, manifest)?;
            dir.prune(&name, &file)?;
            manifest.segments.remove(0);
            manifest.pruned_through = id;
            manifest.pending_prune = None;
            publish(dir, manifest)?;
        }
        let id = manifest.next_id;
        manifest.next_id = id.checked_add(1).context("audit segment id exhausted")?;
        manifest.segments.push(Segment {
            id,
            closed: false,
            bytes: 0,
            sha256: None,
            partial_tail: false,
        });
        publish(dir, manifest)?;
        dir.create_active(&name)
    }

    fn rotate(&mut self, allow_partial: bool) -> Result<()> {
        self.check_active()?;
        self.active
            .sync_all()
            .context("audit segment flush failed")?;
        let (bytes, digest, partial) = scan(
            &mut self.active,
            self.config.segment_size_bytes,
            self.config.max_record_bytes,
        )?;
        ensure!(!partial || allow_partial, "audit active tail is incomplete");
        let last = self
            .manifest
            .segments
            .last_mut()
            .context("audit manifest is empty")?;
        last.closed = true;
        last.bytes = bytes;
        last.sha256 = Some(digest);
        last.partial_tail = partial;
        publish(&self.dir, &mut self.manifest)?;
        self.active = Self::reserve_next(&self.dir, &self.config, &mut self.manifest)?;
        self.active_bytes = 0;
        self.manifest_identity = identity(
            &self
                .dir
                .existing(MANIFEST)?
                .context("audit manifest missing")?,
            false,
        )?;
        let new_inventory = closed_inventory(&self.dir, &self.manifest)?;
        for (id, expected) in &self.closed_identities {
            if let Some((_, actual)) = new_inventory.iter().find(|(current, _)| current == id) {
                ensure!(actual == expected, "audit closed segment was replaced");
            }
        }
        self.closed_identities = new_inventory;
        Ok(())
    }

    fn check_active(&self) -> Result<()> {
        self.dir.check()?;
        identity(&self.lock, false)?;
        let mut manifest_file = self
            .dir
            .existing(MANIFEST)?
            .context("audit manifest missing")?;
        ensure!(
            identity(&manifest_file, false)? == self.manifest_identity,
            "audit manifest was replaced"
        );
        let mut bytes = Vec::new();
        Read::by_ref(&mut manifest_file)
            .take((MAX_MANIFEST + 1) as u64)
            .read_to_end(&mut bytes)?;
        ensure!(
            bytes == serde_json::to_vec(&self.manifest)?,
            "audit manifest changed outside writer"
        );
        let id = self
            .manifest
            .segments
            .last()
            .context("audit manifest is empty")?
            .id;
        self.dir.check_named(&segment_name(id), &self.active)?;
        ensure!(
            self.active.metadata()?.len() == self.active_bytes,
            "audit active segment changed outside writer"
        );
        for (id, expected) in &self.closed_identities {
            let file = self
                .dir
                .read_existing(&segment_name(*id))?
                .context("audit closed segment is missing")?;
            ensure!(
                closed_identity(&file)? == *expected,
                "audit closed segment changed"
            );
            let known = self
                .manifest
                .segments
                .iter()
                .find(|segment| segment.id == *id)
                .context("audit closed segment inventory is inconsistent")?;
            ensure!(
                file.metadata()?.len() == known.bytes,
                "audit closed segment size changed"
            );
        }
        Ok(())
    }

    pub(super) fn health(&self) -> serde_json::Value {
        let healthy = !self.failed && self.check_active().is_ok();
        serde_json::json!({"mode":"retained", "state":if healthy {"healthy"} else {"unavailable"},
            "reason":if healthy {None} else {Some("audit_unavailable")},
            "retained_segments":self.manifest.segments.len(), "pruned_through":self.manifest.pruned_through})
    }

    pub(super) fn write_serialized(&mut self, line: &impl Serialize) -> Result<()> {
        ensure!(!self.failed, "audit sink requires explicit recovery");
        let result = self.write_inner(line);
        if result.is_err() {
            self.failed = true;
        }
        result
    }

    fn write_inner(&mut self, line: &impl Serialize) -> Result<()> {
        let mut writer = LimitedWriter {
            bytes: Vec::with_capacity(1024),
            max: self.config.max_record_bytes - 1,
        };
        serde_json::to_writer(&mut writer, line)
            .map_err(|_| anyhow!("audit record exceeds configured limit or cannot serialize"))?;
        writer.bytes.push(b'\n');
        let len = writer.bytes.len() as u64;
        self.check_active()?;
        if self.active_bytes + len > self.config.segment_size_bytes {
            self.rotate(false)?;
            self.check_active()?;
        }
        #[cfg(test)]
        if let Some(bytes) = self.fail_after_bytes.take() {
            self.active.seek(SeekFrom::End(0))?;
            self.active
                .write_all(&writer.bytes[..bytes.min(writer.bytes.len())])?;
            self.active.sync_all()?;
            bail!("injected short audit write");
        }
        #[cfg(test)]
        if let Some(errno) = self.fail_errno.take() {
            return Err(std::io::Error::from_raw_os_error(errno).into());
        }
        self.active.seek(SeekFrom::End(0))?;
        self.active
            .write_all(&writer.bytes)
            .context("audit segment write failed")?;
        self.active
            .sync_all()
            .context("audit segment flush failed")?;
        self.active_bytes += len;
        Ok(())
    }

    #[cfg(test)]
    pub(super) fn inject_write_error(&mut self, errno: i32) {
        self.fail_errno = Some(errno);
    }
}

pub fn recover_retention(config: &RetentionConfig) -> Result<()> {
    let _sink = RetainedSink::open(config, true)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn config(path: &Path) -> RetentionConfig {
        RetentionConfig {
            version: 1,
            directory: path.to_owned(),
            segment_size_bytes: 64 * 1024,
            segment_count: 2,
            total_disk_bytes: 300_000,
            max_record_bytes: 1024,
        }
    }

    fn event(index: usize) -> serde_json::Value {
        json!({"at_ms":index,"session":"native-windows-test","event":"native_call",
            "verdict":"allow","seq":index,"raw":"x".repeat(700)})
    }

    #[test]
    fn rotations_prune_and_restart_within_owned_cap() {
        let root = tempfile::tempdir().unwrap();
        let c = config(&root.path().canonicalize().unwrap().join("retained"));
        let mut sink = RetainedSink::open(&c, false).unwrap();
        for index in 0..230 {
            sink.write_serialized(&event(index)).unwrap();
        }
        assert!(sink.manifest.pruned_through > 0);
        assert!(RetainedSink::open(&c, false).is_err());
        drop(sink);
        let mut reopened = RetainedSink::open(&c, false).unwrap();
        reopened.write_serialized(&event(231)).unwrap();
        let owned: u64 = std::fs::read_dir(&c.directory)
            .unwrap()
            .map(|entry| {
                let entry = entry.unwrap();
                let name = entry.file_name().to_string_lossy().into_owned();
                if matches!(name.as_str(), MANIFEST | PENDING | LOCK)
                    || name.starts_with("segment-")
                {
                    entry.metadata().unwrap().len()
                } else {
                    0
                }
            })
            .sum();
        assert!(owned <= c.total_disk_bytes, "owned bytes {owned}");
    }

    #[test]
    fn short_write_is_sticky_and_recovery_keeps_incomplete_tail() {
        let root = tempfile::tempdir().unwrap();
        let c = config(&root.path().canonicalize().unwrap().join("retained"));
        let mut sink = RetainedSink::open(&c, false).unwrap();
        sink.fail_after_bytes = Some(13);
        assert!(sink.write_serialized(&event(1)).is_err());
        assert!(sink.write_serialized(&event(2)).is_err());
        drop(sink);
        assert!(RetainedSink::open(&c, false).is_err());
        recover_retention(&c).unwrap();
        let mut reopened = RetainedSink::open(&c, false).unwrap();
        assert!(reopened.manifest.segments.iter().any(|s| s.partial_tail));
        reopened.write_serialized(&event(3)).unwrap();
    }

    #[test]
    fn unsafe_existing_directory_and_foreign_file_are_not_adopted() {
        let root = tempfile::tempdir().unwrap();
        let unsafe_dir = root.path().canonicalize().unwrap().join("unsafe");
        std::fs::create_dir(&unsafe_dir).unwrap();
        assert!(RetainedSink::open(&config(&unsafe_dir), false).is_err());
        let c = config(&root.path().canonicalize().unwrap().join("retained"));
        let mut sink = RetainedSink::open(&c, false).unwrap();
        let foreign = c.directory.join("operator-note.txt");
        std::fs::write(&foreign, "preserve").unwrap();
        for index in 0..230 {
            sink.write_serialized(&event(index)).unwrap();
        }
        assert_eq!(std::fs::read_to_string(foreign).unwrap(), "preserve");
    }

    #[test]
    fn interrupted_invalid_manifest_is_preserved_and_refused() {
        let root = tempfile::tempdir().unwrap();
        let c = config(&root.path().canonicalize().unwrap().join("retained"));
        let sink = RetainedSink::open(&c, false).unwrap();
        drop(sink);
        let original = std::fs::read(c.directory.join(MANIFEST)).unwrap();
        let dir = OwnedDir::open(&c.directory).unwrap();
        let mut pending = dir.create(PENDING).unwrap();
        pending.write_all(b"{incomplete").unwrap();
        pending.sync_all().unwrap();
        drop(pending);
        drop(dir);
        assert!(recover_retention(&c).is_err());
        assert_eq!(std::fs::read(c.directory.join(MANIFEST)).unwrap(), original);
        assert_eq!(
            std::fs::read(c.directory.join(PENDING)).unwrap(),
            b"{incomplete"
        );
    }

    #[test]
    fn active_hard_link_poison_is_sticky() {
        let root = tempfile::tempdir().unwrap();
        let c = config(&root.path().canonicalize().unwrap().join("retained"));
        let mut sink = RetainedSink::open(&c, false).unwrap();
        let active = c.directory.join(segment_name(1));
        let alias = c.directory.join("foreign-hardlink.txt");
        std::fs::hard_link(active, &alias).unwrap();
        assert!(sink.write_serialized(&event(1)).is_err());
        assert_eq!(sink.health()["state"], "unavailable");
        assert!(sink.write_serialized(&event(2)).is_err());
        assert!(alias.exists());
    }

    #[test]
    fn unowned_segment_name_is_preserved_instead_of_adopted() {
        let root = tempfile::tempdir().unwrap();
        let c = config(&root.path().canonicalize().unwrap().join("retained"));
        let dir = OwnedDir::open(&c.directory).unwrap();
        let name = segment_name(1);
        let mut foreign = dir.create(&name).unwrap();
        foreign.write_all(b"foreign\n").unwrap();
        foreign.sync_all().unwrap();
        drop(foreign);
        drop(dir);
        assert!(RetainedSink::open(&c, false).is_err());
        assert_eq!(std::fs::read(c.directory.join(name)).unwrap(), b"foreign\n");
    }

    #[test]
    fn missing_closed_segment_stops_live_writes() {
        let root = tempfile::tempdir().unwrap();
        let c = config(&root.path().canonicalize().unwrap().join("retained"));
        let mut sink = RetainedSink::open(&c, false).unwrap();
        for index in 0..100 {
            sink.write_serialized(&event(index)).unwrap();
        }
        assert!(sink.manifest.segments[0].closed);
        std::fs::remove_file(c.directory.join(segment_name(1))).unwrap();
        assert!(sink.write_serialized(&event(101)).is_err());
        assert_eq!(sink.health()["state"], "unavailable");
    }

    #[test]
    fn same_length_closed_rewrite_stops_live_writes() {
        let root = tempfile::tempdir().unwrap();
        let c = config(&root.path().canonicalize().unwrap().join("retained"));
        let mut sink = RetainedSink::open(&c, false).unwrap();
        for index in 0..100 {
            sink.write_serialized(&event(index)).unwrap();
        }
        assert!(sink.manifest.segments[0].closed);
        let mut changed = std::fs::OpenOptions::new()
            .write(true)
            .open(c.directory.join(segment_name(1)))
            .unwrap();
        changed.write_all(b"!").unwrap();
        changed.sync_all().unwrap();
        drop(changed);
        assert!(sink.write_serialized(&event(101)).is_err());
        assert_eq!(sink.health()["state"], "unavailable");
    }
}
