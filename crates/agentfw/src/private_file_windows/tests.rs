// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Arthur Lin (carbon-evolution)
use std::fs::{self, File};
use std::io::Write;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::path::Path;
use std::ptr::null_mut;

use windows_sys::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_INVALID_OWNER, ERROR_PRIVILEGE_NOT_HELD,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSecurityDescriptorToStringSecurityDescriptorW, ConvertStringSidToSidW, GetSecurityInfo,
    SetSecurityInfo, SDDL_REVISION_1, SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
};

use super::{
    current_user_sid, open_directory_handle, owner_is_trusted, owner_sid, wide_path, LocalMemory,
    PrivateAcl, FILE_READ_DATA, FILE_WRITE_DATA, READ_CONTROL, WRITE_DAC,
};
use windows_sys::Win32::Storage::FileSystem::WRITE_OWNER;

fn security_sddl(path: &Path) -> String {
    let file = File::open(path).unwrap();
    security_sddl_handle(&file)
}

fn directory_sddl(path: &Path) -> String {
    let wide = wide_path(path).unwrap();
    let raw = open_directory_handle(&wide).unwrap();
    // SAFETY: The helper returns an owned directory handle.
    let directory = unsafe { File::from_raw_handle(raw) };
    security_sddl_handle(&directory)
}

fn security_sddl_handle(file: &File) -> String {
    let mut descriptor = null_mut();
    // SAFETY: The file handle is live and the requested descriptor is
    // returned as LocalAlloc memory owned by this test.
    let code = unsafe {
        GetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
            &mut descriptor,
        )
    };
    assert_eq!(code, 0, "GetSecurityInfo failed: {code}");
    let _descriptor = LocalMemory(descriptor);
    security_sddl_descriptor(descriptor)
}

fn security_sddl_descriptor(descriptor: PSECURITY_DESCRIPTOR) -> String {
    let mut wide = null_mut();
    let mut length = 0;
    // SAFETY: The descriptor is live and output pointers are writable.
    assert_ne!(
        unsafe {
            ConvertSecurityDescriptorToStringSecurityDescriptorW(
                descriptor,
                SDDL_REVISION_1,
                DACL_SECURITY_INFORMATION,
                &mut wide,
                &mut length,
            )
        },
        0,
        "ConvertSecurityDescriptorToStringSecurityDescriptorW failed"
    );
    let _wide = LocalMemory(wide.cast());
    // SAFETY: The API returned exactly `length` UTF-16 code units.
    String::from_utf16(unsafe { std::slice::from_raw_parts(wide, length as usize) })
        .unwrap()
        .trim_end_matches('\0')
        .to_string()
}

fn assert_private(path: &Path) {
    let sddl = security_sddl(path);
    assert_private_sddl(&sddl);
    assert_eq!(sddl.matches("(A;").count(), 2, "unexpected ACE: {sddl}");
    let file = File::open(path).unwrap();
    assert_only_trusted_aces(&file);
    assert_eq!(
        owner_sid(file.as_raw_handle()).unwrap(),
        current_user_sid().unwrap()
    );
}

fn assert_private_directory(path: &Path) {
    let sddl = directory_sddl(path);
    assert_private_sddl(&sddl);
    assert!(
        sddl.matches(";OICI").count() >= 2,
        "directory inheritance missing: {sddl}"
    );
    let wide = wide_path(path).unwrap();
    let raw = open_directory_handle(&wide).unwrap();
    // SAFETY: The helper returns an owned directory handle.
    let directory = unsafe { File::from_raw_handle(raw) };
    assert_only_trusted_aces(&directory);
    assert_eq!(
        owner_sid(directory.as_raw_handle()).unwrap(),
        current_user_sid().unwrap()
    );
}

fn assert_private_sddl(sddl: &str) {
    assert!(sddl.starts_with("D:P"), "DACL must be protected: {sddl}");
}

fn ace_trustees(sddl: &str) -> Vec<&str> {
    let dacl = sddl.strip_prefix("D:").expect("missing DACL");
    let first_ace = dacl.find('(').expect("DACL must contain ACEs");
    assert!(
        matches!(&dacl[..first_ace], "" | "P" | "AI" | "PAI"),
        "unexpected DACL control flags: {sddl}"
    );
    let mut remaining = &dacl[first_ace..];
    let mut trustees = Vec::new();
    while !remaining.is_empty() {
        let ace = remaining.strip_prefix('(').expect("invalid ACE opening");
        let (fields, rest) = ace.split_once(')').expect("invalid ACE closing");
        let fields: Vec<_> = fields.split(';').collect();
        assert_eq!(fields.len(), 6, "unexpected ACE fields: {sddl}");
        assert_eq!(fields[0], "A", "unexpected ACE type: {sddl}");
        assert!(!fields[5].is_empty(), "ACE has no trustee: {sddl}");
        trustees.push(fields[5]);
        remaining = rest;
    }
    trustees
}

fn assert_only_trusted_aces(file: &File) {
    let user = current_user_sid().unwrap();
    // Let Windows canonicalize SID aliases (notably LA for the built-in
    // Administrator) before comparing trustees. Windows can also map GA
    // to FA and split inheritable directory ACEs during file creation.
    let expected = PrivateAcl::from_sddl(&format!("D:P(A;;GA;;;{user})(A;;GA;;;SY)")).unwrap();
    let expected_sddl = security_sddl_descriptor(expected.descriptor.0);
    let expected_trustees = ace_trustees(&expected_sddl);
    let actual_sddl = security_sddl_handle(file);
    let actual_trustees = ace_trustees(&actual_sddl);
    for trustee in &actual_trustees {
        assert!(
            expected_trustees.contains(trustee),
            "unexpected ACL trustee {trustee}: {actual_sddl}"
        );
    }
    for trustee in &expected_trustees {
        assert!(
            actual_trustees.contains(trustee),
            "missing ACL trustee {trustee}: {actual_sddl}"
        );
    }
}

fn make_world_readable(path: &Path, contents: &str) {
    // Create with the tested user's owner SID even when the runner's
    // default owner is the Administrators group.
    let mut file = super::open_token(path).unwrap();
    file.write_all(contents.as_bytes()).unwrap();
    let loose = PrivateAcl::from_sddl("D:P(A;;GA;;;WD)").unwrap();
    loose.apply(file.as_raw_handle()).unwrap();
    assert!(security_sddl(path).contains(";;;WD)"));
}

#[test]
fn new_token_and_audit_files_have_protected_owner_only_acls() {
    let dir = tempfile::tempdir().unwrap();
    let token = dir.path().join("token");
    let audit = dir.path().join("audit.jsonl");
    crate::token::load_or_create(&token).unwrap();
    let _sink = crate::audit::AuditSink::open(&audit).unwrap();
    assert_private(&token);
    assert_private(&audit);
}

#[test]
fn existing_loose_files_are_secured_without_losing_data() {
    let dir = tempfile::tempdir().unwrap();
    let token = dir.path().join("token");
    let audit = dir.path().join("audit.jsonl");
    make_world_readable(&token, "old-token\n");
    make_world_readable(&audit, "old-audit\n");

    assert_eq!(crate::token::load_or_create(&token).unwrap(), "old-token");
    let _sink = crate::audit::AuditSink::open(&audit).unwrap();
    assert_eq!(fs::read_to_string(&audit).unwrap(), "old-audit\n");
    assert_private(&token);
    assert_private(&audit);
}

#[test]
fn token_path_does_not_follow_a_file_symlink() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("target");
    let link = dir.path().join("token-link");
    fs::write(&target, "target-data").unwrap();
    match std::os::windows::fs::symlink_file(&target, &link) {
        Ok(()) => {}
        // Creating symlinks requires Developer Mode or SeCreateSymbolicLinkPrivilege
        // on some Windows hosts. The ACL tests above still run there.
        Err(error) if error.raw_os_error() == Some(1314) => {
            eprintln!("symlink privilege unavailable; reparse test skipped");
            return;
        }
        Err(error) => panic!("cannot create test symlink: {error}"),
    }
    assert!(crate::token::load_or_create(&link).is_err());
    assert_eq!(fs::read_to_string(&target).unwrap(), "target-data");
}

#[test]
fn inaccessible_existing_token_fails_without_overwriting_it() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("token");
    let mut file = super::open_token(&path).unwrap();
    file.write_all(b"keep-me").unwrap();
    let user = current_user_sid().unwrap();
    let narrow = PrivateAcl::from_sddl(&format!("D:P(A;;RCWD;;;{user})(A;;GA;;;SY)")).unwrap();
    narrow.apply(file.as_raw_handle()).unwrap();

    assert!(crate::token::load_or_create(&path).is_err());

    // The already-open owner handle can restore the ACL for inspection and
    // cleanup; the denied open above must not have rewritten the token.
    PrivateAcl::new()
        .unwrap()
        .apply(file.as_raw_handle())
        .unwrap();
    assert_eq!(fs::read_to_string(&path).unwrap(), "keep-me");
}

#[test]
fn new_agent_home_has_protected_inheritable_acl() {
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join(".agentfw");
    super::ensure_private_directory(&home).unwrap();
    assert_private_directory(&home);

    // Files created by other Agent stores inherit a private ACL too.
    let child = home.join("grant.json");
    fs::write(&child, "grant").unwrap();
    assert_only_trusted_aces(&File::open(&child).unwrap());
}

#[test]
fn existing_loose_agent_home_is_tightened_before_use() {
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join(".agentfw");
    // Windows may otherwise assign BUILTIN\Administrators as the owner
    // when this test runs under an elevated account.
    super::ensure_private_directory(&home).unwrap();
    fs::write(home.join("existing"), "keep").unwrap();
    let wide = wide_path(&home).unwrap();
    let raw = open_directory_handle(&wide).unwrap();
    // SAFETY: The helper returns an owned directory handle.
    let directory = unsafe { File::from_raw_handle(raw) };
    PrivateAcl::from_sddl("D:P(A;OICI;GA;;;WD)")
        .unwrap()
        .apply(directory.as_raw_handle())
        .unwrap();
    drop(directory);
    assert!(directory_sddl(&home).contains(";;;WD)"));

    super::ensure_private_directory(&home).unwrap();
    assert_private_directory(&home);
    assert_eq!(fs::read_to_string(home.join("existing")).unwrap(), "keep");
}

#[test]
fn agent_home_does_not_follow_a_directory_symlink() {
    let root = tempfile::tempdir().unwrap();
    let target = root.path().join("target");
    let link = root.path().join(".agentfw");
    fs::create_dir(&target).unwrap();
    match std::os::windows::fs::symlink_dir(&target, &link) {
        Ok(()) => {}
        Err(error) if error.raw_os_error() == Some(1314) => {
            eprintln!("symlink privilege unavailable; reparse test skipped");
            return;
        }
        Err(error) => panic!("cannot create test symlink: {error}"),
    }
    assert!(super::ensure_private_directory(&link).is_err());
    assert!(target.is_dir());
}

#[test]
fn owner_policy_rejects_foreign_sids() {
    let user = current_user_sid().unwrap();
    assert!(owner_is_trusted(&user, &user));
    assert!(owner_is_trusted("S-1-5-18", &user));
    assert!(!owner_is_trusted("S-1-5-32-544", &user));
    assert!(!owner_is_trusted("S-1-1-0", &user));
}

#[test]
fn foreign_owned_existing_token_is_rejected_when_fixture_is_available() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("token");
    crate::token::load_or_create(&path).unwrap();
    let file = fs::OpenOptions::new()
        .read(true)
        .access_mode(FILE_READ_DATA | FILE_WRITE_DATA | READ_CONTROL | WRITE_DAC | WRITE_OWNER)
        .open(&path)
        .unwrap();
    let administrator = wide_sid("S-1-5-32-544");
    let mut administrator_sid: PSID = null_mut();
    // SAFETY: The SDDL text is NUL-terminated and the SID output is writable.
    assert_ne!(
        unsafe { ConvertStringSidToSidW(administrator.as_ptr(), &mut administrator_sid) },
        0
    );
    let _administrator_sid = LocalMemory(administrator_sid);
    // SAFETY: This test handle has WRITE_OWNER; the SID buffer remains live.
    let code = unsafe {
        SetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            administrator_sid,
            null_mut(),
            std::ptr::null(),
            std::ptr::null(),
        )
    };
    if matches!(
        code,
        ERROR_ACCESS_DENIED | ERROR_INVALID_OWNER | ERROR_PRIVILEGE_NOT_HELD
    ) {
        eprintln!("foreign-owner fixture unavailable on this Windows account");
        return;
    }
    assert_eq!(code, 0, "cannot set foreign owner: {code}");
    assert_eq!(owner_sid(file.as_raw_handle()).unwrap(), "S-1-5-32-544");
    let error = crate::token::load_or_create(&path).unwrap_err();
    assert!(error.to_string().contains("untrusted owner"), "{error}");

    // Restore the current owner through the already-open handle so the
    // temporary directory can be cleaned up normally.
    let user = wide_sid(&current_user_sid().unwrap());
    let mut user_sid: PSID = null_mut();
    // SAFETY: The SID text is NUL-terminated and output is writable.
    assert_ne!(
        unsafe { ConvertStringSidToSidW(user.as_ptr(), &mut user_sid) },
        0
    );
    let _user_sid = LocalMemory(user_sid);
    // SAFETY: This handle retained WRITE_OWNER from before the owner change.
    let code = unsafe {
        SetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            user_sid,
            null_mut(),
            std::ptr::null(),
            std::ptr::null(),
        )
    };
    assert_eq!(code, 0, "cannot restore owner: {code}");
}

fn wide_sid(sid: &str) -> Vec<u16> {
    sid.encode_utf16().chain(Some(0)).collect()
}
