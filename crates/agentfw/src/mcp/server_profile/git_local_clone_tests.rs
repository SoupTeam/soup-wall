// SPDX-License-Identifier: Apache-2.0
use super::git_local_clone::*;
use std::fs;

const CORE: &str = "[core]\nrepositoryformatversion = 0\nbare = false\nfilemode = true\n";
const ORDINARY: &str = "[user]\nname = Owned Synthetic\nemail = owned@example.invalid\n[remote \"origin\"]\nurl = https://example.invalid/owned/repo.git\nfetch = +refs/heads/*:refs/remotes/origin/*\n[branch \"main\"]\nremote = origin\nmerge = refs/heads/main\n";

#[test]
fn ordinary_config_preserves_v1_refusal() {
    validate_config(format!("{CORE}{ORDINARY}").as_bytes()).unwrap();
    let root = tempfile::tempdir().unwrap();
    fs::create_dir(root.path().join(".git")).unwrap();
    fs::write(root.path().join(".git/config"), format!("{CORE}{ORDINARY}")).unwrap();
    fs::write(root.path().join(".git/HEAD"), "ref: refs/heads/main\n").unwrap();
    validate_repository(root.path()).unwrap();
    assert!(super::git::validate_repository(root.path()).is_err());
    for (path, data) in [
        (".gitattributes", "*.txt text eol=lf\n*.bin binary\n"),
        (".git/info/attributes", "*.txt text\n"),
        (".git/unexpected", "value\n"),
    ] {
        let path = root.path().join(path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, data).unwrap();
        if path.file_name().unwrap() == ".gitattributes" {
            validate_repository(root.path()).unwrap();
        } else {
            assert!(validate_repository(root.path()).is_err());
        }
        fs::remove_file(path).unwrap();
    }
}

#[test]
fn helpers_includes_quoting_and_duplicate_config_are_not_authority() {
    for tail in [
        "[include]\npath = secret\n",
        "[includeIf \"gitdir:/\"]\npath=x\n",
        "[diff]\nexternal = helper\n",
        "[filter \"x\"]\nclean = helper\n",
        "[credential]\nhelper = helper\n",
        "[core]\nfsmonitor = helper\n",
        "[alias]\nx = !helper\n",
        "[extensions]\nobjectformat = sha256\n",
        "[user]\nname = \"quoted\"\n",
        "[user]\nname = x\\\ny\n",
        "[user]\nname = x ; inline\n",
        "[user]\nname = x\nname = y\n",
        "[remote \"origin\"]\nurl = ext::helper\n",
    ] {
        assert!(
            validate_config(format!("{CORE}{tail}").as_bytes()).is_err(),
            "{tail}"
        );
    }
    assert!(validate_config(b"[user]\nname=x\n").is_err());
}

#[test]
fn attributes_accept_only_bounded_builtin_declarations() {
    validate_attributes(
        b"# bounded\n* text=auto\n*.txt text eol=lf\n*.bin binary\nassets/*.raw -text -diff\n",
    )
    .unwrap();
    for bad in [
        "* filter=evil",
        "* diff=evil",
        "[attr]binary filter=evil",
        "* working-tree-encoding=UTF-16",
        "!file text",
        "../file text",
        "\"file name\" text",
        "* custom",
        "* text #inline",
        "[ab] text",
    ] {
        assert!(validate_attributes(bad.as_bytes()).is_err(), "{bad}");
    }
    assert!(validate_attributes(&vec![b' '; 8193]).is_err());
}

#[test]
fn index_fallback_and_submodule_or_symlink_modes_are_inspected() {
    let oid = "a".repeat(40);
    let list = format!("100644 {oid} 0\t.gitattributes\0");
    assert_eq!(
        attribute_objects(list.as_bytes()).unwrap(),
        vec![oid.clone()]
    );
    for entry in [
        format!("120000 {oid} 0\tlink\0"),
        format!("160000 {oid} 0\tsubmodule\0"),
        format!("100644 {oid} 2\tconflict\0"),
        format!("100644 {oid} 0\t../outside\0"),
        format!("100644 {oid} 0\t.gitmodules\0"),
    ] {
        assert!(attribute_objects(entry.as_bytes()).is_err());
    }
}

#[test]
fn repository_changes_are_revalidated_without_rewriting_operator_files() {
    let root = tempfile::tempdir().unwrap();
    fs::create_dir(root.path().join(".git")).unwrap();
    let config = root.path().join(".git/config");
    fs::write(&config, CORE).unwrap();
    fs::write(root.path().join(".git/HEAD"), "ref: refs/heads/main\n").unwrap();
    validate_repository(root.path()).unwrap();
    let changed = format!("{CORE}[include]\npath=/outside\n");
    fs::write(&config, &changed).unwrap();
    assert!(validate_repository(root.path()).is_err());
    assert_eq!(fs::read_to_string(&config).unwrap(), changed);
    fs::write(config, CORE).unwrap();
    fs::write(root.path().join(".gitattributes"), "* filter=evil\n").unwrap();
    assert!(validate_repository(root.path()).is_err());
    fs::write(root.path().join(".gitattributes"), "* text=auto\n").unwrap();
    validate_repository(root.path()).unwrap();
}

#[cfg(unix)]
#[test]
fn nofollow_refuses_config_and_directory_symlink_substitution() {
    use std::os::unix::fs::symlink;
    let root = tempfile::tempdir().unwrap();
    fs::create_dir(root.path().join(".git")).unwrap();
    fs::write(root.path().join(".git/config"), CORE).unwrap();
    fs::write(root.path().join(".git/HEAD"), "ref: refs/heads/main\n").unwrap();
    validate_repository(root.path()).unwrap();
    fs::rename(
        root.path().join(".git/config"),
        root.path().join("original"),
    )
    .unwrap();
    symlink("../original", root.path().join(".git/config")).unwrap();
    assert!(validate_repository(root.path()).is_err());
}
