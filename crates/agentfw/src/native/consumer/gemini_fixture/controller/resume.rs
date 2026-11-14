// SPDX-License-Identifier: Apache-2.0
//! Explicit, separately accounted continuation. Never clear an old attempt fence.
use super::super::ledger::Ledger;
use super::*;

const COPIED: [&str; 7] = [
    "controller-started",
    "controller-terminal",
    "started",
    "terminal",
    "response",
    "count-response",
    "private-review",
];
const FENCES: [&str; 10] = [
    "controller-started",
    "controller-terminal",
    "started",
    "terminal",
    "response",
    "count-response",
    "private-review",
    "failure",
    "count-failure",
    "count-error-response",
];

fn required(ledger: &Ledger, name: &str) -> Result<Vec<u8>> {
    ledger
        .read(name)?
        .ok_or_else(|| anyhow::anyhow!("gemini_resume_missing_evidence"))
}
fn value(bytes: &[u8]) -> Result<Value> {
    let Strict(v) = serde_json::from_slice(bytes)?;
    Ok(v)
}

pub(super) fn bind(
    parent_path: &std::path::Path,
    report_hash: &str,
    child: &Ledger,
    project: &str,
    key_hash: &str,
) -> Result<()> {
    let parent = Ledger::open(parent_path)?;
    let parent_continuation = parent.read("http503-continuation.receipt")?;
    ensure!(
        parent.identity()? != child.identity()?,
        "gemini_resume_same_ledger"
    );
    let report_bytes = required(&parent, &format!("report-{report_hash}.json"))?;
    ensure!(
        hash(&report_bytes) == report_hash,
        "gemini_resume_report_hash"
    );
    let report = value(&report_bytes)?;
    let manifest = value(&required(&parent, "batch.manifest")?)?;
    ensure!(
        manifest["profile"] == profile_hash()
            && report["profile"] == profile_hash()
            && manifest["project"] == project
            && manifest["key_sha256"] == key_hash
            && manifest["plan"] == json_digest(PLAN)
            && manifest["acceptance"] == json_digest(ACCEPTANCE),
        "gemini_resume_identity"
    );
    let rows = report["rows"]
        .as_array()
        .filter(|r| r.len() == 30)
        .ok_or_else(|| anyhow::anyhow!("gemini_resume_rows"))?;
    let completed = rows
        .iter()
        .take_while(|r| r["state"] == "valid_untrusted")
        .count();
    ensure!(
        completed < 30
            && rows[completed]["state"] == "technical_stop"
            && rows[completed + 1..].iter().all(|r| r["state"] == "unrun"),
        "gemini_resume_states"
    );
    let mut copies = Vec::new();
    for (i, record) in rows.iter().enumerate() {
        let source = row(i)?;
        let id = hash(source.frame.as_bytes());
        ensure!(
            record["case_id"] == source.id && record["source_sha256"] == id,
            "gemini_resume_source"
        );
        if i <= completed {
            let terminal = value(&required(&parent, &format!("{id}.controller-terminal"))?)?;
            ensure!(
                terminal["state"] == record["state"],
                "gemini_resume_terminal"
            );
            let raw = required(&parent, &format!("{id}.response"))?;
            ensure!(
                record["raw_sha256"] == hash(&raw),
                "gemini_resume_response_hash"
            );
            if i < completed {
                ensure!(value(&raw)?["modelVersion"] == MODEL, "gemini_resume_model");
                let preflight = counted(
                    &source.frame,
                    &required(&parent, &format!("{id}.count-response"))?,
                )?;
                let prepared = prepare(
                    &source.frame,
                    &crate::token::generate(),
                    Instant::now() + std::time::Duration::from_secs(30),
                    preflight,
                )?;
                decode(&prepared, &raw)?;
                let terminal = value(&required(&parent, &format!("{id}.terminal"))?)?;
                ensure!(
                    terminal["state"] == "valid_untrusted" && terminal["source"] == id,
                    "gemini_resume_terminal"
                );
                ensure!(
                    parent.read(&format!("{id}.failure"))?.is_none()
                        && parent.read(&format!("{id}.count-failure"))?.is_none(),
                    "gemini_resume_conflict"
                );
                for suffix in COPIED {
                    copies.push((
                        format!("{id}.{suffix}"),
                        required(&parent, &format!("{id}.{suffix}"))?,
                    ));
                }
            } else {
                let error = value(&raw)?;
                ensure!(
                    error["error"]["code"] == 503
                        && error["error"]["status"] == "UNAVAILABLE"
                        && error.get("candidates").is_none()
                        && required(&parent, &format!("{id}.failure"))? == b"gemini_http_status",
                    "gemini_resume_not_definite_503"
                );
                ensure!(
                    parent.read(&format!("{id}.private-review"))?.is_none(),
                    "gemini_resume_conflict"
                );
            }
        } else {
            for suffix in FENCES {
                ensure!(
                    parent.read(&format!("{id}.{suffix}"))?.is_none(),
                    "gemini_resume_unreported_attempt"
                );
            }
        }
    }
    let artifacts: Vec<_> = copies
        .iter()
        .map(|(name, bytes)| json!({"name":name,"sha256":hash(bytes)}))
        .collect();
    let mut receipt = json!({"contract":"sw-explicit-http503-continuation/1",
        "parent_ledger":parent.identity()?,"parent_report_sha256":report_hash,"profile":profile_hash(),
        "inherited_completed_rows":completed,"prior_attempted_rows":completed+1,"new_attempt_budget":30-completed,
        "combined_attempt_ceiling":31,"failed_source_sha256":rows[completed]["source_sha256"],
        "failed_response_sha256":rows[completed]["raw_sha256"],"inherited_artifact_manifest_sha256":hash(&serde_json::to_vec(&artifacts)?),
        "parent_unchanged":true,"policy_allow":false});
    if let Some(bytes) = parent_continuation {
        let previous = value(&bytes)?;
        let inherited = previous["inherited_completed_rows"]
            .as_u64()
            .filter(|n| *n <= completed as u64)
            .ok_or_else(|| anyhow::anyhow!("gemini_resume_chain"))?
            as usize;
        ensure!(
            previous["contract"] == "sw-explicit-http503-continuation/1"
                && previous["profile"] == profile_hash()
                && previous.get("parent_continuation").is_none()
                && previous["prior_attempted_rows"] == inherited + 1
                && previous["new_attempt_budget"] == 30 - inherited
                && previous["combined_attempt_ceiling"] == 31
                && previous["failed_source_sha256"] == hash(row(inherited)?.frame.as_bytes())
                && report["continuation"] == previous
                && previous["inherited_artifact_manifest_sha256"]
                    == hash(&serde_json::to_vec(&artifacts[..inherited * COPIED.len()])?),
            "gemini_resume_chain"
        );
        receipt["prior_attempted_rows"] = json!(completed + 2);
        receipt["combined_attempt_ceiling"] = json!(32);
        receipt["parent_continuation_sha256"] = json!(hash(&bytes));
        receipt["parent_continuation"] = previous;
    } else {
        ensure!(report.get("continuation").is_none(), "gemini_resume_chain");
    }
    let receipt = serde_json::to_vec(&receipt)?;
    match child.read("http503-continuation.receipt")? {
        Some(old) => ensure!(old == receipt, "gemini_resume_receipt_changed"),
        None => {
            ensure!(
                child.read("batch.manifest")?.is_none(),
                "gemini_resume_child_not_fresh"
            );
            for i in 0..30 {
                let id = hash(row(i)?.frame.as_bytes());
                for suffix in FENCES {
                    ensure!(
                        child.read(&format!("{id}.{suffix}"))?.is_none(),
                        "gemini_resume_child_not_fresh"
                    );
                }
            }
            child.create("http503-continuation.receipt", &receipt)?;
        }
    }
    // Append-only and idempotent after a local crash during import. Network work
    // starts only after every inherited artifact has been verified/copied.
    for (name, bytes) in copies {
        match child.read(&name)? {
            Some(old) => ensure!(old == bytes, "gemini_resume_import_changed"),
            None => child.create(&name, &bytes)?,
        }
    }
    Ok(())
}

#[test]
fn gemini_http503_continuation_preserves_fifteen_and_rejects_unsafe_imports() {
    use std::os::unix::fs::PermissionsExt;
    for mode in [
        "valid",
        "continued",
        "changed-chain",
        "wrong-key",
        "wrong-profile",
        "wrong-report",
        "non-503",
        "unknown",
        "wrong-source",
        "late-fence",
        "dirty-child",
        "missing-artifact",
        "nested",
    ] {
        let old = tempfile::tempdir().unwrap();
        let new = tempfile::tempdir().unwrap();
        for d in [&old, &new] {
            std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let parent = Ledger::open(old.path()).unwrap();
        let key = hash(b"synthetic-key");
        parent.create("batch.manifest", &serde_json::to_vec(&json!({"profile":if mode=="wrong-profile" {"other".into()} else {profile_hash()},"project":"test-project","key_sha256":key,"plan":json_digest(PLAN),"acceptance":json_digest(ACCEPTANCE)})).unwrap()).unwrap();
        if mode == "nested" {
            parent
                .create("http503-continuation.receipt", b"{}")
                .unwrap();
        }
        let mut rows = Vec::new();
        let mut original = Vec::new();
        for i in 0..30 {
            let r = row(i).unwrap();
            let id = hash(r.frame.as_bytes());
            let state = if i < 15 {
                "valid_untrusted"
            } else if i == 15 {
                "technical_stop"
            } else {
                "unrun"
            };
            let mut record =
                json!({"case_id":r.id,"source_sha256":id,"state":state,"raw_sha256":null});
            if i <= 15 {
                let quote = super::super::quote_catalog::candidates(&r.frame)[0];
                let raw=serde_json::to_vec(&if i<15 {json!({"modelVersion":MODEL,"candidates":[{"finishReason":"STOP","content":{"role":"model","parts":[{"text":json!({"summary":"Synthetic untrusted evidence.","quotes":[quote]}).to_string()}]}}]})} else {json!({"error":{"code":if mode=="non-503" {429} else {503},"status":"UNAVAILABLE"}})}).unwrap();
                record["raw_sha256"] = json!(hash(&raw));
                for suffix in COPIED {
                    if (i == 15 && suffix == "private-review")
                        || (mode == "missing-artifact" && i == 3 && suffix == "count-response")
                    {
                        continue;
                    }
                    let data=match suffix {
                        "response"=>raw.clone(),
                        "count-response"=>b"{\"totalTokens\":100}".to_vec(),
                        "controller-terminal"=>serde_json::to_vec(&json!({"state":state})).unwrap(),
                        "terminal"=>serde_json::to_vec(&json!({"state":if i<15 {"valid_untrusted"}else{"transport_unknown"},"source":id})).unwrap(),
                        _=>b"{}".to_vec()
                    };
                    let name = format!("{id}.{suffix}");
                    parent.create(&name, &data).unwrap();
                    original.push((name, data));
                }
                if i == 15 {
                    parent
                        .create(
                            &format!("{id}.failure"),
                            if mode == "unknown" {
                                b"gemini_transport_unclassified"
                            } else {
                                b"gemini_http_status"
                            },
                        )
                        .unwrap();
                }
            }
            if mode == "late-fence" && i == 16 {
                parent
                    .create(&format!("{id}.controller-started"), b"{}")
                    .unwrap();
            }
            if mode == "wrong-source" && i == 2 {
                record["source_sha256"] = json!(hash(b"wrong"));
            }
            rows.push(record);
        }
        let mut report_value = json!({"profile":profile_hash(),"rows":rows});
        if matches!(mode, "continued" | "changed-chain") {
            let first: Vec<_> = original[..2 * COPIED.len()]
                .iter()
                .map(|(n, b)| json!({"name":n,"sha256":hash(b)}))
                .collect();
            let previous = json!({"contract":"sw-explicit-http503-continuation/1","profile":profile_hash(),"inherited_completed_rows":2,"prior_attempted_rows":3,"new_attempt_budget":28,"combined_attempt_ceiling":31,"failed_source_sha256":hash(row(2).unwrap().frame.as_bytes()),"inherited_artifact_manifest_sha256":if mode=="changed-chain" {hash(b"changed")}else{hash(&serde_json::to_vec(&first).unwrap())}});
            parent
                .create(
                    "http503-continuation.receipt",
                    &serde_json::to_vec(&previous).unwrap(),
                )
                .unwrap();
            report_value["continuation"] = previous;
        }
        let report = serde_json::to_vec(&report_value).unwrap();
        let digest = hash(&report);
        let requested = if mode == "wrong-report" {
            hash(b"different")
        } else {
            digest.clone()
        };
        parent
            .create(&format!("report-{requested}.json"), &report)
            .unwrap();
        drop(parent);
        let child = Ledger::open(new.path()).unwrap();
        if mode == "dirty-child" {
            child.create("batch.manifest", b"{}").unwrap();
        }
        let result = bind(
            old.path(),
            &requested,
            &child,
            "test-project",
            if mode == "wrong-key" { "wrong" } else { &key },
        );
        if matches!(mode, "valid" | "continued") {
            result.unwrap();
            bind(old.path(), &digest, &child, "test-project", &key).unwrap();
            let receipt =
                value(&required(&child, "http503-continuation.receipt").unwrap()).unwrap();
            assert_eq!(receipt["inherited_completed_rows"], 15);
            assert_eq!(receipt["new_attempt_budget"], 15);
            assert_eq!(
                receipt["combined_attempt_ceiling"],
                if mode == "continued" { 32 } else { 31 }
            );
            let retry = hash(row(15).unwrap().frame.as_bytes());
            for suffix in FENCES {
                assert!(child.read(&format!("{retry}.{suffix}")).unwrap().is_none());
            }
            for (name, data) in original.iter().filter(|(n, _)| !n.starts_with(&retry)) {
                assert_eq!(required(&child, name).unwrap(), *data);
            }
        } else {
            assert!(result.is_err(), "{mode}");
            assert!(child
                .read("http503-continuation.receipt")
                .unwrap()
                .is_none());
        }
        let parent = Ledger::open(old.path()).unwrap();
        for (name, data) in original {
            assert_eq!(required(&parent, &name).unwrap(), data);
        }
        assert_eq!(
            required(&parent, &format!("report-{requested}.json")).unwrap(),
            report
        );
    }
}

#[test]
#[ignore = "explicit offline dry-run of retained public HTTP503 journal; no provider or key input"]
fn manual_gemini_http503_resume_preview() {
    use std::os::unix::fs::PermissionsExt;
    let path =
        std::path::PathBuf::from(std::env::var_os("SOUP_WALL_RESUME_PREVIEW_PARENT").unwrap());
    let report = std::env::var("SOUP_WALL_RESUME_PREVIEW_REPORT").unwrap();
    let parent = Ledger::open(&path).unwrap();
    let manifest = value(&required(&parent, "batch.manifest").unwrap()).unwrap();
    let old = required(&parent, &format!("report-{report}.json")).unwrap();
    drop(parent);
    let tmp = tempfile::tempdir().unwrap();
    std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let child = Ledger::open(tmp.path()).unwrap();
    bind(
        &path,
        &report,
        &child,
        manifest["project"].as_str().unwrap(),
        manifest["key_sha256"].as_str().unwrap(),
    )
    .unwrap();
    let receipt = value(&required(&child, "http503-continuation.receipt").unwrap()).unwrap();
    let completed = value(&old).unwrap()["rows"]
        .as_array()
        .unwrap()
        .iter()
        .take_while(|r| r["state"] == "valid_untrusted")
        .count();
    assert_eq!(receipt["inherited_completed_rows"], completed);
    assert_eq!(receipt["new_attempt_budget"], 30 - completed);
    let parent = Ledger::open(&path).unwrap();
    assert_eq!(
        required(&parent, &format!("report-{report}.json")).unwrap(),
        old
    );
    println!("Offline preview passed: {completed} exact inherited rows; {} remaining; no provider calls, no key read, original report unchanged.",30-completed);
}
