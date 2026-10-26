// SPDX-License-Identifier: Apache-2.0
//! Adapter to the accepted shallow snapshot, never a replacement launcher.
use super::*;

pub(super) fn capture(workspace: &std::fs::File, profile: &str) -> anyhow::Result<Arc<Snapshot>> {
    use crate::mcp::server_profile::git_tracked_symlinks as tracked;
    ensure!(
        super::super::is_profile(profile) || profile == tracked::FORMAT,
        "unsupported Git witness profile"
    );
    let path = std::path::PathBuf::from(format!(
        "/proc/self/fd/{}/.",
        std::os::fd::AsRawFd::as_raw_fd(workspace)
    ));
    let shallow = profile == super::super::SHALLOW_FORMAT;
    let validate = || {
        if profile == tracked::FORMAT {
            tracked::validate_repository(&path)
        } else {
            super::super::validate_repository_with_shallow(&path, shallow)
        }
    };
    validate()?;
    let view = super::super::shallow_view::View::capture_object_witness(workspace)?;
    // Revalidate after the workspace watch has been installed. Both passes
    // preserve existing configuration/attributes/indirection guards; source
    // mutations from this point remain sticky and cannot refresh authority.
    validate()?;
    let repository = Repository::images(view.object_witness_images()?)?;
    view.object_witness_valid()?;
    Ok(Arc::new(Snapshot {
        source: Source::Native(view),
        repository,
        generation: rand::random(),
        profile: profile.to_owned(),
    }))
}
