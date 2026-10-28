// SPDX-License-Identifier: Apache-2.0
//! Mutually exclusive source proofs for separately qualified Git profiles.
use serde_json::Value;
use std::sync::Arc;

#[derive(Debug)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) enum SelectedView {
    LocalReferences(Arc<super::reference_view::View>),
    FileRevisions(Arc<super::revision_view::View>),
    Shallow(Arc<super::shallow_view::View>),
}
impl SelectedView {
    pub(crate) fn validate_call(&self, tool: &str, args: &Value) -> anyhow::Result<()> {
        match self {
            Self::LocalReferences(view) => view.validate_call(tool, args),
            Self::FileRevisions(view) => view.validate_call(tool, args),
            Self::Shallow(view) => view.validate_call(tool, args),
        }
    }
    #[cfg(target_os = "linux")]
    pub(crate) fn capture(
        format: &str,
        workspace: &std::fs::File,
    ) -> anyhow::Result<Option<Arc<Self>>> {
        Ok(match format {
            super::LOCAL_REFS_FORMAT => Some(Arc::new(Self::LocalReferences(
                super::reference_view::View::capture(workspace)?,
            ))),
            super::FILE_READS_FORMAT => Some(Arc::new(Self::FileRevisions(
                super::revision_view::View::capture(workspace)?,
            ))),
            super::SHALLOW_FORMAT => Some(Arc::new(Self::Shallow(
                super::shallow_view::View::capture(workspace)?,
            ))),
            _ => None,
        })
    }
    #[cfg(target_os = "linux")]
    pub(crate) fn mount(
        &self,
        command: &mut tokio::process::Command,
        pins: &mut Vec<std::fs::File>,
    ) -> anyhow::Result<()> {
        match self {
            Self::LocalReferences(view) => view.mount(command, pins),
            Self::FileRevisions(view) => view.mount(command, pins),
            Self::Shallow(view) => view.mount(command, pins),
        }
    }
}
