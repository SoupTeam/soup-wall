// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Arthur Lin (carbon-evolution)

//! The MCP collector: a transparent stdio proxy that pins each server's tool
//! manifest at handshake. Opt-in native admission also gates supported calls
//! and text results; see `docs/operations/MCP_STDIO_ADMISSION.md`.

pub mod admission;
pub mod connection;
pub mod create_file;
pub mod https_get;
pub mod https_post;
pub mod input;
pub mod jsonrpc;
pub(crate) mod linux_budget;
#[doc(hidden)]
pub mod linux_owner;
pub mod manifest;
mod native_child;
#[cfg(target_os = "linux")]
pub(crate) use native_child::OwnedChild;
mod original_create;
pub mod profile_author;
pub mod profile_lifecycle;
pub mod profile_upgrade;
pub mod proxy;
pub mod replace_file;
pub mod resources;
pub mod server_profile;
pub mod server_sandbox;
#[cfg(unix)]
pub(crate) mod stdio;
pub mod store;
pub(crate) mod verified_closure;
pub(crate) mod verified_git;
pub(crate) mod windows_budget;
