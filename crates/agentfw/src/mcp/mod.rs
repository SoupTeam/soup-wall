// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Arthur Lin (carbon-evolution)

//! The MCP collector: a transparent stdio proxy that pins each server's tool
//! manifest at handshake. Opt-in native admission also gates supported calls
//! and text results; see `docs/operations/MCP_STDIO_ADMISSION.md`.

pub mod admission;
pub mod connection;
pub mod create_file;
pub mod https_get;
pub mod input;
pub mod jsonrpc;
pub mod manifest;
pub mod profile_author;
pub mod proxy;
pub mod resources;
pub mod server_profile;
pub mod server_sandbox;
#[cfg(unix)]
mod stdio;
pub mod store;
