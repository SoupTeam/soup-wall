// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Arthur Lin (carbon-evolution)

//! `agentfw` — the agent firewall daemon. The only crate performing I/O for the
//! agent layer; all verdict logic lives in `soup-wall-agent`.

pub mod audit;
pub mod classifier_runtime;
pub mod config;
pub mod decision;
pub mod doctor;
pub mod grant;
pub mod handlers;
pub mod hook;
pub mod install;
pub mod judge;
pub mod lifecycle;
pub mod managed_credential;
pub mod managed_policy;
pub mod managed_sync;
pub mod map;
pub mod mcp;
pub mod native;
pub mod policy_transition;
pub use native::child_authority;
pub mod preflight;
#[cfg(windows)]
mod private_file_windows;
pub mod protection_status;
pub mod provenance;
pub mod replay;
pub mod sandbox;
pub mod self_test;
#[cfg(target_os = "linux")]
pub mod service;
pub mod spans;
pub mod support_bundle;
pub mod token;
#[cfg(windows)]
pub(crate) mod windows_create;
#[cfg(windows)]
pub(crate) mod windows_read;

use axum::routing::{get, post};
use axum::Router;

pub use config::Config;
pub use handlers::{AppState, Shared};

/// The axum router. Exposed so integration tests can drive it without a socket.
pub fn app(state: Shared) -> Router {
    let runtime = std::sync::Arc::new(protection_status::Runtime::new(&state.config));
    app_with_diagnostics(state, runtime)
}

pub const MAX_ROUTE_BODY: usize = 16 * 1024 * 1024;

/// Attach immutable startup identity and bounded read-only transport observations.
pub fn app_with_diagnostics(
    state: Shared,
    runtime: std::sync::Arc<protection_status::Runtime>,
) -> Router {
    Router::new()
        .route(
            "/hook",
            post(handlers::hook).layer(axum::extract::DefaultBodyLimit::max(MAX_ROUTE_BODY)),
        )
        .route(
            "/mcp",
            post(handlers::mcp).layer(axum::extract::DefaultBodyLimit::max(MAX_ROUTE_BODY)),
        )
        .route(
            "/native/approval/v1",
            post(native::approval::handler)
                .layer(axum::extract::DefaultBodyLimit::max(native::MAX_BODY)),
        )
        .route(
            "/native/v1",
            post(native::handler).layer(axum::extract::DefaultBodyLimit::max(native::MAX_BODY)),
        )
        .route("/native/v1/instance", get(native::instance))
        .route(
            native::continuity::BARRIER,
            post(native::continuity::barrier),
        )
        .route("/health", get(handlers::health))
        .route(protection_status::ENDPOINT, get(protection_status::handler))
        .layer(axum::Extension(runtime.clone()))
        .layer(axum::middleware::from_fn_with_state(
            (state.clone(), runtime),
            protection_status::observe,
        ))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            native::continuity::middleware,
        ))
        .with_state(state)
}
