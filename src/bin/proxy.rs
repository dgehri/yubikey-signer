// Copyright 2025 Daniel Gehriger
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! `YubiKey` Signing Proxy Server
//!
//! A lightweight HTTPS server that exposes `YubiKey` signing operations
//! via a REST API, allowing remote clients to request signatures through
//! firewalls and Cloudflare tunnels.

#![allow(clippy::missing_errors_doc)]

use clap::Parser;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use warp::Filter;
use yubikey_signer::{
    adapters::remote::{
        protocol::{GetCertificateRequest, SignRequest, StatusRequest},
        server::{
            handle_get_certificate, handle_sign, handle_status, initialize_proxy,
            validate_request_auth, ProxyServerConfig, ProxyState,
        },
    },
    PivPin,
};

#[derive(Parser)]
#[command(name = "yubikey-proxy")]
#[command(about = "YubiKey signing proxy server for remote code signing")]
#[command(version)]
struct Cli {
    /// Address to bind to (e.g., "0.0.0.0:8443")
    #[arg(short, long, default_value = "127.0.0.1:8443")]
    bind: String,

    /// Authentication token for clients (or set `YUBIKEY_PROXY_TOKEN` env var)
    #[arg(short, long, env = "YUBIKEY_PROXY_TOKEN")]
    token: String,

    /// TLS certificate file (PEM format)
    #[arg(long)]
    tls_cert: Option<String>,

    /// TLS private key file (PEM format)
    #[arg(long)]
    tls_key: Option<String>,

    /// Rate limit (requests per minute per client)
    #[arg(long, default_value = "60")]
    rate_limit: u32,

    /// Verbose output
    #[arg(short, long)]
    verbose: bool,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    // Initialize logging
    let log_level = if cli.verbose { "debug" } else { "info" };
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(log_level)).init();

    // Get PIN from environment
    let pin = if let Ok(p) = std::env::var("YUBICO_PIN") {
        match PivPin::new(&p) {
            Ok(pin) => pin,
            Err(e) => {
                eprintln!("❌ Invalid PIN: {e}");
                std::process::exit(1);
            }
        }
    } else {
        eprintln!("❌ YUBICO_PIN environment variable not set");
        std::process::exit(1);
    };

    // Build configuration
    let mut config =
        ProxyServerConfig::new(&cli.bind, &cli.token, pin).with_rate_limit(cli.rate_limit);

    if let (Some(cert), Some(key)) = (&cli.tls_cert, &cli.tls_key) {
        config = config.with_tls(cert, key);
    }

    // Initialize proxy state
    println!("🔐 Initializing YubiKey proxy server...");
    let state = match initialize_proxy(&config) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("❌ Failed to initialize: {e}");
            std::process::exit(1);
        }
    };

    // Parse bind address
    let addr: SocketAddr = match cli.bind.parse() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("❌ Invalid bind address: {e}");
            std::process::exit(1);
        }
    };

    // Build routes
    let routes = build_routes(state.clone());

    println!("🚀 YubiKey proxy server listening on {addr}");
    println!("   Endpoints:");
    println!("     POST /api/v1/status     - Check server and YubiKey status");
    println!("     POST /api/v1/certificate - Get certificate from slot");
    println!("     POST /api/v1/sign        - Sign a hash digest");
    println!();
    println!("   Use Ctrl+C to stop the server");

    // Run server
    if config.tls_cert_path.is_some() && config.tls_key_path.is_some() {
        warp::serve(routes)
            .tls()
            .cert_path(config.tls_cert_path.as_ref().unwrap())
            .key_path(config.tls_key_path.as_ref().unwrap())
            .run(addr)
            .await;
    } else {
        println!("⚠️  Running without TLS - use only behind a TLS-terminating proxy!");
        warp::serve(routes).run(addr).await;
    }
}

/// Build all API routes.
fn build_routes(
    state: Arc<ProxyState>,
) -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
    let status = status_route(state.clone());
    let certificate = certificate_route(state.clone());
    let sign = sign_route(state);

    status.or(certificate).or(sign)
}

/// Status endpoint route.
fn status_route(
    state: Arc<ProxyState>,
) -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
    warp::path!("api" / "v1" / "status")
        .and(warp::post())
        .and(warp::header::optional::<String>("authorization"))
        .and(warp::body::json::<StatusRequest>())
        .and(with_state(state))
        .and_then(handle_status_request)
}

/// Certificate endpoint route.
fn certificate_route(
    state: Arc<ProxyState>,
) -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
    warp::path!("api" / "v1" / "certificate")
        .and(warp::post())
        .and(warp::header::optional::<String>("authorization"))
        .and(warp::body::json::<GetCertificateRequest>())
        .and(with_state(state))
        .and_then(handle_certificate_request)
}

/// Sign endpoint route.
fn sign_route(
    state: Arc<ProxyState>,
) -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
    warp::path!("api" / "v1" / "sign")
        .and(warp::post())
        .and(warp::header::optional::<String>("authorization"))
        .and(warp::body::json::<SignRequest>())
        .and(with_state(state))
        .and_then(handle_sign_request)
}

/// Inject state into handlers.
fn with_state(
    state: Arc<ProxyState>,
) -> impl Filter<Extract = (Arc<ProxyState>,), Error = Infallible> + Clone {
    warp::any().map(move || state.clone())
}

/// Handle status request.
async fn handle_status_request(
    auth: Option<String>,
    _request: StatusRequest,
    state: Arc<ProxyState>,
) -> Result<impl warp::Reply, Infallible> {
    // Status endpoint allows unauthenticated access for health checks
    if let Some(auth_header) = auth {
        if validate_request_auth(&state, Some(&auth_header)).is_err() {
            // Still allow status but with less info
        }
    }

    let response = handle_status(&state);
    Ok(warp::reply::json(&response))
}

/// Handle certificate request.
async fn handle_certificate_request(
    auth: Option<String>,
    request: GetCertificateRequest,
    state: Arc<ProxyState>,
) -> Result<impl warp::Reply, Infallible> {
    // Validate authentication
    if let Err(error) = validate_request_auth(&state, auth.as_deref()) {
        return Ok(warp::reply::with_status(
            warp::reply::json(&error),
            warp::http::StatusCode::UNAUTHORIZED,
        ));
    }

    match handle_get_certificate(&state, &request) {
        Ok(response) => Ok(warp::reply::with_status(
            warp::reply::json(&response),
            warp::http::StatusCode::OK,
        )),
        Err(error) => Ok(warp::reply::with_status(
            warp::reply::json(&error),
            warp::http::StatusCode::BAD_REQUEST,
        )),
    }
}

/// Handle sign request.
async fn handle_sign_request(
    auth: Option<String>,
    request: SignRequest,
    state: Arc<ProxyState>,
) -> Result<impl warp::Reply, Infallible> {
    // Validate authentication
    if let Err(error) = validate_request_auth(&state, auth.as_deref()) {
        return Ok(warp::reply::with_status(
            warp::reply::json(&error),
            warp::http::StatusCode::UNAUTHORIZED,
        ));
    }

    log::debug!(
        "Sign request: slot={}, digest_size={}",
        request.slot,
        request.digest_b64.len()
    );

    match handle_sign(&state, &request) {
        Ok(response) => {
            log::info!("Signing successful for slot {}", request.slot);
            Ok(warp::reply::with_status(
                warp::reply::json(&response),
                warp::http::StatusCode::OK,
            ))
        }
        Err(error) => {
            log::warn!("Signing failed: {} - {}", error.error_code, error.message);
            Ok(warp::reply::with_status(
                warp::reply::json(&error),
                warp::http::StatusCode::BAD_REQUEST,
            ))
        }
    }
}
