/// Axum hello world example application.

mod dashboard;
mod keygen;
mod auxinfo;
mod tshare;
mod presign;
mod sign;
mod delete_key;
mod logging;

use axum::{
    extract::FromRequestParts, http::{request::Parts, StatusCode}, routing::{get, post}, Router
};
use axum_server::tls_rustls::RustlsConfig;
use base64::{engine::general_purpose, Engine as _};
use tower_http::services::ServeDir;
use std::{future::Future, net::SocketAddr};

struct BasicAuth {
    username: String,
    password: String,
}

// Implement BasicAuth extractor
impl<S> FromRequestParts<S> for BasicAuth
where
    S: Send + Sync,
{
    type Rejection = (StatusCode, String);

    fn from_request_parts<'a, 'b>(
        parts: &'a mut Parts,
        _state: &'b S,
    ) -> impl Future<Output = Result<Self, <Self as FromRequestParts<S>>::Rejection>> + Send 
    {
        Box::pin(async move {
            let header = match parts.headers.get("authorization") {
                Some(h) => h.to_str().unwrap_or(""),
                None => return Err((StatusCode::UNAUTHORIZED, "Missing Authorization".into())),
            };

            if !header.starts_with("Basic ") {
                return Err((StatusCode::UNAUTHORIZED, "Unsupported auth scheme".into()));
            }

            let b64 = &header[6..];
            let decoded = general_purpose::STANDARD
                .decode(b64)
                .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid Base64".into()))?;
            let cred = String::from_utf8(decoded)
                .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid UTF-8".into()))?;

            let mut parts = cred.splitn(2, ':');
            let username = parts.next().unwrap_or("").to_string();
            let password = parts.next().unwrap_or("").to_string();

            if username == "admin" && password == "admin123" {
                Ok(BasicAuth { username, password })
            } else {
                Err((StatusCode::UNAUTHORIZED, "Invalid credentials".into()))
            }
        })
    }
}

// Route
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing with Zama.ai UI colors
    logging::init_zama_logging();

    tracing::info!(
        service = "TSS-ECDSA Wallet-as-a-Service",
        version = env!("CARGO_PKG_VERSION"),
        "🚀 Starting TSS-ECDSA server"
    );

    // Build application routes with logging
    tracing::debug!("📋 Configuring application routes");
    let app = Router::new()
        .route("/dashboard", get(dashboard::dashboard))
        .route("/keygen", post(keygen::keygen).get(keygen::check_keygen))
        .route("/delete_key", post(delete_key::delete_key))
        .route("/sign", post(sign::sign))
        .route("/verify", post(sign::verify))
        // Serve everything under ./static, with index.html support
        .fallback_service(ServeDir::new("src/static").append_index_html_on_directories(true));

    tracing::info!(
        routes_count = 8,
        routes = "/dashboard, /keygen (GET/POST), /delete_key, /sign, /verify",
        static_content = "src/static",
        "✅ Application routes configured"
    );

    // Load TLS cert and key (PEM files)
    tracing::debug!(
        cert_file = "cert.pem",
        key_file = "key.pem",
        "🔐 Loading TLS configuration"
    );
    
    let tls = RustlsConfig::from_pem_file("cert.pem", "key.pem").await
        .map_err(|e| {
            tracing::error!(
                error = %e,
                cert_file = "cert.pem",
                key_file = "key.pem",
                "❌ Failed to load TLS configuration"
            );
            e
        })?;

    tracing::info!("✅ TLS configuration loaded successfully");

    let addr: SocketAddr = "0.0.0.0:8443".parse()?;
    
    tracing::info!(
        address = %addr,
        protocol = "HTTPS",
        tls_enabled = true,
        "🌐 Server configuration ready"
    );

    println!("\n🎯 TSS-ECDSA Wallet-as-a-Service Server");
    println!("📍 Listening on https://localhost:8443");
    println!("🔐 TLS encryption enabled");
    println!("🔑 Authentication: admin/admin123");
    println!("📊 Dashboard: https://localhost:8443/dashboard");
    println!("\n✨ Ready to process TSS operations!");

    tracing::info!(
        bind_address = %addr,
        "🚀 Starting HTTPS server with TLS"
    );

    // Serve with TLS (axum-server wraps hyper + rustls neatly)
    axum_server::bind_rustls(addr, tls)
        .serve(app.into_make_service())
        .await
        .map_err(|e| {
            tracing::error!(
                error = %e,
                "❌ Server failed to start"
            );
            e
        })?;

    tracing::info!("👋 Server shutdown completed");
    Ok(())
}