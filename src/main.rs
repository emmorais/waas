/// Axum hello world example application.

use axum::{
    extract::FromRequestParts, http::{request::Parts, StatusCode}, response::IntoResponse, routing::get, Json, Router
};
use axum_server::tls_rustls::RustlsConfig;
use base64::{engine::general_purpose, Engine as _};
use serde::Serialize;
use tower_http::services::ServeDir;
use std::{future::Future, net::SocketAddr};
use std::pin::Pin;

struct BasicAuth {
    username: String,
    password: String,
}

// Wallet data (fake for now)
#[derive(Serialize)]
struct WalletData {
    balance: u64,
    transactions: Vec<String>,
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
    ) -> Pin<Box<dyn Future<Output = Result<Self, Self::Rejection>> + Send + 'a>> 
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

            if username == "admin" && password == "secret" {
                Ok(BasicAuth { username, password })
            } else {
                Err((StatusCode::UNAUTHORIZED, "Invalid credentials".into()))
            }
        })
    }
}

// Route handler
async fn protected(_auth: BasicAuth) -> impl IntoResponse {
    let wallet = WalletData {
        balance: 4200,
        transactions: vec![
            "Deposit 1000".to_string(),
            "Withdraw 200".to_string(),
            "Deposit 3400".to_string(),
        ],
    };
    Json(wallet)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
     let app = Router::new()
        .route("/protected", get(protected))
        // Serve everything under ./static, with index.html support
        .fallback_service(ServeDir::new("src/static").append_index_html_on_directories(true));

    // Load TLS cert and key (PEM files)
    // You can also build RustlsConfig from bytes or from a certificate store.
    let tls = RustlsConfig::from_pem_file("cert.pem", "key.pem").await?;
    let addr: SocketAddr = "0.0.0.0:8443".parse()?; // use 443 in production if you control the machine

    println!("Listening on https://localhost:8443");

    // Serve with TLS (axum-server wraps hyper + rustls neatly)
    axum_server::bind_rustls(addr, tls)
        .serve(app.into_make_service())
        .await?;

    Ok(())
}