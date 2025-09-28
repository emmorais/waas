/// Axum hello world example application.

mod dashboard;
mod keygen;
mod auxinfo;
mod tshare;

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
     let app = Router::new()
        .route("/dashboard", get(dashboard::dashboard))
        .route("/keygen", post(keygen::keygen))
        .route("/auxinfo", post(auxinfo::auxinfo))
        .route("/tshare", post(tshare::tshare))
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