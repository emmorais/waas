/// Axum hello world example application.

use axum::{
    routing::get,
    Router,
};

/* 
Next function creates an Axum endpoint that responds with "Hello, World!" to any GET request.
It must be run within an async runtime, such as Tokio.
It uses localhost and port 3000 by default.
*/
#[tokio::main]
async fn main() {
    let address = "127.0.0.1:3000";
    let listener = tokio::net::TcpListener::bind(address).await.unwrap();
    println!("Listening on {}", listener.local_addr().unwrap());
    axum::serve(listener, router()).await.unwrap();
}

fn router() -> Router {
    Router::new().route("/", get(hello_world))
    // Add route for keygen
    .route("/keygen", get(keygen))
}

async fn hello_world() -> &'static str {
    "Hello, World!"
} 

async fn keygen() -> &'static str {
    // Placeholder for key generation logic
    "Key generation endpoint"
}