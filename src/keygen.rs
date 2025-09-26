use axum::{response::Json, response::IntoResponse};
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
pub struct KeygenResponse {
    pub public_key: String,
    pub private_key: String,
    pub message: String,
}

pub async fn keygen(_auth: crate::BasicAuth) -> impl IntoResponse {
    let response = KeygenResponse {
        public_key: "sample_public_key_12345".to_string(),
        private_key: "sample_private_key_67890".to_string(),
        message: "Key pair generated successfully".to_string(),
    };
    Json(response)
}
