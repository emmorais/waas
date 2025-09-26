use axum::{response::Json, response::IntoResponse};
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
pub struct WalletData {
    pub balance: i32,
    pub transactions: Vec<String>,
}

pub async fn dashboard(_auth: crate::BasicAuth) -> impl IntoResponse {
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