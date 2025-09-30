use axum::{response::Json, http::StatusCode};
use serde::{Serialize, Deserialize};
use std::fs;
use anyhow::Result;

#[derive(Serialize, Deserialize)]
pub struct DeleteKeyResponse {
    pub success: bool,
    pub message: String,
    pub deleted_files: Vec<String>,
}

/// Delete all key material and associated data from local storage
pub async fn delete_key(_auth: crate::BasicAuth) -> Result<Json<DeleteKeyResponse>, (StatusCode, Json<DeleteKeyResponse>)> {
    tracing::info!("🗑️ Starting key deletion process");
    let start_time = std::time::Instant::now();
    
    match delete_all_key_material().await {
        Ok(deleted_files) => {
            let duration = start_time.elapsed();
            tracing::info!(
                deleted_files_count = deleted_files.len(),
                duration_ms = duration.as_millis(),
                files = ?deleted_files,
                "✅ Key deletion completed successfully"
            );
            
            Ok(Json(DeleteKeyResponse {
                success: true,
                message: format!("Successfully deleted {} key files from local storage", deleted_files.len()),
                deleted_files,
            }))
        },
        Err(e) => {
            let duration = start_time.elapsed();
            tracing::error!(
                error = %e,
                duration_ms = duration.as_millis(),
                "❌ Key deletion failed"
            );
            
            Err((StatusCode::INTERNAL_SERVER_ERROR, Json(DeleteKeyResponse {
                success: false,
                message: format!("Key deletion failed: {}", e),
                deleted_files: vec![],
            })))
        }
    }
}

async fn delete_all_key_material() -> Result<Vec<String>> {
    let mut deleted_files = Vec::new();
    
    // List all key-related files that should be deleted
    let key_files = [
        "keygen_completed.marker",    // Keygen completion marker
        "keygen_essentials.json",     // Stored keygen configurations and essentials
        "public_key.bin",             // Public key for verification
        "auxinfo_outputs.json",       // Auxiliary info outputs (if cached)
        "presign_outputs.json",       // Presign outputs (if cached)
    ];
    
    tracing::debug!(
        files_to_check = key_files.len(),
        "🔍 Checking for key files to delete"
    );
    
    // Attempt to delete each file
    for file_path in &key_files {
        match delete_file_if_exists(file_path) {
            Ok(was_deleted) => {
                if was_deleted {
                    deleted_files.push(file_path.to_string());
                    tracing::debug!(
                        file = file_path,
                        "✅ File deleted successfully"
                    );
                } else {
                    tracing::debug!(
                        file = file_path,
                        "ℹ️ File did not exist (skipped)"
                    );
                }
            },
            Err(e) => {
                tracing::warn!(
                    file = file_path,
                    error = %e,
                    "⚠️ Failed to delete file"
                );
                // Continue with other files even if one fails
            }
        }
    }
    
    // Also check for any additional key-related files with common patterns
    let patterns_to_check = [
        "*.key",
        "tss_*.json",
        "*_key_*",
    ];
    
    for pattern in &patterns_to_check {
        if let Ok(matching_files) = find_files_by_pattern(pattern) {
            for file_path in matching_files {
                match delete_file_if_exists(&file_path) {
                    Ok(was_deleted) => {
                        if was_deleted {
                            deleted_files.push(file_path.clone());
                            tracing::debug!(
                                file = %file_path,
                                "✅ Pattern-matched file deleted"
                            );
                        }
                    },
                    Err(e) => {
                        tracing::warn!(
                            file = %file_path,
                            error = %e,
                            "⚠️ Failed to delete pattern-matched file"
                        );
                    }
                }
            }
        }
    }
    
    if deleted_files.is_empty() {
        tracing::info!("ℹ️ No key files found to delete - storage was already clean");
        return Ok(vec!["No key files found".to_string()]);
    }
    
    tracing::info!(
        deleted_count = deleted_files.len(),
        "🧹 Key material cleanup completed"
    );
    
    Ok(deleted_files)
}

fn delete_file_if_exists(file_path: &str) -> Result<bool> {
    if fs::metadata(file_path).is_ok() {
        fs::remove_file(file_path)
            .map_err(|e| anyhow::anyhow!("Failed to delete file '{}': {}", file_path, e))?;
        Ok(true) // File existed and was deleted
    } else {
        Ok(false) // File did not exist
    }
}

fn find_files_by_pattern(pattern: &str) -> Result<Vec<String>> {
    // Simple pattern matching for wallet key file patterns (excludes TLS .pem files)
    let current_dir = std::env::current_dir()?;
    let mut matching_files = Vec::new();
    
    if let Ok(entries) = fs::read_dir(&current_dir) {
        for entry in entries {
            if let Ok(entry) = entry {
                let file_name = entry.file_name();
                let file_name_str = file_name.to_string_lossy();
                
                // Simple pattern matching
                let matches = match pattern {
                    "*.key" => file_name_str.ends_with(".key"),
                    "tss_*.json" => file_name_str.starts_with("tss_") && file_name_str.ends_with(".json"),
                    "*_key_*" => file_name_str.contains("_key_"),
                    _ => false,
                };
                
                if matches {
                    matching_files.push(file_name_str.to_string());
                }
            }
        }
    }
    
    Ok(matching_files)
}

/// Check if any key material exists in local storage
pub async fn check_key_existence() -> bool {
    let key_files = [
        "keygen_completed.marker",
        "keygen_essentials.json", 
        "public_key.bin",
    ];
    
    key_files.iter().any(|file| fs::metadata(file).is_ok())
}
