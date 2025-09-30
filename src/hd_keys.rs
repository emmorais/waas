use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use axum::{extract::Json, response::Json as ResponseJson};
use anyhow::Result;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DerivedKeyInfo {
    pub child_index: u32,
    pub public_key_hex: String,
    pub created_at: String,
    pub label: Option<String>, // Optional user-friendly name
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HdKeyStore {
    pub root_key: Option<DerivedKeyInfo>,
    pub derived_keys: HashMap<u32, DerivedKeyInfo>,
}

impl HdKeyStore {
    pub fn new() -> Self {
        Self {
            root_key: None,
            derived_keys: HashMap::new(),
        }
    }

    pub fn add_root_key(&mut self, public_key_hex: String) {
        self.root_key = Some(DerivedKeyInfo {
            child_index: 0,
            public_key_hex,
            created_at: chrono::Utc::now().to_rfc3339(),
            label: Some("Root Key".to_string()),
        });
    }

    pub fn add_derived_key(&mut self, child_index: u32, public_key_hex: String, label: Option<String>) {
        self.derived_keys.insert(child_index, DerivedKeyInfo {
            child_index,
            public_key_hex,
            created_at: chrono::Utc::now().to_rfc3339(),
            label,
        });
    }

    pub fn remove_key(&mut self, child_index: u32) -> bool {
        if child_index == 0 {
            let had_root = self.root_key.is_some();
            self.root_key = None;
            had_root
        } else {
            self.derived_keys.remove(&child_index).is_some()
        }
    }

    pub fn get_key(&self, child_index: u32) -> Option<&DerivedKeyInfo> {
        if child_index == 0 {
            self.root_key.as_ref()
        } else {
            self.derived_keys.get(&child_index)
        }
    }

    pub fn list_all_keys(&self) -> Vec<&DerivedKeyInfo> {
        let mut keys = Vec::new();
        if let Some(ref root) = self.root_key {
            keys.push(root);
        }
        keys.extend(self.derived_keys.values());
        keys.sort_by_key(|k| k.child_index);
        keys
    }
}

// Storage functions
pub fn load_hd_key_store() -> Result<HdKeyStore> {
    use std::fs;
    
    if let Ok(data) = fs::read_to_string("hd_keys.json") {
        Ok(serde_json::from_str(&data)?)
    } else {
        Ok(HdKeyStore::new())
    }
}

pub fn save_hd_key_store(store: &HdKeyStore) -> Result<()> {
    use std::fs;
    
    let data = serde_json::to_string_pretty(store)?;
    fs::write("hd_keys.json", data)?;
    Ok(())
}

// API Response structures
#[derive(Serialize)]
pub struct DeriveKeyResponse {
    pub success: bool,
    pub message: String,
    pub child_index: Option<u32>,
    pub public_key: Option<String>,
    pub label: Option<String>,
}

#[derive(Serialize)]
pub struct ListKeysResponse {
    pub success: bool,
    pub keys: Vec<DerivedKeyInfo>,
}

#[derive(Deserialize)]
pub struct DeriveKeyRequest {
    pub child_index: Option<u32>, // If None, auto-generate next available
    pub label: Option<String>,
}

#[derive(Deserialize)]
pub struct DeleteKeyRequest {
    pub child_index: u32,
}

#[derive(Serialize)]
pub struct DeleteKeyResponse {
    pub success: bool,
    pub message: String,
    pub deleted_child_index: Option<u32>,
}

// Handler functions for API endpoints
pub async fn derive_key(Json(request): Json<DeriveKeyRequest>) -> ResponseJson<DeriveKeyResponse> {
    tracing::info!(
        requested_child_index = ?request.child_index,
        label = ?request.label,
        "🔑 Starting child key derivation"
    );

    let start_time = std::time::Instant::now();
    
    match derive_child_key_impl(request.child_index, request.label).await {
        Ok(response) => {
            let duration = start_time.elapsed();
            tracing::info!(
                child_index = ?response.child_index,
                duration_ms = duration.as_millis(),
                "✅ Child key derivation completed successfully"
            );
            ResponseJson(response)
        },
        Err(e) => {
            let duration = start_time.elapsed();
            tracing::error!(
                error = %e,
                duration_ms = duration.as_millis(),
                "❌ Child key derivation failed"
            );
            ResponseJson(DeriveKeyResponse {
                success: false,
                message: format!("Key derivation failed: {}", e),
                child_index: None,
                public_key: None,
                label: None,
            })
        }
    }
}

pub async fn list_keys(_auth: crate::BasicAuth) -> ResponseJson<ListKeysResponse> {
    tracing::debug!("📋 Listing all derived keys");
    
    match load_hd_key_store() {
        Ok(store) => {
            let keys: Vec<DerivedKeyInfo> = store.list_all_keys().into_iter().cloned().collect();
            tracing::info!(
                total_keys = keys.len(),
                "📋 Retrieved key list successfully"
            );
            ResponseJson(ListKeysResponse {
                success: true,
                keys,
            })
        },
        Err(e) => {
            tracing::error!(
                error = %e,
                "❌ Failed to load HD key store"
            );
            ResponseJson(ListKeysResponse {
                success: false,
                keys: vec![],
            })
        }
    }
}

pub async fn delete_child_key(Json(request): Json<DeleteKeyRequest>) -> ResponseJson<DeleteKeyResponse> {
    tracing::info!(
        child_index = request.child_index,
        "🗑️ Deleting child key"
    );

    match delete_child_key_impl(request.child_index) {
        Ok(_) => {
            tracing::info!(
                child_index = request.child_index,
                "✅ Child key deleted successfully"
            );
            ResponseJson(DeleteKeyResponse {
                success: true,
                message: format!("Child key {} deleted successfully", request.child_index),
                deleted_child_index: Some(request.child_index),
            })
        },
        Err(e) => {
            tracing::error!(
                child_index = request.child_index,
                error = %e,
                "❌ Failed to delete child key"
            );
            ResponseJson(DeleteKeyResponse {
                success: false,
                message: format!("Failed to delete child key: {}", e),
                deleted_child_index: None,
            })
        }
    }
}

// Implementation functions
async fn derive_child_key_impl(requested_index: Option<u32>, label: Option<String>) -> Result<DeriveKeyResponse> {
    // Check if root keygen exists
    if !crate::sign::is_keygen_completed() {
        anyhow::bail!("No root key found. Please generate keys first using the keygen button.");
    }

    // Load HD key store
    let mut store = load_hd_key_store()?;
    
    // Determine child index
    let child_index = match requested_index {
        Some(index) => {
            if index == 0 {
                anyhow::bail!("Child index 0 is reserved for the root key");
            }
            if store.get_key(index).is_some() {
                anyhow::bail!("Child key with index {} already exists", index);
            }
            index
        },
        None => {
            // Auto-generate next available index
            let existing_indices: Vec<u32> = store.derived_keys.keys().cloned().collect();
            let mut next_index = 1u32;
            while existing_indices.contains(&next_index) {
                next_index += 1;
            }
            next_index
        }
    };

    // Real HD key derivation using cryptographic methods
    let (public_key_hex, derived_key_bytes) = derive_child_key_real(child_index)?;
    
    // Store the actual derived public key for verification
    store_child_public_key(child_index, &derived_key_bytes)?;
    
    // Add to store
    store.add_derived_key(child_index, public_key_hex.clone(), label.clone());
    save_hd_key_store(&store)?;

    // Also initialize root key if not present
    if store.root_key.is_none() {
        let root_public_key = get_root_public_key()?;
        store.add_root_key(root_public_key);
        save_hd_key_store(&store)?;
    }

    Ok(DeriveKeyResponse {
        success: true,
        message: format!("Child key {} derived successfully", child_index),
        child_index: Some(child_index),
        public_key: Some(public_key_hex),
        label,
    })
}

fn delete_child_key_impl(child_index: u32) -> Result<()> {
    let mut store = load_hd_key_store()?;
    
    if child_index == 0 {
        anyhow::bail!("Cannot delete root key using this endpoint. Use the main delete_key endpoint instead.");
    }
    
    if !store.remove_key(child_index) {
        anyhow::bail!("Child key with index {} not found", child_index);
    }
    
    save_hd_key_store(&store)?;
    
    // Also delete any associated storage files for this child key
    use std::fs;
    let _ = fs::remove_file(format!("public_key_child_{}.bin", child_index));
    
    Ok(())
}

// Helper functions
fn derive_child_key_real(child_index: u32) -> Result<(String, Vec<u8>)> {
    // Real HD key derivation using HMAC-based key derivation
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    
    tracing::debug!(
        child_index = child_index,
        "🔑 Starting real HD key derivation"
    );
    
    // Get root public key and chain code from keygen essentials
    let (root_public_key, chain_code) = get_root_key_and_chain_code()?;
    
    tracing::debug!(
        root_key_size = root_public_key.len(),
        chain_code_size = chain_code.len(),
        "📂 Loaded root key material for derivation"
    );
    
    // Create HMAC key from chain code
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(&chain_code)
        .map_err(|_| anyhow::anyhow!("Failed to create HMAC from chain code"))?;
    
    // Add public key and child index to HMAC
    mac.update(&root_public_key);
    mac.update(&child_index.to_be_bytes());
    
    // Compute the derived key material
    let derived_material = mac.finalize().into_bytes();
    
    tracing::debug!(
        derived_material_size = derived_material.len(),
        "🧮 Computed derived key material using HMAC-SHA256"
    );
    
    // Split derived material: first 32 bytes for key, remaining for new chain code
    let key_bytes = &derived_material[..32];
    
    // For secp256k1, we need to ensure the key is a valid scalar
    // Convert to a proper public key by deriving from the root key
    let derived_public_key = derive_public_key_from_material(&root_public_key, key_bytes)?;
    
    let public_key_hex = hex::encode(&derived_public_key);
    
    tracing::info!(
        child_index = child_index,
        public_key_hex = %public_key_hex[..16],
        "✅ Successfully derived child key (showing first 16 hex chars)"
    );
    
    Ok((public_key_hex, derived_public_key))
}

fn derive_public_key_from_material(root_key_bytes: &[u8], key_material: &[u8]) -> Result<Vec<u8>> {
    use k256::{PublicKey, Scalar, ProjectivePoint};
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    use k256::elliptic_curve::PrimeField;
    
    tracing::debug!("🔄 Deriving public key from key material");
    
    // Parse root public key
    let root_public_key = PublicKey::from_sec1_bytes(root_key_bytes)
        .map_err(|e| anyhow::anyhow!("Failed to parse root public key: {}", e))?;
    
    // Create scalar from key material (mod curve order)
    let scalar_bytes: [u8; 32] = key_material.try_into()
        .map_err(|_| anyhow::anyhow!("Key material must be 32 bytes"))?;
    
    // Create scalar from bytes using PrimeField trait
    let scalar = Scalar::from_repr(scalar_bytes.into())
        .into_option()
        .ok_or_else(|| anyhow::anyhow!("Invalid scalar from key material"))?;
    
    // Convert root public key to projective point
    let root_point = ProjectivePoint::from(*root_public_key.as_affine());
    
    // Derive child public key: child_pk = root_pk + scalar * G
    let derived_point = root_point + (ProjectivePoint::GENERATOR * scalar);
    
    // Convert back to affine and then to public key
    let derived_affine = derived_point.to_affine();
    let derived_public_key = PublicKey::from_affine(derived_affine)
        .map_err(|e| anyhow::anyhow!("Failed to create public key from derived point: {}", e))?;
    
    // Convert to SEC1 bytes
    let derived_bytes = derived_public_key.to_encoded_point(true).as_bytes().to_vec();
    
    tracing::debug!(
        derived_key_size = derived_bytes.len(),
        "✅ Derived public key computed successfully"
    );
    
    Ok(derived_bytes)
}

fn get_root_key_and_chain_code() -> Result<(Vec<u8>, [u8; 32])> {
    tracing::debug!("📂 Loading root key and chain code from keygen result");
    
    // Load the complete keygen result from storage
    use crate::sign::load_keygen_outputs;
    let (_configs, keygen_result) = load_keygen_outputs()?;
    
    // Extract root key material from the first keygen output
    let first_keygen_output = keygen_result.keygen_outputs.values().next()
        .ok_or_else(|| anyhow::anyhow!("No keygen outputs found in loaded data"))?;
    
    let public_key = first_keygen_output.public_key()
        .map_err(|e| anyhow::anyhow!("Failed to get public key: {}", e))?;
    let chain_code = *first_keygen_output.chain_code();
    let public_key_bytes = public_key.to_sec1_bytes().to_vec();
    
    tracing::debug!(
        root_key_size = public_key_bytes.len(),
        chain_code_size = chain_code.len(),
        "✅ Successfully loaded root key material from keygen result"
    );
    
    Ok((public_key_bytes, chain_code))
}

fn store_child_public_key(child_index: u32, key_bytes: &[u8]) -> Result<()> {
    use std::fs;
    
    let filename = format!("public_key_child_{}.bin", child_index);
    
    tracing::debug!(
        child_index = child_index,
        key_size = key_bytes.len(),
        filename = %filename,
        "💾 Storing derived child public key to file"
    );
    
    fs::write(&filename, key_bytes)
        .map_err(|e| anyhow::anyhow!("Failed to store child public key {}: {}", child_index, e))?;
    
    tracing::info!(
        child_index = child_index,
        filename = %filename,
        "✅ Child public key stored successfully"
    );
    
    Ok(())
}

fn get_root_public_key() -> Result<String> {
    use std::fs;
    
    // Try to load from public_key.bin first
    if let Ok(bytes) = fs::read("public_key.bin") {
        return Ok(hex::encode(bytes));
    }
    
    // Fallback: try to get from stored keygen result
    if let Ok(_) = fs::metadata("keygen_result.json") {
        // Get the public key from keygen result
        let (public_key_bytes, _chain_code) = get_root_key_and_chain_code()?;
        return Ok(hex::encode(&public_key_bytes));
    }
    
    anyhow::bail!("No root public key found")
}
