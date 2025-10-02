use std::collections::HashMap;

use anyhow::Result;
use axum::{extract::Json, response::Json as ResponseJson};
//use k256::Secp256k1;
use rand::{rngs::StdRng, SeedableRng};
use serde::{Deserialize, Serialize};
// SHA3 imports removed as they're not needed in the current implementation
use tss_ecdsa::{
    curve::{CurveTrait, VerifyingKeyTrait},
    keygen::KeySharePublic,
    messages::Message,
    presign::PresignRecord,
    protocol::participant_config::ParticipantConfig,
    sign::{Input as SignInput, SignParticipant},
    Identifier, Participant, ParticipantIdentifier, ProtocolParticipant
};

#[derive(Deserialize)]
pub struct SignRequest {
    pub message: String,
    pub child_index: Option<u32>, // Optional: if None, use root key (0)
}

#[derive(Serialize)]
pub struct SignResponse {
    pub signature: String,
    pub success: bool,
    pub message: String,
}

#[derive(Deserialize)]
pub struct VerifyRequest {
    pub message: String,
    pub signature: String,
    pub child_index: Option<u32>, // Optional: if None, use root key (0)
}

#[derive(Serialize)]
pub struct VerifyResponse {
    pub valid: bool,
    pub success: bool,
    pub message: String,
}

#[allow(dead_code)]
pub struct SignHelperInput {
    pub public_key_shares: Vec<KeySharePublic<tss_ecdsa::curve::TestCurve>>,
    pub saved_public_key: <tss_ecdsa::curve::TestCurve as CurveTrait>::VerifyingKey,
    pub presign_outputs: HashMap<ParticipantIdentifier, PresignRecord<tss_ecdsa::curve::TestCurve>>,
    pub chain_code: [u8; 32],
    pub inboxes: HashMap<ParticipantIdentifier, Vec<Message>>,
    pub child_index: u32,
    pub threshold: usize,
}

pub fn sign_helper(
    configs: Vec<ParticipantConfig>,
    sign_helper_input: SignHelperInput,
    message: &[u8],
    mut rng: StdRng,
) -> Result<Vec<u8>> {
    let quorum_real = configs.len();
    let sign_sid = Identifier::random(&mut rng);

    tracing::debug!(
        quorum_size = quorum_real,
        threshold = sign_helper_input.threshold,
        message_length = message.len(),
        session_id = %sign_sid,
        "🔐 Initializing signing session"
    );

    let mut presign_outputs = sign_helper_input.presign_outputs;
    let public_key_shares = sign_helper_input.public_key_shares;
    let threshold = sign_helper_input.threshold;
    let mut inboxes = sign_helper_input.inboxes;

    // Make signing participants
    tracing::debug!("👥 Creating signing participants");
    let mut sign_quorum = configs
        .clone()
        .into_iter()
        .map(|config| {
            let record = presign_outputs.remove(&config.id()).unwrap();
            let input = SignInput::new(message, record, public_key_shares.clone(), threshold, None);
            Participant::<SignParticipant<tss_ecdsa::curve::TestCurve>>::from_config(config, sign_sid, input)
        })
        .collect::<Result<Vec<_>, _>>()?;
        
    tracing::debug!(
        participants_created = sign_quorum.len(),
        "✅ Signing participants initialized"
    );

    // Ensure all participants have inboxes
    for participant in &sign_quorum {
        if !inboxes.contains_key(&participant.id()) {
            inboxes.insert(participant.id(), Vec::new());
        }
    }

    // Prepare output storage and initial "ready" messages
    let mut sign_outputs = Vec::with_capacity(quorum_real);
    for participant in &mut sign_quorum {
        let inbox = inboxes.get_mut(&participant.id()).unwrap();
        inbox.push(participant.initialize_message()?);
    }

    // Run signing protocol
    tracing::debug!("🔄 Starting signing protocol message exchange");
    let protocol_start = std::time::Instant::now();
    let mut round_count = 0;
    
    while sign_outputs.len() < quorum_real {
        let output = process_random_message(&mut sign_quorum, &mut inboxes, &mut rng)?;

        if let Some((pid, output)) = output {
            round_count += 1;
            tracing::trace!(
                participant_id = %pid,
                round = round_count,
                outputs_collected = sign_outputs.len() + 1,
                total_required = quorum_real,
                "📨 Collected signature output from participant"
            );
            sign_outputs.push(output);
        }
    }
    
    tracing::info!(
        protocol_duration_ms = protocol_start.elapsed().as_millis(),
        total_rounds = round_count,
        outputs_collected = sign_outputs.len(),
        "✅ Signing protocol completed successfully"
    );

    // Return the first signature (they should all be the same)
    // Since we're using TestCurve which defaults to K256, we know the signature type
    use std::ops::Deref;
    let signature_bytes = sign_outputs[0].deref().to_der().as_bytes().to_vec();
    
    tracing::debug!(
        signature_length = signature_bytes.len(),
        signature_hex = hex::encode(&signature_bytes[..8.min(signature_bytes.len())]),
        "🔏 Generated DER signature (showing first 8 bytes)"
    );
    
    Ok(signature_bytes)
}

fn process_random_message<R: rand::RngCore + rand::CryptoRng>(
    quorum: &mut Vec<Participant<SignParticipant<tss_ecdsa::curve::TestCurve>>>,
    inboxes: &mut HashMap<ParticipantIdentifier, Vec<Message>>,
    rng: &mut R,
) -> Result<Option<(ParticipantIdentifier, <SignParticipant<tss_ecdsa::curve::TestCurve> as ProtocolParticipant>::Output)>> {
    // Find all participants with messages
    let participants_with_messages: Vec<usize> = quorum
        .iter()
        .enumerate()
        .filter(|(_, p)| !inboxes.get(&p.id()).unwrap().is_empty())
        .map(|(i, _)| i)
        .collect();

    if participants_with_messages.is_empty() {
        return Ok(None);
    }

    use rand::seq::SliceRandom;
    // Pick a random participant with messages
    let participant_idx = *participants_with_messages.choose(rng).unwrap();
    let participant = &mut quorum[participant_idx];
    let pid = participant.id();

    // Get the inbox and pop a message
    let inbox = inboxes.get_mut(&pid).unwrap();
    if let Some(message) = inbox.pop() {
        let (output, new_messages) = participant.process_single_message(&message, rng)?;

        // Deliver new messages to their recipients
        for msg in new_messages {
            let recipient = msg.to();
            if let Some(inbox) = inboxes.get_mut(&recipient) {
                inbox.push(msg);
            }
        }

        match output {
            Some(output) => Ok(Some((pid, output))),
            None => Ok(None),
        }
    } else {
        Ok(None)
    }
}

pub async fn sign(Json(request): Json<SignRequest>) -> ResponseJson<SignResponse> {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    
    let mut hasher = DefaultHasher::new();
    request.message.hash(&mut hasher);
    let message_hash = format!("{:x}", hasher.finish());
    
    tracing::info!(
        message = %request.message,
        message_length = request.message.len(),
        message_hash = %message_hash,
        "🔐 Starting TSS signing process"
    );

    let start_time = std::time::Instant::now();
    
    let child_index = request.child_index.unwrap_or(0);
    match run_tss_sign(&request.message, child_index).await {
        Ok(signature) => {
            let duration = start_time.elapsed();
            let sig_hex = hex::encode(&signature);
            
            tracing::info!(
                message = %request.message,
                signature = %sig_hex,
                signature_length = signature.len(),
                duration_ms = duration.as_millis(),
                "✅ TSS signing completed successfully"
            );

            ResponseJson(SignResponse {
                signature: sig_hex,
                success: true,
                message: format!("Successfully signed message: '{}'", request.message),
            })
        },
        Err(e) => {
            let duration = start_time.elapsed();
            
            tracing::error!(
                message = %request.message,
                error = %e,
                duration_ms = duration.as_millis(),
                "❌ TSS signing failed"
            );
            
            ResponseJson(SignResponse {
                signature: String::new(),
                success: false,
                message: format!("Signing failed: {}", e),
            })
        }
    }
}

async fn run_tss_sign(message: &str, child_index: u32) -> anyhow::Result<Vec<u8>> {
    use tss_ecdsa::curve::TestCurve;
    use crate::keygen::KeygenHelperOutput;
    
    tracing::info!(
        threshold = 2,
        "🚀 Initializing TSS protocol participants"
    );
    
    // Run the full protocol chain to generate presign records
    // 1. Generate or restore keygen outputs
    let (configs, keygen_result): (Vec<ParticipantConfig>, KeygenHelperOutput<TestCurve>) = if is_keygen_completed() {
        tracing::info!("🔄 Loading keygen outputs from storage");
        let keygen_start = std::time::Instant::now();
        
        let (loaded_configs, loaded_keygen_result) = load_keygen_outputs()?;
        
        tracing::info!(
            duration_ms = keygen_start.elapsed().as_millis(),
            key_shares = loaded_keygen_result.keygen_outputs.len(),
            participants = loaded_configs.len(),
            "✅ Keygen data loaded from storage with configs and private shares"
        );
        
        (loaded_configs, loaded_keygen_result)
    } else {
        tracing::debug!("📋 Phase 1: Starting key generation protocol (first time)");
        let keygen_start = std::time::Instant::now();
        
        // SECURITY: Always use fresh entropy for keygen generation
        let mut keygen_rng = StdRng::from_entropy();
        let configs = ParticipantConfig::random_quorum(3, &mut keygen_rng)?;
        
        let keygen_rng = StdRng::from_entropy();
        use crate::keygen::{keygen_helper, KeygenHelperOutput};
        let keygen_result: KeygenHelperOutput<TestCurve> = {
            let keygen_inboxes: HashMap<ParticipantIdentifier, Vec<Message>> = configs
                .iter()
                .map(|config| (config.id(), Vec::new()))
                .collect();
            keygen_helper(configs.clone(), keygen_inboxes, keygen_rng)?
        };

        tracing::info!(
            duration_ms = keygen_start.elapsed().as_millis(),
            key_shares = keygen_result.keygen_outputs.len(),
            participants = configs.len(),
            "✅ Key generation completed (first time) with fresh entropy"
        );

        // Store complete keygen outputs to local storage
        store_keygen_outputs(&configs, &keygen_result)?;
        tracing::debug!("💾 Complete keygen outputs stored to local storage");
        
        (configs, keygen_result)
    };

    // 2. Generate auxinfo outputs (always fresh for security)
    tracing::debug!("🔧 Phase 2: Starting auxiliary info generation");
    let auxinfo_start = std::time::Instant::now();
    
    // SECURITY: Always use fresh entropy for auxinfo generation - NEVER cache or use deterministic seeds!
    let auxinfo_rng = StdRng::from_entropy();
    
    use crate::auxinfo::{auxinfo_helper, AuxInfoHelperOutput};
    let auxinfo_result: AuxInfoHelperOutput<TestCurve> = auxinfo_helper(configs.clone(), auxinfo_rng)?;
    
    tracing::info!(
        duration_ms = auxinfo_start.elapsed().as_millis(),
        auxinfo_outputs = auxinfo_result.auxinfo_outputs.len(),
        "✅ Auxiliary info generation completed with fresh entropy"
    );

    // Extract needed data from keygen before moving it
    let first_keygen_output = keygen_result.keygen_outputs.values().next().unwrap();
    let public_key_shares = first_keygen_output.public_key_shares().to_vec();
    let saved_public_key = first_keygen_output.public_key()?;
    let chain_code = *first_keygen_output.chain_code();

    // 3. Generate presign outputs (always fresh for security)
    tracing::debug!("📝 Phase 3: Starting presignature generation");
    let presign_start = std::time::Instant::now();
    
    // SECURITY: Always use fresh entropy for secure presign generation - NEVER use deterministic seeds!
    let presign_rng = StdRng::from_entropy();
    
    use crate::presign::{presign_helper, PresignHelperOutput};
    let presign_result: PresignHelperOutput<TestCurve> = {
        let mut inboxes = auxinfo_result.inboxes;
        presign_helper(
            configs.clone(), 
            auxinfo_result.auxinfo_outputs, 
            keygen_result.keygen_outputs, 
            &mut inboxes, 
            presign_rng
        )?
    };
    
    tracing::info!(
        duration_ms = presign_start.elapsed().as_millis(),
        presign_records = presign_result.presign_outputs.len(),
        "✅ Presignature generation completed with fresh entropy"
    );
    
    // Initialize fresh inboxes for all participants
    let sign_inboxes: HashMap<ParticipantIdentifier, Vec<Message>> = configs
        .iter()
        .map(|config| (config.id(), Vec::new()))
        .collect();

    let sign_helper_input = SignHelperInput {
        public_key_shares,
        saved_public_key,
        presign_outputs: presign_result.presign_outputs,
        chain_code,
        inboxes: sign_inboxes,
        child_index,
        threshold: 2, // t-of-n threshold
    };

    // Store the public key for verification use
    tracing::debug!("💾 Storing public key for future verification");
    store_public_key_for_verification(&saved_public_key)?;
    tracing::debug!("✅ Public key stored successfully");

    // Run the signing protocol
    tracing::debug!("✍️ Phase 4: Starting signature generation");
    let sign_start = std::time::Instant::now();
    
    // Use fresh entropy for each signature (this should vary between messages)
    let signing_rng = StdRng::from_entropy();
    
    let signature_bytes = sign_helper(configs, sign_helper_input, message.as_bytes(), signing_rng)?;
    
    tracing::info!(
        duration_ms = sign_start.elapsed().as_millis(),
        signature_size = signature_bytes.len(),
        "✅ Signature generation completed"
    );
    
    Ok(signature_bytes)
}

// Simple storage mechanism for the public key (in a real app, this would be in a database)
fn store_public_key_for_verification(public_key: &<tss_ecdsa::curve::TestCurve as CurveTrait>::VerifyingKey) -> Result<()> {
    use std::fs;
    
    // Convert public key to bytes for storage
    let public_key_bytes = public_key.to_sec1_bytes();
    
    tracing::debug!(
        key_size_bytes = public_key_bytes.len(),
        storage_path = "public_key.bin",
        "💾 Storing public key to filesystem"
    );
    
    fs::write("public_key.bin", &public_key_bytes)?;
    
    tracing::info!(
        key_size_bytes = public_key_bytes.len(),
        "✅ Public key stored successfully for future verification"
    );
    
    Ok(())
}

fn load_public_key_for_verification_with_child(child_index: u32) -> Result<Option<<tss_ecdsa::curve::TestCurve as CurveTrait>::VerifyingKey>> {
    // NOTE: Currently, all signatures are generated using the root TSS private key shares
    // regardless of child_index, because TSS child key derivation for private shares
    // is not yet implemented in the TSS library.
    // 
    // Therefore, for consistency, we always verify against the root public key
    // until full HD-TSS support is available.
    
    if child_index == 0 {
        tracing::debug!("🔑 Loading root key for verification (child index 0)");
        load_public_key_for_verification()
    } else {
        // For child keys, check if they exist in the HD key store first
        use crate::hd_keys::{load_hd_key_store};
        let store = load_hd_key_store()?;
        
        if let Some(_key_info) = store.get_key(child_index) {
            tracing::info!(
                child_index = child_index,
                "🔑 Child key exists in store, but using root key for verification (TSS limitation)"
            );
            
            // Use root key for verification since signing also uses root TSS key
            load_public_key_for_verification()
        } else {
            anyhow::bail!("Child key {} not found in HD key store", child_index);
        }
    }
}

fn load_public_key_for_verification() -> Result<Option<<tss_ecdsa::curve::TestCurve as CurveTrait>::VerifyingKey>> {
    use std::fs;
    
    tracing::debug!(
        storage_path = "public_key.bin",
        "📂 Attempting to load public key from filesystem"
    );
    
    if let Ok(bytes) = fs::read("public_key.bin") {
        tracing::debug!(
            key_size_bytes = bytes.len(),
            "✅ Public key file found, reconstructing verifying key"
        );
        
        // Reconstruct the verifying key from bytes
        let verifying_key = <tss_ecdsa::curve::TestCurve as CurveTrait>::VerifyingKey::from_sec1_bytes(&bytes)
            .map_err(|e| {
                tracing::error!(
                    error = %e,
                    "❌ Failed to reconstruct public key from stored bytes"
                );
                anyhow::anyhow!("Failed to reconstruct public key from bytes")
            })?;
            
        tracing::debug!("✅ Public key reconstructed successfully");
        Ok(Some(verifying_key))
    } else {
        tracing::warn!("⚠️ No public key file found - verification requires a previous signing operation");
        Ok(None)
    }
}

// Direct keygen output storage and loading - serialize the entire keygen result
pub fn store_keygen_outputs(
    configs: &Vec<ParticipantConfig>,
    keygen_result: &crate::keygen::KeygenHelperOutput<tss_ecdsa::curve::TestCurve>
) -> Result<()> {
    use std::fs;
    
    tracing::debug!(
        configs_count = configs.len(),
        keygen_outputs_count = keygen_result.keygen_outputs.len(),
        "💾 Storing complete keygen result with all private shares to filesystem"
    );
    
    // Serialize the entire KeygenHelperOutput directly (including all private shares)
    let keygen_json = serde_json::to_string_pretty(keygen_result)
        .map_err(|e| anyhow::anyhow!("Failed to serialize keygen result: {}", e))?;
    
    // Serialize configs separately using bincode for compatibility
    let configs_bincode = bincode::serialize(configs)
        .map_err(|e| anyhow::anyhow!("Failed to serialize configs: {}", e))?;
    
    // Write both files
    fs::write("keygen_result.json", keygen_json)?;
    fs::write("keygen_configs.bin", configs_bincode)?;
    fs::write("keygen_completed.marker", "1")?;
    
    tracing::info!(
        configs_count = configs.len(),
        outputs_count = keygen_result.keygen_outputs.len(),
        "✅ Complete keygen result and configs stored successfully with all private shares"
    );
    
    Ok(())
}

pub fn load_keygen_outputs() -> Result<(Vec<ParticipantConfig>, crate::keygen::KeygenHelperOutput<tss_ecdsa::curve::TestCurve>)> {
    use std::fs;
    
    tracing::debug!(
        keygen_path = "keygen_result.json",
        configs_path = "keygen_configs.bin",
        "📂 Loading complete keygen result and configs from storage"
    );
    
    // Load keygen result
    let keygen_json = fs::read_to_string("keygen_result.json")
        .map_err(|_| anyhow::anyhow!("No keygen result found - will generate new keys"))?;
        
    let keygen_result: crate::keygen::KeygenHelperOutput<tss_ecdsa::curve::TestCurve> = 
        serde_json::from_str(&keygen_json)
            .map_err(|e| anyhow::anyhow!("Failed to deserialize keygen result: {}", e))?;
    
    // Load configs
    let configs_bincode = fs::read("keygen_configs.bin")
        .map_err(|_| anyhow::anyhow!("No keygen configs found"))?;
        
    let configs: Vec<ParticipantConfig> = bincode::deserialize(&configs_bincode)
        .map_err(|e| anyhow::anyhow!("Failed to deserialize configs: {}", e))?;
    
    tracing::info!(
        configs_count = configs.len(),
        outputs_count = keygen_result.keygen_outputs.len(),
        "✅ Complete keygen result and configs loaded successfully from storage"
    );
    
    Ok((configs, keygen_result))
}

pub fn is_keygen_completed() -> bool {
    use std::fs;
    
    tracing::debug!(
        marker_path = "keygen_completed.marker",
        keygen_path = "keygen_result.json",
        configs_path = "keygen_configs.bin",
        "📂 Checking for keygen completion"
    );
    
    let marker_exists = fs::metadata("keygen_completed.marker").is_ok();
    let keygen_exists = fs::metadata("keygen_result.json").is_ok();
    let configs_exist = fs::metadata("keygen_configs.bin").is_ok();
    let completed = marker_exists && keygen_exists && configs_exist;
    
    tracing::debug!(
        marker_exists = marker_exists,
        keygen_exists = keygen_exists,
        configs_exist = configs_exist,
        keygen_completed = completed,
        "🔍 Keygen completion status checked"
    );
    
    completed
}



pub async fn verify(Json(request): Json<VerifyRequest>) -> ResponseJson<VerifyResponse> {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    
    let mut hasher = DefaultHasher::new();
    request.message.hash(&mut hasher);
    let message_hash = format!("{:x}", hasher.finish());
    
    tracing::info!(
        message = %request.message,
        message_length = request.message.len(),
        message_hash = %message_hash,
        signature_length = request.signature.len(),
        signature_preview = %request.signature.get(..16.min(request.signature.len())).unwrap_or(""),
        "🔍 Starting signature verification"
    );

    let start_time = std::time::Instant::now();
    
    let child_index = request.child_index.unwrap_or(0);
    match run_verification(&request.message, &request.signature, child_index).await {
        Ok(is_valid) => {
            let duration = start_time.elapsed();
            
            tracing::info!(
                message = %request.message,
                signature_valid = is_valid,
                duration_ms = duration.as_millis(),
                result = if is_valid { "VALID" } else { "INVALID" },
                "🔍 Signature verification completed"
            );

            ResponseJson(VerifyResponse {
                valid: is_valid,
                success: true,
                message: if is_valid {
                    format!("✅ Signature is valid for message: '{}'", request.message)
                } else {
                    format!("❌ Signature is NOT valid for message: '{}'", request.message)
                },
            })
        },
        Err(e) => {
            let duration = start_time.elapsed();
            
            tracing::error!(
                message = %request.message,
                error = %e,
                duration_ms = duration.as_millis(),
                "❌ Signature verification failed with error"
            );
            
            ResponseJson(VerifyResponse {
                valid: false,
                success: false,
                message: format!("Verification error: {}", e),
            })
        }
    }
}

async fn run_verification(message: &str, signature_hex: &str, child_index: u32) -> anyhow::Result<bool> {
    // Load the stored public key for the specified child index
    tracing::debug!(
        child_index = child_index,
        "📂 Loading stored public key for verification"
    );
    let public_key = load_public_key_for_verification_with_child(child_index)?
        .ok_or_else(|| anyhow::anyhow!("No public key found for child index {}. Please derive or generate the key first.", child_index))?;
    tracing::debug!("✅ Public key loaded successfully");

    // Decode the signature from hex
    tracing::debug!(
        signature_hex_length = signature_hex.len(),
        "🔓 Decoding signature from hex format"
    );
    let signature_bytes = hex::decode(signature_hex)
        .map_err(|_| anyhow::anyhow!("Invalid signature format. Expected hex string."))?;
    tracing::debug!(
        signature_bytes_length = signature_bytes.len(),
        "✅ Signature decoded from hex"
    );

    // Parse the DER-encoded signature using k256's from_der method
    tracing::debug!("📋 Parsing DER-encoded signature");
    use k256::ecdsa::Signature as K256Signature;
    let k256_signature = K256Signature::from_der(&signature_bytes)
        .map_err(|_| anyhow::anyhow!("Failed to parse DER signature"))?;
    tracing::debug!("✅ DER signature parsed successfully");
    
    // Extract r and s scalars from the k256 signature to recreate TSS signature
    tracing::debug!("🔢 Extracting r and s scalars from k256 signature");
    let (r_scalar, s_scalar) = k256_signature.split_scalars();
    
    // Convert scalars to BigNumbers for TSS signature creation
    use tss_ecdsa::curve::{TestCurve, ScalarTrait};
    let r_bytes = r_scalar.to_bytes();
    let s_bytes = s_scalar.to_bytes();
    
    tracing::debug!(
        r_scalar_length = r_bytes.len(),
        s_scalar_length = s_bytes.len(),
        "🔄 Converting scalars to TSS format"
    );
    
    // Use the TSS library's BigNumber type (accessed through the curve trait)
    let r_scalar_tss = <TestCurve as CurveTrait>::Scalar::from_repr(r_bytes.to_vec());
    let s_scalar_tss = <TestCurve as CurveTrait>::Scalar::from_repr(s_bytes.to_vec());
    let r_bn = <TestCurve as CurveTrait>::scalar_to_bn(&r_scalar_tss);
    let s_bn = <TestCurve as CurveTrait>::scalar_to_bn(&s_scalar_tss);
    
    // Create TSS signature using from_scalars
    tracing::debug!("🏗️ Reconstructing TSS signature from scalars");
    use tss_ecdsa::curve::SignatureTrait;
    let signature = <tss_ecdsa::curve::TestCurve as CurveTrait>::ECDSASignature::from_scalars(&r_bn, &s_bn)
        .map_err(|_| anyhow::anyhow!("Failed to create TSS signature from scalars"))?;
    tracing::debug!("✅ TSS signature reconstructed successfully");

    // Create the message digest (same as used in signing)
    tracing::debug!("🏷️ Computing message digest using Keccak256");
    use sha3::{Digest, Keccak256};
    let digest = Keccak256::new_with_prefix(message.as_bytes());
    tracing::debug!("✅ Message digest computed");

    // Verify the signature
    tracing::debug!("🔍 Performing cryptographic signature verification");
    let verification_start = std::time::Instant::now();
    
    match public_key.verify_signature(digest, signature) {
        Ok(_) => {
            let verification_duration = verification_start.elapsed();
            tracing::debug!(
                verification_duration_us = verification_duration.as_micros(),
                "✅ Cryptographic verification succeeded"
            );
            Ok(true)
        },
        Err(e) => {
            let verification_duration = verification_start.elapsed();
            tracing::debug!(
                verification_duration_us = verification_duration.as_micros(),
                error = %e,
                "❌ Cryptographic verification failed"
            );
            Ok(false)
        }
    }
}
