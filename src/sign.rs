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
}

#[derive(Serialize)]
pub struct VerifyResponse {
    pub valid: bool,
    pub success: bool,
    pub message: String,
}

#[derive(Debug)]
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

    let mut presign_outputs = sign_helper_input.presign_outputs;
    let public_key_shares = sign_helper_input.public_key_shares;
    let threshold = sign_helper_input.threshold;
    let mut inboxes = sign_helper_input.inboxes;

    // Make signing participants
    let mut sign_quorum = configs
        .clone()
        .into_iter()
        .map(|config| {
            let record = presign_outputs.remove(&config.id()).unwrap();
            let input = SignInput::new(message, record, public_key_shares.clone(), threshold, None);
            Participant::<SignParticipant<tss_ecdsa::curve::TestCurve>>::from_config(config, sign_sid, input)
        })
        .collect::<Result<Vec<_>, _>>()?;

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
    while sign_outputs.len() < quorum_real {
        let output = process_random_message(&mut sign_quorum, &mut inboxes, &mut rng)?;

        if let Some((_pid, output)) = output {
            sign_outputs.push(output);
        }
    }

    // Return the first signature (they should all be the same)
    // Since we're using TestCurve which defaults to K256, we know the signature type
    use std::ops::Deref;
    Ok(sign_outputs[0].deref().to_der().as_bytes().to_vec())
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
    match run_tss_sign(&request.message).await {
        Ok(signature) => ResponseJson(SignResponse {
            signature: hex::encode(signature),
            success: true,
            message: format!("Successfully signed message: '{}'", request.message),
        }),
        Err(e) => {
            tracing::error!("Signing failed: {}", e);
            ResponseJson(SignResponse {
                signature: String::new(),
                success: false,
                message: format!("Signing failed: {}", e),
            })
        }
    }
}

async fn run_tss_sign(message: &str) -> anyhow::Result<Vec<u8>> {
    use tss_ecdsa::curve::TestCurve;
    
    let mut rng = StdRng::from_entropy();
    let configs = ParticipantConfig::random_quorum(3, &mut rng)?;
    
    // Run the full protocol chain to generate presign records
    // 1. Generate keygen outputs
    use crate::keygen::{keygen_helper, KeygenHelperOutput};
    let keygen_result: KeygenHelperOutput<TestCurve> = {
        let keygen_inboxes: HashMap<ParticipantIdentifier, Vec<Message>> = configs
            .iter()
            .map(|config| (config.id(), Vec::new()))
            .collect();
        keygen_helper(configs.clone(), keygen_inboxes, rng.clone())?
    };

    // 2. Generate auxinfo outputs
    use crate::auxinfo::{auxinfo_helper, AuxInfoHelperOutput};
    let auxinfo_result: AuxInfoHelperOutput<TestCurve> = auxinfo_helper(configs.clone(), rng.clone())?;

    // Extract needed data from keygen before moving it
    let first_keygen_output = keygen_result.keygen_outputs.values().next().unwrap();
    let public_key_shares = first_keygen_output.public_key_shares().to_vec();
    let saved_public_key = first_keygen_output.public_key()?;
    let chain_code = *first_keygen_output.chain_code();

    // 3. Generate presign outputs
    use crate::presign::{presign_helper, PresignHelperOutput};
    let presign_result: PresignHelperOutput<TestCurve> = {
        let mut inboxes = auxinfo_result.inboxes;
        presign_helper(
            configs.clone(), 
            auxinfo_result.auxinfo_outputs, 
            keygen_result.keygen_outputs, 
            &mut inboxes, 
            rng.clone()
        )?
    };
    
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
        child_index: 0,
        threshold: 2, // t-of-n threshold
    };

    // Store the public key for verification use
    store_public_key_for_verification(&saved_public_key)?;

    // Run the signing protocol
    sign_helper(configs, sign_helper_input, message.as_bytes(), rng)
}

// Simple storage mechanism for the public key (in a real app, this would be in a database)
fn store_public_key_for_verification(public_key: &<tss_ecdsa::curve::TestCurve as CurveTrait>::VerifyingKey) -> Result<()> {
    use std::fs;
    
    // Convert public key to bytes for storage
    let public_key_bytes = public_key.to_sec1_bytes();
    fs::write("public_key.bin", public_key_bytes)?;
    Ok(())
}

fn load_public_key_for_verification() -> Result<Option<<tss_ecdsa::curve::TestCurve as CurveTrait>::VerifyingKey>> {
    use std::fs;
    
    if let Ok(bytes) = fs::read("public_key.bin") {
        // Reconstruct the verifying key from bytes
        let verifying_key = <tss_ecdsa::curve::TestCurve as CurveTrait>::VerifyingKey::from_sec1_bytes(&bytes)
            .map_err(|_| anyhow::anyhow!("Failed to reconstruct public key from bytes"))?;
        Ok(Some(verifying_key))
    } else {
        Ok(None)
    }
}

pub async fn verify(Json(request): Json<VerifyRequest>) -> ResponseJson<VerifyResponse> {
    match run_verification(&request.message, &request.signature).await {
        Ok(is_valid) => ResponseJson(VerifyResponse {
            valid: is_valid,
            success: true,
            message: if is_valid {
                format!("✅ Signature is valid for message: '{}'", request.message)
            } else {
                format!("❌ Signature is NOT valid for message: '{}'", request.message)
            },
        }),
        Err(e) => {
            tracing::error!("Verification failed: {}", e);
            ResponseJson(VerifyResponse {
                valid: false,
                success: false,
                message: format!("Verification error: {}", e),
            })
        }
    }
}

async fn run_verification(message: &str, signature_hex: &str) -> anyhow::Result<bool> {
    // Load the stored public key
    let public_key = load_public_key_for_verification()?
        .ok_or_else(|| anyhow::anyhow!("No public key found. Please run the signing protocol first to generate a key."))?;

    // Decode the signature from hex
    let signature_bytes = hex::decode(signature_hex)
        .map_err(|_| anyhow::anyhow!("Invalid signature format. Expected hex string."))?;

    // Parse the DER-encoded signature using k256's from_der method
    use k256::ecdsa::Signature as K256Signature;
    let k256_signature = K256Signature::from_der(&signature_bytes)
        .map_err(|_| anyhow::anyhow!("Failed to parse DER signature"))?;
    
    // Extract r and s scalars from the k256 signature to recreate TSS signature
    let (r_scalar, s_scalar) = k256_signature.split_scalars();
    
    // Convert scalars to BigNumbers for TSS signature creation
    use tss_ecdsa::curve::{TestCurve, ScalarTrait};
    let r_bytes = r_scalar.to_bytes();
    let s_bytes = s_scalar.to_bytes();
    // Use the TSS library's BigNumber type (accessed through the curve trait)
    let r_scalar_tss = <TestCurve as CurveTrait>::Scalar::from_repr(r_bytes.to_vec());
    let s_scalar_tss = <TestCurve as CurveTrait>::Scalar::from_repr(s_bytes.to_vec());
    let r_bn = <TestCurve as CurveTrait>::scalar_to_bn(&r_scalar_tss);
    let s_bn = <TestCurve as CurveTrait>::scalar_to_bn(&s_scalar_tss);
    
    // Create TSS signature using from_scalars
    use tss_ecdsa::curve::SignatureTrait;
    let signature = <tss_ecdsa::curve::TestCurve as CurveTrait>::ECDSASignature::from_scalars(&r_bn, &s_bn)
        .map_err(|_| anyhow::anyhow!("Failed to create TSS signature from scalars"))?;

    // Create the message digest (same as used in signing)
    use sha3::{Digest, Keccak256};
    let digest = Keccak256::new_with_prefix(message.as_bytes());

    // Verify the signature
    match public_key.verify_signature(digest, signature) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}
