use std::collections::HashMap;

use anyhow::Result;
use axum::{extract::Json, response::Json as ResponseJson};
//use k256::Secp256k1;
use rand::{rngs::StdRng, SeedableRng};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use tss_ecdsa::{
    curve::{CurveTrait, Secp256k1},
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

#[derive(Debug)]
pub struct SignHelperInput {
    pub public_key_shares: Vec<KeySharePublic<tss_ecdsa::curve::Secp256k1>>,
    pub saved_public_key: <tss_ecdsa::curve::Secp256k1 as CurveTrait>::VerifyingKey,
    pub presign_outputs: HashMap<ParticipantIdentifier, PresignRecord<tss_ecdsa::curve::Secp256k1>>,
    pub chain_code: [u8; 32],
    pub inboxes: HashMap<ParticipantIdentifier, Vec<Message>>,
    pub child_index: u32,
    pub threshold: usize,
}

pub fn sign_helper(
    configs: Vec<ParticipantConfig>,
    sign_helper_input: SignHelperInput,
    mut rng: StdRng,
) -> Result<Vec<u8>> {
    let message = b"Message from web interface";
    let quorum_real = configs.len();
    let digest = Keccak256::new_with_prefix(message);
    let sign_sid = Identifier::random(&mut rng);

    let mut presign_outputs = sign_helper_input.presign_outputs;
    let public_key_shares = sign_helper_input.public_key_shares;
    let saved_public_key = sign_helper_input.saved_public_key;
    let threshold = sign_helper_input.threshold;
    let mut inboxes = sign_helper_input.inboxes;

    // Make signing participants
    let mut sign_quorum = configs
        .clone()
        .into_iter()
        .map(|config| {
            let record = presign_outputs.remove(&config.id()).unwrap();
            let input = SignInput::new(message, record, public_key_shares.clone(), threshold, None);
            Participant::<SignParticipant<Secp256k1>>::from_config(config, sign_sid, input)
        })
        .collect::<Result<Vec<_>, _>>()?;

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
    Ok(sign_outputs[0].to_bytes().to_vec())
}

fn process_random_message<R: rand::RngCore + rand::CryptoRng>(
    quorum: &mut Vec<Participant<SignParticipant<Secp256k1>>>,
    inboxes: &mut HashMap<ParticipantIdentifier, Vec<Message>>,
    rng: &mut R,
) -> Result<Option<(ParticipantIdentifier, <SignParticipant<Secp256k1> as ProtocolParticipant>::Output)>> {
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
    // Create dummy data for demonstration
    // In a real implementation, you would load the actual presign records and other data
    // from your secure storage
    
    let mut rng = StdRng::from_entropy();
    
    // Create minimal configs for testing
    let configs = match ParticipantConfig::random_quorum(3, &mut rng) {
        Ok(configs) => configs,
        Err(_) => {
            return ResponseJson(SignResponse {
                signature: String::new(),
                success: false,
                message: "Failed to create participant configs".to_string(),
            });
        }
    };

    // For now, return a mock response indicating the sign endpoint is working
    // but needs proper integration with stored keygen/auxinfo/tshare/presign data
    ResponseJson(SignResponse {
        signature: format!("mock_signature_for_message_{}", request.message),
        success: true,
        message: format!("Sign endpoint received message: '{}'. Full implementation requires integration with stored protocol outputs.", request.message),
    })
}
