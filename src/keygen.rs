use axum::{response::Json, response::IntoResponse};
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use rand::{rngs::StdRng, SeedableRng};
use tss_ecdsa::{
    curve::{CurveTrait, TestCurve},
    keygen::KeygenParticipant,
    messages::Message,
    ParticipantConfig, ParticipantIdentifier, ProtocolParticipant, Participant, Identifier,
};

const NUMBER_OF_WORKERS: usize = 3;

#[derive(Serialize, Deserialize)]
pub struct KeygenResponse {
    pub public_key: String,
    pub private_key_share: String,
    pub rid: String,
    pub chain_code: String,
    pub message: String,
    pub participants: Vec<String>,
}

// KeygenHelperOutput struct to match the one in your fork
#[derive(Debug)]
pub struct KeygenHelperOutput<C: CurveTrait> {
    pub keygen_outputs: HashMap<ParticipantIdentifier, <KeygenParticipant<C> as ProtocolParticipant>::Output>,
}

// Keygen helper function from your fork
pub fn keygen_helper<C: CurveTrait>(
    configs: Vec<ParticipantConfig>,
    mut inboxes: HashMap<ParticipantIdentifier, Vec<Message>>,
    mut rng: StdRng,
) -> anyhow::Result<KeygenHelperOutput<C>> {
    let quorum_size = configs.len();
    
    // Set up keygen participants
    let keygen_sid = Identifier::random(&mut rng);
    let mut keygen_quorum = configs
        .clone()
        .into_iter()
        .map(|config| {
            Participant::<KeygenParticipant<C>>::from_config(config, keygen_sid, ()).unwrap()
        })
        .collect::<Vec<_>>();

    let mut keygen_outputs: HashMap<
        ParticipantIdentifier,
        <KeygenParticipant<C> as ProtocolParticipant>::Output,
    > = HashMap::new();

    // Initialize keygen for all participants
    for participant in &keygen_quorum {
        let inbox = inboxes.get_mut(&participant.id()).unwrap();
        inbox.push(participant.initialize_message()?);
    }

    // Run keygen until all parties have outputs
    while keygen_outputs.len() < quorum_size {
        let output = process_random_message(&mut keygen_quorum, &mut inboxes, &mut rng)?;

        if let Some((pid, output)) = output {
            // Save the output, and make sure this participant didn't already return an
            // output.
            assert!(keygen_outputs.insert(pid, output).is_none());
        }
    }

    // Keygen is done! Make sure there are no more messages.
    assert!(inboxes_are_empty(&inboxes));

    Ok(KeygenHelperOutput { keygen_outputs })
}

// Helper functions used by keygen_helper
fn process_random_message<C: CurveTrait>(
    quorum: &mut [Participant<KeygenParticipant<C>>],
    inboxes: &mut HashMap<ParticipantIdentifier, Vec<Message>>,
    rng: &mut StdRng,
) -> anyhow::Result<Option<(ParticipantIdentifier, <KeygenParticipant<C> as ProtocolParticipant>::Output)>> {
    use rand::seq::SliceRandom;
    
    // Get all non-empty inboxes
    let non_empty_inboxes: Vec<ParticipantIdentifier> = inboxes
        .iter()
        .filter(|(_, messages)| !messages.is_empty())
        .map(|(pid, _)| *pid)
        .collect();

    if non_empty_inboxes.is_empty() {
        return Ok(None);
    }

    // Pick a random participant with messages
    let selected_pid = *non_empty_inboxes.choose(rng).unwrap();
    let message = inboxes.get_mut(&selected_pid).unwrap().remove(0);

    // Find the participant and process the message
    let participant = quorum
        .iter_mut()
        .find(|p| p.id() == selected_pid)
        .unwrap();

    let (output, new_messages) = participant.process_single_message(&message, rng)?;

    // Deliver new messages to their recipients
    for msg in new_messages {
        let recipient = msg.to();
        if let Some(inbox) = inboxes.get_mut(&recipient) {
            inbox.push(msg);
        }
    }

    match output {
        Some(output) => Ok(Some((selected_pid, output))),
        None => Ok(None),
    }
}

fn inboxes_are_empty(inboxes: &HashMap<ParticipantIdentifier, Vec<Message>>) -> bool {
    inboxes.values().all(|messages| messages.is_empty())
}

// Main keygen endpoint
pub async fn keygen(_auth: crate::BasicAuth) -> impl IntoResponse {
    match run_tss_keygen().await {
        Ok(response) => Json(response),
        Err(e) => {
            tracing::error!("Key generation failed: {}", e);
            Json(KeygenResponse {
                public_key: "error".to_string(),
                private_key_share: "error".to_string(),
                rid: "error".to_string(),
                chain_code: "error".to_string(),
                message: format!("Key generation failed: {}", e),
                participants: vec![],
            })
        }
    }
}

async fn run_tss_keygen() -> anyhow::Result<KeygenResponse> {
    let num_workers = NUMBER_OF_WORKERS;
    
    // Generate participant configurations
    let mut rng = StdRng::from_entropy();
    let configs = ParticipantConfig::random_quorum(num_workers, &mut rng)?;

    // Initialize empty inboxes for all participants
    let inboxes: HashMap<ParticipantIdentifier, Vec<Message>> = configs
        .iter()
        .map(|config| (config.id(), Vec::new()))
        .collect();

    // Call keygen_helper with the configs and inboxes
    let keygen_result = keygen_helper::<TestCurve>(configs.clone(), inboxes, rng)?;

    // Extract the first participant's output for response
    let first_participant_id = configs[0].id();
    if let Some(output) = keygen_result.keygen_outputs.get(&first_participant_id) {
        // Convert the output to a response format
        let public_key = match output.public_key() {
            Ok(pk) => hex::encode(pk.to_sec1_bytes()),
            Err(_) => "error_getting_public_key".to_string(),
        };
        let private_key_share = format!("{:?}", output.private_key_share());
        let rid = hex::encode(output.rid());
        let chain_code = hex::encode(output.chain_code());
        
        Ok(KeygenResponse {
            public_key,
            private_key_share,
            rid,
            chain_code,
            message: "TSS Key generation completed successfully".to_string(),
            participants: configs
                .iter()
                .map(|config| format!("{:?}", config.id()))
                .collect(),
        })
    } else {
        anyhow::bail!("No keygen output found for first participant");
    }
}
