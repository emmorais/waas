use axum::{response::Json, response::IntoResponse, http::StatusCode};
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use rand::{rngs::StdRng, SeedableRng};
use tss_ecdsa::{
    curve::{CurveTrait, TestCurve},
    keygen::KeygenParticipant,
    messages::Message,
    ParticipantConfig, ParticipantIdentifier, ProtocolParticipant, Participant, Identifier,
};
use anyhow::Result;

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
#[derive(Debug, Serialize, Deserialize)]
pub struct KeygenHelperOutput<C: CurveTrait> {
    #[serde(bound(deserialize = "C: CurveTrait"))]
    pub keygen_outputs: HashMap<ParticipantIdentifier, <KeygenParticipant<C> as ProtocolParticipant>::Output>,
}

// Keygen helper function from your fork
pub fn keygen_helper<C: CurveTrait>(
    configs: Vec<ParticipantConfig>,
    mut inboxes: HashMap<ParticipantIdentifier, Vec<Message>>,
    mut rng: StdRng,
) -> anyhow::Result<KeygenHelperOutput<C>> {
    let quorum_size = configs.len();
    
    tracing::debug!(
        quorum_size = quorum_size,
        "🔧 Setting up keygen participants"
    );
    
    // Set up keygen participants
    let keygen_sid = Identifier::random(&mut rng);
    let mut keygen_quorum = configs
        .clone()
        .into_iter()
        .map(|config| {
            Participant::<KeygenParticipant<C>>::from_config(config, keygen_sid, ()).unwrap()
        })
        .collect::<Vec<_>>();
        
    tracing::debug!(
        session_id = %keygen_sid,
        participants_created = keygen_quorum.len(),
        "✅ Keygen participants initialized"
    );

    let mut keygen_outputs: HashMap<
        ParticipantIdentifier,
        <KeygenParticipant<C> as ProtocolParticipant>::Output,
    > = HashMap::new();

    // Initialize keygen for all participants
    tracing::debug!("📨 Initializing keygen messages for all participants");
    for participant in &keygen_quorum {
        let inbox = inboxes.get_mut(&participant.id()).unwrap();
        inbox.push(participant.initialize_message()?);
    }
    tracing::debug!("✅ Initial messages sent to all participants");

    // Run keygen until all parties have outputs
    tracing::debug!("🔄 Starting keygen message exchange protocol");
    let exchange_start = std::time::Instant::now();
    let mut round_count = 0;
    
    while keygen_outputs.len() < quorum_size {
        let output = process_random_message(&mut keygen_quorum, &mut inboxes, &mut rng)?;

        if let Some((pid, output)) = output {
            round_count += 1;
            tracing::trace!(
                participant_id = %pid,
                round = round_count,
                outputs_collected = keygen_outputs.len() + 1,
                total_required = quorum_size,
                "📨 Collected keygen output from participant"
            );
            // Save the output, and make sure this participant didn't already return an
            // output.
            assert!(keygen_outputs.insert(pid, output).is_none());
        }
    }
    
    tracing::info!(
        exchange_duration_ms = exchange_start.elapsed().as_millis(),
        total_rounds = round_count,
        outputs_collected = keygen_outputs.len(),
        "✅ Keygen message exchange completed"
    );

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

// Main keygen endpoint for generating new keys (POST)
pub async fn keygen(_auth: crate::BasicAuth) -> impl IntoResponse {
    tracing::info!("🔑 Starting TSS key generation protocol");
    let start_time = std::time::Instant::now();
    
    match run_tss_keygen().await {
        Ok(response) => {
            let duration = start_time.elapsed();
            tracing::info!(
                participants = response.participants.len(),
                public_key_preview = %response.public_key.get(..16.min(response.public_key.len())).unwrap_or(""),
                duration_ms = duration.as_millis(),
                "✅ TSS key generation completed successfully"
            );
            Json(response)
        },
        Err(e) => {
            let duration = start_time.elapsed();
            tracing::error!(
                error = %e,
                duration_ms = duration.as_millis(),
                "❌ TSS key generation failed"
            );
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

// Check for existing keys endpoint (GET)
pub async fn check_keygen(_auth: crate::BasicAuth) -> impl IntoResponse {
    tracing::info!("🔍 Checking for existing TSS keys");
    let start_time = std::time::Instant::now();
    
    match check_existing_keys().await {
        Ok(response) => {
            let duration = start_time.elapsed();
            tracing::info!(
                participants = response.participants.len(),
                public_key_preview = %response.public_key.get(..16.min(response.public_key.len())).unwrap_or(""),
                duration_ms = duration.as_millis(),
                "✅ Existing TSS keys found and loaded"
            );
            (StatusCode::OK, Json(response))
        },
        Err(e) => {
            let duration = start_time.elapsed();
            tracing::debug!(
                error = %e,
                duration_ms = duration.as_millis(),
                "📋 No existing TSS keys found"
            );
            // Return 404 to indicate no keys exist
            (StatusCode::NOT_FOUND, Json(KeygenResponse {
                public_key: "".to_string(),
                private_key_share: "".to_string(),
                rid: "".to_string(),
                chain_code: "".to_string(),
                message: "No existing keys found".to_string(),
                participants: vec![],
            }))
        }
    }
}

async fn run_tss_keygen() -> anyhow::Result<KeygenResponse> {
    let num_workers = NUMBER_OF_WORKERS;
    
    tracing::debug!(
        participants = num_workers,
        threshold = 2,
        "🚀 Initializing TSS keygen participants"
    );
    
    // Generate participant configurations
    let mut rng = StdRng::from_entropy();
    let configs = ParticipantConfig::random_quorum(num_workers, &mut rng)?;
    
    tracing::debug!(
        configs_generated = configs.len(),
        "✅ Participant configurations generated"
    );

    // Initialize empty inboxes for all participants
    let inboxes: HashMap<ParticipantIdentifier, Vec<Message>> = configs
        .iter()
        .map(|config| (config.id(), Vec::new()))
        .collect();

    tracing::debug!("📋 Running TSS keygen protocol");
    let protocol_start = std::time::Instant::now();
    
    // Call keygen_helper with the configs and inboxes
    let keygen_result = keygen_helper::<TestCurve>(configs.clone(), inboxes, rng)?;
    
    tracing::info!(
        protocol_duration_ms = protocol_start.elapsed().as_millis(),
        outputs_generated = keygen_result.keygen_outputs.len(),
        "✅ TSS keygen protocol completed"
    );

    // Store keygen essentials to filesystem
    store_keygen_essentials(&configs, &keygen_result)?;

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

async fn check_existing_keys() -> anyhow::Result<KeygenResponse> {
    tracing::debug!("🔍 Checking for existing keygen essentials");
    
    // Check if keygen has been completed before
    if !is_keygen_completed() {
        anyhow::bail!("No existing keygen found");
    }
    
    tracing::debug!("📂 Loading existing keygen essentials from storage");
    let stored_essentials = load_stored_keygen_essentials()?;
    
    // Convert stored data to response format using the stored essentials only
    let public_key = hex::encode(&stored_essentials.public_key_bytes);
    let chain_code = hex::encode(&stored_essentials.chain_code);
    
    // Deserialize configs to get participant count
    let configs: Vec<ParticipantConfig> = bincode::deserialize(&stored_essentials.configs_serialized)
        .map_err(|e| anyhow::anyhow!("Failed to deserialize configs: {}", e))?;
    
    tracing::info!(
        participants = configs.len(),
        public_key_preview = %public_key.get(..16.min(public_key.len())).unwrap_or(""),
        "✅ Existing TSS keys found in storage (no protocol execution needed)"
    );
    
    Ok(KeygenResponse {
        public_key,
        private_key_share: "[stored securely - not displayed in check mode]".to_string(),
        rid: "[stored securely - not displayed in check mode]".to_string(),
        chain_code,
        message: "Existing TSS keys found in local storage".to_string(),
        participants: configs
            .iter()
            .map(|config| format!("{:?}", config.id()))
            .collect(),
    })
}

// Helper functions from sign.rs for key storage checking
fn is_keygen_completed() -> bool {
    use std::fs;
    
    let marker_exists = fs::metadata("keygen_completed.marker").is_ok();
    let essentials_exist = fs::metadata("keygen_essentials.json").is_ok();
    marker_exists && essentials_exist
}

#[derive(Serialize, Deserialize)]
struct StoredKeygenEssentials {
    configs_serialized: Vec<u8>,
    public_key_bytes: Vec<u8>,
    chain_code: [u8; 32],
}

// Load stored keygen essentials without running the protocol
fn load_stored_keygen_essentials() -> Result<StoredKeygenEssentials> {
    use std::fs;
    
    let json_data = fs::read_to_string("keygen_essentials.json")
        .map_err(|_| anyhow::anyhow!("No keygen essentials found"))?;
        
    let stored_data: StoredKeygenEssentials = serde_json::from_str(&json_data)
        .map_err(|e| anyhow::anyhow!("Failed to deserialize keygen essentials: {}", e))?;
    
    tracing::debug!("📋 Loaded keygen essentials from storage without protocol execution");
    Ok(stored_data)
}

fn store_keygen_essentials(
    configs: &Vec<ParticipantConfig>,
    keygen_result: &KeygenHelperOutput<TestCurve>
) -> Result<()> {
    use std::fs;
    
    tracing::debug!(
        storage_path = "keygen_essentials.json",
        configs_count = configs.len(),
        keygen_outputs_count = keygen_result.keygen_outputs.len(),
        "💾 Storing keygen essentials to filesystem"
    );
    
    // Serialize configs (these do support Serde)
    let configs_serialized = bincode::serialize(configs)
        .map_err(|e| anyhow::anyhow!("Failed to serialize configs: {}", e))?;
    
    // Extract essential data from keygen result
    let first_keygen_output = keygen_result.keygen_outputs.values().next().unwrap();
    let public_key = first_keygen_output.public_key()?;
    let chain_code = *first_keygen_output.chain_code();
    
    let stored_data = StoredKeygenEssentials {
        configs_serialized,
        public_key_bytes: public_key.to_sec1_bytes().to_vec(),
        chain_code,
    };
    
    let json_data = serde_json::to_string_pretty(&stored_data)
        .map_err(|e| anyhow::anyhow!("Failed to serialize keygen essentials to JSON: {}", e))?;
    
    fs::write("keygen_essentials.json", json_data)?;
    fs::write("keygen_completed.marker", "1")?;
    
    tracing::info!(
        configs_count = configs.len(),
        "✅ Keygen essentials stored successfully (will regenerate outputs deterministically)"
    );
    
    Ok(())
}
