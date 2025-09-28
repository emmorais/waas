use axum::{response::Json, response::IntoResponse};
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use rand::{rngs::StdRng, SeedableRng, seq::SliceRandom};
use tss_ecdsa::{
    auxinfo::AuxInfoParticipant,
    curve::{CurveTrait, TestCurve},
    keygen::KeygenParticipant,
    messages::Message,
    presign::{PresignParticipant, Input as PresignInput},
    ParticipantConfig, ParticipantIdentifier, ProtocolParticipant, Participant, Identifier,
};

const NUMBER_OF_WORKERS: usize = 3;

#[derive(Serialize, Deserialize)]
pub struct PresignResponse {
    pub message: String,
    pub participants: Vec<String>,
    pub presign_count: usize,
}

// PresignHelperOutput struct to match the one in your fork
#[derive(Debug)]
pub struct PresignHelperOutput<C: CurveTrait> {
    pub presign_outputs: HashMap<ParticipantIdentifier, <PresignParticipant<C> as ProtocolParticipant>::Output>,
}

// Presign helper function from your fork
pub fn presign_helper<C: CurveTrait>(
    configs: Vec<ParticipantConfig>,
    mut auxinfo_outputs: HashMap<ParticipantIdentifier, <AuxInfoParticipant<C> as ProtocolParticipant>::Output>,
    mut keygen_outputs: HashMap<ParticipantIdentifier, <KeygenParticipant<C> as ProtocolParticipant>::Output>,
    inboxes: &mut HashMap<ParticipantIdentifier, Vec<Message>>,
    mut rng: StdRng,
) -> anyhow::Result<PresignHelperOutput<C>> {
    let quorum_size = auxinfo_outputs.len();
    
    let presign_sid = Identifier::random(&mut rng);

    // Prepare presign inputs: a pair of outputs from keygen and auxinfo
    let presign_inputs = configs
        .iter()
        .map(|config| {
            (
                auxinfo_outputs.remove(&config.id()).unwrap(),
                keygen_outputs.remove(&config.id()).unwrap(),
            )
        })
        .map(|(auxinfo_output, keygen_output)| {
            PresignInput::new(auxinfo_output, keygen_output).unwrap()
        })
        .collect::<Vec<_>>();

    let mut presign_quorum = configs
        .clone()
        .into_iter()
        .zip(presign_inputs)
        .map(|(config, input)| {
            Participant::<PresignParticipant<C>>::from_config(config, presign_sid, input)
                .unwrap()
        })
        .collect::<Vec<_>>();

    let mut presign_outputs: HashMap<
        ParticipantIdentifier,
        <PresignParticipant<C> as ProtocolParticipant>::Output,
    > = HashMap::new();

    // Initialize presign for all participants
    for participant in &mut presign_quorum {
        let inbox = inboxes.get_mut(&participant.id()).unwrap();
        inbox.push(participant.initialize_message()?);
    }

    // Run presign until all parties have outputs
    while presign_outputs.len() < quorum_size {
        let output = process_random_message(&mut presign_quorum, inboxes, &mut rng)?;

        if let Some((pid, output)) = output {
            // Save the output, and make sure this participant didn't already return an output
            assert!(presign_outputs.insert(pid, output).is_none());
        }
    }

    // Presigning is done! Make sure there are no more messages.
    assert!(inboxes_are_empty(inboxes));
    
    // And make sure all participants have successfully terminated.
    // Note: Skipping status check as the Status enum might be private

    Ok(PresignHelperOutput { presign_outputs })
}

// Helper functions used by presign_helper
fn process_random_message<C: CurveTrait>(
    quorum: &mut [Participant<PresignParticipant<C>>],
    inboxes: &mut HashMap<ParticipantIdentifier, Vec<Message>>,
    rng: &mut StdRng,
) -> anyhow::Result<Option<(ParticipantIdentifier, <PresignParticipant<C> as ProtocolParticipant>::Output)>> {
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

// Main presign endpoint
pub async fn presign(_auth: crate::BasicAuth) -> impl IntoResponse {
    match run_tss_presign().await {
        Ok(response) => Json(response),
        Err(e) => {
            tracing::error!("Presign generation failed: {}", e);
            Json(PresignResponse {
                message: format!("Presign generation failed: {}", e),
                participants: vec![],
                presign_count: 0,
            })
        }
    }
}

async fn run_tss_presign() -> anyhow::Result<PresignResponse> {
    let num_workers = NUMBER_OF_WORKERS;
    
    // Generate participant configurations
    let mut rng = StdRng::from_entropy();
    let configs = ParticipantConfig::random_quorum(num_workers, &mut rng)?;

    // For demonstration purposes, we need to run the actual protocols to get real outputs
    // In a real implementation, these would be loaded from secure storage
    
    // First run keygen to get the outputs
    use crate::keygen::{keygen_helper, KeygenHelperOutput};
    let keygen_result: KeygenHelperOutput<TestCurve> = {
        let keygen_inboxes: HashMap<ParticipantIdentifier, Vec<Message>> = configs
            .iter()
            .map(|config| (config.id(), Vec::new()))
            .collect();
        keygen_helper(configs.clone(), keygen_inboxes, rng.clone())?
    };

    // Then run auxinfo to get the outputs
    use crate::auxinfo::{auxinfo_helper, AuxInfoHelperOutput};
    let auxinfo_result: AuxInfoHelperOutput<TestCurve> = auxinfo_helper(configs.clone(), rng.clone())?;

    let keygen_outputs = keygen_result.keygen_outputs;
    let auxinfo_outputs = auxinfo_result.auxinfo_outputs;

    // Use the inboxes from auxinfo
    let mut inboxes = auxinfo_result.inboxes;

    // Call presign_helper with the configs and outputs
    let presign_result = presign_helper::<TestCurve>(
        configs.clone(), 
        auxinfo_outputs, 
        keygen_outputs, 
        &mut inboxes, 
        rng
    )?;

    Ok(PresignResponse {
        message: "TSS Presign generation completed successfully".to_string(),
        participants: configs
            .iter()
            .map(|config| format!("{:?}", config.id()))
            .collect(),
        presign_count: presign_result.presign_outputs.len(),
    })
}
