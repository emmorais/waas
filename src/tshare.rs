use axum::{response::Json, response::IntoResponse};
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use rand::{rngs::StdRng, SeedableRng, seq::SliceRandom};
use tss_ecdsa::{
    tshare::{TshareParticipant, Input as TshareInput, CoeffPrivate},
    auxinfo::AuxInfoParticipant,
    curve::{CurveTrait, TestCurve, ScalarTrait},
    messages::Message,
    ParticipantConfig, ParticipantIdentifier, ProtocolParticipant, Participant, Identifier,
};

const NUMBER_OF_WORKERS: usize = 3;
const THRESHOLD: usize = 2;

#[derive(Serialize, Deserialize)]
pub struct TshareResponse {
    pub message: String,
    pub participants: Vec<String>,
    pub tshare_count: usize,
}

// TshareHelperOutput struct to match the one in your fork
#[derive(Debug)]
pub struct TshareHelperOutput<C: CurveTrait> {
    pub tshare_inputs: Vec<TshareInput<C>>,
    pub tshare_outputs: HashMap<ParticipantIdentifier, <TshareParticipant<C> as ProtocolParticipant>::Output>,
}

// Tshare helper function from your fork
pub fn tshare_helper<C: CurveTrait>(
    configs: Vec<ParticipantConfig>,
    auxinfo_outputs: HashMap<
        ParticipantIdentifier,
        <AuxInfoParticipant<C> as ProtocolParticipant>::Output,
    >,
    threshold: usize,
    mut rng: StdRng,
) -> anyhow::Result<TshareHelperOutput<C>> {
    let quorum_size = configs.len();
    
    // Set up Tshare participants
    let tshare_sid = Identifier::random(&mut rng);
    let tshare_inputs = configs
        .iter()
        .map(|config| {
            let auxinfo_output = auxinfo_outputs.get(&config.id()).unwrap();
            let secret = C::Scalar::random();
            TshareInput::new(
                auxinfo_output.clone(),
                Some(CoeffPrivate { x: secret }),
                threshold,
            )
            .unwrap()
        })
        .collect::<Vec<_>>();

    let mut tshare_quorum = configs
        .clone()
        .into_iter()
        .zip(tshare_inputs.clone())
        .map(|(config, input)| {
            Participant::<TshareParticipant<C>>::from_config(config, tshare_sid, input).unwrap()
        })
        .collect::<Vec<_>>();

    let mut tshare_outputs: HashMap<
        ParticipantIdentifier,
        <TshareParticipant<C> as ProtocolParticipant>::Output,
    > = HashMap::new();

    let mut inboxes = HashMap::from_iter(
        tshare_quorum
            .iter()
            .map(|p| (p.id(), vec![]))
            .collect::<Vec<_>>(),
    );

    // Initialize tshare for all parties
    for participant in &tshare_quorum {
        let inbox = inboxes.get_mut(&participant.id()).unwrap();
        inbox.push(participant.initialize_message()?);
    }

    // Run tshare until all parties have outputs
    while tshare_outputs.len() < quorum_size {
        let output = process_random_message(&mut tshare_quorum, &mut inboxes, &mut rng)?;

        if let Some((pid, output)) = output {
            // Save the output, and make sure this participant didn't already return an
            // output.
            assert!(tshare_outputs.insert(pid, output).is_none());
        }
    }

    // Tshare is done! Make sure there are no more messages.
    assert!(inboxes_are_empty(&inboxes));

    Ok(TshareHelperOutput {
        tshare_inputs,
        tshare_outputs,
    })
}

// Helper functions used by tshare_helper
fn process_random_message<C: CurveTrait>(
    quorum: &mut [Participant<TshareParticipant<C>>],
    inboxes: &mut HashMap<ParticipantIdentifier, Vec<Message>>,
    rng: &mut StdRng,
) -> anyhow::Result<Option<(ParticipantIdentifier, <TshareParticipant<C> as ProtocolParticipant>::Output)>> {
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

// Main tshare endpoint
pub async fn tshare(_auth: crate::BasicAuth) -> impl IntoResponse {
    match run_tss_tshare().await {
        Ok(response) => Json(response),
        Err(e) => {
            tracing::error!("Tshare generation failed: {}", e);
            Json(TshareResponse {
                message: format!("Tshare generation failed: {}", e),
                participants: vec![],
                tshare_count: 0,
            })
        }
    }
}

async fn run_tss_tshare() -> anyhow::Result<TshareResponse> {
    let num_workers = NUMBER_OF_WORKERS;
    
    // Generate participant configurations
    let mut rng = StdRng::from_entropy();
    let configs = ParticipantConfig::random_quorum(num_workers, &mut rng)?;

    // First, we need auxinfo outputs for tshare
    // Reusing the auxinfo_helper from auxinfo.rs
    let auxinfo_result = crate::auxinfo::auxinfo_helper::<TestCurve>(configs.clone(), rng.clone())?;

    // Call tshare_helper with the configs, auxinfo outputs, and threshold
    let tshare_result = tshare_helper::<TestCurve>(
        configs.clone(), 
        auxinfo_result.auxinfo_outputs, 
        THRESHOLD, 
        rng
    )?;

    Ok(TshareResponse {
        message: "TSS Tshare generation completed successfully".to_string(),
        participants: configs
            .iter()
            .map(|config| format!("{:?}", config.id()))
            .collect(),
        tshare_count: tshare_result.tshare_outputs.len(),
    })
}
