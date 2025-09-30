use std::collections::HashMap;
use rand::{rngs::StdRng, seq::SliceRandom};
use tss_ecdsa::{
    auxinfo::AuxInfoParticipant,
    curve::CurveTrait,
    messages::Message,
    ParticipantConfig, ParticipantIdentifier, ProtocolParticipant, Participant, Identifier,
};
// AuxInfoHelperOutput struct to match the one in your fork
#[derive(Debug)]
pub struct AuxInfoHelperOutput<C: CurveTrait> {
    pub auxinfo_outputs: HashMap<ParticipantIdentifier, <AuxInfoParticipant<C> as ProtocolParticipant>::Output>,
    pub inboxes: HashMap<ParticipantIdentifier, Vec<Message>>,
}

// AuxInfo helper function from your fork
pub fn auxinfo_helper<C: CurveTrait>(
    configs: Vec<ParticipantConfig>,
    mut rng: StdRng,
) -> anyhow::Result<AuxInfoHelperOutput<C>> {
    let quorum_size = configs.len();
    
    // Set up auxinfo participants
    let auxinfo_sid = Identifier::random(&mut rng);
    let mut auxinfo_quorum = configs
        .clone()
        .into_iter()
        .map(|config| {
            Participant::<AuxInfoParticipant<C>>::from_config(config, auxinfo_sid, ()).unwrap()
        })
        .collect::<Vec<_>>();

    let mut inboxes = HashMap::from_iter(
        auxinfo_quorum
            .iter()
            .map(|p| (p.id(), vec![]))
            .collect::<Vec<_>>(),
    );

    let mut auxinfo_outputs: HashMap<
        ParticipantIdentifier,
        <AuxInfoParticipant<C> as ProtocolParticipant>::Output,
    > = HashMap::new();

    // Initialize auxinfo for all parties
    for participant in &auxinfo_quorum {
        let inbox: &mut Vec<Message> = inboxes.get_mut(&participant.id()).unwrap();
        inbox.push(participant.initialize_message()?);
    }

    // Run auxinfo until all parties have outputs
    while auxinfo_outputs.len() < quorum_size {
        let output = process_random_message(&mut auxinfo_quorum, &mut inboxes, &mut rng)?;

        if let Some((pid, output)) = output {
            // Save the output, and make sure this participant didn't already return an
            // output.
            assert!(auxinfo_outputs.insert(pid, output).is_none());
        }
    }

    // Auxinfo is done! Make sure there are no more messages.
    assert!(inboxes_are_empty(&inboxes));

    Ok(AuxInfoHelperOutput {
        auxinfo_outputs,
        inboxes,
    })
}

// Helper functions used by auxinfo_helper
fn process_random_message<C: CurveTrait>(
    quorum: &mut [Participant<AuxInfoParticipant<C>>],
    inboxes: &mut HashMap<ParticipantIdentifier, Vec<Message>>,
    rng: &mut StdRng,
) -> anyhow::Result<Option<(ParticipantIdentifier, <AuxInfoParticipant<C> as ProtocolParticipant>::Output)>> {
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