use axum::{response::Json, response::IntoResponse};
use serde::{Serialize, Deserialize};
use std::{
    any::Any,
    collections::HashMap,
    sync::mpsc::{channel, Receiver, Sender},
    thread,
};
use rand::{rngs::StdRng, SeedableRng};
use tracing::{info, instrument};
use tss_ecdsa::{
    auxinfo::AuxInfoParticipant,
    curve::{CurveTrait, TestCurve},
    keygen::{KeygenParticipant, Output},
    messages::Message,
    presign::PresignParticipant,
    sign::SignParticipant,
    tshare::TshareParticipant,
    Identifier, Participant, ParticipantConfig, ParticipantIdentifier, ProtocolParticipant,
};
use uuid::Uuid;

const THRESHOLD: usize = 2;
const NUMBER_OF_WORKERS: usize = 3;

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
struct SessionId(Identifier);

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
struct KeyId(Uuid);

#[derive(Debug, Copy, Clone, Eq, Hash, PartialEq)]
pub enum SubProtocol {
    KeyGeneration,
    AuxInfo,
    Tshare,
    Presign,
    Sign,
}

#[derive(Debug)]
pub enum MessageFromWorker {
    FinishedRound(Vec<Message>),
    SubProtocolEnded,
}

enum MessageFromCoordinator {
    SubProtocolMessage(Message),
    NewSubProtocol(SubProtocol, KeyId, SessionId),
}

type WorkerChannels = HashMap<ParticipantIdentifier, Sender<MessageFromCoordinator>>;

#[derive(Serialize, Deserialize)]
pub struct KeygenResponse {
    pub public_key: String,
    pub private_key_share: String,
    pub rid: String,
    pub chain_code: String,
    pub message: String,
    pub participants: Vec<String>,
}

struct StoredOutput<P: ProtocolParticipant> {
    stored_output: HashMap<KeyId, P::Output>,
}

impl<P: ProtocolParticipant> StoredOutput<P> {
    fn new() -> Self {
        StoredOutput {
            stored_output: Default::default(),
        }
    }

    fn store(&mut self, id: KeyId, store: P::Output) {
        self.stored_output.insert(id, store);
    }

    fn retrieve(&self, id: &KeyId) -> &P::Output {
        self.stored_output.get(id).unwrap()
    }

    fn take(&mut self, id: &KeyId) -> P::Output {
        self.stored_output.remove(id).unwrap()
    }
}

type StoredParticipant = Box<dyn Any + 'static>;

#[derive(Default)]
struct ParticipantStorage {
    storage: HashMap<SessionId, (StoredParticipant, KeyId)>,
}

impl ParticipantStorage {
    fn new() -> Self {
        ParticipantStorage {
            storage: Default::default(),
        }
    }

    fn get_mut<T: ProtocolParticipant + 'static>(
        &mut self,
        id: &SessionId,
    ) -> (&mut Participant<T>, KeyId) {
        let (dynamic, key_id) = self.storage.get_mut(id).unwrap();
        (dynamic.downcast_mut().unwrap(), *key_id)
    }

    fn insert<P: ProtocolParticipant + 'static>(
        &mut self,
        id: SessionId,
        participant: Participant<P>,
        key_id: KeyId,
    ) {
        self.storage.insert(id, (Box::new(participant), key_id));
    }
}

pub async fn keygen(_auth: crate::BasicAuth) -> impl IntoResponse {
    match run_tss_keygen().await {
        Ok(response) => Json(response),
        Err(_) => Json(KeygenResponse {
            public_key: "error".to_string(),
            private_key_share: "error".to_string(),
            rid: "error".to_string(),
            chain_code: "error".to_string(),
            message: "Key generation failed".to_string(),
            participants: vec![],
        }),
    }
}

async fn run_tss_keygen() -> anyhow::Result<KeygenResponse> {
    let num_workers = NUMBER_OF_WORKERS;
    assert!(
        num_workers >= THRESHOLD,
        "Number of workers must be >= threshold {THRESHOLD}."
    );

    let (outgoing_tx, workers_rx) = channel::<MessageFromWorker>();
    let mut worker_messages: WorkerChannels = HashMap::new();

    let participants: Vec<ParticipantConfig> =
        ParticipantConfig::random_quorum(num_workers, &mut StdRng::from_entropy())?;

    // Spawn worker threads
    for config in participants {
        let (from_coordinator_tx, from_coordinator_rx) = channel::<MessageFromCoordinator>();
        worker_messages.insert(config.id(), from_coordinator_tx);

        let outgoing = outgoing_tx.clone();
        thread::spawn(|| participant_worker::<TestCurve>(config, from_coordinator_rx, outgoing));
    }

    let mut coordinator = Coordinator::new(worker_messages, workers_rx);
    let key_gen_output = coordinator.run_keygen_only()?;

    Ok(key_gen_output)
}

struct Coordinator {
    send_to_workers: WorkerChannels,
    from_workers: Receiver<MessageFromWorker>,
}

impl Coordinator {
    pub fn new(send_to_workers: WorkerChannels, from_workers: Receiver<MessageFromWorker>) -> Self {
        Self {
            send_to_workers,
            from_workers,
        }
    }

    fn run_keygen_only(&mut self) -> anyhow::Result<KeygenResponse> {
        let key_id = KeyId(Uuid::new_v4());
        self.initiate_sub_protocol(SubProtocol::KeyGeneration, key_id)?;

        // For now, just return a placeholder response with the key_id
        Ok(KeygenResponse {
            public_key: format!("public_key_{}", key_id.0),
            private_key_share: format!("private_key_share_{}", key_id.0),
            rid: format!("rid_{}", key_id.0),
            chain_code: format!("chain_code_{}", key_id.0),
            message: "TSS Key generation completed successfully".to_string(),
            participants: self.send_to_workers.keys().map(|pid| format!("{:?}", pid)).collect(),
        })
    }

    fn initiate_sub_protocol(
        &mut self,
        sub_protocol: SubProtocol,
        key_id: KeyId,
    ) -> anyhow::Result<()> {
        info!("Starting sub-protocol: {:?} for {:?}.", sub_protocol, key_id);

        let n_workers = self.start_new_subprotocol(sub_protocol, key_id)?;
        self.route_worker_messages(n_workers)?;

        info!("Finished sub-protocol: {:?}.", sub_protocol);
        Ok(())
    }

    fn start_new_subprotocol(
        &self,
        sub_protocol: SubProtocol,
        key_id: KeyId,
    ) -> anyhow::Result<usize> {
        let sid = SessionId(Identifier::random(&mut rand::thread_rng()));
        let participants = self.participants(sub_protocol);

        for pid in &participants {
            let worker = self.send_to_workers.get(pid).unwrap();
            worker.send(MessageFromCoordinator::NewSubProtocol(
                sub_protocol,
                key_id,
                sid,
            ))?;
        }

        Ok(participants.len())
    }

    fn route_worker_messages(&self, n_workers: usize) -> anyhow::Result<()> {
        let mut sub_protocol_ended = 0;

        for message in &self.from_workers {
            match message {
                MessageFromWorker::FinishedRound(messages) => {
                    if messages.is_empty() {
                        continue;
                    }
                    for m in messages {
                        let recipient = m.to();
                        self.send_to_workers
                            .get(&recipient)
                            .unwrap()
                            .send(MessageFromCoordinator::SubProtocolMessage(m))?;
                    }
                }
                MessageFromWorker::SubProtocolEnded => {
                    sub_protocol_ended += 1;
                    if sub_protocol_ended == n_workers {
                        break;
                    }
                }
            }
        }
        Ok(())
    }

    fn participants(&self, sub_protocol: SubProtocol) -> Vec<ParticipantIdentifier> {
        use SubProtocol::*;
        let pids = self.send_to_workers.keys().cloned().collect::<Vec<_>>();
        match sub_protocol {
            KeyGeneration | AuxInfo | Tshare => pids,
            Presign | Sign => {
                let mut sorted_pids = pids;
                sorted_pids.sort();
                sorted_pids.truncate(THRESHOLD);
                sorted_pids
            }
        }
    }
}

struct Worker<C: CurveTrait + 'static> {
    config: ParticipantConfig,
    participants: ParticipantStorage,
    key_gen_material: StoredOutput<KeygenParticipant<C>>,
    aux_info: StoredOutput<AuxInfoParticipant<C>>,
    tshares: StoredOutput<TshareParticipant<C>>,
    presign_records: StoredOutput<PresignParticipant<C>>,
    signatures: StoredOutput<SignParticipant<C>>,
    outgoing: Sender<MessageFromWorker>,
}

impl<C: CurveTrait> Worker<C> {
    fn new(config: ParticipantConfig, outgoing: Sender<MessageFromWorker>) -> Self {
        Worker {
            config,
            participants: ParticipantStorage::new(),
            key_gen_material: StoredOutput::new(),
            aux_info: StoredOutput::new(),
            tshares: StoredOutput::new(),
            presign_records: StoredOutput::new(),
            signatures: StoredOutput::new(),
            outgoing,
        }
    }

    fn new_keygen(&mut self, sid: SessionId, key_id: KeyId) -> anyhow::Result<()> {
        println!("Starting new keygen with SID: {:?} and KeyID: {:?}", sid, key_id);
        self.new_sub_protocol::<KeygenParticipant<C>>(self.config.clone(), sid, (), key_id)
    }

    #[instrument(skip_all)]
    fn new_sub_protocol<P: ProtocolParticipant + 'static>(
        &mut self,
        config: ParticipantConfig,
        sid: SessionId,
        inputs: P::Input,
        key_id: KeyId,
    ) -> anyhow::Result<()> {
        println!("Initializing new sub-protocol for SID: {:?} and KeyID: {:?}", sid, key_id);
        let rng = &mut rand::thread_rng();

        let mut participant: Participant<P> = Participant::from_config(config, sid.0, inputs)?;
        let init_message = participant.initialize_message()?;

        let (_output, messages) = participant.process_single_message(&init_message, rng)?;
        self.outgoing
            .send(MessageFromWorker::FinishedRound(messages))?;
        self.participants.insert(sid, participant, key_id);

        Ok(())
    }

    fn process_keygen(&mut self, sid: SessionId, incoming: Message) -> anyhow::Result<()> {
        println!("Processing keygen message for SID: {:?}", sid);
        let (p, key_id) = self.participants.get_mut::<KeygenParticipant<C>>(&sid);
        Self::process_message(
            p,
            key_id,
            incoming,
            &mut self.key_gen_material,
            &self.outgoing,
        )
    }

    #[instrument(skip_all)]
    fn process_message<P: ProtocolParticipant + 'static>(
        participant: &mut Participant<P>,
        key_id: KeyId,
        incoming: Message,
        stored_output: &mut StoredOutput<P>,
        outgoing: &Sender<MessageFromWorker>,
    ) -> anyhow::Result<()> {
        let (output, messages) =
            participant.process_single_message(&incoming, &mut rand::thread_rng())?;

        if !messages.is_empty() {
            outgoing.send(MessageFromWorker::FinishedRound(messages))?;
        }

        if let Some(output) = output {
            stored_output.store(key_id, output);
            outgoing.send(MessageFromWorker::SubProtocolEnded)?;
        }
        Ok(())
    }
}

#[instrument(skip_all)]
fn participant_worker<C: CurveTrait + 'static>(
    config: ParticipantConfig,
    from_coordinator: Receiver<MessageFromCoordinator>,
    outgoing: Sender<MessageFromWorker>,
) -> anyhow::Result<()> {
    let mut worker: Worker<C> = Worker::new(config, outgoing);
    let mut current_subprotocol: HashMap<SessionId, SubProtocol> = Default::default();

    for incoming in from_coordinator {
        match incoming {
            MessageFromCoordinator::SubProtocolMessage(message) => {
                let sid = SessionId(message.id());
                let sub_protocol = current_subprotocol.get(&sid).unwrap();

                match sub_protocol {
                    SubProtocol::KeyGeneration => {
                        worker.process_keygen(sid, message)?;
                    }
                    _ => {} // Only handling keygen for now
                }
            }
            MessageFromCoordinator::NewSubProtocol(sub_protocol, key_id, sid) => {
                current_subprotocol.insert(sid, sub_protocol);

                match sub_protocol {
                    SubProtocol::KeyGeneration => {
                        worker.new_keygen(sid, key_id)?;
                    }
                    _ => {} // Only handling keygen for now
                }
            }
        }
    }

    Ok(())
}
