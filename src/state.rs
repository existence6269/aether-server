use std::{
    collections::{HashMap, HashSet, VecDeque},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use aether_crypto::{DeviceAuthChallenge, IdentityPublicKey};
use tokio::sync::{mpsc, watch, Mutex};
use uuid::Uuid;

use crate::{
    accounts::AccountDirectory, DeviceAddress, DeviceAuthorizer, OpaqueEnvelope, ServerConfig,
    ServerError, ServerFrame,
};

const AUTH_CHALLENGE_REPLAY_RETENTION: Duration = Duration::from_secs(10 * 60);
const MAX_AUTH_CHALLENGE_REPLAY_IDS: usize = 1_000_000;

#[derive(Clone)]
pub struct AppState {
    inner: Arc<Inner>,
}

struct Inner {
    config: ServerConfig,
    authorizer: Arc<dyn DeviceAuthorizer>,
    accounts: Option<AccountDirectory>,
    hub: Mutex<Hub>,
    used_auth_challenges: Mutex<HashMap<[u8; 16], Instant>>,
    next_connection_id: AtomicU64,
    accepting: AtomicBool,
    shutdown: watch::Sender<bool>,
}

#[derive(Default)]
struct Hub {
    connections: HashMap<DeviceAddress, Connection>,
    mailboxes: HashMap<DeviceAddress, Mailbox>,
    queued_messages: usize,
    queued_bytes: usize,
}

#[derive(Default)]
struct Mailbox {
    messages: VecDeque<OpaqueEnvelope>,
    bytes: usize,
}

struct Connection {
    id: u64,
    sender: mpsc::Sender<OutboundFrame>,
    sent_message_ids: HashSet<Uuid>,
}

pub(crate) struct ConnectionHandle {
    pub id: u64,
    pub receiver: mpsc::Receiver<OutboundFrame>,
}

pub(crate) enum OutboundFrame {
    Protocol(ServerFrame),
    Pong(Vec<u8>),
    Close,
}

impl AppState {
    pub fn new(
        config: ServerConfig,
        authorizer: Arc<dyn DeviceAuthorizer>,
    ) -> Result<Self, ServerError> {
        Self::build(config, authorizer, None)
    }

    pub(crate) fn with_account_directory(
        config: ServerConfig,
        directory: AccountDirectory,
    ) -> Result<Self, ServerError> {
        Self::build(config, Arc::new(directory.clone()), Some(directory))
    }

    fn build(
        config: ServerConfig,
        authorizer: Arc<dyn DeviceAuthorizer>,
        accounts: Option<AccountDirectory>,
    ) -> Result<Self, ServerError> {
        config.validate()?;
        let (shutdown, _) = watch::channel(false);
        Ok(Self {
            inner: Arc::new(Inner {
                config,
                authorizer,
                accounts,
                hub: Mutex::new(Hub::default()),
                used_auth_challenges: Mutex::new(HashMap::new()),
                next_connection_id: AtomicU64::new(1),
                accepting: AtomicBool::new(true),
                shutdown,
            }),
        })
    }

    pub(crate) fn accounts(&self) -> Option<&AccountDirectory> {
        self.inner.accounts.as_ref()
    }

    pub fn config(&self) -> &ServerConfig {
        &self.inner.config
    }

    pub fn is_ready(&self) -> bool {
        self.inner.accepting.load(Ordering::Acquire)
    }

    pub fn stop_accepting(&self) {
        self.inner.accepting.store(false, Ordering::Release);
        self.inner.shutdown.send_replace(true);
    }

    pub(crate) fn shutdown_receiver(&self) -> watch::Receiver<bool> {
        self.inner.shutdown.subscribe()
    }

    pub async fn authorize_device(
        &self,
        identity: IdentityPublicKey,
        device: &DeviceAddress,
    ) -> Result<(), ServerError> {
        if !self.is_ready() {
            return Err(ServerError::ShuttingDown);
        }
        device.validate()?;
        self.inner.authorizer.authorize(identity, device).await
    }

    pub async fn authorize_recipient(&self, device: &DeviceAddress) -> Result<(), ServerError> {
        device.validate()?;
        self.inner.authorizer.authorize_recipient(device).await
    }

    pub(crate) async fn revoke_route_device(&self, address: &DeviceAddress) {
        let sender = {
            let mut hub = self.inner.hub.lock().await;
            let sender = hub
                .connections
                .remove(address)
                .map(|connection| connection.sender);
            if let Some(mailbox) = hub.mailboxes.remove(address) {
                hub.queued_messages -= mailbox.messages.len();
                hub.queued_bytes -= mailbox.bytes;
            }
            sender
        };
        if let Some(sender) = sender {
            let _ = sender.send(OutboundFrame::Close).await;
        }
    }

    pub(crate) async fn consume_auth_challenge(
        &self,
        challenge: &DeviceAuthChallenge,
    ) -> Result<(), ServerError> {
        let now = Instant::now();
        let mut used = self.inner.used_auth_challenges.lock().await;
        used.retain(|_, inserted| now.duration_since(*inserted) < AUTH_CHALLENGE_REPLAY_RETENTION);
        if used.contains_key(challenge.challenge_id()) {
            return Err(ServerError::Unauthorized);
        }
        if used.len() >= MAX_AUTH_CHALLENGE_REPLAY_IDS {
            return Err(ServerError::ResourceLimit);
        }
        used.insert(*challenge.challenge_id(), now);
        Ok(())
    }

    pub(crate) async fn connect(
        &self,
        address: DeviceAddress,
    ) -> Result<ConnectionHandle, ServerError> {
        if !self.is_ready() {
            return Err(ServerError::ShuttingDown);
        }
        address.validate()?;
        let mut hub = self.inner.hub.lock().await;
        if !hub.connections.contains_key(&address)
            && hub.connections.len() >= self.inner.config.max_connections
        {
            return Err(ServerError::ResourceLimit);
        }
        if !hub.connections.contains_key(&address) && !hub.mailboxes.contains_key(&address) {
            let known_devices: HashSet<_> =
                hub.mailboxes.keys().chain(hub.connections.keys()).collect();
            if known_devices.len() >= self.inner.config.max_known_devices {
                return Err(ServerError::ResourceLimit);
            }
        }
        let id = self
            .inner
            .next_connection_id
            .fetch_add(1, Ordering::Relaxed);
        let (sender, receiver) = mpsc::channel(self.inner.config.outbound_channel_capacity);
        if let Some(previous) = hub.connections.insert(
            address.clone(),
            Connection {
                id,
                sender,
                sent_message_ids: HashSet::new(),
            },
        ) {
            let _ = previous
                .sender
                .try_send(OutboundFrame::Protocol(ServerFrame::Error {
                    code: "connection_replaced".to_owned(),
                }));
        }
        pump_device(&mut hub, &address);
        Ok(ConnectionHandle { id, receiver })
    }

    pub(crate) async fn disconnect(&self, address: &DeviceAddress, id: u64) {
        let mut hub = self.inner.hub.lock().await;
        if hub
            .connections
            .get(address)
            .is_some_and(|connection| connection.id == id)
        {
            hub.connections.remove(address);
        }
    }

    pub(crate) async fn refill(&self, address: &DeviceAddress, id: u64) {
        let mut hub = self.inner.hub.lock().await;
        if hub
            .connections
            .get(address)
            .is_some_and(|connection| connection.id == id)
        {
            pump_device(&mut hub, address);
        }
    }

    pub(crate) async fn enqueue_from(
        &self,
        sender: &DeviceAddress,
        connection_id: u64,
        recipient: DeviceAddress,
        payload: Vec<u8>,
    ) -> Result<Uuid, ServerError> {
        self.enqueue_inner(sender.clone(), recipient, payload, Some(connection_id))
            .await
    }

    #[cfg(test)]
    async fn enqueue(
        &self,
        sender: DeviceAddress,
        recipient: DeviceAddress,
        payload: Vec<u8>,
    ) -> Result<Uuid, ServerError> {
        self.enqueue_inner(sender, recipient, payload, None).await
    }

    async fn enqueue_inner(
        &self,
        sender: DeviceAddress,
        recipient: DeviceAddress,
        payload: Vec<u8>,
        expected_connection_id: Option<u64>,
    ) -> Result<Uuid, ServerError> {
        if !self.is_ready() {
            return Err(ServerError::ShuttingDown);
        }
        sender.validate()?;
        recipient.validate()?;
        if payload.len() > self.inner.config.max_message_bytes {
            return Err(ServerError::MessageTooLarge);
        }
        let payload_len = payload.len();
        let message_id = Uuid::new_v4();
        let envelope = OpaqueEnvelope {
            message_id,
            sender: sender.clone(),
            recipient: recipient.clone(),
            payload,
        };
        let encoded = serde_json::to_vec(&envelope).map_err(|_| ServerError::Internal)?;
        if encoded.len() > self.inner.config.max_websocket_frame_bytes {
            return Err(ServerError::MessageTooLarge);
        }

        let mut hub = self.inner.hub.lock().await;
        if let Some(connection_id) = expected_connection_id {
            if !hub
                .connections
                .get(&sender)
                .is_some_and(|connection| connection.id == connection_id)
            {
                return Err(ServerError::ShuttingDown);
            }
        }
        if hub.queued_messages >= self.inner.config.max_queued_messages_total {
            return Err(ServerError::ResourceLimit);
        }
        let device_queue_len = hub
            .mailboxes
            .get(&recipient)
            .map_or(0, |mailbox| mailbox.messages.len());
        if device_queue_len >= self.inner.config.max_queued_messages_per_device {
            return Err(ServerError::QueueFull);
        }
        let device_queue_bytes = hub
            .mailboxes
            .get(&recipient)
            .map_or(0, |mailbox| mailbox.bytes);
        if envelope.payload.len()
            > self
                .inner
                .config
                .max_queued_bytes_per_device
                .saturating_sub(device_queue_bytes)
            || envelope.payload.len()
                > self
                    .inner
                    .config
                    .max_queued_bytes_total
                    .saturating_sub(hub.queued_bytes)
        {
            return Err(ServerError::ResourceLimit);
        }
        if !hub.mailboxes.contains_key(&recipient) && !hub.connections.contains_key(&recipient) {
            let known_devices: HashSet<_> =
                hub.mailboxes.keys().chain(hub.connections.keys()).collect();
            if known_devices.len() >= self.inner.config.max_known_devices {
                return Err(ServerError::ResourceLimit);
            }
        }
        let mailbox = hub.mailboxes.entry(recipient.clone()).or_default();
        mailbox.bytes += envelope.payload.len();
        mailbox.messages.push_back(envelope);
        hub.queued_messages += 1;
        hub.queued_bytes += payload_len;
        pump_device(&mut hub, &recipient);
        Ok(message_id)
    }

    pub(crate) async fn acknowledge(
        &self,
        recipient: &DeviceAddress,
        connection_id: u64,
        message_id: Uuid,
    ) -> Result<(), ServerError> {
        let mut hub = self.inner.hub.lock().await;
        let connection = hub
            .connections
            .get(recipient)
            .filter(|connection| connection.id == connection_id)
            .ok_or(ServerError::InvalidAcknowledgement)?;
        if !connection.sent_message_ids.contains(&message_id) {
            return Err(ServerError::InvalidAcknowledgement);
        }
        let Some(index) = hub
            .mailboxes
            .get(recipient)
            .ok_or(ServerError::InvalidAcknowledgement)?
            .messages
            .iter()
            .position(|envelope| envelope.message_id == message_id)
        else {
            return Err(ServerError::InvalidAcknowledgement);
        };
        let envelope = hub
            .mailboxes
            .get_mut(recipient)
            .and_then(|mailbox| mailbox.messages.remove(index))
            .ok_or(ServerError::InvalidAcknowledgement)?;
        if let Some(connection) = hub.connections.get_mut(recipient) {
            connection.sent_message_ids.remove(&message_id);
        } else {
            return Err(ServerError::InvalidAcknowledgement);
        }
        hub.mailboxes
            .get_mut(recipient)
            .ok_or(ServerError::InvalidAcknowledgement)?
            .bytes -= envelope.payload.len();
        hub.queued_messages -= 1;
        hub.queued_bytes -= envelope.payload.len();
        if hub
            .mailboxes
            .get(recipient)
            .is_some_and(|mailbox| mailbox.messages.is_empty())
        {
            hub.mailboxes.remove(recipient);
        }
        pump_device(&mut hub, recipient);
        Ok(())
    }

    pub(crate) async fn send_control(
        &self,
        address: &DeviceAddress,
        id: u64,
        frame: ServerFrame,
    ) -> Result<(), ServerError> {
        let sender = {
            let hub = self.inner.hub.lock().await;
            hub.connections
                .get(address)
                .filter(|connection| connection.id == id)
                .map(|connection| connection.sender.clone())
                .ok_or(ServerError::ShuttingDown)?
        };
        sender
            .send(OutboundFrame::Protocol(frame))
            .await
            .map_err(|_| ServerError::ShuttingDown)
    }

    pub(crate) async fn send_ws_pong(
        &self,
        address: &DeviceAddress,
        id: u64,
        payload: Vec<u8>,
    ) -> Result<(), ServerError> {
        let sender = {
            let hub = self.inner.hub.lock().await;
            hub.connections
                .get(address)
                .filter(|connection| connection.id == id)
                .map(|connection| connection.sender.clone())
                .ok_or(ServerError::ShuttingDown)?
        };
        sender
            .send(OutboundFrame::Pong(payload))
            .await
            .map_err(|_| ServerError::ShuttingDown)
    }

    pub(crate) async fn send_ws_close(
        &self,
        address: &DeviceAddress,
        id: u64,
    ) -> Result<(), ServerError> {
        let sender = {
            let hub = self.inner.hub.lock().await;
            hub.connections
                .get(address)
                .filter(|connection| connection.id == id)
                .map(|connection| connection.sender.clone())
                .ok_or(ServerError::ShuttingDown)?
        };
        sender
            .send(OutboundFrame::Close)
            .await
            .map_err(|_| ServerError::ShuttingDown)
    }

    pub(crate) async fn pong(
        &self,
        address: &DeviceAddress,
        id: u64,
        expected_nonce: Option<Uuid>,
        received_nonce: Uuid,
    ) -> Result<(), ServerError> {
        if expected_nonce != Some(received_nonce) {
            return Err(ServerError::InvalidRequest);
        }
        let hub = self.inner.hub.lock().await;
        if hub
            .connections
            .get(address)
            .is_some_and(|connection| connection.id == id)
        {
            Ok(())
        } else {
            Err(ServerError::ShuttingDown)
        }
    }

    #[cfg(test)]
    pub(crate) async fn queued_messages(&self) -> usize {
        self.inner.hub.lock().await.queued_messages
    }

    #[cfg(test)]
    pub(crate) async fn queued_bytes(&self) -> usize {
        self.inner.hub.lock().await.queued_bytes
    }
}

fn pump_device(hub: &mut Hub, address: &DeviceAddress) {
    let pending: Vec<_> = hub
        .mailboxes
        .get(address)
        .map(|mailbox| mailbox.messages.iter().cloned().collect())
        .unwrap_or_default();
    let Some(connection) = hub.connections.get_mut(address) else {
        return;
    };
    for envelope in pending {
        if connection.sent_message_ids.contains(&envelope.message_id) {
            continue;
        }
        match connection
            .sender
            .try_send(OutboundFrame::Protocol(ServerFrame::Deliver {
                envelope: envelope.clone(),
            })) {
            Ok(()) => {
                connection.sent_message_ids.insert(envelope.message_id);
            }
            Err(mpsc::error::TrySendError::Full(_)) => break,
            Err(mpsc::error::TrySendError::Closed(_)) => break,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use aether_crypto::{DeviceAuthChallenge, Identity, IdentityPublicKey};
    use uuid::Uuid;

    use crate::{
        config::ServerConfig, DeviceAddress, DeviceAuthorizer, RejectAllAuthenticator, ServerError,
    };

    use super::{AppState, OutboundFrame};

    struct TestAuth;

    #[async_trait::async_trait]
    impl DeviceAuthorizer for TestAuth {
        async fn authorize(
            &self,
            _identity: IdentityPublicKey,
            device: &DeviceAddress,
        ) -> Result<(), ServerError> {
            if device == &DeviceAddress::new("test-user", "test-device")? {
                Ok(())
            } else {
                Err(ServerError::Unauthorized)
            }
        }

        async fn authorize_recipient(&self, device: &DeviceAddress) -> Result<(), ServerError> {
            if device == &DeviceAddress::new("test-user", "test-device")? {
                Ok(())
            } else {
                Err(ServerError::Unauthorized)
            }
        }
    }

    fn state_with_limits(max_per_device: usize, max_total: usize, max_devices: usize) -> AppState {
        let mut config = ServerConfig::default();
        config.max_queued_messages_per_device = max_per_device;
        config.max_queued_messages_total = max_total;
        config.max_known_devices = max_devices;
        AppState::new(config, Arc::new(TestAuth)).expect("valid test config")
    }

    #[tokio::test]
    async fn queues_offline_delivers_online_and_removes_only_after_ack() {
        let state = state_with_limits(4, 8, 8);
        let sender = DeviceAddress::new("alice", "laptop").unwrap();
        let recipient = DeviceAddress::new("bob", "phone").unwrap();
        let id = state
            .enqueue(sender, recipient.clone(), vec![1, 2, 3])
            .await
            .expect("queue offline");
        assert_eq!(state.queued_messages().await, 1);

        let mut connection = state.connect(recipient.clone()).await.unwrap();
        let delivered = connection.receiver.recv().await.unwrap();
        assert!(matches!(
            delivered,
            OutboundFrame::Protocol(crate::ServerFrame::Deliver { envelope }) if envelope.message_id == id && envelope.payload == [1, 2, 3]
        ));
        assert_eq!(state.queued_messages().await, 1);

        state
            .acknowledge(&recipient, connection.id, id)
            .await
            .expect("ack delivery");
        assert_eq!(state.queued_messages().await, 0);
        assert!(matches!(
            state.acknowledge(&recipient, connection.id, id).await,
            Err(ServerError::InvalidAcknowledgement)
        ));
    }

    #[tokio::test]
    async fn delivers_new_message_to_an_already_online_device() {
        let state = state_with_limits(4, 8, 8);
        let recipient = DeviceAddress::new("bob", "phone").unwrap();
        let mut connection = state.connect(recipient.clone()).await.unwrap();
        let id = state
            .enqueue(
                DeviceAddress::new("alice", "laptop").unwrap(),
                recipient.clone(),
                vec![9, 8, 7],
            )
            .await
            .unwrap();
        assert!(matches!(
            connection.receiver.recv().await,
            Some(OutboundFrame::Protocol(crate::ServerFrame::Deliver { envelope })) if envelope.message_id == id && envelope.payload == [9, 8, 7]
        ));
        state
            .acknowledge(&recipient, connection.id, id)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn reconnect_resumes_unacknowledged_messages_and_old_disconnect_cannot_remove_new() {
        let state = state_with_limits(4, 8, 8);
        let recipient = DeviceAddress::new("bob", "phone").unwrap();
        let id = state
            .enqueue(
                DeviceAddress::new("alice", "laptop").unwrap(),
                recipient.clone(),
                b"opaque".to_vec(),
            )
            .await
            .unwrap();
        let mut first = state.connect(recipient.clone()).await.unwrap();
        assert!(matches!(
            first.receiver.recv().await,
            Some(OutboundFrame::Protocol(crate::ServerFrame::Deliver { envelope })) if envelope.message_id == id
        ));
        let mut second = state.connect(recipient.clone()).await.unwrap();
        assert!(matches!(
            second.receiver.recv().await,
            Some(OutboundFrame::Protocol(crate::ServerFrame::Deliver { envelope })) if envelope.message_id == id
        ));
        state.disconnect(&recipient, first.id).await;
        state
            .acknowledge(&recipient, second.id, id)
            .await
            .expect("replacement connection remains registered");
        state.disconnect(&recipient, second.id).await;
        assert_eq!(state.queued_messages().await, 0);
    }

    #[tokio::test]
    async fn queue_and_known_device_limits_are_enforced() {
        let state = state_with_limits(1, 1, 1);
        let recipient = DeviceAddress::new("bob", "phone").unwrap();
        state
            .enqueue(
                DeviceAddress::new("alice", "laptop").unwrap(),
                recipient.clone(),
                vec![1],
            )
            .await
            .unwrap();
        assert!(matches!(
            state
                .enqueue(
                    DeviceAddress::new("alice", "laptop").unwrap(),
                    recipient,
                    vec![2],
                )
                .await,
            Err(ServerError::ResourceLimit) | Err(ServerError::QueueFull)
        ));
        assert!(matches!(
            state
                .enqueue(
                    DeviceAddress::new("alice", "laptop").unwrap(),
                    DeviceAddress::new("carol", "tablet").unwrap(),
                    vec![3],
                )
                .await,
            Err(ServerError::ResourceLimit)
        ));

        let state = state_with_limits(4, 8, 1);
        let _first = state
            .connect(DeviceAddress::new("alice", "laptop").unwrap())
            .await
            .unwrap();
        assert!(matches!(
            state
                .connect(DeviceAddress::new("bob", "phone").unwrap())
                .await,
            Err(ServerError::ResourceLimit)
        ));
    }

    #[tokio::test]
    async fn message_byte_limits_are_enforced_and_accounted() {
        let mut config = ServerConfig::default();
        config.max_message_bytes = 8;
        config.max_queued_bytes_per_device = 4;
        config.max_queued_bytes_total = 8;
        let state = AppState::new(config, Arc::new(TestAuth)).unwrap();
        let sender = DeviceAddress::new("alice", "laptop").unwrap();
        let recipient = DeviceAddress::new("bob", "phone").unwrap();
        state
            .enqueue(sender.clone(), recipient.clone(), vec![1, 2, 3, 4])
            .await
            .unwrap();
        assert_eq!(state.queued_bytes().await, 4);
        assert!(matches!(
            state.enqueue(sender, recipient, vec![5]).await,
            Err(ServerError::ResourceLimit)
        ));
        assert!(matches!(
            state
                .enqueue(
                    DeviceAddress::new("alice", "laptop").unwrap(),
                    DeviceAddress::new("carol", "phone").unwrap(),
                    vec![0; 9],
                )
                .await,
            Err(ServerError::MessageTooLarge)
        ));
    }

    #[tokio::test]
    async fn concurrent_enqueue_respects_global_queue_limit() {
        let state = state_with_limits(100, 10, 20);
        let mut tasks = Vec::new();
        for index in 0..20 {
            let state = state.clone();
            tasks.push(tokio::spawn(async move {
                state
                    .enqueue(
                        DeviceAddress::new("alice", "laptop").unwrap(),
                        DeviceAddress::new(format!("user-{index}"), "phone").unwrap(),
                        vec![index as u8],
                    )
                    .await
            }));
        }
        let mut accepted = 0;
        for task in tasks {
            if task.await.unwrap().is_ok() {
                accepted += 1;
            }
        }
        assert_eq!(accepted, 10);
        assert_eq!(state.queued_messages().await, 10);
    }

    #[tokio::test]
    async fn stale_acknowledgements_and_wrong_heartbeat_nonces_fail() {
        let state = state_with_limits(4, 8, 8);
        let recipient = DeviceAddress::new("bob", "phone").unwrap();
        let connection = state.connect(recipient.clone()).await.unwrap();
        assert!(state
            .acknowledge(&recipient, connection.id, Uuid::new_v4())
            .await
            .is_err());
        assert!(state
            .pong(
                &recipient,
                connection.id,
                Some(Uuid::new_v4()),
                Uuid::new_v4()
            )
            .await
            .is_err());
    }

    #[tokio::test]
    async fn device_revocation_closes_its_relay_and_discards_queued_messages() {
        let state = state_with_limits(4, 8, 8);
        let address = DeviceAddress::new("alice", "phone").unwrap();
        let mut connection = state.connect(address.clone()).await.unwrap();
        state
            .enqueue(
                DeviceAddress::new("bob", "laptop").unwrap(),
                address.clone(),
                vec![1, 2, 3],
            )
            .await
            .unwrap();
        state.revoke_route_device(&address).await;
        let mut closed = false;
        while let Some(frame) = connection.receiver.recv().await {
            if matches!(frame, OutboundFrame::Close) {
                closed = true;
                break;
            }
        }
        assert!(closed);
        assert_eq!(state.queued_messages().await, 0);
        assert_eq!(state.queued_bytes().await, 0);
    }

    #[tokio::test]
    async fn deny_all_authenticator_never_accepts_credentials() {
        let state =
            AppState::new(ServerConfig::default(), Arc::new(RejectAllAuthenticator)).unwrap();
        assert!(matches!(
            state
                .authorize_device(
                    IdentityPublicKey::from_bytes([3; 32]),
                    &DeviceAddress::new("test", "device").unwrap()
                )
                .await,
            Err(ServerError::Unauthorized)
        ));
    }

    #[tokio::test]
    async fn authentication_challenge_ids_are_one_use() {
        let identity = Identity::from_secret_bytes(&[44; 32]).unwrap();
        let challenge = DeviceAuthChallenge::new(
            "local-relay",
            "test-user",
            "test-device",
            identity.public_key(),
            [7; 16],
            [8; 32],
        )
        .unwrap();
        let state = state_with_limits(2, 4, 4);
        assert!(state.consume_auth_challenge(&challenge).await.is_ok());
        assert!(matches!(
            state.consume_auth_challenge(&challenge).await,
            Err(ServerError::Unauthorized)
        ));
    }
}
