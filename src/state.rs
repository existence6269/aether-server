use std::{
    collections::{HashMap, HashSet, VecDeque},
    future::Future,
    hash::{Hash, Hasher},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use aether_crypto::{DeviceAuthChallenge, DeviceAuthProof, IdentityPublicKey};
use tokio::sync::{mpsc, watch, Mutex, OwnedMutexGuard};
use uuid::Uuid;

use crate::{
    accounts::AccountDirectory, DeviceAddress, DeviceAuthorizer, OpaqueEnvelope, ServerConfig,
    ServerError, ServerFrame,
};

const AUTH_CHALLENGE_REPLAY_RETENTION: Duration = Duration::from_secs(10 * 60);
const MAX_AUTH_CHALLENGE_REPLAY_IDS: usize = 1_000_000;
const AUTHORIZATION_LOCK_STRIPES: usize = 64;

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
    authorization_locks: [Arc<Mutex<()>>; AUTHORIZATION_LOCK_STRIPES],
    next_connection_id: AtomicU64,
    instance_id: Uuid,
    coordination_healthy: AtomicBool,
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

pub(crate) struct DeviceAuthorizationGuard {
    device: DeviceAddress,
    _guard: OwnedMutexGuard<()>,
}

pub(crate) struct DeviceAuthorizationGuards {
    _guards: Vec<OwnedMutexGuard<()>>,
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
        Self::build(
            config,
            Arc::new(crate::RejectAllAuthenticator),
            Some(directory),
        )
    }

    fn build(
        config: ServerConfig,
        authorizer: Arc<dyn DeviceAuthorizer>,
        accounts: Option<AccountDirectory>,
    ) -> Result<Self, ServerError> {
        config.validate()?;
        let (shutdown, _) = watch::channel(false);
        let coordination_healthy = accounts.is_none();
        Ok(Self {
            inner: Arc::new(Inner {
                config,
                authorizer,
                accounts,
                hub: Mutex::new(Hub::default()),
                used_auth_challenges: Mutex::new(HashMap::new()),
                authorization_locks: std::array::from_fn(|_| Arc::new(Mutex::new(()))),
                next_connection_id: AtomicU64::new(1),
                instance_id: Uuid::new_v4(),
                coordination_healthy: AtomicBool::new(coordination_healthy),
                accepting: AtomicBool::new(true),
                shutdown,
            }),
        })
    }

    pub(crate) fn accounts(&self) -> Option<&AccountDirectory> {
        self.inner.accounts.as_ref()
    }

    pub(crate) fn instance_id(&self) -> Uuid {
        self.inner.instance_id
    }

    pub(crate) async fn start_coordination(&self) -> Result<(), ServerError> {
        if let Some(accounts) = &self.inner.accounts {
            accounts
                .register_relay_instance(self.inner.instance_id)
                .await?;
            self.inner
                .coordination_healthy
                .store(true, Ordering::Release);
        }
        Ok(())
    }

    pub(crate) async fn poll_revocations(&self) -> Result<(), ServerError> {
        let Some(accounts) = &self.inner.accounts else {
            return Ok(());
        };
        for event in accounts.pending_revocations(self.inner.instance_id).await? {
            let guard = self.lock_device_authorization(&event.address).await;
            self.revoke_route_device(&event.address, guard).await?;
            accounts
                .acknowledge_revocation(self.inner.instance_id, event.event_id)
                .await?;
        }
        Ok(())
    }

    pub(crate) fn set_coordination_health(&self, healthy: bool) {
        self.inner
            .coordination_healthy
            .store(healthy, Ordering::Release);
    }

    pub fn config(&self) -> &ServerConfig {
        &self.inner.config
    }

    pub fn is_ready(&self) -> bool {
        self.inner.accepting.load(Ordering::Acquire)
            && self.inner.coordination_healthy.load(Ordering::Acquire)
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
        if let Some(accounts) = &self.inner.accounts {
            accounts
                .authorize_for_instance(identity, device, self.inner.instance_id)
                .await
        } else {
            self.inner.authorizer.authorize(identity, device).await
        }
    }

    pub async fn authorize_recipient(&self, device: &DeviceAddress) -> Result<(), ServerError> {
        if !self.is_ready() {
            return Err(ServerError::Unavailable);
        }
        device.validate()?;
        if let Some(accounts) = &self.inner.accounts {
            accounts
                .authorize_recipient_for_instance(device, self.inner.instance_id)
                .await
        } else {
            self.inner.authorizer.authorize_recipient(device).await
        }
    }

    pub(crate) async fn register_auth_challenge(
        &self,
        identity: IdentityPublicKey,
        device: &DeviceAddress,
        challenge: &DeviceAuthChallenge,
    ) -> Result<(), ServerError> {
        if let Some(accounts) = &self.inner.accounts {
            accounts
                .issue_auth_challenge(
                    Uuid::from_bytes(*challenge.challenge_id()),
                    identity,
                    device,
                    self.inner.instance_id,
                )
                .await
        } else {
            Ok(())
        }
    }

    pub(crate) async fn lock_device_authorization(
        &self,
        device: &DeviceAddress,
    ) -> DeviceAuthorizationGuard {
        let stripe = self.authorization_stripe(device);
        DeviceAuthorizationGuard {
            device: device.clone(),
            _guard: Arc::clone(&self.inner.authorization_locks[stripe])
                .lock_owned()
                .await,
        }
    }

    fn authorization_stripe(&self, device: &DeviceAddress) -> usize {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        device.hash(&mut hasher);
        hasher.finish() as usize % self.inner.authorization_locks.len()
    }

    pub(crate) async fn lock_devices_authorization(
        &self,
        first: &DeviceAddress,
        second: &DeviceAddress,
    ) -> DeviceAuthorizationGuards {
        let mut stripes = [
            self.authorization_stripe(first),
            self.authorization_stripe(second),
        ];
        stripes.sort_unstable();
        let count = if stripes[0] == stripes[1] { 1 } else { 2 };
        let mut guards = Vec::with_capacity(count);
        for stripe in stripes.into_iter().take(count) {
            guards.push(
                Arc::clone(&self.inner.authorization_locks[stripe])
                    .lock_owned()
                    .await,
            );
        }
        DeviceAuthorizationGuards { _guards: guards }
    }

    pub(crate) async fn revoke_route_device(
        &self,
        address: &DeviceAddress,
        authorization_guard: DeviceAuthorizationGuard,
    ) -> Result<(), ServerError> {
        if &authorization_guard.device != address {
            return Err(ServerError::Internal);
        }
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
            let mut removed_messages = 0;
            let mut removed_bytes = 0;
            for mailbox in hub.mailboxes.values_mut() {
                let before_count = mailbox.messages.len();
                let before_bytes = mailbox.bytes;
                mailbox
                    .messages
                    .retain(|envelope| &envelope.sender != address);
                mailbox.bytes = mailbox
                    .messages
                    .iter()
                    .map(|envelope| envelope.payload.len())
                    .sum();
                removed_messages += before_count - mailbox.messages.len();
                removed_bytes += before_bytes - mailbox.bytes;
            }
            hub.queued_messages -= removed_messages;
            hub.queued_bytes -= removed_bytes;
            let connected_devices: HashSet<_> = hub.connections.keys().cloned().collect();
            hub.mailboxes.retain(|device, mailbox| {
                !mailbox.messages.is_empty() || connected_devices.contains(device)
            });
            sender
        };
        drop(authorization_guard);
        if let Some(sender) = sender {
            let _ = sender.try_send(OutboundFrame::Close);
        }
        Ok(())
    }

    pub(crate) async fn connect_authenticated(
        &self,
        identity: IdentityPublicKey,
        device: &DeviceAddress,
        challenge: &DeviceAuthChallenge,
        returned_challenge_id: &[u8; 16],
        proof: &DeviceAuthProof,
        authorization_guard: &DeviceAuthorizationGuard,
    ) -> Result<ConnectionHandle, ServerError> {
        if &authorization_guard.device != device
            || challenge.audience() != self.inner.config.server_id
            || challenge.user_id() != device.user_id
            || challenge.device_id() != device.device_id
            || challenge.identity_key() != identity
        {
            return Err(ServerError::Unauthorized);
        }
        if returned_challenge_id != challenge.challenge_id() {
            return Err(ServerError::Unauthorized);
        }
        if let Some(accounts) = &self.inner.accounts {
            let challenge_id = Uuid::from_bytes(*challenge.challenge_id());
            let transaction = accounts
                .consume_auth_challenge(challenge_id, identity, device, self.inner.instance_id)
                .await?;
            if identity
                .verify_device_auth_challenge(challenge, proof)
                .is_err()
            {
                transaction
                    .commit()
                    .await
                    .map_err(|_| ServerError::Internal)?;
                return Err(ServerError::Unauthorized);
            }
            let handle = self.connect(device.clone()).await?;
            if transaction.commit().await.is_err() {
                self.disconnect(device, handle.id).await;
                return Err(ServerError::Internal);
            }
            Ok(handle)
        } else {
            self.consume_auth_challenge(challenge).await?;
            if identity
                .verify_device_auth_challenge(challenge, proof)
                .is_err()
            {
                return Err(ServerError::Unauthorized);
            }
            self.authorize_device(identity, device).await?;
            self.connect(device.clone()).await
        }
    }

    #[cfg(test)]
    pub(crate) async fn connect_authenticated_paused(
        &self,
        identity: IdentityPublicKey,
        device: &DeviceAddress,
        challenge: &DeviceAuthChallenge,
        returned_challenge_id: &[u8; 16],
        proof: &DeviceAuthProof,
        authorization_guard: &DeviceAuthorizationGuard,
        locked: tokio::sync::oneshot::Sender<()>,
        resume: tokio::sync::oneshot::Receiver<()>,
    ) -> Result<ConnectionHandle, ServerError> {
        if &authorization_guard.device != device
            || challenge.audience() != self.inner.config.server_id
            || challenge.user_id() != device.user_id
            || challenge.device_id() != device.device_id
            || challenge.identity_key() != identity
            || returned_challenge_id != challenge.challenge_id()
            || identity
                .verify_device_auth_challenge(challenge, proof)
                .is_err()
        {
            return Err(ServerError::Unauthorized);
        }
        let accounts = self
            .inner
            .accounts
            .as_ref()
            .ok_or(ServerError::Unavailable)?;
        let transaction = accounts
            .consume_auth_challenge(
                Uuid::from_bytes(*challenge.challenge_id()),
                identity,
                device,
                self.inner.instance_id,
            )
            .await?;
        let _ = locked.send(());
        let _ = resume.await;
        let handle = self.connect(device.clone()).await?;
        if transaction.commit().await.is_err() {
            self.disconnect(device, handle.id).await;
            return Err(ServerError::Internal);
        }
        Ok(handle)
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
        self.enqueue_from_after_authorization(sender, connection_id, recipient, payload, async {})
            .await
    }

    async fn enqueue_from_after_authorization<F>(
        &self,
        sender: &DeviceAddress,
        connection_id: u64,
        recipient: DeviceAddress,
        payload: Vec<u8>,
        after_authorization: F,
    ) -> Result<Uuid, ServerError>
    where
        F: Future<Output = ()>,
    {
        if !self.is_ready() {
            return Err(ServerError::Unavailable);
        }
        let _guards = self.lock_devices_authorization(sender, &recipient).await;
        self.authorize_relay_pair(sender, &recipient).await?;
        after_authorization.await;
        self.enqueue_inner(sender.clone(), recipient, payload, Some(connection_id))
            .await
    }

    #[cfg(test)]
    pub(crate) async fn enqueue_from_paused(
        &self,
        sender: &DeviceAddress,
        connection_id: u64,
        recipient: DeviceAddress,
        payload: Vec<u8>,
        started: tokio::sync::oneshot::Sender<()>,
        resume: tokio::sync::oneshot::Receiver<()>,
    ) -> Result<Uuid, ServerError> {
        self.enqueue_from_after_authorization(
            sender,
            connection_id,
            recipient,
            payload,
            async move {
                let _ = started.send(());
                let _ = resume.await;
            },
        )
        .await
    }

    async fn authorize_relay_pair(
        &self,
        sender: &DeviceAddress,
        recipient: &DeviceAddress,
    ) -> Result<(), ServerError> {
        if let Some(accounts) = &self.inner.accounts {
            accounts
                .authorize_relay_pair(sender, recipient, self.inner.instance_id)
                .await
        } else {
            self.inner.authorizer.authorize_recipient(sender).await?;
            self.inner.authorizer.authorize_recipient(recipient).await
        }
    }

    pub(crate) async fn authorize_delivery(
        &self,
        sender: &DeviceAddress,
        recipient: &DeviceAddress,
    ) -> Result<(), ServerError> {
        if !self.is_ready() {
            return Err(ServerError::Unavailable);
        }
        self.authorize_relay_pair(sender, recipient).await
    }

    pub(crate) async fn is_current_connection(&self, address: &DeviceAddress, id: u64) -> bool {
        self.inner
            .hub
            .lock()
            .await
            .connections
            .get(address)
            .is_some_and(|connection| connection.id == id)
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
        if !self.is_ready() {
            return Err(ServerError::Unavailable);
        }
        let _guard = self.lock_device_authorization(recipient).await;
        self.authorize_recipient(recipient).await?;
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
            device.validate()
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
        let authorization_guard = state.lock_device_authorization(&address).await;
        state
            .revoke_route_device(&address, authorization_guard)
            .await
            .unwrap();
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

    #[tokio::test]
    async fn concurrent_replay_attempts_consume_a_challenge_once() {
        let identity = Identity::from_secret_bytes(&[47; 32]).unwrap();
        let challenge = DeviceAuthChallenge::new(
            "local-relay",
            "test-user",
            "test-device",
            identity.public_key(),
            [13; 16],
            [14; 32],
        )
        .unwrap();
        let state = state_with_limits(2, 4, 4);
        let (first, second) = tokio::join!(
            state.consume_auth_challenge(&challenge),
            state.consume_auth_challenge(&challenge)
        );
        assert_eq!(usize::from(first.is_ok()) + usize::from(second.is_ok()), 1);
        assert!(matches!(first.and(second), Err(ServerError::Unauthorized)));
    }

    #[tokio::test]
    async fn authenticated_connection_consumes_its_challenge_once() {
        let identity = Identity::from_secret_bytes(&[45; 32]).unwrap();
        let address = DeviceAddress::new("test-user", "test-device").unwrap();
        let challenge = DeviceAuthChallenge::new(
            ServerConfig::default().server_id,
            address.user_id.clone(),
            address.device_id.clone(),
            identity.public_key(),
            [9; 16],
            [10; 32],
        )
        .unwrap();
        let state = state_with_limits(4, 8, 8);
        let guard = state.lock_device_authorization(&address).await;
        let proof = identity.sign_device_auth_challenge(&challenge).unwrap();
        let _connection = state
            .connect_authenticated(
                identity.public_key(),
                &address,
                &challenge,
                challenge.challenge_id(),
                &proof,
                &guard,
            )
            .await
            .expect("registered device authenticates");
        assert!(matches!(
            state
                .connect_authenticated(
                    identity.public_key(),
                    &address,
                    &challenge,
                    challenge.challenge_id(),
                    &proof,
                    &guard
                )
                .await,
            Err(ServerError::Unauthorized)
        ));
    }

    #[tokio::test]
    async fn revoked_device_cannot_consume_challenge_into_a_connection() {
        use std::sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        };

        struct RevocableAuth(AtomicBool);

        #[async_trait::async_trait]
        impl DeviceAuthorizer for RevocableAuth {
            async fn authorize(
                &self,
                _identity: IdentityPublicKey,
                _device: &DeviceAddress,
            ) -> Result<(), ServerError> {
                if self.0.load(Ordering::Acquire) {
                    Err(ServerError::Unauthorized)
                } else {
                    Ok(())
                }
            }

            async fn authorize_recipient(
                &self,
                _device: &DeviceAddress,
            ) -> Result<(), ServerError> {
                Ok(())
            }
        }

        let identity = Identity::from_secret_bytes(&[46; 32]).unwrap();
        let address = DeviceAddress::new("test-user", "test-device").unwrap();
        let challenge = DeviceAuthChallenge::new(
            ServerConfig::default().server_id,
            address.user_id.clone(),
            address.device_id.clone(),
            identity.public_key(),
            [11; 16],
            [12; 32],
        )
        .unwrap();
        let authorizer = Arc::new(RevocableAuth(AtomicBool::new(false)));
        let state = AppState::new(ServerConfig::default(), authorizer.clone()).unwrap();
        authorizer.0.store(true, Ordering::Release);
        let guard = state.lock_device_authorization(&address).await;
        let proof = identity.sign_device_auth_challenge(&challenge).unwrap();
        assert!(matches!(
            state
                .connect_authenticated(
                    identity.public_key(),
                    &address,
                    &challenge,
                    challenge.challenge_id(),
                    &proof,
                    &guard
                )
                .await,
            Err(ServerError::Unauthorized)
        ));
        authorizer.0.store(false, Ordering::Release);
        assert!(matches!(
            state
                .connect_authenticated(
                    identity.public_key(),
                    &address,
                    &challenge,
                    challenge.challenge_id(),
                    &proof,
                    &guard
                )
                .await,
            Err(ServerError::Unauthorized)
        ));
    }
}
