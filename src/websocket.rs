use std::time::Instant;

use axum::{
    extract::{
        ws::{Message as WsMessage, WebSocket, WebSocketUpgrade},
        State,
    },
    response::Response,
};
use futures_util::{stream::SplitSink, SinkExt, StreamExt};
use tokio::time::{self, MissedTickBehavior};
use tracing::{debug, warn};
use uuid::Uuid;

use aether_crypto::DeviceAuthChallenge;

use crate::{
    protocol::{parse_client_frame, AuthClientFrame, AuthServerFrame},
    state::OutboundFrame,
    AppState, ClientFrame, DeviceAddress, ServerError, ServerFrame,
};

#[cfg(not(test))]
const AUTHENTICATION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);
#[cfg(test)]
const AUTHENTICATION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(1);

pub(crate) async fn upgrade(
    State(state): State<AppState>,
    websocket: WebSocketUpgrade,
) -> Result<Response, ServerError> {
    let config = state.config();
    Ok(websocket
        .max_message_size(config.max_websocket_frame_bytes)
        .max_frame_size(config.max_websocket_frame_bytes)
        .on_upgrade(move |socket| serve_connection(socket, state)))
}

async fn serve_connection(socket: WebSocket, state: AppState) {
    let (sink, mut stream, device, handle) = match authenticate_socket(socket, &state).await {
        Ok(authenticated) => authenticated,
        Err(error) => {
            debug!(error = error.code(), "websocket authentication rejected");
            return;
        }
    };
    let connection_id = handle.id;
    let interval_duration = state.config().heartbeat_interval;
    let timeout_duration = state.config().heartbeat_timeout;
    let writer_state = state.clone();
    let writer_device = device.clone();
    let mut receiver = handle.receiver;
    let mut writer = tokio::spawn(async move {
        write_frames(
            sink,
            &writer_state,
            &writer_device,
            connection_id,
            &mut receiver,
            timeout_duration,
        )
        .await;
    });
    let mut shutdown = state.shutdown_receiver();
    let mut heartbeat = time::interval(interval_duration);
    heartbeat.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let _ = heartbeat.tick().await;
    let mut outstanding_ping: Option<(Uuid, Instant)> = None;

    loop {
        tokio::select! {
            _ = &mut writer => {
                break;
            }
            incoming = stream.next() => {
                let Some(Ok(message)) = incoming else { break };
                match message {
                    WsMessage::Text(text) => {
                        let frame = match parse_client_frame(
                            text.as_bytes(),
                            state.config().max_websocket_frame_bytes,
                            state.config().max_message_bytes,
                        ) {
                            Ok(frame) => frame,
                            Err(error) => {
                                if send_error(&state, &device, connection_id, error).await.is_err() {
                                    break;
                                }
                                continue;
                            }
                        };
                        if handle_client_frame(
                            &state,
                            &device,
                            connection_id,
                            frame,
                            &mut outstanding_ping,
                        )
                        .await
                        .is_err()
                        {
                            break;
                        }
                    }
                    WsMessage::Binary(bytes) => {
                        let frame = match parse_client_frame(
                            &bytes,
                            state.config().max_websocket_frame_bytes,
                            state.config().max_message_bytes,
                        ) {
                            Ok(frame) => frame,
                            Err(error) => {
                                if send_error(&state, &device, connection_id, error).await.is_err() {
                                    break;
                                }
                                continue;
                            }
                        };
                        if handle_client_frame(
                            &state,
                            &device,
                            connection_id,
                            frame,
                            &mut outstanding_ping,
                        )
                        .await
                        .is_err()
                        {
                            break;
                        }
                    }
                    WsMessage::Ping(payload) => {
                        if state.send_ws_pong(&device, connection_id, payload.to_vec()).await.is_err() {
                            break;
                        }
                    }
                    WsMessage::Pong(_) => {}
                    WsMessage::Close(_) => break,
                }
            }
            changed = shutdown.changed() => {
                if changed.is_ok() && *shutdown.borrow() {
                    let _ = state.send_ws_close(&device, connection_id).await;
                    break;
                }
            }
            _ = heartbeat.tick() => {
                if outstanding_ping
                    .as_ref()
                    .is_some_and(|(_, sent_at)| sent_at.elapsed() >= timeout_duration)
                {
                    warn!("websocket heartbeat timed out");
                    break;
                }
                if outstanding_ping.is_none() {
                    let nonce = Uuid::new_v4();
                    match state
                        .send_control(
                            &device,
                            connection_id,
                            ServerFrame::Ping { nonce },
                        )
                        .await
                    {
                        Ok(()) => outstanding_ping = Some((nonce, Instant::now())),
                        Err(_) => break,
                    }
                }
            }
        }
    }

    state.disconnect(&device, connection_id).await;
    if !writer.is_finished() {
        if time::timeout(std::time::Duration::from_secs(2), &mut writer)
            .await
            .is_err()
        {
            writer.abort();
            let _ = writer.await;
        }
    }
    debug!("websocket connection closed");
}

type WebSocketSink = SplitSink<WebSocket, WsMessage>;
type WebSocketStream = futures_util::stream::SplitStream<WebSocket>;

async fn authenticate_socket(
    socket: WebSocket,
    state: &AppState,
) -> Result<
    (
        WebSocketSink,
        WebSocketStream,
        DeviceAddress,
        crate::state::ConnectionHandle,
    ),
    ServerError,
> {
    let (mut sink, mut stream) = socket.split();
    let start = read_auth_frame(&mut stream, state).await?;
    let AuthClientFrame::Start {
        device,
        identity_key,
    } = start
    else {
        send_auth_rejected(&mut sink, ServerError::Unauthorized).await;
        return Err(ServerError::Unauthorized);
    };
    if let Err(error) = state.authorize_device(identity_key, &device).await {
        send_auth_rejected(&mut sink, error).await;
        return Err(ServerError::Unauthorized);
    }
    let challenge_id = *Uuid::new_v4().as_bytes();
    let mut nonce = [0u8; 32];
    nonce[..16].copy_from_slice(Uuid::new_v4().as_bytes());
    nonce[16..].copy_from_slice(Uuid::new_v4().as_bytes());
    let challenge = DeviceAuthChallenge::new(
        state.config().server_id.clone(),
        device.user_id.clone(),
        device.device_id.clone(),
        identity_key,
        challenge_id,
        nonce,
    )
    .map_err(|_| ServerError::Internal)?;
    if let Err(error) = state
        .register_auth_challenge(identity_key, &device, &challenge)
        .await
    {
        send_auth_rejected(&mut sink, error).await;
        return Err(ServerError::Unauthorized);
    }
    send_auth_frame(
        &mut sink,
        &AuthServerFrame::Challenge {
            challenge: challenge.clone(),
        },
        state.config().max_websocket_frame_bytes,
    )
    .await?;

    let proof_frame = read_auth_frame(&mut stream, state).await?;
    let AuthClientFrame::Proof {
        challenge_id: returned_id,
        proof,
    } = proof_frame
    else {
        send_auth_rejected(&mut sink, ServerError::Unauthorized).await;
        return Err(ServerError::Unauthorized);
    };
    let authorization_guard = state.lock_device_authorization(&device).await;
    let handle = match state
        .connect_authenticated(
            identity_key,
            &device,
            &challenge,
            &returned_id,
            &proof,
            &authorization_guard,
        )
        .await
    {
        Ok(handle) => handle,
        Err(error) => {
            drop(authorization_guard);
            send_auth_rejected(&mut sink, error).await;
            return Err(ServerError::Unauthorized);
        }
    };
    let authenticated = time::timeout(
        AUTHENTICATION_TIMEOUT,
        send_auth_frame(
            &mut sink,
            &AuthServerFrame::Authenticated {
                device: device.clone(),
            },
            state.config().max_websocket_frame_bytes,
        ),
    )
    .await;
    let authenticated = match authenticated {
        Ok(result) => result,
        Err(_) => {
            state.disconnect(&device, handle.id).await;
            return Err(ServerError::Unauthorized);
        }
    };
    if let Err(error) = authenticated {
        state.disconnect(&device, handle.id).await;
        return Err(error);
    }
    drop(authorization_guard);
    Ok((sink, stream, device, handle))
}

async fn read_auth_frame(
    stream: &mut WebSocketStream,
    state: &AppState,
) -> Result<AuthClientFrame, ServerError> {
    let incoming = time::timeout(AUTHENTICATION_TIMEOUT, stream.next())
        .await
        .map_err(|_| ServerError::Unauthorized)?
        .ok_or(ServerError::Unauthorized)?
        .map_err(|_| ServerError::Unauthorized)?;
    let bytes = match incoming {
        WsMessage::Text(text) => text.as_bytes().to_vec(),
        WsMessage::Binary(bytes) => bytes.to_vec(),
        _ => return Err(ServerError::Unauthorized),
    };
    if bytes.len() > state.config().max_websocket_frame_bytes {
        return Err(ServerError::MessageTooLarge);
    }
    serde_json::from_slice(&bytes).map_err(|_| ServerError::Unauthorized)
}

async fn send_auth_frame(
    sink: &mut WebSocketSink,
    frame: &AuthServerFrame,
    max_bytes: usize,
) -> Result<(), ServerError> {
    let encoded = serde_json::to_string(frame).map_err(|_| ServerError::Internal)?;
    if encoded.len() > max_bytes {
        return Err(ServerError::MessageTooLarge);
    }
    time::timeout(
        AUTHENTICATION_TIMEOUT,
        sink.send(WsMessage::Text(encoded.into())),
    )
    .await
    .map_err(|_| ServerError::ShuttingDown)?
    .map_err(|_| ServerError::ShuttingDown)
}

async fn send_auth_rejected(sink: &mut WebSocketSink, error: ServerError) {
    let frame = AuthServerFrame::Rejected {
        code: error.code().to_owned(),
    };
    if let Ok(encoded) = serde_json::to_string(&frame) {
        let _ = time::timeout(
            AUTHENTICATION_TIMEOUT,
            sink.send(WsMessage::Text(encoded.into())),
        )
        .await;
    }
}

async fn write_frames(
    mut sink: SplitSink<WebSocket, WsMessage>,
    state: &AppState,
    device: &DeviceAddress,
    connection_id: u64,
    receiver: &mut tokio::sync::mpsc::Receiver<OutboundFrame>,
    write_timeout: std::time::Duration,
) {
    while let Some(frame) = receiver.recv().await {
        let result = match frame {
            OutboundFrame::Protocol(ServerFrame::Deliver { envelope }) => {
                let _guards = state
                    .lock_devices_authorization(&envelope.sender, &envelope.recipient)
                    .await;
                if !state.is_ready()
                    || !state.is_current_connection(device, connection_id).await
                    || &envelope.recipient != device
                {
                    break;
                }
                match state
                    .authorize_delivery(&envelope.sender, &envelope.recipient)
                    .await
                {
                    Ok(()) => {
                        let frame = ServerFrame::Deliver { envelope };
                        match serde_json::to_string(&frame) {
                            Ok(encoded)
                                if encoded.len() <= state.config().max_websocket_frame_bytes =>
                            {
                                send_with_timeout(
                                    &mut sink,
                                    WsMessage::Text(encoded.into()),
                                    write_timeout,
                                )
                                .await
                            }
                            _ => {
                                let _ = send_with_timeout(
                                    &mut sink,
                                    WsMessage::Close(None),
                                    write_timeout,
                                )
                                .await;
                                break;
                            }
                        }
                    }
                    Err(ServerError::Unauthorized) => Ok(()),
                    Err(_) => break,
                }
            }
            OutboundFrame::Protocol(frame) => match serde_json::to_string(&frame) {
                Ok(encoded) if encoded.len() <= state.config().max_websocket_frame_bytes => {
                    send_with_timeout(&mut sink, WsMessage::Text(encoded.into()), write_timeout)
                        .await
                }
                _ => {
                    let _ =
                        send_with_timeout(&mut sink, WsMessage::Close(None), write_timeout).await;
                    break;
                }
            },
            OutboundFrame::Pong(payload) => {
                send_with_timeout(&mut sink, WsMessage::Pong(payload.into()), write_timeout).await
            }
            OutboundFrame::Close => {
                let _ = send_with_timeout(&mut sink, WsMessage::Close(None), write_timeout).await;
                break;
            }
        };
        if result.is_err() {
            break;
        }
        state.refill(device, connection_id).await;
    }
}

async fn send_with_timeout(
    sink: &mut SplitSink<WebSocket, WsMessage>,
    message: WsMessage,
    timeout_duration: std::time::Duration,
) -> Result<(), ()> {
    match time::timeout(timeout_duration, sink.send(message)).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(_)) | Err(_) => Err(()),
    }
}

async fn handle_client_frame(
    state: &AppState,
    device: &DeviceAddress,
    connection_id: u64,
    frame: ClientFrame,
    outstanding_ping: &mut Option<(Uuid, Instant)>,
) -> Result<(), ()> {
    match frame {
        ClientFrame::Send {
            to,
            payload,
            message_id,
        } => {
            match state
                .enqueue_from_with_id(device, connection_id, to, payload, message_id)
                .await
            {
                Ok(message_id) => state
                    .send_control(device, connection_id, ServerFrame::Accepted { message_id })
                    .await
                    .map_err(|_| ()),
                Err(error) => send_error(state, device, connection_id, error).await,
            }
        }
        ClientFrame::Ack { message_id } => {
            match state.acknowledge(device, connection_id, message_id).await {
                Ok(()) => Ok(()),
                Err(error) => send_error(state, device, connection_id, error).await,
            }
        }
        ClientFrame::History {
            request_id,
            with,
            before,
            limit,
        } => match state.relay_history(device, &with, before, limit).await {
            Ok((messages, has_more)) => state
                .send_control(
                    device,
                    connection_id,
                    ServerFrame::History {
                        request_id,
                        with,
                        messages,
                        has_more,
                    },
                )
                .await
                .map_err(|_| ()),
            Err(error) => send_error(state, device, connection_id, error).await,
        },
        ClientFrame::DeleteForMe { message_id } => {
            match state.delete_message_for_me(device, message_id).await {
                Ok(()) => state
                    .send_control(device, connection_id, ServerFrame::Hidden { message_id })
                    .await
                    .map_err(|_| ()),
                Err(error) => send_error(state, device, connection_id, error).await,
            }
        }
        ClientFrame::DeleteForEveryone { message_id } => {
            match state
                .delete_message_for_everyone(device, connection_id, message_id)
                .await
            {
                Ok(()) => Ok(()),
                Err(error) => send_error(state, device, connection_id, error).await,
            }
        }
        ClientFrame::Typing { to, is_typing } => {
            match state
                .set_typing(device, connection_id, &to, is_typing)
                .await
            {
                Ok(()) => Ok(()),
                Err(error) => send_error(state, device, connection_id, error).await,
            }
        }
        ClientFrame::MarkRead { message_id } => {
            match state.mark_message_read(device, message_id).await {
                Ok(()) => Ok(()),
                Err(error) => send_error(state, device, connection_id, error).await,
            }
        }
        ClientFrame::Pong { nonce } => {
            let expected = outstanding_ping.as_ref().map(|(expected, _)| *expected);
            match state.pong(device, connection_id, expected, nonce).await {
                Ok(()) => {
                    *outstanding_ping = None;
                    Ok(())
                }
                Err(error) => send_error(state, device, connection_id, error).await,
            }
        }
    }
}

async fn send_error(
    state: &AppState,
    device: &DeviceAddress,
    connection_id: u64,
    error: ServerError,
) -> Result<(), ()> {
    state
        .send_control(
            device,
            connection_id,
            ServerFrame::Error {
                code: error.code().to_owned(),
            },
        )
        .await
        .map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use std::sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    };

    use aether_crypto::{DeviceAuthChallenge, Identity};
    use futures_util::{SinkExt, StreamExt};
    use serde_json::{json, Value};
    use tokio::{
        net::TcpListener,
        sync::Notify,
        time::{sleep, timeout},
    };
    use tokio_tungstenite::{
        connect_async,
        tungstenite::{client::IntoClientRequest, Message as ClientMessage},
    };

    use crate::{
        serve, AppState, AuthServerFrame, DeviceAddress, DeviceAuthorizer, ServerConfig,
        ServerError, StaticDeviceAuthorizer,
    };

    type ClientSocket = tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >;

    struct RevocableAuthorizer {
        revoked: AtomicBool,
        authorization_checks: AtomicUsize,
        block_second_check: bool,
        second_check_started: Notify,
        release_second_check: Notify,
    }

    impl RevocableAuthorizer {
        fn new(block_second_check: bool) -> Self {
            Self {
                revoked: AtomicBool::new(false),
                authorization_checks: AtomicUsize::new(0),
                block_second_check,
                second_check_started: Notify::new(),
                release_second_check: Notify::new(),
            }
        }
    }

    #[async_trait::async_trait]
    impl DeviceAuthorizer for RevocableAuthorizer {
        async fn authorize(
            &self,
            _identity: aether_crypto::IdentityPublicKey,
            device: &DeviceAddress,
        ) -> Result<(), ServerError> {
            if device != &DeviceAddress::new("alice", "phone")? {
                return Err(ServerError::Unauthorized);
            }
            let check = self.authorization_checks.fetch_add(1, Ordering::AcqRel) + 1;
            if check == 2 && self.block_second_check {
                self.second_check_started.notify_one();
                self.release_second_check.notified().await;
            }
            if self.revoked.load(Ordering::Acquire) {
                Err(ServerError::Unauthorized)
            } else {
                Ok(())
            }
        }

        async fn authorize_recipient(&self, device: &DeviceAddress) -> Result<(), ServerError> {
            if device == &DeviceAddress::new("alice", "phone")?
                && !self.revoked.load(Ordering::Acquire)
            {
                Ok(())
            } else {
                Err(ServerError::Unauthorized)
            }
        }
    }

    async fn connect_socket(address: std::net::SocketAddr) -> ClientSocket {
        let request = format!("ws://{address}/ws")
            .into_client_request()
            .expect("construct websocket request");
        connect_async(request)
            .await
            .expect("websocket connection")
            .0
    }

    async fn read_json(socket: &mut ClientSocket) -> Value {
        let message = timeout(std::time::Duration::from_secs(2), socket.next())
            .await
            .expect("websocket frame timeout")
            .expect("websocket remains open")
            .expect("websocket frame received");
        match message {
            ClientMessage::Text(text) => serde_json::from_str(&text).expect("valid server JSON"),
            other => panic!("unexpected websocket frame: {other:?}"),
        }
    }

    async fn start_authentication(
        socket: &mut ClientSocket,
        identity: &Identity,
    ) -> DeviceAuthChallenge {
        socket
            .send(ClientMessage::Text(
                json!({
                    "type": "start",
                    "device": { "user_id": "alice", "device_id": "phone" },
                    "identity_key": identity.public_key()
                })
                .to_string()
                .into(),
            ))
            .await
            .expect("send auth start");
        let frame: AuthServerFrame =
            serde_json::from_value(read_json(socket).await).expect("decode auth challenge");
        let AuthServerFrame::Challenge { challenge } = frame else {
            panic!("expected auth challenge");
        };
        challenge
    }

    async fn submit_proof(
        socket: &mut ClientSocket,
        identity: &Identity,
        challenge: &DeviceAuthChallenge,
    ) {
        let proof = identity
            .sign_device_auth_challenge(challenge)
            .expect("sign server challenge");
        socket
            .send(ClientMessage::Text(
                json!({
                    "type": "proof",
                    "challenge_id": challenge.challenge_id(),
                    "proof": proof
                })
                .to_string()
                .into(),
            ))
            .await
            .expect("send auth proof");
    }

    async fn authenticate(
        socket: &mut ClientSocket,
        identity: &Identity,
        user_id: &str,
        device_id: &str,
    ) -> Result<(), String> {
        socket
            .send(ClientMessage::Text(
                json!({
                    "type": "start",
                    "device": { "user_id": user_id, "device_id": device_id },
                    "identity_key": identity.public_key()
                })
                .to_string()
                .into(),
            ))
            .await
            .map_err(|error| error.to_string())?;
        let challenge_message = timeout(std::time::Duration::from_secs(2), socket.next())
            .await
            .map_err(|error| error.to_string())?
            .ok_or_else(|| "socket closed".to_owned())?
            .map_err(|error| error.to_string())?;
        let challenge_frame: AuthServerFrame = match challenge_message {
            ClientMessage::Text(text) => {
                serde_json::from_str(&text).map_err(|error| error.to_string())?
            }
            other => return Err(format!("unexpected challenge frame: {other:?}")),
        };
        let AuthServerFrame::Challenge { challenge } = challenge_frame else {
            return Err("server rejected authentication start".to_owned());
        };
        let proof = identity
            .sign_device_auth_challenge(&challenge)
            .map_err(|error| error.to_string())?;
        socket
            .send(ClientMessage::Text(
                json!({
                    "type": "proof",
                    "challenge_id": challenge.challenge_id(),
                    "proof": proof
                })
                .to_string()
                .into(),
            ))
            .await
            .map_err(|error| error.to_string())?;
        let result = read_json(socket).await;
        match serde_json::from_value::<AuthServerFrame>(result)
            .map_err(|error| error.to_string())?
        {
            AuthServerFrame::Authenticated { .. } => Ok(()),
            AuthServerFrame::Rejected { code } => Err(code.to_owned()),
            AuthServerFrame::Challenge { .. } => Err("unexpected second challenge".to_owned()),
        }
    }

    #[tokio::test]
    async fn authenticated_clients_route_opaque_payload_and_ack_delivery() {
        let alice_identity = Identity::from_secret_bytes(&[21; 32]).expect("Alice identity");
        let bob_identity = Identity::from_secret_bytes(&[22; 32]).expect("Bob identity");
        let mut authorizer = StaticDeviceAuthorizer::new();
        authorizer
            .insert(
                DeviceAddress::new("alice", "laptop").unwrap(),
                alice_identity.public_key(),
            )
            .unwrap();
        authorizer
            .insert(
                DeviceAddress::new("bob", "phone").unwrap(),
                bob_identity.public_key(),
            )
            .unwrap();
        let state =
            AppState::new(ServerConfig::default(), Arc::new(authorizer)).expect("valid state");
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let server_state = state.clone();
        let server = tokio::spawn(async move {
            serve(listener, server_state, async {
                let _ = shutdown_rx.await;
            })
            .await
            .expect("server exits cleanly");
        });

        let mut alice = connect_socket(address).await;
        let mut bob = connect_socket(address).await;
        authenticate(&mut alice, &alice_identity, "alice", "laptop")
            .await
            .expect("Alice authenticates");
        authenticate(&mut bob, &bob_identity, "bob", "phone")
            .await
            .expect("Bob authenticates");
        alice
            .send(ClientMessage::Text(
                json!({
                    "type": "send",
                    "to": { "user_id": "unprovisioned", "device_id": "laptop" },
                    "payload": [1, 2, 3]
                })
                .to_string()
                .into(),
            ))
            .await
            .unwrap();
        assert_eq!(read_json(&mut alice).await["type"], "error");
        alice
            .send(ClientMessage::Text(
                json!({
                    "type": "send",
                    "to": { "user_id": "bob", "device_id": "phone" },
                    "payload": [0, 255, 23]
                })
                .to_string()
                .into(),
            ))
            .await
            .unwrap();

        let accepted = read_json(&mut alice).await;
        assert_eq!(accepted["type"], "accepted");
        let delivery = read_json(&mut bob).await;
        assert_eq!(delivery["type"], "deliver");
        assert_eq!(delivery["envelope"]["sender"]["user_id"], "alice");
        assert_eq!(delivery["envelope"]["recipient"]["device_id"], "phone");
        assert_eq!(delivery["envelope"]["payload"], json!([0, 255, 23]));
        assert_eq!(accepted["message_id"], delivery["envelope"]["message_id"]);
        let message_id = delivery["envelope"]["message_id"]
            .as_str()
            .expect("message ID string");
        bob.send(ClientMessage::Text(
            json!({ "type": "ack", "message_id": message_id })
                .to_string()
                .into(),
        ))
        .await
        .unwrap();
        timeout(std::time::Duration::from_secs(2), async {
            while state.queued_messages().await != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("ack removes queued envelope");

        shutdown_tx.send(()).unwrap();
        server.await.unwrap();
        assert!(!state.is_ready());
        drop(alice);
        drop(bob);
    }

    #[tokio::test]
    async fn authentication_rejects_unprovisioned_identity_and_bad_signature() {
        let registered = Identity::from_secret_bytes(&[31; 32]).unwrap();
        let untrusted = Identity::from_secret_bytes(&[32; 32]).unwrap();
        let device = DeviceAddress::new("alice", "phone").unwrap();
        let mut authorizer = StaticDeviceAuthorizer::new();
        authorizer.insert(device, registered.public_key()).unwrap();
        let state = AppState::new(ServerConfig::default(), Arc::new(authorizer)).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let server_state = state.clone();
        let server = tokio::spawn(async move {
            serve(listener, server_state, async {
                let _ = shutdown_rx.await;
            })
            .await
            .unwrap();
        });

        let mut unknown = connect_socket(address).await;
        unknown
            .send(ClientMessage::Text(
                json!({
                    "type": "start",
                    "device": { "user_id": "alice", "device_id": "phone" },
                    "identity_key": untrusted.public_key()
                })
                .to_string()
                .into(),
            ))
            .await
            .unwrap();
        let rejected = read_json(&mut unknown).await;
        assert_eq!(rejected["type"], "rejected");

        let mut invalid = connect_socket(address).await;
        invalid
            .send(ClientMessage::Text(
                json!({
                    "type": "start",
                    "device": { "user_id": "alice", "device_id": "phone" },
                    "identity_key": registered.public_key()
                })
                .to_string()
                .into(),
            ))
            .await
            .unwrap();
        let challenge_frame: AuthServerFrame =
            serde_json::from_value(read_json(&mut invalid).await).unwrap();
        let AuthServerFrame::Challenge { challenge } = challenge_frame else {
            panic!("expected auth challenge");
        };
        let wrong_challenge = DeviceAuthChallenge::new(
            challenge.audience(),
            challenge.user_id(),
            challenge.device_id(),
            challenge.identity_key(),
            *challenge.challenge_id(),
            [0x99; 32],
        )
        .unwrap();
        let proof = registered
            .sign_device_auth_challenge(&wrong_challenge)
            .unwrap();
        invalid
            .send(ClientMessage::Text(
                json!({
                    "type": "proof",
                    "challenge_id": challenge.challenge_id(),
                    "proof": proof
                })
                .to_string()
                .into(),
            ))
            .await
            .unwrap();
        let rejected = read_json(&mut invalid).await;
        assert_eq!(rejected["type"], "rejected");
        shutdown_tx.send(()).unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn challenge_expires_when_client_does_not_prove_key_possession() {
        let identity = Identity::from_secret_bytes(&[33; 32]).unwrap();
        let device = DeviceAddress::new("alice", "phone").unwrap();
        let mut authorizer = StaticDeviceAuthorizer::new();
        authorizer.insert(device, identity.public_key()).unwrap();
        let state = AppState::new(ServerConfig::default(), Arc::new(authorizer)).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let server_state = state.clone();
        let server = tokio::spawn(async move {
            serve(listener, server_state, async {
                let _ = shutdown_rx.await;
            })
            .await
            .unwrap();
        });

        let mut socket = connect_socket(address).await;
        socket
            .send(ClientMessage::Text(
                json!({
                    "type": "start",
                    "device": { "user_id": "alice", "device_id": "phone" },
                    "identity_key": identity.public_key()
                })
                .to_string()
                .into(),
            ))
            .await
            .unwrap();
        assert_eq!(read_json(&mut socket).await["type"], "challenge");
        let closed = timeout(std::time::Duration::from_secs(3), socket.next())
            .await
            .expect("expired authentication closes the socket");
        assert!(matches!(
            closed,
            None | Some(Err(_)) | Some(Ok(ClientMessage::Close(_)))
        ));
        assert_eq!(state.queued_messages().await, 0);

        shutdown_tx.send(()).unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn relay_send_frame_before_authentication_is_rejected_without_routing() {
        let identity = Identity::from_secret_bytes(&[34; 32]).unwrap();
        let device = DeviceAddress::new("alice", "phone").unwrap();
        let mut authorizer = StaticDeviceAuthorizer::new();
        authorizer.insert(device, identity.public_key()).unwrap();
        let state = AppState::new(ServerConfig::default(), Arc::new(authorizer)).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let server_state = state.clone();
        let server = tokio::spawn(async move {
            serve(listener, server_state, async {
                let _ = shutdown_rx.await;
            })
            .await
            .unwrap();
        });

        let mut socket = connect_socket(address).await;
        socket
            .send(ClientMessage::Text(
                json!({
                    "type": "start",
                    "device": { "user_id": "alice", "device_id": "phone" },
                    "identity_key": identity.public_key()
                })
                .to_string()
                .into(),
            ))
            .await
            .unwrap();
        assert_eq!(read_json(&mut socket).await["type"], "challenge");
        socket
            .send(ClientMessage::Text(
                json!({
                    "type": "send",
                    "to": { "user_id": "bob", "device_id": "phone" },
                    "payload": [1, 2, 3]
                })
                .to_string()
                .into(),
            ))
            .await
            .unwrap();
        let closed = timeout(std::time::Duration::from_secs(2), socket.next())
            .await
            .expect("unauthenticated send closes the socket");
        assert!(matches!(
            closed,
            None | Some(Err(_)) | Some(Ok(ClientMessage::Close(_)))
        ));
        assert_eq!(state.queued_messages().await, 0);

        shutdown_tx.send(()).unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn revocation_after_challenge_issuance_rejects_the_proof() {
        let identity = Identity::from_secret_bytes(&[35; 32]).unwrap();
        let authorizer = Arc::new(RevocableAuthorizer::new(false));
        let state = AppState::new(ServerConfig::default(), authorizer.clone()).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let server_state = state.clone();
        let server = tokio::spawn(async move {
            serve(listener, server_state, async {
                let _ = shutdown_rx.await;
            })
            .await
            .unwrap();
        });

        let mut socket = connect_socket(address).await;
        let challenge = start_authentication(&mut socket, &identity).await;
        authorizer.revoked.store(true, Ordering::Release);
        submit_proof(&mut socket, &identity, &challenge).await;
        assert_eq!(read_json(&mut socket).await["type"], "rejected");
        let _ = socket
            .send(ClientMessage::Text(
                json!({
                    "type": "send",
                    "to": { "user_id": "bob", "device_id": "phone" },
                    "payload": [1, 2, 3]
                })
                .to_string()
                .into(),
            ))
            .await;
        assert_eq!(state.queued_messages().await, 0);

        shutdown_tx.send(()).unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn revocation_racing_with_authentication_is_ordered_by_device_guard() {
        let identity = Identity::from_secret_bytes(&[36; 32]).unwrap();
        let device = DeviceAddress::new("alice", "phone").unwrap();
        let authorizer = Arc::new(RevocableAuthorizer::new(true));
        let state = AppState::new(ServerConfig::default(), authorizer.clone()).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let server_state = state.clone();
        let server = tokio::spawn(async move {
            serve(listener, server_state, async {
                let _ = shutdown_rx.await;
            })
            .await
            .unwrap();
        });

        let mut socket = connect_socket(address).await;
        let challenge = start_authentication(&mut socket, &identity).await;
        submit_proof(&mut socket, &identity, &challenge).await;
        timeout(
            std::time::Duration::from_secs(2),
            authorizer.second_check_started.notified(),
        )
        .await
        .expect("proof revalidation started while holding device guard");

        let revocation_started = Arc::new(Notify::new());
        let revocation_state = state.clone();
        let revocation_device = device.clone();
        let revocation_authorizer = authorizer.clone();
        let revocation_started_signal = revocation_started.clone();
        let revocation = tokio::spawn(async move {
            revocation_started_signal.notify_one();
            let guard = revocation_state
                .lock_device_authorization(&revocation_device)
                .await;
            revocation_authorizer.revoked.store(true, Ordering::Release);
            revocation_state
                .revoke_route_device(&revocation_device, guard)
                .await
                .expect("remove revoked route");
        });
        timeout(
            std::time::Duration::from_secs(2),
            revocation_started.notified(),
        )
        .await
        .expect("revocation started");
        sleep(std::time::Duration::from_millis(20)).await;
        assert!(
            !revocation.is_finished(),
            "revocation waits for in-flight auth"
        );

        authorizer.release_second_check.notify_one();
        assert_eq!(read_json(&mut socket).await["type"], "authenticated");
        timeout(std::time::Duration::from_secs(2), revocation)
            .await
            .expect("revocation completes after auth linearizes")
            .expect("revocation task succeeds");
        let closed = timeout(std::time::Duration::from_secs(2), socket.next())
            .await
            .expect("revoked socket closes");
        assert!(matches!(
            closed,
            None | Some(Err(_)) | Some(Ok(ClientMessage::Close(_)))
        ));
        assert_eq!(state.queued_messages().await, 0);

        shutdown_tx.send(()).unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn replayed_proof_from_a_previous_connection_is_rejected() {
        let identity = Identity::from_secret_bytes(&[37; 32]).unwrap();
        let device = DeviceAddress::new("alice", "phone").unwrap();
        let mut authorizer = StaticDeviceAuthorizer::new();
        authorizer.insert(device, identity.public_key()).unwrap();
        let state = AppState::new(ServerConfig::default(), Arc::new(authorizer)).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let server_state = state.clone();
        let server = tokio::spawn(async move {
            serve(listener, server_state, async {
                let _ = shutdown_rx.await;
            })
            .await
            .unwrap();
        });

        let mut first = connect_socket(address).await;
        let first_challenge = start_authentication(&mut first, &identity).await;
        submit_proof(&mut first, &identity, &first_challenge).await;
        assert_eq!(read_json(&mut first).await["type"], "authenticated");
        submit_proof(&mut first, &identity, &first_challenge).await;
        assert_eq!(read_json(&mut first).await["type"], "error");

        let mut replay = connect_socket(address).await;
        let second_challenge = start_authentication(&mut replay, &identity).await;
        let old_proof = identity
            .sign_device_auth_challenge(&first_challenge)
            .unwrap();
        replay
            .send(ClientMessage::Text(
                json!({
                    "type": "proof",
                    "challenge_id": first_challenge.challenge_id(),
                    "proof": old_proof
                })
                .to_string()
                .into(),
            ))
            .await
            .unwrap();
        assert_ne!(
            first_challenge.challenge_id(),
            second_challenge.challenge_id()
        );
        assert_eq!(read_json(&mut replay).await["type"], "rejected");
        assert_eq!(state.queued_messages().await, 0);

        shutdown_tx.send(()).unwrap();
        server.await.unwrap();
    }
}
