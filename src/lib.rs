mod accounts;
mod auth;
mod config;
mod error;
mod http;
mod protocol;
mod state;
mod websocket;

pub use auth::{DeviceAuthorizer, RejectAllAuthenticator, StaticDeviceAuthorizer};
pub use config::ServerConfig;
pub use error::ServerError;
pub use http::router;
pub use protocol::{
    AuthClientFrame, AuthServerFrame, ClientFrame, DeviceAddress, OpaqueEnvelope, ServerFrame,
};
pub use state::AppState;

use std::{error::Error, future::Future, io, sync::Arc};

use tokio::{net::TcpListener, signal};
use tracing::info;

/// Serves HTTP health/readiness routes and the authenticated WebSocket relay.
/// The shutdown future is the only trigger for graceful termination.
pub async fn serve(
    listener: TcpListener,
    state: AppState,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> io::Result<()> {
    state
        .start_coordination()
        .await
        .map_err(|error| io::Error::other(error.to_string()))?;
    if state.accounts().is_some() {
        tracing::info!(instance_id = %state.instance_id(), "registered relay instance");
    }
    let app = router(state.clone());
    let revocation_worker = if state.accounts().is_some() {
        let worker_state = state.clone();
        Some(tokio::spawn(async move {
            loop {
                match worker_state.poll_revocations().await {
                    Ok(()) => worker_state.set_coordination_health(true),
                    Err(error) => {
                        worker_state.set_coordination_health(false);
                        tracing::error!(error = error.code(), "revocation coordination failed");
                    }
                }
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        }))
    } else {
        None
    };
    let shutdown_state = state.clone();
    let result = axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            shutdown.await;
            shutdown_state.stop_accepting();
        })
        .await;
    if let Some(worker) = revocation_worker {
        worker.abort();
        let _ = worker.await;
    }
    state.stop_accepting();
    if result.is_ok() {
        if let Some(directory) = state.accounts() {
            directory
                .fence_relay_instance(state.instance_id())
                .await
                .map_err(|error| io::Error::other(error.to_string()))?;
        }
    }
    result
}

/// Loads environment configuration, binds, and serves until Ctrl-C.
pub async fn run_from_env(
    authorizer: Arc<dyn DeviceAuthorizer>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let config = ServerConfig::from_env()?;
    let listener = TcpListener::bind(config.bind_addr).await?;
    info!(bind_addr = %config.bind_addr, "Aether relay listening");
    let state = match accounts::AccountDirectory::connect_from_env(&config.server_id).await? {
        Some(directory) => AppState::with_account_directory(config, directory)?,
        None => AppState::new(config, authorizer)?,
    };
    serve(listener, state, shutdown_signal()).await?;
    Ok(())
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        match signal::unix::signal(signal::unix::SignalKind::terminate()) {
            Ok(mut terminate) => {
                tokio::select! {
                    result = signal::ctrl_c() => {
                        if let Err(error) = result {
                            tracing::error!(%error, "failed to listen for interrupt signal");
                        }
                    }
                    _ = terminate.recv() => {}
                }
            }
            Err(error) => {
                tracing::error!(%error, "failed to listen for termination signal");
                if let Err(error) = signal::ctrl_c().await {
                    tracing::error!(%error, "failed to listen for interrupt signal");
                }
            }
        }
    }
    #[cfg(not(unix))]
    if let Err(error) = signal::ctrl_c().await {
        tracing::error!(%error, "failed to listen for interrupt signal");
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use tokio::{net::TcpListener, sync::oneshot};

    use crate::{AppState, RejectAllAuthenticator, ServerConfig};

    use super::serve;

    #[tokio::test]
    async fn server_stops_readiness_and_exits_on_graceful_shutdown() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let state =
            AppState::new(ServerConfig::default(), Arc::new(RejectAllAuthenticator)).unwrap();
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let server_state = state.clone();
        let server = tokio::spawn(async move {
            serve(listener, server_state, async {
                let _ = shutdown_rx.await;
            })
            .await
            .unwrap();
        });
        shutdown_tx.send(()).unwrap();
        server.await.unwrap();
        assert!(!state.is_ready());
    }

    #[cfg(test)]
    mod postgres_revocation_tests {
        use std::time::Duration;

        use aether_crypto::{DeviceAuthChallenge, Identity};
        use tokio::time::timeout;
        use uuid::Uuid;

        use crate::{
            accounts::AccountDirectory, state::OutboundFrame, AppState, DeviceAddress,
            ServerConfig, ServerError,
        };

        async fn authenticate(
            state: &AppState,
            identity: &Identity,
            device: &DeviceAddress,
        ) -> Result<crate::state::ConnectionHandle, ServerError> {
            let challenge_id = *Uuid::new_v4().as_bytes();
            let mut nonce = [0u8; 32];
            nonce[..16].copy_from_slice(Uuid::new_v4().as_bytes());
            nonce[16..].copy_from_slice(Uuid::new_v4().as_bytes());
            let challenge = DeviceAuthChallenge::new(
                state.config().server_id.clone(),
                device.user_id.clone(),
                device.device_id.clone(),
                identity.public_key(),
                challenge_id,
                nonce,
            )
            .expect("valid challenge");
            state
                .register_auth_challenge(identity.public_key(), device, &challenge)
                .await
                .expect("persist one-use auth challenge");
            let proof = identity
                .sign_device_auth_challenge(&challenge)
                .expect("challenge signing succeeds");
            let guard = state.lock_device_authorization(device).await;
            state
                .connect_authenticated(
                    identity.public_key(),
                    device,
                    &challenge,
                    &challenge_id,
                    &proof,
                    &guard,
                )
                .await
        }

        fn account_state(directory: AccountDirectory) -> AppState {
            AppState::with_account_directory(ServerConfig::default(), directory)
                .expect("valid account server state")
        }

        fn signed_challenge(
            state: &AppState,
            identity: &Identity,
            device: &DeviceAddress,
        ) -> (
            [u8; 16],
            DeviceAuthChallenge,
            aether_crypto::DeviceAuthProof,
        ) {
            let id = *Uuid::new_v4().as_bytes();
            let mut nonce = [0u8; 32];
            nonce[..16].copy_from_slice(Uuid::new_v4().as_bytes());
            nonce[16..].copy_from_slice(Uuid::new_v4().as_bytes());
            let challenge = DeviceAuthChallenge::new(
                state.config().server_id.clone(),
                device.user_id.clone(),
                device.device_id.clone(),
                identity.public_key(),
                id,
                nonce,
            )
            .expect("valid device challenge");
            let proof = identity
                .sign_device_auth_challenge(&challenge)
                .expect("device challenge signing succeeds");
            (id, challenge, proof)
        }

        #[tokio::test]
        async fn postgres_two_instance_revocation_is_durable_and_fails_closed() {
            let Ok(database_url) = std::env::var("TEST_DATABASE_URL") else {
                eprintln!(
                    "skipping PostgreSQL revocation integration test: TEST_DATABASE_URL is unset"
                );
                return;
            };

            let schema = format!("revocation_test_{}", Uuid::new_v4().simple());
            let admin_pool = sqlx::postgres::PgPoolOptions::new()
                .max_connections(1)
                .connect(&database_url)
                .await
                .expect("TEST_DATABASE_URL must be reachable");
            sqlx::query(&format!("CREATE SCHEMA {schema}"))
                .execute(&admin_pool)
                .await
                .expect("test schema creation succeeds");

            let directory_a =
                AccountDirectory::test_directory(&database_url, "local-relay", &schema)
                    .await
                    .expect("test PostgreSQL database is reachable and migrations apply");
            let directory_b =
                AccountDirectory::test_directory(&database_url, "local-relay", &schema)
                    .await
                    .expect("second independent account pool connects");
            let directory_c =
                AccountDirectory::test_directory(&database_url, "local-relay", &schema)
                    .await
                    .expect("restart test account pool connects");
            let state_a = account_state(directory_a.clone());
            let state_b = account_state(directory_b.clone());
            state_a
                .start_coordination()
                .await
                .expect("register instance A");
            state_b
                .start_coordination()
                .await
                .expect("register instance B");

            let sender = DeviceAddress::new("cluster_sender", "laptop").unwrap();
            let recipient = DeviceAddress::new("cluster_recipient", "phone").unwrap();
            let sender_identity = Identity::from_secret_bytes(&[81; 32]).unwrap();
            let recipient_identity = Identity::from_secret_bytes(&[82; 32]).unwrap();
            let (sender_id, sender_account) = directory_a
                .insert_test_device(&sender, sender_identity.public_key())
                .await
                .expect("insert sender");
            directory_a
                .insert_test_device(&recipient, recipient_identity.public_key())
                .await
                .expect("insert recipient");

            let mut live_connection_a = authenticate(&state_a, &sender_identity, &sender)
                .await
                .expect("sender also connected to instance A");
            let live_connection = authenticate(&state_b, &sender_identity, &sender)
                .await
                .expect("authentication wins before revocation");
            state_b
                .enqueue_from(
                    &sender,
                    live_connection.id,
                    recipient.clone(),
                    vec![1, 2, 3],
                )
                .await
                .expect("active sender may relay opaque bytes");
            let stale_challenge_id = *Uuid::new_v4().as_bytes();
            let mut stale_nonce = [0u8; 32];
            stale_nonce[..16].copy_from_slice(Uuid::new_v4().as_bytes());
            stale_nonce[16..].copy_from_slice(Uuid::new_v4().as_bytes());
            let stale_challenge = DeviceAuthChallenge::new(
                state_b.config().server_id.clone(),
                sender.user_id.clone(),
                sender.device_id.clone(),
                sender_identity.public_key(),
                stale_challenge_id,
                stale_nonce,
            )
            .expect("valid challenge before revocation");
            state_b
                .register_auth_challenge(sender_identity.public_key(), &sender, &stale_challenge)
                .await
                .expect("persist pre-revocation challenge");
            let stale_proof = sender_identity
                .sign_device_auth_challenge(&stale_challenge)
                .expect("sign pre-revocation challenge");
            let mut replaced_connection = live_connection;
            let live_connection = authenticate(&state_b, &sender_identity, &sender)
                .await
                .expect("connection replacement on instance B");
            assert!(matches!(
                replaced_connection.receiver.try_recv(),
                Ok(OutboundFrame::Protocol(crate::ServerFrame::Error { code }))
                    if code == "connection_replaced"
            ));
            let mut live_connection = live_connection;

            let (revoked_address, event_id) = directory_a
                .revoke_device(&sender_account, sender_id)
                .await
                .expect("revocation commits with durable outbox event");
            assert_eq!(revoked_address, sender);
            assert!(
                timeout(
                    Duration::from_millis(150),
                    directory_a.wait_for_revocation(event_id)
                )
                .await
                .is_err(),
                "revocation remains pending until every active node acknowledges"
            );
            assert!(
                state_b
                    .enqueue_from(&sender, live_connection.id, recipient.clone(), vec![4])
                    .await
                    .is_err(),
                "a stale connection cannot authorize a send after DB revocation"
            );

            state_a.poll_revocations().await.expect("node A catches up");
            state_b.poll_revocations().await.expect("node B catches up");
            state_b
                .poll_revocations()
                .await
                .expect("duplicate polling is idempotent");
            directory_a
                .wait_for_revocation(event_id)
                .await
                .expect("all registered nodes acknowledged");
            assert!(matches!(
                live_connection.receiver.try_recv(),
                Ok(OutboundFrame::Close)
            ));
            assert!(matches!(
                live_connection_a.receiver.try_recv(),
                Ok(OutboundFrame::Close)
            ));
            assert!(
                authenticate(&state_b, &sender_identity, &sender)
                    .await
                    .is_err(),
                "revoked identity cannot reconnect"
            );
            let stale_guard = state_b.lock_device_authorization(&sender).await;
            assert!(
                state_b
                    .connect_authenticated(
                        sender_identity.public_key(),
                        &sender,
                        &stale_challenge,
                        &stale_challenge_id,
                        &stale_proof,
                        &stale_guard,
                    )
                    .await
                    .is_err(),
                "proof for a pre-revocation challenge cannot reconnect"
            );

            let auth_race_device = DeviceAddress::new("cluster_auth_race", "desktop").unwrap();
            let auth_race_identity = Identity::from_secret_bytes(&[85; 32]).unwrap();
            let (auth_race_id, auth_race_account) = directory_a
                .insert_test_device(&auth_race_device, auth_race_identity.public_key())
                .await
                .expect("insert authentication race device");
            let auth_race_challenge_id = *Uuid::new_v4().as_bytes();
            let mut auth_race_nonce = [0u8; 32];
            auth_race_nonce[..16].copy_from_slice(Uuid::new_v4().as_bytes());
            auth_race_nonce[16..].copy_from_slice(Uuid::new_v4().as_bytes());
            let auth_race_challenge = DeviceAuthChallenge::new(
                state_b.config().server_id.clone(),
                auth_race_device.user_id.clone(),
                auth_race_device.device_id.clone(),
                auth_race_identity.public_key(),
                auth_race_challenge_id,
                auth_race_nonce,
            )
            .expect("valid auth race challenge");
            let auth_race_proof = auth_race_identity
                .sign_device_auth_challenge(&auth_race_challenge)
                .expect("sign auth race challenge");
            state_b
                .register_auth_challenge(
                    auth_race_identity.public_key(),
                    &auth_race_device,
                    &auth_race_challenge,
                )
                .await
                .expect("persist auth race challenge");
            let auth_race_guard = state_b.lock_device_authorization(&auth_race_device).await;
            let (auth_locked_tx, auth_locked_rx) = tokio::sync::oneshot::channel();
            let (auth_resume_tx, auth_resume_rx) = tokio::sync::oneshot::channel();
            let auth_state = state_b.clone();
            let auth_device = auth_race_device.clone();
            let auth_key = auth_race_identity.public_key();
            let auth_task = tokio::spawn(async move {
                auth_state
                    .connect_authenticated_paused(
                        auth_key,
                        &auth_device,
                        &auth_race_challenge,
                        &auth_race_challenge_id,
                        &auth_race_proof,
                        &auth_race_guard,
                        auth_locked_tx,
                        auth_resume_rx,
                    )
                    .await
            });
            auth_locked_rx
                .await
                .expect("authentication holds the database device lock");
            let (revoke_started_tx, revoke_started_rx) = tokio::sync::oneshot::channel();
            let revoke_directory = directory_a.clone();
            let revoke_account = auth_race_account.clone();
            let auth_race_revoke = tokio::spawn(async move {
                let _ = revoke_started_tx.send(());
                revoke_directory
                    .revoke_device(&revoke_account, auth_race_id)
                    .await
            });
            revoke_started_rx.await.expect("revocation attempt started");
            tokio::time::sleep(Duration::from_millis(100)).await;
            assert!(
                !auth_race_revoke.is_finished(),
                "revocation waits for an authentication holding the PostgreSQL row lock"
            );
            auth_resume_tx
                .send(())
                .expect("release final authentication");
            let mut auth_race_connection = auth_task
                .await
                .expect("authentication task joins")
                .expect("authentication registers before revocation");
            let (_auth_race_address, auth_race_event) = auth_race_revoke
                .await
                .expect("revocation task joins")
                .expect("revocation commits after authentication");
            state_a
                .poll_revocations()
                .await
                .expect("node A processes auth race revocation");
            state_b
                .poll_revocations()
                .await
                .expect("node B closes auth race connection");
            directory_a
                .wait_for_revocation(auth_race_event)
                .await
                .expect("auth race revocation waits for connection shutdown");
            assert!(matches!(
                auth_race_connection.receiver.try_recv(),
                Ok(OutboundFrame::Close)
            ));

            let replay_device = DeviceAddress::new("cluster_replay", "phone").unwrap();
            let replay_identity = Identity::from_secret_bytes(&[88; 32]).unwrap();
            let (replay_id, replay_account) = directory_a
                .insert_test_device(&replay_device, replay_identity.public_key())
                .await
                .expect("insert global challenge replay test device");
            let (replay_challenge_id, replay_challenge, replay_proof) =
                signed_challenge(&state_a, &replay_identity, &replay_device);
            state_a
                .register_auth_challenge(
                    replay_identity.public_key(),
                    &replay_device,
                    &replay_challenge,
                )
                .await
                .expect("issue challenge on A");
            let guard_on_b = state_b.lock_device_authorization(&replay_device).await;
            assert!(
                state_b
                    .connect_authenticated(
                        replay_identity.public_key(),
                        &replay_device,
                        &replay_challenge,
                        &replay_challenge_id,
                        &replay_proof,
                        &guard_on_b,
                    )
                    .await
                    .is_err(),
                "a challenge cannot be replayed on a different server instance"
            );
            let issuing_guard = state_a.lock_device_authorization(&replay_device).await;
            let mut replay_connection = state_a
                .connect_authenticated(
                    replay_identity.public_key(),
                    &replay_device,
                    &replay_challenge,
                    &replay_challenge_id,
                    &replay_proof,
                    &issuing_guard,
                )
                .await
                .expect("challenge authenticates once on its issuing instance");
            let replay_guard = state_a.lock_device_authorization(&replay_device).await;
            assert!(
                state_a
                    .connect_authenticated(
                        replay_identity.public_key(),
                        &replay_device,
                        &replay_challenge,
                        &replay_challenge_id,
                        &replay_proof,
                        &replay_guard,
                    )
                    .await
                    .is_err(),
                "a consumed database challenge cannot be replayed"
            );
            let (_, replay_event) = directory_a
                .revoke_device(&replay_account, replay_id)
                .await
                .expect("revoke replay test device");
            state_a
                .poll_revocations()
                .await
                .expect("A processes revoke");
            state_b
                .poll_revocations()
                .await
                .expect("B processes revoke");
            directory_a
                .wait_for_revocation(replay_event)
                .await
                .expect("replay device revocation completes");
            assert!(matches!(
                replay_connection.receiver.try_recv(),
                Ok(OutboundFrame::Close)
            ));

            let concurrent_one = DeviceAddress::new("cluster_concurrent_1", "phone").unwrap();
            let concurrent_two = DeviceAddress::new("cluster_concurrent_2", "phone").unwrap();
            let (concurrent_one_id, concurrent_one_account) = directory_a
                .insert_test_device(
                    &concurrent_one,
                    Identity::from_secret_bytes(&[86; 32]).unwrap().public_key(),
                )
                .await
                .expect("insert concurrent revoke target one");
            let (concurrent_two_id, concurrent_two_account) = directory_a
                .insert_test_device(
                    &concurrent_two,
                    Identity::from_secret_bytes(&[87; 32]).unwrap().public_key(),
                )
                .await
                .expect("insert concurrent revoke target two");
            let (revoke_one, revoke_two) = tokio::join!(
                directory_a.revoke_device(&concurrent_one_account, concurrent_one_id),
                directory_a.revoke_device(&concurrent_two_account, concurrent_two_id),
            );
            let (_, concurrent_event_one) = revoke_one.expect("first concurrent revoke");
            let (_, concurrent_event_two) = revoke_two.expect("second concurrent revoke");
            state_a.poll_revocations().await.expect("A catches up");
            state_b.poll_revocations().await.expect("B catches up");
            directory_a
                .wait_for_revocation(concurrent_event_one)
                .await
                .expect("first concurrent event is acknowledged");
            directory_a
                .wait_for_revocation(concurrent_event_two)
                .await
                .expect("second concurrent event is acknowledged");

            let second_device = DeviceAddress::new("cluster_other", "tablet").unwrap();
            let second_identity = Identity::from_secret_bytes(&[83; 32]).unwrap();
            let (second_id, second_account) = directory_a
                .insert_test_device(&second_device, second_identity.public_key())
                .await
                .expect("insert second test device");
            let second_connection = authenticate(&state_b, &second_identity, &second_device)
                .await
                .expect("second device authenticates");
            let (send_started, send_started_rx) = tokio::sync::oneshot::channel();
            let (resume_send, resume_send_rx) = tokio::sync::oneshot::channel();
            let send_state = state_b.clone();
            let send_sender = second_device.clone();
            let send_recipient = recipient.clone();
            let in_flight_send = tokio::spawn(async move {
                send_state
                    .enqueue_from_paused(
                        &send_sender,
                        second_connection.id,
                        send_recipient,
                        vec![9],
                        send_started,
                        resume_send_rx,
                    )
                    .await
            });
            send_started_rx
                .await
                .expect("relay authorization is held in its local critical section");
            let (_address, delayed_event) = directory_a
                .revoke_device(&second_account, second_id)
                .await
                .expect("second revocation commits while an ingress is in flight");
            assert!(
                timeout(
                    Duration::from_millis(150),
                    directory_a.wait_for_revocation(delayed_event)
                )
                .await
                .is_err(),
                "revocation waits for the in-flight relay critical section"
            );
            let pending_state = state_b.clone();
            let pending_delivery =
                tokio::spawn(async move { pending_state.poll_revocations().await });
            tokio::time::sleep(Duration::from_millis(100)).await;
            assert!(!pending_delivery.is_finished());
            resume_send.send(()).expect("release in-flight ingress");
            assert!(
                in_flight_send
                    .await
                    .expect("in-flight send task joins")
                    .is_ok(),
                "send authorization linearized before revocation"
            );
            pending_delivery
                .await
                .expect("event delivery task joins")
                .expect("B removes route and acknowledges the event");
            state_a
                .poll_revocations()
                .await
                .expect("A acknowledges event");
            assert!(
                state_b
                    .authorize_delivery(&second_device, &recipient)
                    .await
                    .is_err(),
                "a pre-revocation queued envelope cannot egress after revocation"
            );

            let unavailable_device = DeviceAddress::new("cluster_unreachable", "phone").unwrap();
            let unavailable_identity = Identity::from_secret_bytes(&[84; 32]).unwrap();
            let (unavailable_id, unavailable_account) = directory_a
                .insert_test_device(&unavailable_device, unavailable_identity.public_key())
                .await
                .expect("insert unreachable-node test device");
            authenticate(&state_b, &unavailable_identity, &unavailable_device)
                .await
                .expect("device authenticates on B before B becomes unreachable");
            let (_address, unreachable_event) = directory_a
                .revoke_device(&unavailable_account, unavailable_id)
                .await
                .expect("revocation commits");
            state_a
                .poll_revocations()
                .await
                .expect("reachable instance A processes event");
            assert!(
                timeout(
                    Duration::from_millis(150),
                    directory_a.wait_for_revocation(unreachable_event)
                )
                .await
                .is_err(),
                "an unreachable instance cannot be assumed fenced"
            );

            let state_c = account_state(directory_c.clone());
            state_c
                .start_coordination()
                .await
                .expect("restarted instance reconciles historical outbox events before serving");
            state_c
                .poll_revocations()
                .await
                .expect("restart poll succeeds");
            state_b.stop_accepting();
            let guard = state_b.lock_device_authorization(&unavailable_device).await;
            state_b
                .revoke_route_device(&unavailable_device, guard)
                .await
                .expect("test simulates confirmed external fencing and local route shutdown");
            directory_b
                .fence_relay_instance(state_b.instance_id())
                .await
                .expect("record operator-confirmed fence");
            directory_a
                .wait_for_revocation(unreachable_event)
                .await
                .expect("revocation completes only after ack or confirmed fencing");
            assert!(
                state_b
                    .enqueue_from(&unavailable_device, 999, recipient.clone(), vec![5])
                    .await
                    .is_err(),
                "fenced instance is not ready to relay"
            );

            let directory_d =
                AccountDirectory::test_directory(&database_url, "local-relay", &schema)
                    .await
                    .expect("database failure test pool connects");
            let fail_closed_state = account_state(directory_d.clone());
            fail_closed_state
                .start_coordination()
                .await
                .expect("register database failure test instance");
            let failed_instance_id = fail_closed_state.instance_id();
            directory_d.close_test_pool().await;
            assert!(
                matches!(
                    fail_closed_state
                        .authorize_device(recipient_identity.public_key(), &recipient)
                        .await,
                    Err(ServerError::Internal | ServerError::Unavailable)
                ),
                "database failure denies authorization"
            );

            directory_a
                .fence_relay_instance(failed_instance_id)
                .await
                .expect("record failed test process as fenced");
            state_a.stop_accepting();
            state_c.stop_accepting();
            directory_a
                .fence_relay_instance(state_a.instance_id())
                .await
                .expect("fence instance A after test shutdown");
            directory_a
                .fence_relay_instance(state_c.instance_id())
                .await
                .expect("fence restarted instance C after test shutdown");
            directory_a
                .fence_relay_instance(state_b.instance_id())
                .await
                .expect("instance B remains externally fenced");

            directory_a.close_test_pool().await;
            directory_b.close_test_pool().await;
            directory_c.close_test_pool().await;
            directory_d.close_test_pool().await;
            sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
                .execute(&admin_pool)
                .await
                .expect("test schema cleanup");
            admin_pool.close().await;
        }
    }
}
