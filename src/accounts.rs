use std::{
    collections::HashMap,
    env,
    net::IpAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use aether_crypto::{DeviceAuthChallenge, DeviceAuthProof, IdentityPublicKey};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::{postgres::PgPoolOptions, PgPool, Postgres, Row, Transaction};
use tokio::{sync::Mutex, time::sleep};
use uuid::Uuid;
use webauthn_rs::prelude::{
    CreationChallengeResponse, Passkey, PasskeyAuthentication, PasskeyRegistration,
    PublicKeyCredential, RegisterPublicKeyCredential, RequestChallengeResponse, Url, Webauthn,
    WebauthnBuilder,
};

use crate::{protocol::StoredRelayMessage, DeviceAddress, OpaqueEnvelope, ServerError};

const EMAIL_TOKEN_TTL: Duration = Duration::from_secs(60 * 60 * 24);
const PASSKEY_CEREMONY_TTL: Duration = Duration::from_secs(5 * 60);
const SESSION_TTL: Duration = Duration::from_secs(60 * 60 * 24 * 30);
const DEVICE_LINK_TTL: Duration = Duration::from_secs(60 * 60);
const MAX_PENDING_CEREMONIES: usize = 10_000;
const MAX_PENDING_RELAY_CHALLENGES: i64 = 10_000;
const MAX_SIGNUPS_PER_MINUTE: i32 = 30;
const INSTANCE_REGISTRY_LOCK: i64 = 0x4145_5448_4552;
const REVOCATION_POLL_INTERVAL: Duration = Duration::from_millis(100);

pub(crate) struct PendingRevocation {
    pub event_id: Uuid,
    pub address: DeviceAddress,
}

pub(crate) struct TypingState {
    pub sender: DeviceAddress,
    pub recipient: DeviceAddress,
    pub is_typing: bool,
    pub updated_at: String,
}

#[derive(Clone)]
pub(crate) struct AccountDirectory {
    inner: Arc<DirectoryInner>,
}

struct DirectoryInner {
    pool: PgPool,
    webauthn: Webauthn,
    server_id: String,
    webauthn_origin: String,
    public_url: Option<String>,
    resend_api_key: Option<String>,
    resend_from_email: Option<String>,
    http: Client,
    registrations: Mutex<HashMap<Uuid, RegistrationCeremony>>,
    authentications: Mutex<HashMap<Uuid, AuthenticationCeremony>>,
    device_challenges: Mutex<HashMap<Uuid, DeviceChallenge>>,
    first_device_challenges: Mutex<HashMap<Uuid, FirstDeviceChallenge>>,
}

struct RegistrationCeremony {
    account_id: Uuid,
    state: PasskeyRegistration,
    expires_at: Instant,
}

struct AuthenticationCeremony {
    account_id: Uuid,
    state: PasskeyAuthentication,
    callback_uri: String,
    browser_state: String,
    code_challenge: Vec<u8>,
    expires_at: Instant,
}

struct DeviceChallenge {
    account_id: Uuid,
    session_hash: Vec<u8>,
    device: DeviceAddress,
    identity_key: IdentityPublicKey,
    challenge: DeviceAuthChallenge,
    expires_at: Instant,
}

struct FirstDeviceChallenge {
    account_id: Uuid,
    session_hash: Vec<u8>,
    device: DeviceAddress,
    identity_key: IdentityPublicKey,
    display_name: String,
    challenge: DeviceAuthChallenge,
    expires_at: Instant,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SignupRequest {
    pub tag: String,
    pub email: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AccountProfileUpdate {
    pub tag: Option<String>,
    pub email: Option<String>,
}

struct ValidatedProfileUpdate {
    tag: Option<String>,
    email: Option<(String, String)>,
}

#[derive(Serialize)]
pub(crate) struct SignupResponse {
    pub account_id: Uuid,
    pub ceremony_id: Uuid,
    pub options: CreationChallengeResponse,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RegistrationFinish {
    pub ceremony_id: Uuid,
    pub credential: RegisterPublicKeyCredential,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SigninStart {
    pub tag: String,
    pub callback_uri: String,
    pub state: String,
    pub code_challenge: String,
}

#[derive(Serialize)]
pub(crate) struct SigninStartResponse {
    pub ceremony_id: Uuid,
    pub options: RequestChallengeResponse,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SigninFinish {
    pub ceremony_id: Uuid,
    pub credential: PublicKeyCredential,
}

#[derive(Serialize)]
pub(crate) struct SigninHandoffResponse {
    pub redirect_uri: String,
}

#[derive(Serialize)]
pub(crate) struct SigninResponse {
    pub account_id: Uuid,
    pub tag: String,
    pub session_token: String,
    pub expires_at: i64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SessionExchange {
    pub code: String,
    pub state: String,
    pub code_verifier: String,
    pub callback_uri: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EmailVerifyRequest {
    pub token: String,
}

#[derive(Serialize)]
pub(crate) struct AccountSummary {
    pub account_id: Uuid,
    pub tag: String,
    pub email: String,
    pub email_verified: bool,
    pub email_change_pending: bool,
}

#[derive(Serialize)]
pub(crate) struct DirectoryEntry {
    pub account_id: Uuid,
    pub tag: String,
}

#[derive(Serialize)]
pub(crate) struct DeviceEntry {
    pub id: Uuid,
    pub user_id: String,
    pub device_id: String,
    pub display_name: String,
    pub created_at: String,
    pub current: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LinkStart {
    pub device: DeviceAddress,
    pub identity_public_key: [u8; 32],
    pub display_name: String,
}

#[derive(Serialize)]
pub(crate) struct LinkStartResponse {
    pub request_id: Uuid,
    pub approval_token: String,
    pub expires_in_seconds: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LinkComplete {
    pub approval_token: String,
}

#[derive(Serialize)]
pub(crate) struct LinkRequestEntry {
    pub request_id: Uuid,
    pub user_id: String,
    pub device_id: String,
    pub display_name: String,
    pub created_at: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DeviceChallengeStart {
    pub device: DeviceAddress,
    pub identity_public_key: [u8; 32],
}

#[derive(Serialize)]
pub(crate) struct DeviceChallengeResponse {
    pub challenge_id: Uuid,
    pub challenge: DeviceAuthChallenge,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DeviceChallengeFinish {
    pub challenge_id: Uuid,
    pub proof: DeviceAuthProof,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FirstDeviceStart {
    pub device: DeviceAddress,
    pub identity_public_key: [u8; 32],
    pub display_name: String,
}

#[derive(Serialize)]
pub(crate) struct FirstDeviceStartResponse {
    pub challenge_id: Uuid,
    pub challenge: DeviceAuthChallenge,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FirstDeviceFinish {
    pub challenge_id: Uuid,
    pub proof: DeviceAuthProof,
}

#[derive(Serialize)]
pub(crate) struct FirstDeviceResponse {
    pub device: DeviceEntry,
}

#[derive(Clone)]
pub(crate) struct AuthenticatedAccount {
    pub account_id: Uuid,
    pub session_hash: Vec<u8>,
    pub device_id: Option<Uuid>,
}

impl AccountDirectory {
    #[cfg(test)]
    pub(crate) async fn test_directory(
        database_url: &str,
        server_id: &str,
        schema: &str,
    ) -> Result<Self, ServerError> {
        let options = database_url
            .parse::<sqlx::postgres::PgConnectOptions>()
            .map_err(|_| ServerError::InvalidConfiguration("test database URL"))?
            .options([("search_path", schema)]);
        let pool = PgPoolOptions::new()
            .max_connections(8)
            .connect_with(options)
            .await
            .map_err(|_| ServerError::Internal)?;
        sqlx::migrate!("./migrations")
            .run(&pool)
            .await
            .map_err(|_| ServerError::Internal)?;
        let origin = Url::parse("https://localhost")
            .map_err(|_| ServerError::InvalidConfiguration("test origin"))?;
        let webauthn = WebauthnBuilder::new("localhost", &origin)
            .map_err(|_| ServerError::InvalidConfiguration("test WebAuthn"))?
            .rp_name("Void")
            .build()
            .map_err(|_| ServerError::InvalidConfiguration("test WebAuthn"))?;
        Ok(Self {
            inner: Arc::new(DirectoryInner {
                pool,
                webauthn,
                server_id: server_id.to_owned(),
                webauthn_origin: origin.origin().ascii_serialization(),
                public_url: Some("https://localhost".to_owned()),
                resend_api_key: Some("test".to_owned()),
                resend_from_email: Some("test@example.invalid".to_owned()),
                http: Client::new(),
                registrations: Mutex::new(HashMap::new()),
                authentications: Mutex::new(HashMap::new()),
                device_challenges: Mutex::new(HashMap::new()),
                first_device_challenges: Mutex::new(HashMap::new()),
            }),
        })
    }

    #[cfg(test)]
    pub(crate) async fn insert_test_device(
        &self,
        device: &DeviceAddress,
        identity: IdentityPublicKey,
    ) -> Result<(Uuid, AuthenticatedAccount), ServerError> {
        let account_id = Uuid::new_v4();
        let suffix = account_id.simple().to_string();
        sqlx::query(
            "INSERT INTO accounts (id, tag, tag_normalized, email, email_normalized) \
             VALUES ($1, $2, $2, $3, $3)",
        )
        .bind(account_id)
        .bind(format!("t{}", &suffix[..10]))
        .bind(format!("{suffix}@example.invalid"))
        .execute(&self.inner.pool)
        .await
        .map_err(|_| ServerError::Internal)?;
        let device_record_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO account_devices \
             (id, account_id, user_id, device_id, identity_public_key, display_name) \
             VALUES ($1, $2, $3, $4, $5, 'test device')",
        )
        .bind(device_record_id)
        .bind(account_id)
        .bind(&device.user_id)
        .bind(&device.device_id)
        .bind(identity.as_bytes().as_slice())
        .execute(&self.inner.pool)
        .await
        .map_err(|_| ServerError::Internal)?;
        Ok((
            device_record_id,
            AuthenticatedAccount {
                account_id,
                session_hash: vec![0; 32],
                device_id: Some(device_record_id),
            },
        ))
    }

    #[cfg(test)]
    pub(crate) async fn close_test_pool(&self) {
        self.inner.pool.close().await;
    }

    pub(crate) async fn connect_from_env(server_id: &str) -> Result<Option<Self>, ServerError> {
        let database_url = match env::var("DATABASE_URL") {
            Ok(value) if !value.is_empty() => value,
            Ok(_) => {
                return Err(ServerError::InvalidConfiguration(
                    "DATABASE_URL must not be empty",
                ))
            }
            Err(env::VarError::NotPresent) => return Ok(None),
            Err(env::VarError::NotUnicode(_)) => {
                return Err(ServerError::InvalidConfiguration(
                    "DATABASE_URL must be Unicode",
                ))
            }
        };

        let rp_id = required_env("AETHER_WEBAUTHN_RP_ID")?;
        let rp_origin = required_env("AETHER_WEBAUTHN_ORIGIN")?;
        let public_url = optional_env("AETHER_PUBLIC_URL")?;
        let resend_api_key = optional_env("RESEND_API_KEY")?;
        let resend_from_email = optional_env("RESEND_FROM_EMAIL")?;
        let email_delivery_configured =
            public_url.is_some() && resend_api_key.is_some() && resend_from_email.is_some();
        if [
            public_url.is_some(),
            resend_api_key.is_some(),
            resend_from_email.is_some(),
        ]
        .iter()
        .any(|configured| *configured)
            && !email_delivery_configured
        {
            return Err(ServerError::InvalidConfiguration(
                "AETHER_PUBLIC_URL, RESEND_API_KEY, and RESEND_FROM_EMAIL must be configured together",
            ));
        }
        let database_max_connections = env_u32("AETHER_DATABASE_MAX_CONNECTIONS", 20)?;
        let database_connect_timeout_secs = env_u32("AETHER_DATABASE_CONNECT_TIMEOUT_SECS", 10)?;
        if let Some(from_email) = resend_from_email.as_deref() {
            validate_email(from_email).map_err(|_| {
                ServerError::InvalidConfiguration("RESEND_FROM_EMAIL must be a valid email")
            })?;
        }

        let origin = Url::parse(&rp_origin)
            .map_err(|_| ServerError::InvalidConfiguration("AETHER_WEBAUTHN_ORIGIN"))?;
        if origin.scheme() != "https"
            || origin.host_str().is_none()
            || !origin.username().is_empty()
            || origin.password().is_some()
            || !matches!(origin.path(), "" | "/")
            || origin.query().is_some()
            || origin.fragment().is_some()
        {
            return Err(ServerError::InvalidConfiguration(
                "AETHER_WEBAUTHN_ORIGIN must be an HTTPS origin",
            ));
        }
        if let Some(public_url) = public_url.as_deref() {
            let public_origin = Url::parse(public_url)
                .map_err(|_| ServerError::InvalidConfiguration("AETHER_PUBLIC_URL"))?;
            if public_origin.scheme() != "https"
                || public_origin.host_str().is_none()
                || !public_origin.username().is_empty()
                || public_origin.password().is_some()
                || !matches!(public_origin.path(), "" | "/")
                || public_origin.query().is_some()
                || public_origin.fragment().is_some()
            {
                return Err(ServerError::InvalidConfiguration(
                    "AETHER_PUBLIC_URL must be an HTTPS origin",
                ));
            }
            if public_origin.origin() != origin.origin() {
                return Err(ServerError::InvalidConfiguration(
                    "AETHER_PUBLIC_URL must use the WebAuthn browser origin",
                ));
            }
        }
        let webauthn = WebauthnBuilder::new(&rp_id, &origin)
            .map_err(|_| ServerError::InvalidConfiguration("WebAuthn RP configuration"))?
            .rp_name("Void")
            .build()
            .map_err(|_| ServerError::InvalidConfiguration("WebAuthn RP configuration"))?;
        let pool = PgPoolOptions::new()
            .max_connections(database_max_connections)
            .acquire_timeout(Duration::from_secs(u64::from(
                database_connect_timeout_secs,
            )))
            .connect(&database_url)
            .await
            .map_err(|_| ServerError::InvalidConfiguration("DATABASE_URL connection failed"))?;
        sqlx::migrate!("./migrations")
            .run(&pool)
            .await
            .map_err(|_| ServerError::Internal)?;

        Ok(Some(Self {
            inner: Arc::new(DirectoryInner {
                pool,
                webauthn,
                server_id: server_id.to_owned(),
                webauthn_origin: origin.origin().ascii_serialization(),
                public_url: public_url.map(|value| value.trim_end_matches('/').to_owned()),
                resend_api_key,
                resend_from_email,
                http: Client::builder()
                    .timeout(Duration::from_secs(10))
                    .build()
                    .map_err(|_| ServerError::Internal)?,
                registrations: Mutex::new(HashMap::new()),
                authentications: Mutex::new(HashMap::new()),
                device_challenges: Mutex::new(HashMap::new()),
                first_device_challenges: Mutex::new(HashMap::new()),
            }),
        }))
    }

    pub(crate) fn webauthn_origin(&self) -> &str {
        &self.inner.webauthn_origin
    }

    pub(crate) async fn signup(
        &self,
        request: SignupRequest,
    ) -> Result<SignupResponse, ServerError> {
        let tag = validate_tag(&request.tag)?;
        let email = validate_email(&request.email)?;
        let account_id = Uuid::new_v4();
        let registration = self
            .inner
            .webauthn
            .start_passkey_registration(account_id, &tag, &tag, None)
            .map_err(|_| ServerError::Internal)?;
        let ceremony_id = Uuid::new_v4();
        let normalized_tag = normalize_tag(&tag);
        let normalized_email = email.to_ascii_lowercase();

        let mut transaction = self
            .inner
            .pool
            .begin()
            .await
            .map_err(|_| ServerError::Internal)?;
        sqlx::query(
            "DELETE FROM account_signup_rate_limits \
             WHERE window_start < date_trunc('minute', now()) - interval '1 hour'",
        )
        .execute(&mut *transaction)
        .await
        .map_err(|_| ServerError::Internal)?;
        let signup_count: Option<i32> = sqlx::query_scalar(
            "INSERT INTO account_signup_rate_limits (window_start, signup_count) \
             VALUES (date_trunc('minute', now()), 1) \
             ON CONFLICT (window_start) DO UPDATE \
               SET signup_count = account_signup_rate_limits.signup_count + 1 \
               WHERE account_signup_rate_limits.signup_count < $1 \
             RETURNING signup_count",
        )
        .bind(MAX_SIGNUPS_PER_MINUTE)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| ServerError::Internal)?;
        if signup_count.is_none() {
            return Err(ServerError::ResourceLimit);
        }
        sqlx::query(
            "DELETE FROM accounts a \
             WHERE a.created_at < now() - interval '10 minutes' \
               AND NOT EXISTS (SELECT 1 FROM account_passkeys p WHERE p.account_id = a.id)",
        )
        .execute(&mut *transaction)
        .await
        .map_err(|_| ServerError::Internal)?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
            .bind(&normalized_email)
            .execute(&mut *transaction)
            .await
            .map_err(|_| ServerError::Internal)?;
        sqlx::query(
            "INSERT INTO accounts (id, tag, tag_normalized, email, email_normalized) \
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(account_id)
        .bind(&tag)
        .bind(normalized_tag)
        .bind(&email)
        .bind(&normalized_email)
        .execute(&mut *transaction)
        .await
        .map_err(|error| {
            if is_unique_violation(&error) {
                ServerError::InvalidRequest
            } else {
                ServerError::Internal
            }
        })?;
        transaction
            .commit()
            .await
            .map_err(|_| ServerError::Internal)?;

        let (options, state) = registration;
        if let Err(error) = self
            .add_registration(
                ceremony_id,
                RegistrationCeremony {
                    account_id,
                    state,
                    expires_at: Instant::now() + PASSKEY_CEREMONY_TTL,
                },
            )
            .await
        {
            let _ = sqlx::query("DELETE FROM accounts WHERE id = $1")
                .bind(account_id)
                .execute(&self.inner.pool)
                .await;
            return Err(error);
        }
        Ok(SignupResponse {
            account_id,
            ceremony_id,
            options,
        })
    }

    pub(crate) async fn finish_signup(
        &self,
        request: RegistrationFinish,
    ) -> Result<(), ServerError> {
        let ceremony = self.take_registration(request.ceremony_id).await?;
        let passkey = self
            .inner
            .webauthn
            .finish_passkey_registration(&request.credential, &ceremony.state)
            .map_err(|_| ServerError::InvalidRequest)?;
        let credential_id = passkey.cred_id().as_ref().to_vec();
        let credential = serde_json::to_value(passkey).map_err(|_| ServerError::Internal)?;
        let mut transaction = self
            .inner
            .pool
            .begin()
            .await
            .map_err(|_| ServerError::Internal)?;
        sqlx::query(
            "INSERT INTO account_passkeys (credential_id, account_id, credential) \
             VALUES ($1, $2, $3)",
        )
        .bind(credential_id)
        .bind(ceremony.account_id)
        .bind(credential)
        .execute(&mut *transaction)
        .await
        .map_err(|error| {
            if is_unique_violation(&error) {
                ServerError::InvalidRequest
            } else {
                ServerError::Internal
            }
        })?;
        transaction
            .commit()
            .await
            .map_err(|_| ServerError::Internal)
    }

    pub(crate) async fn start_signin(
        &self,
        request: SigninStart,
    ) -> Result<SigninStartResponse, ServerError> {
        let tag = validate_tag(&request.tag)?;
        let callback_uri = validate_loopback_callback(&request.callback_uri)?;
        validate_browser_state(&request.state)?;
        let code_challenge = validate_code_challenge(&request.code_challenge)?;
        let row = sqlx::query(
            "SELECT a.id FROM accounts a WHERE a.tag_normalized = $1 \
             AND EXISTS (SELECT 1 FROM account_passkeys p WHERE p.account_id = a.id)",
        )
        .bind(normalize_tag(&tag))
        .fetch_optional(&self.inner.pool)
        .await
        .map_err(|_| ServerError::Internal)?
        .ok_or(ServerError::Unauthorized)?;
        let account_id: Uuid = row.try_get("id").map_err(|_| ServerError::Internal)?;
        let credentials = self.load_passkeys(account_id).await?;
        if credentials.is_empty() {
            return Err(ServerError::Unauthorized);
        }
        let (options, state) = self
            .inner
            .webauthn
            .start_passkey_authentication(&credentials)
            .map_err(|_| ServerError::Unauthorized)?;
        let ceremony_id = Uuid::new_v4();
        let mut ceremonies = self.inner.authentications.lock().await;
        prune_expired(&mut ceremonies);
        if ceremonies.len() >= MAX_PENDING_CEREMONIES {
            return Err(ServerError::ResourceLimit);
        }
        ceremonies.insert(
            ceremony_id,
            AuthenticationCeremony {
                account_id,
                state,
                callback_uri,
                browser_state: request.state,
                code_challenge,
                expires_at: Instant::now() + PASSKEY_CEREMONY_TTL,
            },
        );
        Ok(SigninStartResponse {
            ceremony_id,
            options,
        })
    }

    pub(crate) async fn finish_signin(
        &self,
        request: SigninFinish,
    ) -> Result<SigninHandoffResponse, ServerError> {
        let ceremony = self.take_authentication(request.ceremony_id).await?;
        let result = self
            .inner
            .webauthn
            .finish_passkey_authentication(&request.credential, &ceremony.state)
            .map_err(|_| ServerError::Unauthorized)?;
        let credential_id = result.cred_id().as_ref().to_vec();
        let mut credentials = self.load_passkeys(ceremony.account_id).await?;
        let Some(passkey) = credentials
            .iter_mut()
            .find(|passkey| passkey.cred_id().as_ref() == credential_id.as_slice())
        else {
            return Err(ServerError::Unauthorized);
        };
        let changed = passkey
            .update_credential(&result)
            .ok_or(ServerError::Unauthorized)?;
        if changed {
            let credential = serde_json::to_value(passkey).map_err(|_| ServerError::Internal)?;
            sqlx::query(
                "UPDATE account_passkeys SET credential = $1, last_used_at = now() \
                 WHERE credential_id = $2 AND account_id = $3",
            )
            .bind(credential)
            .bind(&credential_id)
            .bind(ceremony.account_id)
            .execute(&self.inner.pool)
            .await
            .map_err(|_| ServerError::Internal)?;
        } else {
            sqlx::query(
                "UPDATE account_passkeys SET last_used_at = now() \
                 WHERE credential_id = $1 AND account_id = $2",
            )
            .bind(&credential_id)
            .bind(ceremony.account_id)
            .execute(&self.inner.pool)
            .await
            .map_err(|_| ServerError::Internal)?;
        }
        let exchange_code = opaque_token();
        let code_hash = hash_token(&exchange_code);
        sqlx::query(
            "INSERT INTO browser_session_exchanges \
             (code_hash, account_id, callback_uri, state_hash, code_challenge_hash, expires_at) \
             VALUES ($1, $2, $3, $4, $5, \
                     now() + ($6::double precision * interval '1 second'))",
        )
        .bind(code_hash)
        .bind(ceremony.account_id)
        .bind(&ceremony.callback_uri)
        .bind(hash_token(&ceremony.browser_state))
        .bind(&ceremony.code_challenge)
        .bind(PASSKEY_CEREMONY_TTL.as_secs() as i64)
        .execute(&self.inner.pool)
        .await
        .map_err(|_| ServerError::Internal)?;
        let redirect_uri = make_callback_uri(
            &ceremony.callback_uri,
            &exchange_code,
            &ceremony.browser_state,
        )?;
        Ok(SigninHandoffResponse { redirect_uri })
    }

    pub(crate) async fn exchange_session(
        &self,
        request: SessionExchange,
    ) -> Result<SigninResponse, ServerError> {
        let callback_uri = validate_loopback_callback(&request.callback_uri)
            .map_err(|_| ServerError::Unauthorized)?;
        validate_browser_state(&request.state).map_err(|_| ServerError::Unauthorized)?;
        let code_challenge_hash = code_challenge_for_verifier(&request.code_verifier)
            .map_err(|_| ServerError::Unauthorized)?;
        if request.code.len() != 64 || !request.code.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(ServerError::Unauthorized);
        }
        let code_hash = hash_token(&request.code);
        let state_hash = hash_token(&request.state);
        let mut transaction = self
            .inner
            .pool
            .begin()
            .await
            .map_err(|_| ServerError::Internal)?;
        let row = sqlx::query(
            "UPDATE browser_session_exchanges SET consumed_at = now() \
             WHERE code_hash = $1 AND state_hash = $2 AND callback_uri = $3 \
               AND code_challenge_hash = $4 \
               AND consumed_at IS NULL AND expires_at > now() \
             RETURNING account_id",
        )
        .bind(code_hash)
        .bind(state_hash)
        .bind(&callback_uri)
        .bind(code_challenge_hash)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| ServerError::Internal)?
        .ok_or(ServerError::Unauthorized)?;
        let account_id: Uuid = row
            .try_get("account_id")
            .map_err(|_| ServerError::Internal)?;
        let account = sqlx::query("SELECT tag FROM accounts WHERE id = $1")
            .bind(account_id)
            .fetch_optional(&mut *transaction)
            .await
            .map_err(|_| ServerError::Internal)?
            .ok_or(ServerError::Unauthorized)?;
        let tag: String = account.try_get("tag").map_err(|_| ServerError::Internal)?;
        let token = opaque_token();
        let hash = hash_token(&token);
        let session_row = sqlx::query(
            "INSERT INTO account_sessions (token_hash, account_id, expires_at) \
             VALUES ($1, $2, now() + ($3::double precision * interval '1 second')) \
             RETURNING floor(extract(epoch from expires_at))::bigint AS expires_at",
        )
        .bind(&hash)
        .bind(account_id)
        .bind(SESSION_TTL.as_secs() as i64)
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| ServerError::Internal)?;
        let expires_at = session_row
            .try_get("expires_at")
            .map_err(|_| ServerError::Internal)?;
        transaction
            .commit()
            .await
            .map_err(|_| ServerError::Internal)?;
        Ok(SigninResponse {
            account_id,
            tag,
            session_token: token,
            expires_at,
        })
    }

    pub(crate) async fn verify_email(
        &self,
        request: EmailVerifyRequest,
    ) -> Result<(), ServerError> {
        if request.token.len() != 64 || !request.token.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(ServerError::InvalidRequest);
        }
        let hash = hash_token(&request.token);
        let mut transaction = self
            .inner
            .pool
            .begin()
            .await
            .map_err(|_| ServerError::Internal)?;
        let challenge = sqlx::query(
            "SELECT id, account_id, purpose, target_email_normalized \
             FROM email_verification_challenges \
             WHERE token_hash = $1 AND consumed_at IS NULL AND expires_at > now()",
        )
        .bind(&hash)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| ServerError::Internal)?
        .ok_or(ServerError::Unauthorized)?;
        let challenge_id: Uuid = challenge.try_get("id").map_err(|_| ServerError::Internal)?;
        let account_id: Uuid = challenge
            .try_get("account_id")
            .map_err(|_| ServerError::Internal)?;
        let purpose: String = challenge
            .try_get("purpose")
            .map_err(|_| ServerError::Internal)?;
        let target_email_normalized: String = challenge
            .try_get("target_email_normalized")
            .map_err(|_| ServerError::Internal)?;

        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
            .bind(&target_email_normalized)
            .execute(&mut *transaction)
            .await
            .map_err(|_| ServerError::Internal)?;
        let account = sqlx::query(
            "SELECT email_normalized, pending_email_normalized \
             FROM accounts WHERE id = $1 FOR UPDATE",
        )
        .bind(account_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| ServerError::Internal)?
        .ok_or(ServerError::Unauthorized)?;
        let current_email_normalized: String = account
            .try_get("email_normalized")
            .map_err(|_| ServerError::Internal)?;
        let pending_email_normalized: Option<String> = account
            .try_get("pending_email_normalized")
            .map_err(|_| ServerError::Internal)?;

        let consumed = sqlx::query(
            "UPDATE email_verification_challenges SET consumed_at = now() \
             WHERE id = $1 AND token_hash = $2 AND consumed_at IS NULL AND expires_at > now()",
        )
        .bind(challenge_id)
        .bind(hash)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ServerError::Internal)?;
        if consumed.rows_affected() != 1 {
            return Err(ServerError::Unauthorized);
        }

        match purpose.as_str() {
            "signup" if current_email_normalized == target_email_normalized => {
                sqlx::query(
                    "UPDATE accounts SET email_verified_at = now(), updated_at = now() WHERE id = $1",
                )
                .bind(account_id)
                .execute(&mut *transaction)
                .await
                .map_err(|_| ServerError::Internal)?;
            }
            "email_change"
                if pending_email_normalized.as_deref()
                    == Some(target_email_normalized.as_str()) =>
            {
                sqlx::query(
                    "UPDATE accounts \
                     SET email = pending_email, email_normalized = pending_email_normalized, \
                         pending_email = NULL, pending_email_normalized = NULL, \
                         email_verified_at = now(), updated_at = now() \
                     WHERE id = $1",
                )
                .bind(account_id)
                .execute(&mut *transaction)
                .await
                .map_err(|error| {
                    if is_unique_violation(&error) {
                        ServerError::InvalidRequest
                    } else {
                        ServerError::Internal
                    }
                })?;
            }
            _ => return Err(ServerError::Unauthorized),
        }
        transaction
            .commit()
            .await
            .map_err(|_| ServerError::Internal)?;
        Ok(())
    }

    pub(crate) async fn authenticate(
        &self,
        bearer: &str,
    ) -> Result<AuthenticatedAccount, ServerError> {
        if bearer.len() != 64 || !bearer.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(ServerError::Unauthorized);
        }
        let hash = hash_token(bearer);
        let row = sqlx::query(
            "SELECT account_id, device_id FROM account_sessions \
             WHERE token_hash = $1 AND revoked_at IS NULL AND expires_at > now()",
        )
        .bind(&hash)
        .fetch_optional(&self.inner.pool)
        .await
        .map_err(|_| ServerError::Internal)?
        .ok_or(ServerError::Unauthorized)?;
        Ok(AuthenticatedAccount {
            account_id: row
                .try_get("account_id")
                .map_err(|_| ServerError::Internal)?,
            device_id: row
                .try_get("device_id")
                .map_err(|_| ServerError::Internal)?,
            session_hash: hash,
        })
    }

    pub(crate) async fn logout(&self, account: &AuthenticatedAccount) -> Result<(), ServerError> {
        sqlx::query("UPDATE account_sessions SET revoked_at = now() WHERE token_hash = $1")
            .bind(&account.session_hash)
            .execute(&self.inner.pool)
            .await
            .map_err(|_| ServerError::Internal)?;
        Ok(())
    }

    pub(crate) async fn account_summary(
        &self,
        account: &AuthenticatedAccount,
    ) -> Result<AccountSummary, ServerError> {
        let row = sqlx::query(
            "SELECT id, tag, email, email_verified_at IS NOT NULL AS verified, \
                    pending_email_normalized IS NOT NULL AS email_change_pending \
             FROM accounts WHERE id = $1",
        )
        .bind(account.account_id)
        .fetch_one(&self.inner.pool)
        .await
        .map_err(|_| ServerError::Internal)?;
        Ok(AccountSummary {
            account_id: row.try_get("id").map_err(|_| ServerError::Internal)?,
            tag: row.try_get("tag").map_err(|_| ServerError::Internal)?,
            email: row.try_get("email").map_err(|_| ServerError::Internal)?,
            email_verified: row.try_get("verified").map_err(|_| ServerError::Internal)?,
            email_change_pending: row
                .try_get("email_change_pending")
                .map_err(|_| ServerError::Internal)?,
        })
    }

    pub(crate) async fn update_account_profile(
        &self,
        account: &AuthenticatedAccount,
        request: AccountProfileUpdate,
    ) -> Result<AccountSummary, ServerError> {
        let update = validate_profile_update(request)?;
        let mut transaction = self
            .inner
            .pool
            .begin()
            .await
            .map_err(|_| ServerError::Internal)?;
        if let Some((_, email_normalized)) = &update.email {
            sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
                .bind(email_normalized)
                .execute(&mut *transaction)
                .await
                .map_err(|_| ServerError::Internal)?;
        }
        let current = sqlx::query(
            "SELECT tag, email_normalized, pending_email_normalized \
             FROM accounts WHERE id = $1 FOR UPDATE",
        )
        .bind(account.account_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| ServerError::Internal)?
        .ok_or(ServerError::Unauthorized)?;

        if let Some(tag) = update.tag {
            sqlx::query(
                "UPDATE accounts SET tag = $1, tag_normalized = $2, updated_at = now() WHERE id = $3",
            )
            .bind(&tag)
            .bind(normalize_tag(&tag))
            .bind(account.account_id)
            .execute(&mut *transaction)
            .await
            .map_err(|error| {
                if is_unique_violation(&error) {
                    ServerError::InvalidRequest
                } else {
                    ServerError::Internal
                }
            })?;
        }

        if let Some((email, email_normalized)) = update.email {
            let current_email_normalized: String = current
                .try_get("email_normalized")
                .map_err(|_| ServerError::Internal)?;
            if email_normalized == current_email_normalized {
                sqlx::query(
                    "UPDATE accounts SET pending_email = NULL, pending_email_normalized = NULL, updated_at = now() WHERE id = $1",
                )
                .bind(account.account_id)
                .execute(&mut *transaction)
                .await
                .map_err(|_| ServerError::Internal)?;
                sqlx::query(
                    "UPDATE email_verification_challenges SET consumed_at = now() \
                     WHERE account_id = $1 AND purpose = 'email_change' AND consumed_at IS NULL",
                )
                .bind(account.account_id)
                .execute(&mut *transaction)
                .await
                .map_err(|_| ServerError::Internal)?;
            } else {
                let (Some(public_url), Some(_), Some(_)) = (
                    self.inner.public_url.as_deref(),
                    self.inner.resend_api_key.as_deref(),
                    self.inner.resend_from_email.as_deref(),
                ) else {
                    return Err(ServerError::Unavailable);
                };
                let already_reserved = sqlx::query(
                    "SELECT 1 FROM accounts \
                     WHERE id <> $1 AND (email_normalized = $2 OR pending_email_normalized = $2) \
                     LIMIT 1",
                )
                .bind(account.account_id)
                .bind(&email_normalized)
                .fetch_optional(&mut *transaction)
                .await
                .map_err(|_| ServerError::Internal)?
                .is_some();
                if already_reserved {
                    return Err(ServerError::InvalidRequest);
                }

                let email_token = opaque_token();
                let token_hash = hash_token(&email_token);
                let challenge_id = Uuid::new_v4();
                sqlx::query(
                    "UPDATE email_verification_challenges SET consumed_at = now() \
                     WHERE account_id = $1 AND purpose = 'email_change' AND consumed_at IS NULL",
                )
                .bind(account.account_id)
                .execute(&mut *transaction)
                .await
                .map_err(|_| ServerError::Internal)?;
                sqlx::query(
                    "UPDATE accounts SET pending_email = $1, pending_email_normalized = $2, updated_at = now() WHERE id = $3",
                )
                .bind(&email)
                .bind(&email_normalized)
                .bind(account.account_id)
                .execute(&mut *transaction)
                .await
                .map_err(|error| {
                    if is_unique_violation(&error) {
                        ServerError::InvalidRequest
                    } else {
                        ServerError::Internal
                    }
                })?;
                sqlx::query(
                    "INSERT INTO email_verification_challenges \
                     (id, account_id, token_hash, expires_at, purpose, target_email_normalized) \
                     VALUES ($1, $2, $3, now() + ($4::double precision * interval '1 second'), 'email_change', $5)",
                )
                .bind(challenge_id)
                .bind(account.account_id)
                .bind(token_hash.clone())
                .bind(EMAIL_TOKEN_TTL.as_secs() as i64)
                .bind(&email_normalized)
                .execute(&mut *transaction)
                .await
                .map_err(|_| ServerError::Internal)?;
                transaction
                    .commit()
                    .await
                    .map_err(|_| ServerError::Internal)?;

                let verification_url = format!(
                    "{}/api/accounts/email/verify?token={}",
                    public_url, email_token
                );
                if self
                    .send_verification_email(&email, &verification_url)
                    .await
                    .is_err()
                {
                    self.cancel_failed_email_change(
                        account.account_id,
                        challenge_id,
                        token_hash,
                        &email_normalized,
                    )
                    .await;
                    return Err(ServerError::Internal);
                }
                return self.account_summary(account).await;
            }
        }

        transaction
            .commit()
            .await
            .map_err(|_| ServerError::Internal)?;
        self.account_summary(account).await
    }

    async fn cancel_failed_email_change(
        &self,
        account_id: Uuid,
        challenge_id: Uuid,
        token_hash: Vec<u8>,
        email_normalized: &str,
    ) {
        let Ok(mut transaction) = self.inner.pool.begin().await else {
            return;
        };
        let result = sqlx::query(
            "UPDATE email_verification_challenges SET consumed_at = now() \
             WHERE id = $1 AND token_hash = $2 AND consumed_at IS NULL",
        )
        .bind(challenge_id)
        .bind(token_hash)
        .execute(&mut *transaction)
        .await;
        if result
            .map(|result| result.rows_affected() == 1)
            .unwrap_or(false)
        {
            let _ = sqlx::query(
                "UPDATE accounts SET pending_email = NULL, pending_email_normalized = NULL \
                 WHERE id = $1 AND pending_email_normalized = $2",
            )
            .bind(account_id)
            .bind(email_normalized)
            .execute(&mut *transaction)
            .await;
        }
        let _ = transaction.commit().await;
    }

    pub(crate) async fn lookup_tag(&self, tag: &str) -> Result<DirectoryEntry, ServerError> {
        let tag = validate_tag(tag)?;
        let row = sqlx::query(
            "SELECT a.id, a.tag FROM accounts a WHERE a.tag_normalized = $1 \
             AND EXISTS (SELECT 1 FROM account_passkeys p WHERE p.account_id = a.id)",
        )
        .bind(normalize_tag(&tag))
        .fetch_optional(&self.inner.pool)
        .await
        .map_err(|_| ServerError::Internal)?
        .ok_or(ServerError::InvalidRequest)?;
        Ok(DirectoryEntry {
            account_id: row.try_get("id").map_err(|_| ServerError::Internal)?,
            tag: row.try_get("tag").map_err(|_| ServerError::Internal)?,
        })
    }

    pub(crate) async fn devices(
        &self,
        account: &AuthenticatedAccount,
    ) -> Result<Vec<DeviceEntry>, ServerError> {
        let rows = sqlx::query(
            "SELECT id, user_id, device_id, display_name, created_at::text AS created_at \
             FROM account_devices WHERE account_id = $1 \
               AND registration_status = 'active' AND revoked_at IS NULL ORDER BY created_at",
        )
        .bind(account.account_id)
        .fetch_all(&self.inner.pool)
        .await
        .map_err(|_| ServerError::Internal)?;
        rows.into_iter()
            .map(|row| {
                let id: Uuid = row.try_get("id").map_err(|_| ServerError::Internal)?;
                Ok(DeviceEntry {
                    id,
                    user_id: row.try_get("user_id").map_err(|_| ServerError::Internal)?,
                    device_id: row
                        .try_get("device_id")
                        .map_err(|_| ServerError::Internal)?,
                    display_name: row
                        .try_get("display_name")
                        .map_err(|_| ServerError::Internal)?,
                    created_at: row
                        .try_get("created_at")
                        .map_err(|_| ServerError::Internal)?,
                    current: account.device_id == Some(id),
                })
            })
            .collect()
    }

    pub(crate) async fn revoke_device(
        &self,
        account: &AuthenticatedAccount,
        device_id: Uuid,
    ) -> Result<(DeviceAddress, Uuid), ServerError> {
        let mut transaction = self
            .inner
            .pool
            .begin()
            .await
            .map_err(|_| ServerError::Internal)?;
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(INSTANCE_REGISTRY_LOCK)
            .execute(&mut *transaction)
            .await
            .map_err(|_| ServerError::Internal)?;
        let row = sqlx::query(
            "SELECT user_id, device_id FROM account_devices \
             WHERE id = $1 AND account_id = $2 \
               AND registration_status = 'active' AND revoked_at IS NULL FOR UPDATE",
        )
        .bind(device_id)
        .bind(account.account_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| ServerError::Internal)?
        .ok_or(ServerError::InvalidRequest)?;
        let address = DeviceAddress::new(
            row.try_get::<String, _>("user_id")
                .map_err(|_| ServerError::Internal)?,
            row.try_get::<String, _>("device_id")
                .map_err(|_| ServerError::Internal)?,
        )?;
        let result = sqlx::query(
            "UPDATE account_devices SET revoked_at = now(), registration_status = 'revoked' \
             WHERE id = $1 AND account_id = $2 \
               AND registration_status = 'active' AND revoked_at IS NULL",
        )
        .bind(device_id)
        .bind(account.account_id)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ServerError::Internal)?;
        if result.rows_affected() > 0 {
            sqlx::query(
                "UPDATE account_sessions SET revoked_at = now() \
                 WHERE device_id = $1 AND account_id = $2 AND revoked_at IS NULL",
            )
            .bind(device_id)
            .bind(account.account_id)
            .execute(&mut *transaction)
            .await
            .map_err(|_| ServerError::Internal)?;
        }
        let event_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO device_revocation_outbox \
             (id, device_record_id, user_id, device_id) VALUES ($1, $2, $3, $4)",
        )
        .bind(event_id)
        .bind(device_id)
        .bind(&address.user_id)
        .bind(&address.device_id)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ServerError::Internal)?;
        sqlx::query(
            "INSERT INTO device_revocation_deliveries (event_id, instance_id) \
             SELECT $1, instance_id FROM relay_instances WHERE fenced_at IS NULL",
        )
        .bind(event_id)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ServerError::Internal)?;
        transaction
            .commit()
            .await
            .map_err(|_| ServerError::Internal)?;
        Ok((address, event_id))
    }

    pub(crate) async fn register_relay_instance(
        &self,
        instance_id: Uuid,
    ) -> Result<(), ServerError> {
        let mut transaction = self
            .inner
            .pool
            .begin()
            .await
            .map_err(|_| ServerError::Internal)?;
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(INSTANCE_REGISTRY_LOCK)
            .execute(&mut *transaction)
            .await
            .map_err(|_| ServerError::Internal)?;
        sqlx::query("INSERT INTO relay_instances (instance_id) VALUES ($1)")
            .bind(instance_id)
            .execute(&mut *transaction)
            .await
            .map_err(|_| ServerError::Internal)?;
        sqlx::query(
            "INSERT INTO device_revocation_deliveries \
             (event_id, instance_id, acknowledged_at) \
             SELECT id, $1, now() FROM device_revocation_outbox",
        )
        .bind(instance_id)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ServerError::Internal)?;
        transaction
            .commit()
            .await
            .map_err(|_| ServerError::Internal)
    }

    pub(crate) async fn pending_revocations(
        &self,
        instance_id: Uuid,
    ) -> Result<Vec<PendingRevocation>, ServerError> {
        let active_instance: Option<Uuid> = sqlx::query_scalar(
            "SELECT instance_id FROM relay_instances \
             WHERE instance_id = $1 AND fenced_at IS NULL",
        )
        .bind(instance_id)
        .fetch_optional(&self.inner.pool)
        .await
        .map_err(|_| ServerError::Internal)?;
        if active_instance.is_none() {
            return Err(ServerError::Unavailable);
        }
        let rows = sqlx::query(
            "SELECT o.id, o.user_id, o.device_id FROM device_revocation_deliveries d \
             JOIN device_revocation_outbox o ON o.id = d.event_id \
             WHERE d.instance_id = $1 AND d.acknowledged_at IS NULL \
             ORDER BY o.created_at, o.id",
        )
        .bind(instance_id)
        .fetch_all(&self.inner.pool)
        .await
        .map_err(|_| ServerError::Internal)?;
        rows.into_iter()
            .map(|row| {
                Ok(PendingRevocation {
                    event_id: row.try_get("id").map_err(|_| ServerError::Internal)?,
                    address: DeviceAddress::new(
                        row.try_get::<String, _>("user_id")
                            .map_err(|_| ServerError::Internal)?,
                        row.try_get::<String, _>("device_id")
                            .map_err(|_| ServerError::Internal)?,
                    )?,
                })
            })
            .collect()
    }

    pub(crate) async fn acknowledge_revocation(
        &self,
        instance_id: Uuid,
        event_id: Uuid,
    ) -> Result<(), ServerError> {
        let updated = sqlx::query(
            "UPDATE device_revocation_deliveries SET acknowledged_at = COALESCE(acknowledged_at, now()) \
             WHERE event_id = $1 AND instance_id = $2 AND EXISTS ( \
               SELECT 1 FROM relay_instances WHERE instance_id = $2 AND fenced_at IS NULL \
             )",
        )
        .bind(event_id)
        .bind(instance_id)
        .execute(&self.inner.pool)
        .await
        .map_err(|_| ServerError::Internal)?;
        if updated.rows_affected() != 1 {
            return Err(ServerError::Unavailable);
        }
        Ok(())
    }

    pub(crate) async fn wait_for_revocation(&self, event_id: Uuid) -> Result<(), ServerError> {
        loop {
            let complete: bool = sqlx::query_scalar(
                "SELECT NOT EXISTS ( \
                   SELECT 1 FROM device_revocation_deliveries d \
                   JOIN relay_instances i ON i.instance_id = d.instance_id \
                   WHERE d.event_id = $1 AND d.acknowledged_at IS NULL \
                     AND i.fenced_at IS NULL \
                 )",
            )
            .bind(event_id)
            .fetch_one(&self.inner.pool)
            .await
            .map_err(|_| ServerError::Internal)?;
            if complete {
                return Ok(());
            }
            sleep(REVOCATION_POLL_INTERVAL).await;
        }
    }

    pub(crate) async fn fence_relay_instance(&self, instance_id: Uuid) -> Result<(), ServerError> {
        let mut transaction = self
            .inner
            .pool
            .begin()
            .await
            .map_err(|_| ServerError::Internal)?;
        sqlx::query(
            "UPDATE relay_instances SET fenced_at = now() \
             WHERE instance_id = $1 AND fenced_at IS NULL",
        )
        .bind(instance_id)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ServerError::Internal)?;
        sqlx::query(
            "UPDATE relay_messages SET delivery_lease_expires_at = now() \
             WHERE delivery_lease_instance = $1 AND delivered_at IS NULL",
        )
        .bind(instance_id)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ServerError::Internal)?;
        transaction
            .commit()
            .await
            .map_err(|_| ServerError::Internal)
    }

    pub(crate) async fn authorize_relay_pair(
        &self,
        first: &DeviceAddress,
        second: &DeviceAddress,
        instance_id: Uuid,
    ) -> Result<(), ServerError> {
        let mut transaction = self
            .inner
            .pool
            .begin()
            .await
            .map_err(|_| ServerError::Internal)?;
        sqlx::query(
            "SELECT instance_id FROM relay_instances \
             WHERE instance_id = $1 AND fenced_at IS NULL FOR SHARE",
        )
        .bind(instance_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| ServerError::Internal)?
        .ok_or(ServerError::Unavailable)?;
        let mut addresses = [first, second];
        addresses.sort_by(|a, b| (&a.user_id, &a.device_id).cmp(&(&b.user_id, &b.device_id)));
        let mut previous: Option<&DeviceAddress> = None;
        for address in addresses {
            if previous == Some(address) {
                continue;
            }
            let row = sqlx::query(
                "SELECT id FROM account_devices WHERE user_id = $1 AND device_id = $2 \
                 AND registration_status = 'active' AND revoked_at IS NULL FOR SHARE",
            )
            .bind(&address.user_id)
            .bind(&address.device_id)
            .fetch_optional(&mut *transaction)
            .await
            .map_err(|_| ServerError::Internal)?
            .ok_or(ServerError::Unauthorized)?;
            drop(row);
            previous = Some(address);
        }
        transaction
            .commit()
            .await
            .map_err(|_| ServerError::Internal)
    }

    pub(crate) async fn persist_relay_message(
        &self,
        instance_id: Uuid,
        envelope: &OpaqueEnvelope,
    ) -> Result<(), ServerError> {
        let mut transaction = self
            .inner
            .pool
            .begin()
            .await
            .map_err(|_| ServerError::Internal)?;
        sqlx::query(
            "SELECT instance_id FROM relay_instances \
             WHERE instance_id = $1 AND fenced_at IS NULL FOR SHARE",
        )
        .bind(instance_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| ServerError::Internal)?
        .ok_or(ServerError::Unavailable)?;
        let mut addresses = [&envelope.sender, &envelope.recipient];
        addresses.sort_by(|a, b| (&a.user_id, &a.device_id).cmp(&(&b.user_id, &b.device_id)));
        for address in addresses {
            sqlx::query(
                "SELECT id FROM account_devices WHERE user_id = $1 AND device_id = $2 \
                 AND registration_status = 'active' AND revoked_at IS NULL FOR SHARE",
            )
            .bind(&address.user_id)
            .bind(&address.device_id)
            .fetch_optional(&mut *transaction)
            .await
            .map_err(|_| ServerError::Internal)?
            .ok_or(ServerError::Unauthorized)?;
        }
        sqlx::query(
            "INSERT INTO relay_messages \
             (message_id, sender_user_id, sender_device_id, recipient_user_id, \
              recipient_device_id, payload) VALUES ($1, $2, $3, $4, $5, $6) \
             ON CONFLICT (message_id) DO NOTHING",
        )
        .bind(envelope.message_id)
        .bind(&envelope.sender.user_id)
        .bind(&envelope.sender.device_id)
        .bind(&envelope.recipient.user_id)
        .bind(&envelope.recipient.device_id)
        .bind(&envelope.payload)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ServerError::Internal)?;
        let existing_matches: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM relay_messages WHERE message_id = $1 \
             AND sender_user_id = $2 AND sender_device_id = $3 \
             AND recipient_user_id = $4 AND recipient_device_id = $5 AND payload = $6)",
        )
        .bind(envelope.message_id)
        .bind(&envelope.sender.user_id)
        .bind(&envelope.sender.device_id)
        .bind(&envelope.recipient.user_id)
        .bind(&envelope.recipient.device_id)
        .bind(&envelope.payload)
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| ServerError::Internal)?;
        if !existing_matches {
            return Err(ServerError::InvalidRequest);
        }
        transaction
            .commit()
            .await
            .map_err(|_| ServerError::Internal)
    }

    pub(crate) async fn claim_pending_relay_messages(
        &self,
        instance_id: Uuid,
        device: &DeviceAddress,
        limit: u16,
    ) -> Result<Vec<OpaqueEnvelope>, ServerError> {
        let mut transaction = self
            .inner
            .pool
            .begin()
            .await
            .map_err(|_| ServerError::Internal)?;
        sqlx::query(
            "SELECT instance_id FROM relay_instances \
             WHERE instance_id = $1 AND fenced_at IS NULL FOR SHARE",
        )
        .bind(instance_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| ServerError::Internal)?
        .ok_or(ServerError::Unavailable)?;
        sqlx::query(
            "SELECT id FROM account_devices WHERE user_id = $1 AND device_id = $2 \
             AND registration_status = 'active' AND revoked_at IS NULL FOR SHARE",
        )
        .bind(&device.user_id)
        .bind(&device.device_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| ServerError::Internal)?
        .ok_or(ServerError::Unauthorized)?;
        let rows = sqlx::query(
            "WITH pending AS ( \
               SELECT message_id FROM relay_messages \
               WHERE recipient_user_id = $1 AND recipient_device_id = $2 \
                 AND delivered_at IS NULL AND deleted_at IS NULL \
                 AND (delivery_lease_expires_at IS NULL \
                   OR delivery_lease_expires_at <= now()) \
                 AND NOT EXISTS (SELECT 1 FROM relay_message_hides h \
                   JOIN account_devices recipient ON recipient.user_id = $1 \
                     AND recipient.device_id = $2 \
                   WHERE h.account_id = recipient.account_id \
                     AND h.message_id = relay_messages.message_id) \
               ORDER BY relay_sequence \
               FOR UPDATE SKIP LOCKED LIMIT $3 \
             ) \
             UPDATE relay_messages m \
             SET delivery_lease_instance = $4, \
                 delivery_lease_expires_at = now() + interval '30 seconds', \
                 delivery_attempts = delivery_attempts + 1 \
             FROM pending \
             WHERE m.message_id = pending.message_id \
             RETURNING m.message_id, m.sender_user_id, m.sender_device_id, \
                       m.recipient_user_id, m.recipient_device_id, m.payload",
        )
        .bind(&device.user_id)
        .bind(&device.device_id)
        .bind(i64::from(limit))
        .bind(instance_id)
        .fetch_all(&mut *transaction)
        .await
        .map_err(|_| ServerError::Internal)?;
        transaction
            .commit()
            .await
            .map_err(|_| ServerError::Internal)?;
        rows.into_iter()
            .map(|row| {
                Ok(OpaqueEnvelope {
                    message_id: row
                        .try_get("message_id")
                        .map_err(|_| ServerError::Internal)?,
                    sender: DeviceAddress::new(
                        row.try_get::<String, _>("sender_user_id")
                            .map_err(|_| ServerError::Internal)?,
                        row.try_get::<String, _>("sender_device_id")
                            .map_err(|_| ServerError::Internal)?,
                    )?,
                    recipient: DeviceAddress::new(
                        row.try_get::<String, _>("recipient_user_id")
                            .map_err(|_| ServerError::Internal)?,
                        row.try_get::<String, _>("recipient_device_id")
                            .map_err(|_| ServerError::Internal)?,
                    )?,
                    payload: row.try_get("payload").map_err(|_| ServerError::Internal)?,
                })
            })
            .collect()
    }

    pub(crate) async fn acknowledge_relay_message(
        &self,
        instance_id: Uuid,
        device: &DeviceAddress,
        message_id: Uuid,
    ) -> Result<(), ServerError> {
        let mut transaction = self
            .inner
            .pool
            .begin()
            .await
            .map_err(|_| ServerError::Internal)?;
        sqlx::query(
            "SELECT instance_id FROM relay_instances \
             WHERE instance_id = $1 AND fenced_at IS NULL FOR SHARE",
        )
        .bind(instance_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| ServerError::Internal)?
        .ok_or(ServerError::Unavailable)?;
        sqlx::query(
            "SELECT id FROM account_devices WHERE user_id = $1 AND device_id = $2 \
             AND registration_status = 'active' AND revoked_at IS NULL FOR SHARE",
        )
        .bind(&device.user_id)
        .bind(&device.device_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| ServerError::Internal)?
        .ok_or(ServerError::Unauthorized)?;
        let updated = sqlx::query(
            "UPDATE relay_messages SET delivered_at = now(), \
                 delivery_lease_instance = NULL, delivery_lease_expires_at = NULL \
             WHERE message_id = $1 AND recipient_user_id = $2 \
               AND recipient_device_id = $3 AND delivered_at IS NULL \
               AND delivery_lease_instance = $4",
        )
        .bind(message_id)
        .bind(&device.user_id)
        .bind(&device.device_id)
        .bind(instance_id)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ServerError::Internal)?;
        if updated.rows_affected() == 0 {
            let already_acked: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM relay_messages WHERE message_id = $1 \
                 AND recipient_user_id = $2 AND recipient_device_id = $3 \
                 AND delivered_at IS NOT NULL)",
            )
            .bind(message_id)
            .bind(&device.user_id)
            .bind(&device.device_id)
            .fetch_one(&mut *transaction)
            .await
            .map_err(|_| ServerError::Internal)?;
            if !already_acked {
                return Err(ServerError::InvalidAcknowledgement);
            }
        }
        transaction
            .commit()
            .await
            .map_err(|_| ServerError::Internal)
    }

    pub(crate) async fn record_typing_state(
        &self,
        instance_id: Uuid,
        sender: &DeviceAddress,
        recipient: &DeviceAddress,
        is_typing: bool,
    ) -> Result<(), ServerError> {
        if sender == recipient {
            return Err(ServerError::InvalidRequest);
        }
        let mut transaction = self
            .inner
            .pool
            .begin()
            .await
            .map_err(|_| ServerError::Internal)?;
        sqlx::query(
            "SELECT instance_id FROM relay_instances \
             WHERE instance_id = $1 AND fenced_at IS NULL FOR SHARE",
        )
        .bind(instance_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| ServerError::Internal)?
        .ok_or(ServerError::Unavailable)?;
        let mut addresses = [sender, recipient];
        addresses.sort_by(|a, b| (&a.user_id, &a.device_id).cmp(&(&b.user_id, &b.device_id)));
        for address in addresses {
            sqlx::query(
                "SELECT id FROM account_devices WHERE user_id = $1 AND device_id = $2 \
                 AND registration_status = 'active' AND revoked_at IS NULL FOR SHARE",
            )
            .bind(&address.user_id)
            .bind(&address.device_id)
            .fetch_optional(&mut *transaction)
            .await
            .map_err(|_| ServerError::Internal)?
            .ok_or(ServerError::Unauthorized)?;
        }
        sqlx::query(
            "INSERT INTO relay_typing_states \
             (sender_user_id, sender_device_id, recipient_user_id, recipient_device_id, \
              is_typing, updated_at, expires_at) \
             VALUES ($1, $2, $3, $4, $5, now(), now() + interval '5 seconds') \
             ON CONFLICT (sender_user_id, sender_device_id, recipient_user_id, recipient_device_id) \
             DO UPDATE SET is_typing = EXCLUDED.is_typing, updated_at = EXCLUDED.updated_at, \
                           expires_at = EXCLUDED.expires_at",
        )
        .bind(&sender.user_id)
        .bind(&sender.device_id)
        .bind(&recipient.user_id)
        .bind(&recipient.device_id)
        .bind(is_typing)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ServerError::Internal)?;
        transaction
            .commit()
            .await
            .map_err(|_| ServerError::Internal)
    }

    pub(crate) async fn active_typing_states(
        &self,
        instance_id: Uuid,
        connected_devices: &[DeviceAddress],
    ) -> Result<Vec<TypingState>, ServerError> {
        if connected_devices.is_empty() {
            return Ok(Vec::new());
        }
        let mut transaction = self
            .inner
            .pool
            .begin()
            .await
            .map_err(|_| ServerError::Internal)?;
        sqlx::query(
            "SELECT instance_id FROM relay_instances \
             WHERE instance_id = $1 AND fenced_at IS NULL FOR SHARE",
        )
        .bind(instance_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| ServerError::Internal)?
        .ok_or(ServerError::Unavailable)?;
        sqlx::query("DELETE FROM relay_typing_states WHERE expires_at <= now()")
            .execute(&mut *transaction)
            .await
            .map_err(|_| ServerError::Internal)?;
        let recipient_users: Vec<_> = connected_devices
            .iter()
            .map(|device| device.user_id.clone())
            .collect();
        let recipient_devices: Vec<_> = connected_devices
            .iter()
            .map(|device| device.device_id.clone())
            .collect();
        let rows = sqlx::query(
            "SELECT s.sender_user_id, s.sender_device_id, \
                    s.recipient_user_id, s.recipient_device_id, s.is_typing, \
                    s.updated_at::text AS updated_at \
             FROM relay_typing_states s \
             JOIN account_devices sender ON sender.user_id = s.sender_user_id \
               AND sender.device_id = s.sender_device_id \
               AND sender.registration_status = 'active' AND sender.revoked_at IS NULL \
             JOIN account_devices recipient ON recipient.user_id = s.recipient_user_id \
               AND recipient.device_id = s.recipient_device_id \
               AND recipient.registration_status = 'active' AND recipient.revoked_at IS NULL \
             JOIN unnest($2::text[], $3::text[]) AS connected(user_id, device_id) \
               ON connected.user_id = s.recipient_user_id \
               AND connected.device_id = s.recipient_device_id \
             WHERE s.expires_at > now() AND EXISTS (SELECT 1 FROM relay_instances \
               WHERE instance_id = $1 AND fenced_at IS NULL) \
             ORDER BY s.updated_at",
        )
        .bind(instance_id)
        .bind(recipient_users)
        .bind(recipient_devices)
        .fetch_all(&mut *transaction)
        .await
        .map_err(|_| ServerError::Internal)?;
        transaction
            .commit()
            .await
            .map_err(|_| ServerError::Internal)?;
        rows.into_iter()
            .map(|row| {
                Ok(TypingState {
                    sender: DeviceAddress::new(
                        row.try_get::<String, _>("sender_user_id")
                            .map_err(|_| ServerError::Internal)?,
                        row.try_get::<String, _>("sender_device_id")
                            .map_err(|_| ServerError::Internal)?,
                    )?,
                    recipient: DeviceAddress::new(
                        row.try_get::<String, _>("recipient_user_id")
                            .map_err(|_| ServerError::Internal)?,
                        row.try_get::<String, _>("recipient_device_id")
                            .map_err(|_| ServerError::Internal)?,
                    )?,
                    is_typing: row
                        .try_get("is_typing")
                        .map_err(|_| ServerError::Internal)?,
                    updated_at: row
                        .try_get("updated_at")
                        .map_err(|_| ServerError::Internal)?,
                })
            })
            .collect()
    }

    pub(crate) async fn release_relay_delivery_leases(
        &self,
        instance_id: Uuid,
        device: Option<&DeviceAddress>,
    ) -> Result<(), ServerError> {
        let result = if let Some(device) = device {
            sqlx::query(
                "UPDATE relay_messages SET delivery_lease_expires_at = now() \
                 WHERE delivery_lease_instance = $1 AND recipient_user_id = $2 \
                   AND recipient_device_id = $3 AND delivered_at IS NULL",
            )
            .bind(instance_id)
            .bind(&device.user_id)
            .bind(&device.device_id)
            .execute(&self.inner.pool)
            .await
        } else {
            sqlx::query(
                "UPDATE relay_messages SET delivery_lease_expires_at = now() \
                 WHERE delivery_lease_instance = $1 AND delivered_at IS NULL",
            )
            .bind(instance_id)
            .execute(&self.inner.pool)
            .await
        };
        result.map(|_| ()).map_err(|_| ServerError::Internal)
    }

    pub(crate) async fn relay_history(
        &self,
        instance_id: Uuid,
        device: &DeviceAddress,
        with: &DeviceAddress,
        before: Option<Uuid>,
        limit: u16,
    ) -> Result<(Vec<StoredRelayMessage>, bool), ServerError> {
        if limit == 0 || limit > 100 || device == with {
            return Err(ServerError::InvalidRequest);
        }
        let mut transaction = self
            .inner
            .pool
            .begin()
            .await
            .map_err(|_| ServerError::Internal)?;
        sqlx::query(
            "SELECT instance_id FROM relay_instances \
             WHERE instance_id = $1 AND fenced_at IS NULL FOR SHARE",
        )
        .bind(instance_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| ServerError::Internal)?
        .ok_or(ServerError::Unavailable)?;
        let mut addresses = [device, with];
        addresses.sort_by(|a, b| (&a.user_id, &a.device_id).cmp(&(&b.user_id, &b.device_id)));
        for address in addresses {
            sqlx::query(
                "SELECT id FROM account_devices WHERE user_id = $1 AND device_id = $2 \
                 AND registration_status = 'active' AND revoked_at IS NULL FOR SHARE",
            )
            .bind(&address.user_id)
            .bind(&address.device_id)
            .fetch_optional(&mut *transaction)
            .await
            .map_err(|_| ServerError::Internal)?
            .ok_or(ServerError::Unauthorized)?;
        }
        let rows = sqlx::query(
            "SELECT m.message_id, m.sender_user_id, m.sender_device_id, \
                    m.recipient_user_id, m.recipient_device_id, m.payload, \
                    m.deleted_at IS NOT NULL AS deleted, \
                    (SELECT to_char(MAX(r.read_at) AT TIME ZONE 'UTC', \
                      'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') \
                     FROM relay_message_read_receipts r \
                     WHERE r.message_id = m.message_id) AS read_at, \
                    EXISTS (SELECT 1 FROM relay_message_hides h \
                      WHERE h.account_id = d.account_id AND h.message_id = m.message_id) \
                      AS hidden, \
                    to_char(m.created_at AT TIME ZONE 'UTC', \
                      'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') AS created_at \
             FROM relay_messages m \
             JOIN account_devices d ON d.user_id = $1 AND d.device_id = $2 \
               AND d.registration_status = 'active' AND d.revoked_at IS NULL \
             WHERE ((m.sender_user_id = $1 AND m.sender_device_id = $2 \
                       AND m.recipient_user_id = $3 AND m.recipient_device_id = $4) \
                 OR (m.sender_user_id = $3 AND m.sender_device_id = $4 \
                       AND m.recipient_user_id = $1 AND m.recipient_device_id = $2)) \
               AND ($5::uuid IS NULL OR m.relay_sequence < \
                 (SELECT cursor.relay_sequence FROM relay_messages cursor \
                  WHERE cursor.message_id = $5 AND \
                    ((cursor.sender_user_id = $1 AND cursor.sender_device_id = $2 \
                      AND cursor.recipient_user_id = $3 AND cursor.recipient_device_id = $4) \
                     OR (cursor.sender_user_id = $3 AND cursor.sender_device_id = $4 \
                      AND cursor.recipient_user_id = $1 AND cursor.recipient_device_id = $2))) \
             ORDER BY m.relay_sequence DESC LIMIT $6",
        )
        .bind(&device.user_id)
        .bind(&device.device_id)
        .bind(&with.user_id)
        .bind(&with.device_id)
        .bind(before)
        .bind(i64::from(limit) + 1)
        .fetch_all(&mut *transaction)
        .await
        .map_err(|_| ServerError::Internal)?;
        transaction
            .commit()
            .await
            .map_err(|_| ServerError::Internal)?;
        let has_more = rows.len() > usize::from(limit);
        let messages = rows
            .into_iter()
            .take(usize::from(limit))
            .map(|row| {
                let deleted: bool = row.try_get("deleted").map_err(|_| ServerError::Internal)?;
                let envelope = OpaqueEnvelope {
                    message_id: row
                        .try_get("message_id")
                        .map_err(|_| ServerError::Internal)?,
                    sender: DeviceAddress::new(
                        row.try_get::<String, _>("sender_user_id")
                            .map_err(|_| ServerError::Internal)?,
                        row.try_get::<String, _>("sender_device_id")
                            .map_err(|_| ServerError::Internal)?,
                    )?,
                    recipient: DeviceAddress::new(
                        row.try_get::<String, _>("recipient_user_id")
                            .map_err(|_| ServerError::Internal)?,
                        row.try_get::<String, _>("recipient_device_id")
                            .map_err(|_| ServerError::Internal)?,
                    )?,
                    payload: row.try_get("payload").map_err(|_| ServerError::Internal)?,
                };
                Ok(StoredRelayMessage {
                    envelope,
                    created_at: row
                        .try_get("created_at")
                        .map_err(|_| ServerError::Internal)?,
                    deleted,
                    hidden: row.try_get("hidden").map_err(|_| ServerError::Internal)?,
                    read_at: row.try_get("read_at").map_err(|_| ServerError::Internal)?,
                })
            })
            .collect::<Result<Vec<_>, ServerError>>()?;
        Ok((messages, has_more))
    }

    pub(crate) async fn hide_relay_message(
        &self,
        instance_id: Uuid,
        device: &DeviceAddress,
        message_id: Uuid,
    ) -> Result<(), ServerError> {
        let mut transaction = self
            .inner
            .pool
            .begin()
            .await
            .map_err(|_| ServerError::Internal)?;
        sqlx::query(
            "SELECT instance_id FROM relay_instances \
             WHERE instance_id = $1 AND fenced_at IS NULL FOR SHARE",
        )
        .bind(instance_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| ServerError::Internal)?
        .ok_or(ServerError::Unavailable)?;
        let account_id: Uuid = sqlx::query_scalar(
            "SELECT account_id FROM account_devices WHERE user_id = $1 AND device_id = $2 \
             AND registration_status = 'active' AND revoked_at IS NULL FOR SHARE",
        )
        .bind(&device.user_id)
        .bind(&device.device_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| ServerError::Internal)?
        .ok_or(ServerError::Unauthorized)?;
        let message = sqlx::query(
            "SELECT message_id FROM relay_messages WHERE message_id = $1 \
             AND ((sender_user_id = $2 AND sender_device_id = $3) \
               OR (recipient_user_id = $2 AND recipient_device_id = $3)) FOR UPDATE",
        )
        .bind(message_id)
        .bind(&device.user_id)
        .bind(&device.device_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| ServerError::Internal)?;
        if message.is_none() {
            return Err(ServerError::InvalidRequest);
        }
        sqlx::query(
            "INSERT INTO relay_message_hides (account_id, message_id) \
             VALUES ($1, $2) ON CONFLICT (account_id, message_id) DO NOTHING",
        )
        .bind(account_id)
        .bind(message_id)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ServerError::Internal)?;
        transaction
            .commit()
            .await
            .map_err(|_| ServerError::Internal)
    }

    pub(crate) async fn redact_relay_message(
        &self,
        instance_id: Uuid,
        device: &DeviceAddress,
        message_id: Uuid,
    ) -> Result<DeviceAddress, ServerError> {
        let mut transaction = self
            .inner
            .pool
            .begin()
            .await
            .map_err(|_| ServerError::Internal)?;
        sqlx::query(
            "SELECT instance_id FROM relay_instances \
             WHERE instance_id = $1 AND fenced_at IS NULL FOR SHARE",
        )
        .bind(instance_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| ServerError::Internal)?
        .ok_or(ServerError::Unavailable)?;
        sqlx::query(
            "SELECT id FROM account_devices WHERE user_id = $1 AND device_id = $2 \
             AND registration_status = 'active' AND revoked_at IS NULL FOR SHARE",
        )
        .bind(&device.user_id)
        .bind(&device.device_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| ServerError::Internal)?
        .ok_or(ServerError::Unauthorized)?;
        let row = sqlx::query(
            "UPDATE relay_messages SET deleted_at = COALESCE(deleted_at, now()), payload = decode('', 'hex') \
             WHERE message_id = $1 AND sender_user_id = $2 AND sender_device_id = $3 \
             RETURNING recipient_user_id, recipient_device_id",
        )
        .bind(message_id)
        .bind(&device.user_id)
        .bind(&device.device_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| ServerError::Internal)?
        .ok_or(ServerError::InvalidRequest)?;
        let recipient = DeviceAddress::new(
            row.try_get::<String, _>("recipient_user_id")
                .map_err(|_| ServerError::Internal)?,
            row.try_get::<String, _>("recipient_device_id")
                .map_err(|_| ServerError::Internal)?,
        )?;
        transaction
            .commit()
            .await
            .map_err(|_| ServerError::Internal)?;
        Ok(recipient)
    }

    pub(crate) async fn record_read_receipt(
        &self,
        instance_id: Uuid,
        device: &DeviceAddress,
        message_id: Uuid,
    ) -> Result<(DeviceAddress, String), ServerError> {
        let mut transaction = self
            .inner
            .pool
            .begin()
            .await
            .map_err(|_| ServerError::Internal)?;
        sqlx::query(
            "SELECT instance_id FROM relay_instances \
             WHERE instance_id = $1 AND fenced_at IS NULL FOR SHARE",
        )
        .bind(instance_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| ServerError::Internal)?
        .ok_or(ServerError::Unavailable)?;
        sqlx::query(
            "SELECT id FROM account_devices WHERE user_id = $1 AND device_id = $2 \
             AND registration_status = 'active' AND revoked_at IS NULL FOR SHARE",
        )
        .bind(&device.user_id)
        .bind(&device.device_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| ServerError::Internal)?
        .ok_or(ServerError::Unauthorized)?;
        let row = sqlx::query(
            "INSERT INTO relay_message_read_receipts (message_id, reader_device_id) \
             SELECT m.message_id, d.id FROM relay_messages m \
             JOIN account_devices d ON d.user_id = $2 AND d.device_id = $3 \
               AND d.registration_status = 'active' AND d.revoked_at IS NULL \
             WHERE m.message_id = $1 AND m.recipient_user_id = $2 \
               AND m.recipient_device_id = $3 AND m.deleted_at IS NULL \
             ON CONFLICT (message_id, reader_device_id) DO UPDATE \
               SET read_at = relay_message_read_receipts.read_at \
             RETURNING to_char(read_at AT TIME ZONE 'UTC', \
               'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') AS read_at",
        )
        .bind(message_id)
        .bind(&device.user_id)
        .bind(&device.device_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| ServerError::Internal)?
        .ok_or(ServerError::InvalidRequest)?;
        let sender = sqlx::query(
            "SELECT sender_user_id, sender_device_id FROM relay_messages WHERE message_id = $1",
        )
        .bind(message_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| ServerError::Internal)?
        .ok_or(ServerError::InvalidRequest)?;
        let sender = (
            DeviceAddress::new(
                sender
                    .try_get::<String, _>("sender_user_id")
                    .map_err(|_| ServerError::Internal)?,
                sender
                    .try_get::<String, _>("sender_device_id")
                    .map_err(|_| ServerError::Internal)?,
            )?,
            row.try_get("read_at").map_err(|_| ServerError::Internal)?,
        );
        transaction
            .commit()
            .await
            .map_err(|_| ServerError::Internal)?;
        Ok(sender)
    }

    pub(crate) async fn authorize_for_instance(
        &self,
        identity: IdentityPublicKey,
        device: &DeviceAddress,
        instance_id: Uuid,
    ) -> Result<(), ServerError> {
        let mut transaction = self
            .inner
            .pool
            .begin()
            .await
            .map_err(|_| ServerError::Internal)?;
        let instance = sqlx::query(
            "SELECT instance_id FROM relay_instances \
             WHERE instance_id = $1 AND fenced_at IS NULL FOR SHARE",
        )
        .bind(instance_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| ServerError::Internal)?;
        if instance.is_none() {
            return Err(ServerError::Unavailable);
        }
        let active = sqlx::query(
            "SELECT id FROM account_devices WHERE user_id = $1 AND device_id = $2 \
             AND identity_public_key = $3 AND registration_status = 'active' \
             AND revoked_at IS NULL",
        )
        .bind(&device.user_id)
        .bind(&device.device_id)
        .bind(identity.as_bytes().as_slice())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| ServerError::Internal)?;
        if active.is_none() {
            return Err(ServerError::Unauthorized);
        }
        transaction
            .commit()
            .await
            .map_err(|_| ServerError::Internal)
    }

    pub(crate) async fn issue_auth_challenge(
        &self,
        challenge_id: Uuid,
        identity: IdentityPublicKey,
        address: &DeviceAddress,
        instance_id: Uuid,
    ) -> Result<(), ServerError> {
        let mut transaction = self
            .inner
            .pool
            .begin()
            .await
            .map_err(|_| ServerError::Internal)?;
        sqlx::query(
            "SELECT instance_id FROM relay_instances \
             WHERE instance_id = $1 AND fenced_at IS NULL FOR SHARE",
        )
        .bind(instance_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| ServerError::Internal)?
        .ok_or(ServerError::Unavailable)?;
        let device_id: Uuid = sqlx::query_scalar(
            "SELECT id FROM account_devices WHERE user_id = $1 AND device_id = $2 \
             AND identity_public_key = $3 AND registration_status = 'active' \
             AND revoked_at IS NULL FOR SHARE",
        )
        .bind(&address.user_id)
        .bind(&address.device_id)
        .bind(identity.as_bytes().as_slice())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| ServerError::Internal)?
        .ok_or(ServerError::Unauthorized)?;
        sqlx::query("DELETE FROM relay_auth_challenges WHERE expires_at <= now()")
            .execute(&mut *transaction)
            .await
            .map_err(|_| ServerError::Internal)?;
        let pending_count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM relay_auth_challenges \
             WHERE instance_id = $1 AND consumed_at IS NULL AND expires_at > now()",
        )
        .bind(instance_id)
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| ServerError::Internal)?;
        if pending_count >= MAX_PENDING_RELAY_CHALLENGES {
            return Err(ServerError::ResourceLimit);
        }
        sqlx::query(
            "INSERT INTO relay_auth_challenges \
             (challenge_id, instance_id, device_record_id, expires_at) \
             VALUES ($1, $2, $3, now() + interval '15 seconds')",
        )
        .bind(challenge_id)
        .bind(instance_id)
        .bind(device_id)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ServerError::Internal)?;
        transaction
            .commit()
            .await
            .map_err(|_| ServerError::Internal)
    }

    pub(crate) async fn consume_auth_challenge(
        &self,
        challenge_id: Uuid,
        identity: IdentityPublicKey,
        address: &DeviceAddress,
        instance_id: Uuid,
    ) -> Result<Transaction<'static, Postgres>, ServerError> {
        let mut transaction = self
            .inner
            .pool
            .begin()
            .await
            .map_err(|_| ServerError::Internal)?;
        sqlx::query(
            "SELECT instance_id FROM relay_instances \
             WHERE instance_id = $1 AND fenced_at IS NULL FOR SHARE",
        )
        .bind(instance_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| ServerError::Internal)?
        .ok_or(ServerError::Unavailable)?;
        let record = sqlx::query(
            "SELECT c.device_record_id, d.identity_public_key \
             FROM relay_auth_challenges c \
             JOIN account_devices d ON d.id = c.device_record_id \
             WHERE c.challenge_id = $1 AND c.instance_id = $2 \
               AND c.consumed_at IS NULL AND c.expires_at > now() \
               AND d.user_id = $3 AND d.device_id = $4 \
               AND d.identity_public_key = $5 AND d.registration_status = 'active' \
               AND d.revoked_at IS NULL \
             FOR UPDATE OF c, d",
        )
        .bind(challenge_id)
        .bind(instance_id)
        .bind(&address.user_id)
        .bind(&address.device_id)
        .bind(identity.as_bytes().as_slice())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| ServerError::Internal)?
        .ok_or(ServerError::Unauthorized)?;
        let key: Vec<u8> = record
            .try_get("identity_public_key")
            .map_err(|_| ServerError::Internal)?;
        if key.as_slice() != identity.as_bytes().as_slice() {
            return Err(ServerError::Unauthorized);
        }
        let consumed = sqlx::query(
            "UPDATE relay_auth_challenges SET consumed_at = now() \
             WHERE challenge_id = $1 AND consumed_at IS NULL",
        )
        .bind(challenge_id)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ServerError::Internal)?;
        if consumed.rows_affected() != 1 {
            return Err(ServerError::Unauthorized);
        }
        Ok(transaction)
    }

    pub(crate) async fn authorize_recipient_for_instance(
        &self,
        device: &DeviceAddress,
        instance_id: Uuid,
    ) -> Result<(), ServerError> {
        let mut transaction = self
            .inner
            .pool
            .begin()
            .await
            .map_err(|_| ServerError::Internal)?;
        let instance = sqlx::query(
            "SELECT instance_id FROM relay_instances \
             WHERE instance_id = $1 AND fenced_at IS NULL FOR SHARE",
        )
        .bind(instance_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| ServerError::Internal)?;
        if instance.is_none() {
            return Err(ServerError::Unavailable);
        }
        let active = sqlx::query(
            "SELECT id FROM account_devices WHERE user_id = $1 AND device_id = $2 \
             AND registration_status = 'active' AND revoked_at IS NULL FOR SHARE",
        )
        .bind(&device.user_id)
        .bind(&device.device_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| ServerError::Internal)?;
        if active.is_none() {
            return Err(ServerError::Unauthorized);
        }
        transaction
            .commit()
            .await
            .map_err(|_| ServerError::Internal)
    }

    pub(crate) async fn start_device_challenge(
        &self,
        account: &AuthenticatedAccount,
        request: DeviceChallengeStart,
    ) -> Result<DeviceChallengeResponse, ServerError> {
        request.device.validate()?;
        let identity_key = IdentityPublicKey::from_bytes(request.identity_public_key);
        sqlx::query(
            "SELECT id FROM account_devices \
             WHERE account_id = $1 AND user_id = $2 AND device_id = $3 \
               AND identity_public_key = $4 AND registration_status = 'active' \
               AND revoked_at IS NULL",
        )
        .bind(account.account_id)
        .bind(&request.device.user_id)
        .bind(&request.device.device_id)
        .bind(request.identity_public_key.as_slice())
        .fetch_optional(&self.inner.pool)
        .await
        .map_err(|_| ServerError::Internal)?
        .ok_or(ServerError::Unauthorized)?;
        let challenge_id = Uuid::new_v4();
        let mut nonce = [0u8; 32];
        nonce[..16].copy_from_slice(Uuid::new_v4().as_bytes());
        nonce[16..].copy_from_slice(Uuid::new_v4().as_bytes());
        let challenge = DeviceAuthChallenge::new(
            self.inner.server_id.clone(),
            request.device.user_id.clone(),
            request.device.device_id.clone(),
            identity_key,
            *challenge_id.as_bytes(),
            nonce,
        )
        .map_err(|_| ServerError::Internal)?;
        let mut challenges = self.inner.device_challenges.lock().await;
        prune_expired(&mut challenges);
        if challenges.len() >= MAX_PENDING_CEREMONIES {
            return Err(ServerError::ResourceLimit);
        }
        challenges.insert(
            challenge_id,
            DeviceChallenge {
                account_id: account.account_id,
                session_hash: account.session_hash.clone(),
                device: request.device,
                identity_key,
                challenge: challenge.clone(),
                expires_at: Instant::now() + PASSKEY_CEREMONY_TTL,
            },
        );
        Ok(DeviceChallengeResponse {
            challenge_id,
            challenge,
        })
    }

    pub(crate) async fn finish_device_challenge(
        &self,
        account: &AuthenticatedAccount,
        request: DeviceChallengeFinish,
    ) -> Result<(), ServerError> {
        let ceremony = self
            .inner
            .device_challenges
            .lock()
            .await
            .remove(&request.challenge_id)
            .ok_or(ServerError::Unauthorized)?;
        if ceremony.expires_at <= Instant::now()
            || ceremony.account_id != account.account_id
            || ceremony.session_hash != account.session_hash
            || ceremony
                .identity_key
                .verify_device_auth_challenge(&ceremony.challenge, &request.proof)
                .is_err()
        {
            return Err(ServerError::Unauthorized);
        }
        let mut transaction = self
            .inner
            .pool
            .begin()
            .await
            .map_err(|_| ServerError::Internal)?;
        let device_record: Uuid = sqlx::query_scalar(
            "SELECT id FROM account_devices WHERE account_id = $1 AND user_id = $2 \
             AND device_id = $3 AND identity_public_key = $4 \
             AND registration_status = 'active' AND revoked_at IS NULL FOR SHARE",
        )
        .bind(ceremony.account_id)
        .bind(&ceremony.device.user_id)
        .bind(&ceremony.device.device_id)
        .bind(ceremony.identity_key.as_bytes().as_slice())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| ServerError::Internal)?
        .ok_or(ServerError::Unauthorized)?;
        let result = sqlx::query(
            "UPDATE account_sessions SET device_id = $1 \
             WHERE token_hash = $2 AND account_id = $3 AND revoked_at IS NULL \
               AND expires_at > now()",
        )
        .bind(device_record)
        .bind(&account.session_hash)
        .bind(ceremony.account_id)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ServerError::Internal)?;
        if result.rows_affected() != 1 {
            return Err(ServerError::Unauthorized);
        }
        transaction
            .commit()
            .await
            .map_err(|_| ServerError::Internal)?;
        Ok(())
    }

    pub(crate) async fn start_first_device(
        &self,
        account: &AuthenticatedAccount,
        request: FirstDeviceStart,
    ) -> Result<FirstDeviceStartResponse, ServerError> {
        request.device.validate()?;
        let display_name = validate_display_name(&request.display_name)?;
        let identity_key = IdentityPublicKey::from_bytes(request.identity_public_key);
        let registered_key = DeviceAuthChallenge::new(
            self.inner.server_id.clone(),
            request.device.user_id.clone(),
            request.device.device_id.clone(),
            identity_key,
            [0; 16],
            [0; 32],
        );
        if registered_key.is_err() {
            return Err(ServerError::InvalidRequest);
        }
        let key_registered: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM account_devices WHERE identity_public_key = $1)",
        )
        .bind(identity_key.as_bytes().as_slice())
        .fetch_one(&self.inner.pool)
        .await
        .map_err(|_| ServerError::Internal)?;
        if key_registered {
            return Err(ServerError::InvalidRequest);
        }
        let eligible: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM accounts a \
             JOIN account_sessions s ON s.account_id = a.id \
             WHERE a.id = $1 \
               AND s.token_hash = $2 AND s.revoked_at IS NULL \
               AND s.expires_at > now() AND s.device_id IS NULL) \
             AND NOT EXISTS (SELECT 1 FROM account_devices \
               WHERE account_id = $1 AND registration_status = 'active' \
                 AND revoked_at IS NULL)",
        )
        .bind(account.account_id)
        .bind(&account.session_hash)
        .fetch_one(&self.inner.pool)
        .await
        .map_err(|_| ServerError::Internal)?;
        if !eligible {
            return Err(ServerError::Unauthorized);
        }
        let challenge_id = Uuid::new_v4();
        let mut nonce = [0u8; 32];
        nonce[..16].copy_from_slice(Uuid::new_v4().as_bytes());
        nonce[16..].copy_from_slice(Uuid::new_v4().as_bytes());
        let challenge = DeviceAuthChallenge::new(
            self.inner.server_id.clone(),
            request.device.user_id.clone(),
            request.device.device_id.clone(),
            identity_key,
            *challenge_id.as_bytes(),
            nonce,
        )
        .map_err(|_| ServerError::Internal)?;
        let mut challenges = self.inner.first_device_challenges.lock().await;
        prune_expired(&mut challenges);
        if challenges.len() >= MAX_PENDING_CEREMONIES {
            return Err(ServerError::ResourceLimit);
        }
        challenges.insert(
            challenge_id,
            FirstDeviceChallenge {
                account_id: account.account_id,
                session_hash: account.session_hash.clone(),
                device: request.device,
                identity_key,
                display_name,
                challenge: challenge.clone(),
                expires_at: Instant::now() + PASSKEY_CEREMONY_TTL,
            },
        );
        Ok(FirstDeviceStartResponse {
            challenge_id,
            challenge,
        })
    }

    pub(crate) async fn finish_first_device(
        &self,
        account: &AuthenticatedAccount,
        request: FirstDeviceFinish,
    ) -> Result<FirstDeviceResponse, ServerError> {
        let ceremony = self
            .inner
            .first_device_challenges
            .lock()
            .await
            .remove(&request.challenge_id)
            .ok_or(ServerError::Unauthorized)?;
        if ceremony.expires_at <= Instant::now()
            || ceremony.account_id != account.account_id
            || ceremony.session_hash != account.session_hash
            || ceremony
                .identity_key
                .verify_device_auth_challenge(&ceremony.challenge, &request.proof)
                .is_err()
        {
            return Err(ServerError::Unauthorized);
        }

        let mut transaction = self
            .inner
            .pool
            .begin()
            .await
            .map_err(|_| ServerError::Internal)?;
        sqlx::query("SELECT id FROM accounts WHERE id = $1 FOR UPDATE")
            .bind(account.account_id)
            .fetch_optional(&mut *transaction)
            .await
            .map_err(|_| ServerError::Internal)?
            .ok_or(ServerError::Unauthorized)?;
        let eligible: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM account_sessions \
             WHERE token_hash = $1 AND account_id = $2 AND device_id IS NULL \
               AND revoked_at IS NULL AND expires_at > now()) \
             AND NOT EXISTS (SELECT 1 FROM account_devices \
               WHERE account_id = $2 AND registration_status = 'active' \
                 AND revoked_at IS NULL)",
        )
        .bind(&account.session_hash)
        .bind(account.account_id)
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| ServerError::Internal)?;
        if !eligible {
            return Err(ServerError::Unauthorized);
        }
        let id = Uuid::new_v4();
        let created_at: String = sqlx::query_scalar(
            "INSERT INTO account_devices \
             (id, account_id, user_id, device_id, identity_public_key, display_name) \
             VALUES ($1, $2, $3, $4, $5, $6) RETURNING created_at::text",
        )
        .bind(id)
        .bind(account.account_id)
        .bind(&ceremony.device.user_id)
        .bind(&ceremony.device.device_id)
        .bind(ceremony.identity_key.as_bytes().as_slice())
        .bind(&ceremony.display_name)
        .fetch_one(&mut *transaction)
        .await
        .map_err(|error| {
            if is_unique_violation(&error) {
                ServerError::InvalidRequest
            } else {
                ServerError::Internal
            }
        })?;
        let result = sqlx::query(
            "UPDATE account_sessions SET device_id = $1 \
             WHERE token_hash = $2 AND account_id = $3 AND device_id IS NULL \
               AND revoked_at IS NULL AND expires_at > now()",
        )
        .bind(id)
        .bind(&account.session_hash)
        .bind(account.account_id)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ServerError::Internal)?;
        if result.rows_affected() != 1 {
            return Err(ServerError::Unauthorized);
        }
        transaction
            .commit()
            .await
            .map_err(|_| ServerError::Internal)?;
        Ok(FirstDeviceResponse {
            device: DeviceEntry {
                id,
                user_id: ceremony.device.user_id,
                device_id: ceremony.device.device_id,
                display_name: ceremony.display_name,
                created_at,
                current: true,
            },
        })
    }

    pub(crate) async fn start_link(
        &self,
        account: &AuthenticatedAccount,
        request: LinkStart,
    ) -> Result<LinkStartResponse, ServerError> {
        if account.device_id.is_some() {
            return Err(ServerError::Unauthorized);
        }
        request.device.validate()?;
        let display_name = validate_display_name(&request.display_name)?;
        let identity_key = IdentityPublicKey::from_bytes(request.identity_public_key);
        DeviceAuthChallenge::new(
            self.inner.server_id.clone(),
            request.device.user_id.clone(),
            request.device.device_id.clone(),
            identity_key,
            [0; 16],
            [0; 32],
        )
        .map_err(|_| ServerError::InvalidRequest)?;
        let mut transaction = self
            .inner
            .pool
            .begin()
            .await
            .map_err(|_| ServerError::Internal)?;
        let session_exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM account_sessions s \
             WHERE s.token_hash = $1 AND s.account_id = $2 AND s.device_id IS NULL \
               AND s.revoked_at IS NULL AND s.expires_at > now())",
        )
        .bind(&account.session_hash)
        .bind(account.account_id)
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| ServerError::Internal)?;
        if !session_exists {
            return Err(ServerError::Unauthorized);
        }
        let key_registered: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM account_devices WHERE identity_public_key = $1)",
        )
        .bind(identity_key.as_bytes().as_slice())
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| ServerError::Internal)?;
        if key_registered {
            return Err(ServerError::InvalidRequest);
        }
        let address_exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM account_devices \
             WHERE user_id = $1 AND device_id = $2)",
        )
        .bind(&request.device.user_id)
        .bind(&request.device.device_id)
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| ServerError::Internal)?;
        if address_exists {
            return Err(ServerError::InvalidRequest);
        }
        let request_id = Uuid::new_v4();
        let approval_token = opaque_token();
        let approval_hash = hash_token(&approval_token);
        sqlx::query(
            "INSERT INTO device_link_requests \
             (id, account_id, requester_session_hash, proposed_device_id, proposed_user_id, \
              proposed_route_device_id, proposed_identity_public_key, display_name, approval_hash, expires_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, \
                     now() + ($10::double precision * interval '1 second'))",
        )
        .bind(request_id)
        .bind(account.account_id)
        .bind(&account.session_hash)
        .bind(Uuid::new_v4())
        .bind(&request.device.user_id)
        .bind(&request.device.device_id)
        .bind(request.identity_public_key.as_slice())
        .bind(display_name)
        .bind(approval_hash)
        .bind(DEVICE_LINK_TTL.as_secs() as i64)
        .execute(&mut *transaction)
        .await
        .map_err(|error| {
            if is_unique_violation(&error) {
                ServerError::InvalidRequest
            } else {
                ServerError::Internal
            }
        })?;
        transaction
            .commit()
            .await
            .map_err(|_| ServerError::Internal)?;
        Ok(LinkStartResponse {
            request_id,
            approval_token,
            expires_in_seconds: DEVICE_LINK_TTL.as_secs(),
        })
    }

    pub(crate) async fn pending_links(
        &self,
        account: &AuthenticatedAccount,
    ) -> Result<Vec<LinkRequestEntry>, ServerError> {
        if account.device_id.is_none() {
            return Err(ServerError::Unauthorized);
        }
        let rows = sqlx::query(
            "SELECT id, proposed_user_id, proposed_route_device_id, display_name, \
                    created_at::text AS created_at \
             FROM device_link_requests WHERE account_id = $1 AND approved_by_device IS NULL \
               AND consumed_at IS NULL AND expires_at > now() ORDER BY created_at",
        )
        .bind(account.account_id)
        .fetch_all(&self.inner.pool)
        .await
        .map_err(|_| ServerError::Internal)?;
        rows.into_iter()
            .map(|row| {
                Ok(LinkRequestEntry {
                    request_id: row.try_get("id").map_err(|_| ServerError::Internal)?,
                    user_id: row
                        .try_get("proposed_user_id")
                        .map_err(|_| ServerError::Internal)?,
                    device_id: row
                        .try_get("proposed_route_device_id")
                        .map_err(|_| ServerError::Internal)?,
                    display_name: row
                        .try_get("display_name")
                        .map_err(|_| ServerError::Internal)?,
                    created_at: row
                        .try_get("created_at")
                        .map_err(|_| ServerError::Internal)?,
                })
            })
            .collect()
    }

    pub(crate) async fn approve_link(
        &self,
        account: &AuthenticatedAccount,
        request_id: Uuid,
    ) -> Result<(), ServerError> {
        let Some(approver_device) = account.device_id else {
            return Err(ServerError::Unauthorized);
        };
        let mut transaction = self
            .inner
            .pool
            .begin()
            .await
            .map_err(|_| ServerError::Internal)?;
        sqlx::query(
            "SELECT id FROM device_link_requests \
             WHERE id = $1 AND account_id = $2 AND approved_by_device IS NULL \
               AND consumed_at IS NULL AND expires_at > now() FOR UPDATE",
        )
        .bind(request_id)
        .bind(account.account_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| ServerError::Internal)?
        .ok_or(ServerError::InvalidRequest)?;
        sqlx::query(
            "SELECT id FROM account_devices WHERE id = $1 AND account_id = $2 \
             AND registration_status = 'active' AND revoked_at IS NULL FOR UPDATE",
        )
        .bind(approver_device)
        .bind(account.account_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| ServerError::Internal)?
        .ok_or(ServerError::Unauthorized)?;
        let session_is_active: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM account_sessions WHERE token_hash = $1 \
             AND account_id = $2 AND device_id = $3 AND revoked_at IS NULL AND expires_at > now())",
        )
        .bind(&account.session_hash)
        .bind(account.account_id)
        .bind(approver_device)
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| ServerError::Internal)?;
        if !session_is_active {
            return Err(ServerError::Unauthorized);
        }
        let result = sqlx::query(
            "UPDATE device_link_requests r SET approved_by_device = $1 \
             WHERE r.id = $2 AND r.account_id = $3 AND r.approved_by_device IS NULL \
               AND r.consumed_at IS NULL AND r.expires_at > now() \
               AND EXISTS (SELECT 1 FROM account_devices d WHERE d.id = $1 \
                 AND d.account_id = $3 AND d.registration_status = 'active' \
                 AND d.revoked_at IS NULL) \
               AND EXISTS (SELECT 1 FROM account_sessions s WHERE s.token_hash = $4 \
                 AND s.account_id = $3 AND s.device_id = $1 AND s.revoked_at IS NULL \
                 AND s.expires_at > now())",
        )
        .bind(approver_device)
        .bind(request_id)
        .bind(account.account_id)
        .bind(&account.session_hash)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ServerError::Internal)?;
        if result.rows_affected() != 1 {
            return Err(ServerError::InvalidRequest);
        }
        transaction
            .commit()
            .await
            .map_err(|_| ServerError::Internal)?;
        Ok(())
    }

    pub(crate) async fn complete_link(
        &self,
        account: &AuthenticatedAccount,
        request_id: Uuid,
        request: LinkComplete,
    ) -> Result<DeviceEntry, ServerError> {
        if request.approval_token.len() != 64
            || !request
                .approval_token
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(ServerError::Unauthorized);
        }
        let approval_hash = hash_token(&request.approval_token);
        let mut transaction = self
            .inner
            .pool
            .begin()
            .await
            .map_err(|_| ServerError::Internal)?;
        let row = sqlx::query(
            "SELECT proposed_device_id, proposed_user_id, proposed_route_device_id, \
                    proposed_identity_public_key, display_name, approved_by_device \
             FROM device_link_requests WHERE id = $1 AND account_id = $2 \
               AND requester_session_hash = $3 AND approved_by_device IS NOT NULL \
               AND approval_hash = $4 AND consumed_at IS NULL AND expires_at > now() \
               AND EXISTS (SELECT 1 FROM account_sessions s WHERE s.token_hash = $3 \
                 AND s.account_id = $2 AND s.revoked_at IS NULL AND s.expires_at > now()) \
             FOR UPDATE",
        )
        .bind(request_id)
        .bind(account.account_id)
        .bind(&account.session_hash)
        .bind(approval_hash)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| ServerError::Internal)?
        .ok_or(ServerError::Unauthorized)?;
        let id: Uuid = row
            .try_get("proposed_device_id")
            .map_err(|_| ServerError::Internal)?;
        let user_id: String = row
            .try_get("proposed_user_id")
            .map_err(|_| ServerError::Internal)?;
        let device_id: String = row
            .try_get("proposed_route_device_id")
            .map_err(|_| ServerError::Internal)?;
        let key: Vec<u8> = row
            .try_get("proposed_identity_public_key")
            .map_err(|_| ServerError::Internal)?;
        let display_name: String = row
            .try_get("display_name")
            .map_err(|_| ServerError::Internal)?;
        let approver_device: Uuid = row
            .try_get("approved_by_device")
            .map_err(|_| ServerError::Internal)?;
        let approver = sqlx::query(
            "SELECT id FROM account_devices \
             WHERE id = $1 AND account_id = $2 AND registration_status = 'active' \
               AND revoked_at IS NULL FOR UPDATE",
        )
        .bind(approver_device)
        .bind(account.account_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| ServerError::Internal)?
        .ok_or(ServerError::Unauthorized)?;
        drop(approver);
        let created: String = sqlx::query_scalar(
            "INSERT INTO account_devices \
             (id, account_id, user_id, device_id, identity_public_key, display_name) \
             VALUES ($1, $2, $3, $4, $5, $6) RETURNING created_at::text",
        )
        .bind(id)
        .bind(account.account_id)
        .bind(&user_id)
        .bind(&device_id)
        .bind(&key)
        .bind(&display_name)
        .fetch_one(&mut *transaction)
        .await
        .map_err(|error| {
            if is_unique_violation(&error) {
                ServerError::InvalidRequest
            } else {
                ServerError::Internal
            }
        })?;
        let result = sqlx::query(
            "UPDATE device_link_requests SET consumed_at = now() WHERE id = $1 AND consumed_at IS NULL",
        )
        .bind(request_id)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ServerError::Internal)?;
        if result.rows_affected() != 1 {
            return Err(ServerError::Unauthorized);
        }
        let result = sqlx::query(
            "UPDATE account_sessions SET device_id = $1 WHERE token_hash = $2 \
             AND account_id = $3 AND revoked_at IS NULL AND expires_at > now()",
        )
        .bind(id)
        .bind(&account.session_hash)
        .bind(account.account_id)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ServerError::Internal)?;
        if result.rows_affected() != 1 {
            return Err(ServerError::Unauthorized);
        }
        transaction
            .commit()
            .await
            .map_err(|_| ServerError::Internal)?;
        Ok(DeviceEntry {
            id,
            user_id,
            device_id,
            display_name,
            created_at: created,
            current: true,
        })
    }

    async fn load_passkeys(&self, account_id: Uuid) -> Result<Vec<Passkey>, ServerError> {
        let rows = sqlx::query("SELECT credential FROM account_passkeys WHERE account_id = $1")
            .bind(account_id)
            .fetch_all(&self.inner.pool)
            .await
            .map_err(|_| ServerError::Internal)?;
        rows.into_iter()
            .map(|row| {
                let credential: Value = row
                    .try_get("credential")
                    .map_err(|_| ServerError::Internal)?;
                serde_json::from_value(credential).map_err(|_| ServerError::Internal)
            })
            .collect()
    }

    async fn add_registration(
        &self,
        ceremony_id: Uuid,
        ceremony: RegistrationCeremony,
    ) -> Result<(), ServerError> {
        let mut registrations = self.inner.registrations.lock().await;
        prune_expired(&mut registrations);
        if registrations.len() >= MAX_PENDING_CEREMONIES {
            return Err(ServerError::ResourceLimit);
        }
        registrations.insert(ceremony_id, ceremony);
        Ok(())
    }

    async fn take_registration(
        &self,
        ceremony_id: Uuid,
    ) -> Result<RegistrationCeremony, ServerError> {
        self.inner
            .registrations
            .lock()
            .await
            .remove(&ceremony_id)
            .filter(|ceremony| ceremony.expires_at > Instant::now())
            .ok_or(ServerError::Unauthorized)
    }

    async fn take_authentication(
        &self,
        ceremony_id: Uuid,
    ) -> Result<AuthenticationCeremony, ServerError> {
        self.inner
            .authentications
            .lock()
            .await
            .remove(&ceremony_id)
            .filter(|ceremony| ceremony.expires_at > Instant::now())
            .ok_or(ServerError::Unauthorized)
    }

    async fn send_verification_email(
        &self,
        to: &str,
        verification_url: &str,
    ) -> Result<(), ServerError> {
        let api_key = self
            .inner
            .resend_api_key
            .as_deref()
            .ok_or(ServerError::Unavailable)?;
        let from_email = self
            .inner
            .resend_from_email
            .as_deref()
            .ok_or(ServerError::Unavailable)?;
        let response = self
            .inner
            .http
            .post("https://api.resend.com/emails")
            .bearer_auth(api_key)
            .json(&serde_json::json!({
                "from": from_email,
                "to": [to],
                "subject": "Verify your Void account email",
                "html": format!(
                    "<p>Verify your Void account email:</p><p><a href=\"{}\">Verify email</a></p>",
                    html_escape(verification_url)
                )
            }))
            .send()
            .await
            .map_err(|_| ServerError::Internal)?;
        if !response.status().is_success() {
            return Err(ServerError::Internal);
        }
        Ok(())
    }
}

fn validate_tag(tag: &str) -> Result<String, ServerError> {
    const RESERVED: &[&str] = &[
        "abuse",
        "account",
        "accounts",
        "admin",
        "administrator",
        "api",
        "assets",
        "billing",
        "bot",
        "contact",
        "docs",
        "email",
        "help",
        "info",
        "login",
        "logout",
        "mail",
        "moderator",
        "no_reply",
        "noreply",
        "null",
        "official",
        "postmaster",
        "relay",
        "root",
        "security",
        "signin",
        "signup",
        "staff",
        "static",
        "status",
        "support",
        "system",
        "team",
        "undefined",
        "verify",
        "void",
        "webmaster",
    ];
    if !(3..=24).contains(&tag.len())
        || !tag.is_ascii()
        || !tag
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        || RESERVED.contains(&tag.to_ascii_lowercase().as_str())
    {
        return Err(ServerError::InvalidRequest);
    }
    Ok(tag.to_owned())
}

fn normalize_tag(tag: &str) -> String {
    tag.to_ascii_lowercase()
}

fn validate_profile_update(
    request: AccountProfileUpdate,
) -> Result<ValidatedProfileUpdate, ServerError> {
    if request.tag.is_none() && request.email.is_none() {
        return Err(ServerError::InvalidRequest);
    }
    let tag = request.tag.map(|tag| validate_tag(&tag)).transpose()?;
    let email = request
        .email
        .map(|email| {
            let email = validate_email(&email)?;
            let normalized = email.to_ascii_lowercase();
            Ok((email, normalized))
        })
        .transpose()?;
    Ok(ValidatedProfileUpdate { tag, email })
}

fn validate_email(email: &str) -> Result<String, ServerError> {
    if email.len() > 320
        || !email.is_ascii()
        || email.chars().any(char::is_whitespace)
        || email.matches('@').count() != 1
    {
        return Err(ServerError::InvalidRequest);
    }
    let Some((local, domain)) = email.split_once('@') else {
        return Err(ServerError::InvalidRequest);
    };
    if local.is_empty()
        || local.len() > 64
        || domain.is_empty()
        || !domain.contains('.')
        || domain.starts_with('.')
        || domain.ends_with('.')
    {
        return Err(ServerError::InvalidRequest);
    }
    Ok(email.to_owned())
}

fn validate_display_name(name: &str) -> Result<String, ServerError> {
    let trimmed = name.trim();
    if trimmed.is_empty() || trimmed.len() > 80 || trimmed.chars().any(char::is_control) {
        return Err(ServerError::InvalidRequest);
    }
    Ok(trimmed.to_owned())
}

fn validate_browser_state(state: &str) -> Result<(), ServerError> {
    decode_browser_secret(state).map(|_| ())
}

fn code_challenge_for_verifier(verifier: &str) -> Result<Vec<u8>, ServerError> {
    let verifier = decode_browser_secret(verifier)?;
    Ok(Sha256::digest(verifier).to_vec())
}

fn validate_code_challenge(challenge: &str) -> Result<Vec<u8>, ServerError> {
    decode_browser_secret(challenge)
}

fn decode_browser_secret(encoded: &str) -> Result<Vec<u8>, ServerError> {
    let decoded = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| ServerError::InvalidRequest)?;
    if decoded.len() != 32 || URL_SAFE_NO_PAD.encode(&decoded) != encoded {
        return Err(ServerError::InvalidRequest);
    }
    Ok(decoded)
}

fn validate_loopback_callback(callback_uri: &str) -> Result<String, ServerError> {
    let callback = Url::parse(callback_uri).map_err(|_| ServerError::InvalidRequest)?;
    if callback.scheme() != "http"
        || !callback.username().is_empty()
        || callback.password().is_some()
        || callback.port().map_or(true, |port| port == 0)
        || callback.query().is_some()
        || callback.fragment().is_some()
        || callback.host_str().is_none()
    {
        return Err(ServerError::InvalidRequest);
    }
    let loopback = callback
        .host_str()
        .and_then(|host| {
            let host = host
                .strip_prefix('[')
                .and_then(|host| host.strip_suffix(']'))
                .unwrap_or(host);
            host.parse::<IpAddr>().ok()
        })
        .is_some_and(|address| address.is_loopback());
    if !loopback {
        return Err(ServerError::InvalidRequest);
    }
    Ok(callback.to_string())
}

fn make_callback_uri(callback_uri: &str, code: &str, state: &str) -> Result<String, ServerError> {
    let mut callback = Url::parse(callback_uri).map_err(|_| ServerError::Internal)?;
    callback
        .query_pairs_mut()
        .append_pair("code", code)
        .append_pair("state", state);
    Ok(callback.to_string())
}

fn required_env(name: &'static str) -> Result<String, ServerError> {
    match env::var(name) {
        Ok(value) if !value.trim().is_empty() => Ok(value),
        Ok(_) | Err(env::VarError::NotPresent | env::VarError::NotUnicode(_)) => {
            Err(ServerError::InvalidConfiguration(name))
        }
    }
}

fn optional_env(name: &'static str) -> Result<Option<String>, ServerError> {
    match env::var(name) {
        Ok(value) if !value.trim().is_empty() => Ok(Some(value)),
        Ok(_) => Err(ServerError::InvalidConfiguration(name)),
        Err(env::VarError::NotPresent) => Ok(None),
        Err(env::VarError::NotUnicode(_)) => Err(ServerError::InvalidConfiguration(name)),
    }
}

fn env_u32(name: &'static str, default: u32) -> Result<u32, ServerError> {
    match env::var(name) {
        Ok(value) => value
            .parse::<u32>()
            .ok()
            .filter(|value| *value > 0)
            .ok_or(ServerError::InvalidConfiguration(name)),
        Err(env::VarError::NotPresent) => Ok(default),
        Err(env::VarError::NotUnicode(_)) => Err(ServerError::InvalidConfiguration(name)),
    }
}

fn opaque_token() -> String {
    let mut bytes = [0u8; 32];
    bytes[..16].copy_from_slice(Uuid::new_v4().as_bytes());
    bytes[16..].copy_from_slice(Uuid::new_v4().as_bytes());
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut token = String::with_capacity(64);
    for byte in bytes {
        token.push(HEX[(byte >> 4) as usize] as char);
        token.push(HEX[(byte & 0x0f) as usize] as char);
    }
    token
}

fn hash_token(token: &str) -> Vec<u8> {
    Sha256::digest(token.as_bytes()).to_vec()
}

fn is_unique_violation(error: &sqlx::Error) -> bool {
    error
        .as_database_error()
        .is_some_and(|database| database.code().as_deref() == Some("23505"))
}

fn html_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn prune_expired<T>(ceremonies: &mut HashMap<Uuid, T>)
where
    T: HasExpiry,
{
    let now = Instant::now();
    ceremonies.retain(|_, ceremony| ceremony.expires_at() > now);
}

trait HasExpiry {
    fn expires_at(&self) -> Instant;
}

impl HasExpiry for RegistrationCeremony {
    fn expires_at(&self) -> Instant {
        self.expires_at
    }
}

impl HasExpiry for AuthenticationCeremony {
    fn expires_at(&self) -> Instant {
        self.expires_at
    }
}

impl HasExpiry for DeviceChallenge {
    fn expires_at(&self) -> Instant {
        self.expires_at
    }
}

impl HasExpiry for FirstDeviceChallenge {
    fn expires_at(&self) -> Instant {
        self.expires_at
    }
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;

    use super::{
        hash_token, normalize_tag, validate_email, validate_profile_update, validate_tag,
        AccountDirectory, AccountProfileUpdate, AuthenticatedAccount, FirstDeviceFinish,
        FirstDeviceStart, LinkComplete, LinkStart, SignupRequest, MAX_SIGNUPS_PER_MINUTE,
    };
    use crate::{DeviceAddress, OpaqueEnvelope};
    use aether_crypto::Identity;
    use uuid::Uuid;

    async fn insert_test_account(directory: &AccountDirectory) -> (AuthenticatedAccount, String) {
        let account_id = Uuid::new_v4();
        let suffix = account_id.simple().to_string();
        sqlx::query(
            "INSERT INTO accounts \
             (id, tag, tag_normalized, email, email_normalized, email_verified_at) \
             VALUES ($1, $2, $2, $3, $3, now())",
        )
        .bind(account_id)
        .bind(format!("t{}", &suffix[..10]))
        .bind(format!("{suffix}@example.invalid"))
        .execute(&directory.inner.pool)
        .await
        .expect("insert test account");
        insert_unbound_test_session(directory, account_id).await
    }

    async fn insert_unbound_test_session(
        directory: &AccountDirectory,
        account_id: Uuid,
    ) -> (AuthenticatedAccount, String) {
        let token = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
        let session_hash = hash_token(&token);
        sqlx::query(
            "INSERT INTO account_sessions (token_hash, account_id, expires_at) \
             VALUES ($1, $2, now() + interval '1 day')",
        )
        .bind(&session_hash)
        .bind(account_id)
        .execute(&directory.inner.pool)
        .await
        .expect("insert test session");
        (
            AuthenticatedAccount {
                account_id,
                session_hash,
                device_id: None,
            },
            token,
        )
    }

    #[test]
    fn account_tags_are_validated_case_insensitively_and_reserved_names_rejected() {
        assert_eq!(validate_tag("Good_Name").unwrap(), "Good_Name");
        assert!(validate_tag("ad").is_err());
        assert!(validate_tag("ADMIN").is_err());
        assert!(validate_tag("contains-space").is_err());
        assert!(validate_tag("éclair").is_err());
    }

    #[test]
    fn email_addresses_are_bounded_and_normalization_is_separate() {
        assert_eq!(
            validate_email("User@example.com").unwrap(),
            "User@example.com"
        );
        assert!(validate_email("not-an-email").is_err());
        assert!(validate_email("x @example.com").is_err());
        assert!(validate_email(&format!("{}@example.com", "x".repeat(65))).is_err());
    }

    #[test]
    fn profile_updates_validate_only_public_fields_and_normalize_uniqueness_keys() {
        let update = validate_profile_update(AccountProfileUpdate {
            tag: Some("New_Tag".to_owned()),
            email: Some("New.User@example.com".to_owned()),
        })
        .unwrap();
        assert_eq!(update.tag.as_deref(), Some("New_Tag"));
        assert_eq!(normalize_tag(update.tag.as_deref().unwrap()), "new_tag");
        assert_eq!(
            update.email,
            Some((
                "New.User@example.com".to_owned(),
                "new.user@example.com".to_owned()
            ))
        );
        assert!(validate_profile_update(AccountProfileUpdate {
            tag: None,
            email: None,
        })
        .is_err());
        assert!(validate_profile_update(AccountProfileUpdate {
            tag: Some("ADMIN".to_owned()),
            email: None,
        })
        .is_err());
        assert!(validate_profile_update(AccountProfileUpdate {
            tag: None,
            email: Some("invalid".to_owned()),
        })
        .is_err());

        let parsed: Result<AccountProfileUpdate, _> = serde_json::from_str(
            r#"{"tag":"Changed","account_id":"00000000-0000-0000-0000-000000000000","device_id":"device"}"#,
        );
        assert!(parsed.is_err());
    }

    #[test]
    fn session_tokens_are_stored_as_one_way_hashes() {
        assert_ne!(hash_token("secret-token"), b"secret-token");
        assert_eq!(hash_token("secret-token"), hash_token("secret-token"));
    }

    #[test]
    fn browser_handoff_requires_literal_loopback_port_and_256_bit_state() {
        use super::{
            code_challenge_for_verifier, validate_browser_state, validate_code_challenge,
            validate_loopback_callback, URL_SAFE_NO_PAD,
        };
        use sha2::{Digest, Sha256};

        assert!(validate_loopback_callback("http://127.0.0.1:49152/void/callback").is_ok());
        assert!(validate_loopback_callback("http://[::1]:49152/callback").is_ok());
        assert!(validate_loopback_callback("http://localhost:49152/callback").is_err());
        assert!(validate_loopback_callback("http://192.168.1.4:49152/callback").is_err());
        assert!(validate_loopback_callback("https://127.0.0.1:49152/callback").is_err());
        assert!(validate_loopback_callback("http://127.0.0.1/callback").is_err());
        assert!(validate_loopback_callback("http://127.0.0.1:0/callback").is_err());
        assert!(validate_loopback_callback("http://127.0.0.1:49152/callback?x=1").is_err());
        assert!(validate_loopback_callback("http://user@127.0.0.1:49152/callback").is_err());
        let state = URL_SAFE_NO_PAD.encode([19u8; 32]);
        assert!(validate_browser_state(&state).is_ok());
        assert_eq!(validate_code_challenge(&state).unwrap(), [19u8; 32]);
        let verifier = URL_SAFE_NO_PAD.encode([27u8; 32]);
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest([27u8; 32]));
        assert_eq!(
            validate_code_challenge(&challenge).unwrap(),
            code_challenge_for_verifier(&verifier).unwrap()
        );
        assert_ne!(
            code_challenge_for_verifier(&URL_SAFE_NO_PAD.encode([28u8; 32])).unwrap(),
            validate_code_challenge(&challenge).unwrap()
        );
        assert!(validate_browser_state("predictable").is_err());
        assert!(code_challenge_for_verifier("predictable").is_err());
        assert!(validate_code_challenge("predictable").is_err());
        assert!(validate_browser_state("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").is_err());
    }

    #[test]
    fn callback_handoff_appends_only_exchange_code_and_state() {
        use super::make_callback_uri;

        let result = make_callback_uri(
            "http://127.0.0.1:49152/void/callback",
            "opaque-code",
            "state_123",
        )
        .unwrap();
        assert_eq!(
            result,
            "http://127.0.0.1:49152/void/callback?code=opaque-code&state=state_123"
        );
    }

    #[tokio::test]
    async fn account_migrations_run_when_a_test_database_is_configured() {
        let Ok(database_url) = std::env::var("TEST_DATABASE_URL") else {
            return;
        };
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect(&database_url)
            .await
            .expect("TEST_DATABASE_URL must be reachable");
        sqlx::migrate!("./migrations")
            .run(&pool)
            .await
            .expect("account migrations must apply to TEST_DATABASE_URL");
        let identity_key_index: String = sqlx::query_scalar(
            "SELECT indexdef FROM pg_indexes \
             WHERE schemaname = current_schema() AND tablename = 'account_devices' \
               AND indexname = 'account_devices_identity_key_idx'",
        )
        .fetch_one(&pool)
        .await
        .expect("global identity key unique index must exist");
        assert!(identity_key_index.contains("UNIQUE INDEX"));
        assert!(identity_key_index.contains("(identity_public_key)"));
        assert!(!identity_key_index.contains("(account_id, identity_public_key)"));
        let registration_status_column: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM information_schema.columns \
             WHERE table_schema = current_schema() AND table_name = 'account_devices' \
               AND column_name = 'registration_status' AND is_nullable = 'NO')",
        )
        .fetch_one(&pool)
        .await
        .expect("device registration status column must exist");
        assert!(registration_status_column);
        let signup_rate_limit_table: bool = sqlx::query_scalar(
            "SELECT to_regclass(format('%I.%I', current_schema(), 'account_signup_rate_limits')) IS NOT NULL",
        )
        .fetch_one(&pool)
        .await
        .expect("signup rate-limit table must exist");
        assert!(signup_rate_limit_table);
        for table in [
            "relay_messages",
            "relay_message_hides",
            "relay_message_read_receipts",
            "relay_typing_states",
        ] {
            let exists: bool = sqlx::query_scalar(
                "SELECT to_regclass(format('%I.%I', current_schema(), $1)) IS NOT NULL",
            )
            .bind(table)
            .fetch_one(&pool)
            .await
            .expect("persistent DM history table must exist");
            assert!(exists, "missing table {table}");
        }
        let persisted_payload_column: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM information_schema.columns \
             WHERE table_schema = current_schema() AND table_name = 'relay_messages' \
               AND column_name = 'payload' AND udt_name = 'bytea')",
        )
        .fetch_one(&pool)
        .await
        .expect("ciphertext payload storage must be binary");
        assert!(persisted_payload_column);
        pool.close().await;
    }

    #[tokio::test]
    async fn postgres_dm_history_preserves_ciphertext_and_enforces_message_access() {
        let Ok(database_url) = std::env::var("TEST_DATABASE_URL") else {
            eprintln!("skipping PostgreSQL DM history test: TEST_DATABASE_URL is unset");
            return;
        };
        let schema = format!("dm_history_test_{}", Uuid::new_v4().simple());
        let admin_pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect(&database_url)
            .await
            .expect("TEST_DATABASE_URL must be reachable");
        sqlx::query(&format!("CREATE SCHEMA {schema}"))
            .execute(&admin_pool)
            .await
            .expect("create isolated DM history schema");
        let directory = AccountDirectory::test_directory(&database_url, "dm-history-test", &schema)
            .await
            .expect("DM history test directory connects");
        let alice = DeviceAddress::new("alice", "desktop").unwrap();
        let bob = DeviceAddress::new("bob", "phone").unwrap();
        let mallory = DeviceAddress::new("mallory", "laptop").unwrap();
        let alice_identity = Identity::from_secret_bytes(&[31; 32]).unwrap();
        let bob_identity = Identity::from_secret_bytes(&[32; 32]).unwrap();
        let mallory_identity = Identity::from_secret_bytes(&[33; 32]).unwrap();
        directory
            .insert_test_device(
                &alice,
                aether_crypto::IdentityPublicKey::from_bytes(
                    *alice_identity.public_key().as_bytes(),
                ),
            )
            .await
            .expect("insert sender device");
        directory
            .insert_test_device(
                &bob,
                aether_crypto::IdentityPublicKey::from_bytes(*bob_identity.public_key().as_bytes()),
            )
            .await
            .expect("insert recipient device");
        directory
            .insert_test_device(
                &mallory,
                aether_crypto::IdentityPublicKey::from_bytes(
                    *mallory_identity.public_key().as_bytes(),
                ),
            )
            .await
            .expect("insert unrelated device");
        let instance_id = Uuid::new_v4();
        sqlx::query("INSERT INTO relay_instances (instance_id) VALUES ($1)")
            .bind(instance_id)
            .execute(&directory.inner.pool)
            .await
            .expect("register relay instance");

        let original_id = Uuid::new_v4();
        let original_payload = vec![0, 255, 14, 0, 42];
        let original = OpaqueEnvelope {
            message_id: original_id,
            sender: alice.clone(),
            recipient: bob.clone(),
            payload: original_payload.clone(),
        };
        directory
            .persist_relay_message(instance_id, &original)
            .await
            .expect("persist opaque envelope");
        let (recipient_history, has_more) = directory
            .relay_history(instance_id, &bob, &alice, None, 50)
            .await
            .expect("authorized recipient can read history");
        assert!(!has_more);
        assert_eq!(recipient_history.len(), 1);
        assert_eq!(recipient_history[0].envelope.payload, original_payload);
        assert!(!recipient_history[0].deleted);
        let (unrelated_history, _) = directory
            .relay_history(instance_id, &mallory, &alice, None, 50)
            .await
            .expect("unrelated authenticated participant can query only its pair");
        assert!(unrelated_history.is_empty());

        let (receipt_sender, _) = directory
            .record_read_receipt(instance_id, &bob, original_id)
            .await
            .expect("recipient can record a read receipt");
        assert_eq!(receipt_sender, alice);
        let (sender_history, _) = directory
            .relay_history(instance_id, &alice, &bob, None, 50)
            .await
            .expect("sender can read history");
        assert!(sender_history[0].read_at.is_some());

        let second_instance = Uuid::new_v4();
        sqlx::query("INSERT INTO relay_instances (instance_id) VALUES ($1)")
            .bind(second_instance)
            .execute(&directory.inner.pool)
            .await
            .expect("register second relay instance");
        directory
            .record_typing_state(instance_id, &alice, &bob, true)
            .await
            .expect("active sender can record expiring typing state");
        let remote_typing = directory
            .active_typing_states(second_instance, std::slice::from_ref(&bob))
            .await
            .expect("other relay instance can read typing state for its connected device");
        assert_eq!(remote_typing.len(), 1);
        assert_eq!(remote_typing[0].sender, alice);
        assert_eq!(remote_typing[0].recipient, bob);
        assert!(remote_typing[0].is_typing);
        let unknown = DeviceAddress::new("unregistered", "desktop").unwrap();
        assert!(directory
            .record_typing_state(instance_id, &alice, &unknown, true)
            .await
            .is_err());
        let unrelated_typing = directory
            .active_typing_states(second_instance, std::slice::from_ref(&bob))
            .await
            .expect("connected recipient sees only its own typing states");
        assert_eq!(unrelated_typing.len(), 1);
        directory
            .record_typing_state(instance_id, &alice, &bob, false)
            .await
            .expect("active sender can clear typing state");
        let stopped_typing = directory
            .active_typing_states(second_instance, std::slice::from_ref(&bob))
            .await
            .expect("typing stop is visible across relay instances");
        assert_eq!(stopped_typing.len(), 1);
        assert!(!stopped_typing[0].is_typing);
        let first_claim = directory
            .claim_pending_relay_messages(instance_id, &bob, 1)
            .await
            .expect("first instance claims the pending envelope");
        assert_eq!(first_claim.len(), 1);
        assert_eq!(first_claim[0].message_id, original_id);
        assert_eq!(first_claim[0].payload, original_payload);
        assert!(directory
            .claim_pending_relay_messages(second_instance, &bob, 1)
            .await
            .expect("other instance observes the active lease")
            .is_empty());
        directory
            .release_relay_delivery_leases(instance_id, Some(&bob))
            .await
            .expect("simulated instance loss releases its lease");
        let retry = directory
            .claim_pending_relay_messages(second_instance, &bob, 1)
            .await
            .expect("another instance retries after lease release");
        assert_eq!(retry[0].message_id, original_id);
        assert!(directory
            .acknowledge_relay_message(instance_id, &bob, original_id)
            .await
            .is_err());
        directory
            .acknowledge_relay_message(second_instance, &bob, original_id)
            .await
            .expect("current lease holder accepts recipient acknowledgement");
        directory
            .acknowledge_relay_message(second_instance, &bob, original_id)
            .await
            .expect("duplicate acknowledgement is idempotent");
        assert!(directory
            .claim_pending_relay_messages(second_instance, &bob, 1)
            .await
            .expect("acknowledged message is not redelivered")
            .is_empty());

        directory
            .hide_relay_message(instance_id, &bob, original_id)
            .await
            .expect("participant can hide a message for their account");
        let (recipient_history, _) = directory
            .relay_history(instance_id, &bob, &alice, None, 50)
            .await
            .expect("recipient can re-read history");
        assert_eq!(recipient_history.len(), 1);
        assert!(recipient_history[0].hidden);
        let (sender_history, _) = directory
            .relay_history(instance_id, &alice, &bob, None, 50)
            .await
            .expect("hide is scoped to the recipient account");
        assert_eq!(sender_history.len(), 1);
        assert!(!sender_history[0].hidden);

        let deleted_id = Uuid::new_v4();
        let deletable = OpaqueEnvelope {
            message_id: deleted_id,
            sender: alice.clone(),
            recipient: bob.clone(),
            payload: vec![4, 3, 2, 1],
        };
        directory
            .persist_relay_message(instance_id, &deletable)
            .await
            .expect("persist second opaque envelope");
        assert!(directory
            .redact_relay_message(instance_id, &bob, deleted_id)
            .await
            .is_err());
        assert_eq!(
            directory
                .redact_relay_message(instance_id, &alice, deleted_id)
                .await
                .expect("only the sender can delete for everyone"),
            bob
        );
        let (recipient_history, _) = directory
            .relay_history(instance_id, &bob, &alice, None, 50)
            .await
            .expect("recipient can query deleted history");
        let deleted = recipient_history
            .iter()
            .find(|message| message.envelope.message_id == deleted_id)
            .expect("deleted message remains as a tombstone");
        assert!(deleted.deleted);
        assert!(deleted.envelope.payload.is_empty());

        directory.close_test_pool().await;
        sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
            .execute(&admin_pool)
            .await
            .expect("drop isolated DM history schema");
        admin_pool.close().await;
    }

    #[tokio::test]
    async fn postgres_signup_rate_limit_is_shared_across_directories() {
        let Ok(database_url) = std::env::var("TEST_DATABASE_URL") else {
            eprintln!("skipping PostgreSQL signup-rate-limit test: TEST_DATABASE_URL is unset");
            return;
        };
        let schema = format!("signup_limit_test_{}", Uuid::new_v4().simple());
        let admin_pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect(&database_url)
            .await
            .expect("TEST_DATABASE_URL must be reachable");
        sqlx::query(&format!("CREATE SCHEMA {schema}"))
            .execute(&admin_pool)
            .await
            .expect("create isolated signup rate-limit schema");
        let first = AccountDirectory::test_directory(&database_url, "signup-limit", &schema)
            .await
            .expect("first PostgreSQL directory connects");
        let second = AccountDirectory::test_directory(&database_url, "signup-limit", &schema)
            .await
            .expect("second PostgreSQL directory connects");
        for attempt in 0..MAX_SIGNUPS_PER_MINUTE {
            let directory = if attempt % 2 == 0 { &first } else { &second };
            directory
                .signup(SignupRequest {
                    tag: format!("signup_{attempt}"),
                    email: format!("signup_{attempt}@example.invalid"),
                })
                .await
                .expect("signup rate budget is shared across server directories");
        }
        assert!(matches!(
            second
                .signup(SignupRequest {
                    tag: "signup_over_limit".to_owned(),
                    email: "signup_over_limit@example.invalid".to_owned(),
                })
                .await,
            Err(crate::ServerError::ResourceLimit)
        ));
        first.close_test_pool().await;
        second.close_test_pool().await;
        sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
            .execute(&admin_pool)
            .await
            .expect("drop isolated signup rate-limit schema");
        admin_pool.close().await;
    }

    #[tokio::test]
    async fn postgres_device_enrollment_approval_and_persistence() {
        let Ok(database_url) = std::env::var("TEST_DATABASE_URL") else {
            eprintln!("skipping PostgreSQL device enrollment test: TEST_DATABASE_URL is unset");
            return;
        };
        let schema = format!("registration_test_{}", Uuid::new_v4().simple());
        let admin_pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect(&database_url)
            .await
            .expect("TEST_DATABASE_URL must be reachable");
        sqlx::query(&format!("CREATE SCHEMA {schema}"))
            .execute(&admin_pool)
            .await
            .expect("create isolated registration schema");

        let directory =
            AccountDirectory::test_directory(&database_url, "registration-test", &schema)
                .await
                .expect("test PostgreSQL database is reachable and migrations apply");
        let (bootstrap_session, bootstrap_token) = insert_test_account(&directory).await;
        let device = DeviceAddress::new("registered_user", "desktop").unwrap();
        let identity = Identity::from_secret_bytes(&[91; 32]).unwrap();
        let unauthenticated = AuthenticatedAccount {
            account_id: bootstrap_session.account_id,
            session_hash: vec![0; 32],
            device_id: None,
        };
        assert!(directory
            .start_first_device(
                &unauthenticated,
                FirstDeviceStart {
                    device: device.clone(),
                    identity_public_key: *identity.public_key().as_bytes(),
                    display_name: "Desktop".to_owned(),
                },
            )
            .await
            .is_err());
        let first = directory
            .start_first_device(
                &bootstrap_session,
                FirstDeviceStart {
                    device: device.clone(),
                    identity_public_key: *identity.public_key().as_bytes(),
                    display_name: "Desktop".to_owned(),
                },
            )
            .await
            .expect("authenticated account may start first-device enrollment");
        let proof = identity
            .sign_device_auth_challenge(&first.challenge)
            .expect("first device signs its challenge");
        let enrolled = directory
            .finish_first_device(
                &bootstrap_session,
                FirstDeviceFinish {
                    challenge_id: first.challenge_id,
                    proof,
                },
            )
            .await
            .expect("valid device proof registers first device");
        assert!(directory
            .finish_first_device(
                &bootstrap_session,
                FirstDeviceFinish {
                    challenge_id: first.challenge_id,
                    proof: identity
                        .sign_device_auth_challenge(&first.challenge)
                        .expect("replay proof can be constructed"),
                },
            )
            .await
            .is_err());

        let bound_session = directory
            .authenticate(&bootstrap_token)
            .await
            .expect("first-device registration binds the session");
        assert_eq!(bound_session.device_id, Some(enrolled.device.id));

        let (link_session, _) =
            insert_unbound_test_session(&directory, bootstrap_session.account_id).await;
        let additional_device = DeviceAddress::new("registered_user", "phone").unwrap();
        let additional_identity = Identity::from_secret_bytes(&[92; 32]).unwrap();
        let link = directory
            .start_link(
                &link_session,
                LinkStart {
                    device: additional_device.clone(),
                    identity_public_key: *additional_identity.public_key().as_bytes(),
                    display_name: "Phone".to_owned(),
                },
            )
            .await
            .expect("unbound authenticated session may request another device");
        assert_eq!(
            directory.pending_links(&bound_session).await.unwrap().len(),
            1
        );
        directory
            .approve_link(&bound_session, link.request_id)
            .await
            .expect("existing registered device approves exact request");
        assert!(directory
            .approve_link(&bound_session, link.request_id)
            .await
            .is_err());
        let linked = directory
            .complete_link(
                &link_session,
                link.request_id,
                LinkComplete {
                    approval_token: link.approval_token,
                },
            )
            .await
            .expect("requesting session consumes its approved token");
        assert_eq!(linked.user_id, additional_device.user_id);
        assert_eq!(linked.device_id, additional_device.device_id);

        let second_directory =
            AccountDirectory::test_directory(&database_url, "registration-test", &schema)
                .await
                .expect("second directory instance connects to same database");
        let persisted_count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM account_devices \
             WHERE account_id = $1 AND registration_status = 'active' AND revoked_at IS NULL",
        )
        .bind(bootstrap_session.account_id)
        .fetch_one(&second_directory.inner.pool)
        .await
        .expect("registered devices persist in PostgreSQL");
        assert_eq!(persisted_count, 2);
        assert_eq!(
            second_directory
                .devices(&bound_session)
                .await
                .expect("second directory lists persisted devices")
                .len(),
            2
        );
        let instance_id = Uuid::new_v4();
        second_directory
            .register_relay_instance(instance_id)
            .await
            .expect("second instance registers against shared database");
        second_directory
            .authorize_for_instance(identity.public_key(), &device, instance_id)
            .await
            .expect("newly enrolled device is authorized from another directory");
        let (revoked_address, event_id) = directory
            .revoke_device(&bound_session, enrolled.device.id)
            .await
            .expect("authenticated account revokes registered device");
        assert_eq!(revoked_address, device);
        let pending = second_directory
            .pending_revocations(instance_id)
            .await
            .expect("other instance recovers durable revocation");
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].event_id, event_id);
        second_directory
            .acknowledge_revocation(instance_id, event_id)
            .await
            .expect("instance acknowledges revocation");
        directory
            .wait_for_revocation(event_id)
            .await
            .expect("revocation completes after instance acknowledgment");
        assert!(second_directory
            .authorize_for_instance(identity.public_key(), &device, instance_id)
            .await
            .is_err());
        let registration_status: String =
            sqlx::query_scalar("SELECT registration_status FROM account_devices WHERE id = $1")
                .bind(enrolled.device.id)
                .fetch_one(&second_directory.inner.pool)
                .await
                .expect("revocation status persists");
        assert_eq!(registration_status, "revoked");
        second_directory
            .fence_relay_instance(instance_id)
            .await
            .expect("test instance is fenced");
        assert!(second_directory
            .start_first_device(
                &bootstrap_session,
                FirstDeviceStart {
                    device: DeviceAddress::new("other_alias", "other_device").unwrap(),
                    identity_public_key: *identity.public_key().as_bytes(),
                    display_name: "Key reuse".to_owned(),
                },
            )
            .await
            .is_err());

        directory.close_test_pool().await;
        second_directory.close_test_pool().await;
        sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
            .execute(&admin_pool)
            .await
            .expect("drop isolated registration schema");
        admin_pool.close().await;
    }
}
