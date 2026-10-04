use std::{
    collections::HashMap,
    env,
    net::IpAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use aether_crypto::{DeviceAuthChallenge, DeviceAuthProof, IdentityPublicKey};
use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::{postgres::PgPoolOptions, PgPool, Row};
use tokio::sync::Mutex;
use uuid::Uuid;
use webauthn_rs::prelude::{
    CreationChallengeResponse, Passkey, PasskeyAuthentication, PasskeyRegistration,
    PublicKeyCredential, RegisterPublicKeyCredential, RequestChallengeResponse, Url, Webauthn,
    WebauthnBuilder,
};

use crate::{DeviceAddress, DeviceAuthorizer, ServerError};

const EMAIL_TOKEN_TTL: Duration = Duration::from_secs(60 * 60 * 24);
const PASSKEY_CEREMONY_TTL: Duration = Duration::from_secs(5 * 60);
const SESSION_TTL: Duration = Duration::from_secs(60 * 60 * 24 * 30);
const DEVICE_LINK_TTL: Duration = Duration::from_secs(60 * 60);
const MAX_PENDING_CEREMONIES: usize = 10_000;

#[derive(Clone)]
pub(crate) struct AccountDirectory {
    inner: Arc<DirectoryInner>,
}

struct DirectoryInner {
    pool: PgPool,
    webauthn: Webauthn,
    server_id: String,
    webauthn_origin: String,
    public_url: String,
    resend_api_key: String,
    resend_from_email: String,
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
        let public_url = required_env("AETHER_PUBLIC_URL")?;
        let public_origin = Url::parse(&public_url)
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
        let resend_api_key = required_env("RESEND_API_KEY")?;
        let resend_from_email = required_env("RESEND_FROM_EMAIL")?;
        let database_max_connections = env_u32("AETHER_DATABASE_MAX_CONNECTIONS", 20)?;
        let database_connect_timeout_secs = env_u32("AETHER_DATABASE_CONNECT_TIMEOUT_SECS", 10)?;
        validate_email(&resend_from_email).map_err(|_| {
            ServerError::InvalidConfiguration("RESEND_FROM_EMAIL must be a valid email")
        })?;

        let origin = Url::parse(&rp_origin)
            .map_err(|_| ServerError::InvalidConfiguration("AETHER_WEBAUTHN_ORIGIN"))?;
        if public_origin.origin() != origin.origin() {
            return Err(ServerError::InvalidConfiguration(
                "AETHER_PUBLIC_URL must use the WebAuthn browser origin",
            ));
        }
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
                public_url: public_url.trim_end_matches('/').to_owned(),
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
        let email_token = opaque_token();
        let token_hash = hash_token(&email_token);
        let normalized_tag = normalize_tag(&tag);
        let normalized_email = email.to_ascii_lowercase();

        let mut transaction = self
            .inner
            .pool
            .begin()
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
        sqlx::query(
            "INSERT INTO email_verification_challenges \
             (id, account_id, token_hash, expires_at, purpose, target_email_normalized) \
             VALUES ($1, $2, $3, now() + ($4::double precision * interval '1 second'), 'signup', $5)",
        )
        .bind(Uuid::new_v4())
        .bind(account_id)
        .bind(token_hash)
        .bind(EMAIL_TOKEN_TTL.as_secs() as i64)
        .bind(&normalized_email)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ServerError::Internal)?;

        let verification_url = format!(
            "{}/api/accounts/email/verify?token={}",
            self.inner.public_url, email_token
        );
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
        if let Err(error) = self
            .send_verification_email(&email, &verification_url)
            .await
        {
            self.inner.registrations.lock().await.remove(&ceremony_id);
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
        let result = sqlx::query(
            "INSERT INTO account_passkeys (credential_id, account_id, credential) \
             VALUES ($1, $2, $3)",
        )
        .bind(credential_id)
        .bind(ceremony.account_id)
        .bind(credential)
        .execute(&self.inner.pool)
        .await;
        match result {
            Ok(_) => Ok(()),
            Err(error) if is_unique_violation(&error) => Err(ServerError::InvalidRequest),
            Err(_) => Err(ServerError::Internal),
        }
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
            "SELECT id FROM accounts WHERE tag_normalized = $1 AND email_verified_at IS NOT NULL",
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
        let row =
            sqlx::query("SELECT tag FROM accounts WHERE id = $1 AND email_verified_at IS NOT NULL")
                .bind(ceremony.account_id)
                .fetch_optional(&self.inner.pool)
                .await
                .map_err(|_| ServerError::Internal)?
                .ok_or(ServerError::Unauthorized)?;
        let tag: String = row.try_get("tag").map_err(|_| ServerError::Internal)?;
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
        let account =
            sqlx::query("SELECT tag FROM accounts WHERE id = $1 AND email_verified_at IS NOT NULL")
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
                    self.inner.public_url, email_token
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
            "SELECT id, tag FROM accounts WHERE tag_normalized = $1 AND email_verified_at IS NOT NULL",
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
             FROM account_devices WHERE account_id = $1 AND revoked_at IS NULL ORDER BY created_at",
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
    ) -> Result<DeviceAddress, ServerError> {
        let mut transaction = self
            .inner
            .pool
            .begin()
            .await
            .map_err(|_| ServerError::Internal)?;
        let row = sqlx::query(
            "SELECT user_id, device_id FROM account_devices \
             WHERE id = $1 AND account_id = $2 AND revoked_at IS NULL FOR UPDATE",
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
            "UPDATE account_devices SET revoked_at = now() \
             WHERE id = $1 AND account_id = $2 AND revoked_at IS NULL",
        )
        .bind(device_id)
        .bind(account.account_id)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ServerError::Internal)?;
        if result.rows_affected() == 0 {
            return Err(ServerError::InvalidRequest);
        }
        sqlx::query(
            "UPDATE account_sessions SET revoked_at = now() \
             WHERE device_id = $1 AND account_id = $2 AND revoked_at IS NULL",
        )
        .bind(device_id)
        .bind(account.account_id)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ServerError::Internal)?;
        transaction
            .commit()
            .await
            .map_err(|_| ServerError::Internal)?;
        Ok(address)
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
               AND identity_public_key = $4 AND revoked_at IS NULL",
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
        let result = sqlx::query(
            "UPDATE account_sessions SET device_id = ( \
                 SELECT id FROM account_devices WHERE account_id = $1 AND user_id = $2 \
                   AND device_id = $3 AND identity_public_key = $4 AND revoked_at IS NULL \
             ) WHERE token_hash = $5 AND account_id = $1 AND revoked_at IS NULL \
               AND expires_at > now() AND EXISTS ( \
                 SELECT 1 FROM account_devices WHERE account_id = $1 AND user_id = $2 \
                   AND device_id = $3 AND identity_public_key = $4 AND revoked_at IS NULL \
               )",
        )
        .bind(ceremony.account_id)
        .bind(&ceremony.device.user_id)
        .bind(&ceremony.device.device_id)
        .bind(ceremony.identity_key.as_bytes().as_slice())
        .bind(&account.session_hash)
        .execute(&self.inner.pool)
        .await
        .map_err(|_| ServerError::Internal)?;
        if result.rows_affected() != 1 {
            return Err(ServerError::Unauthorized);
        }
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
             WHERE a.id = $1 AND a.email_verified_at IS NOT NULL \
               AND s.token_hash = $2 AND s.revoked_at IS NULL \
               AND s.expires_at > now() AND s.device_id IS NULL) \
             AND NOT EXISTS (SELECT 1 FROM account_devices \
               WHERE account_id = $1 AND revoked_at IS NULL)",
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
               WHERE account_id = $2 AND revoked_at IS NULL)",
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
             JOIN accounts a ON a.id = s.account_id \
             WHERE s.token_hash = $1 AND s.account_id = $2 AND s.device_id IS NULL \
               AND s.revoked_at IS NULL AND s.expires_at > now() \
               AND a.email_verified_at IS NOT NULL)",
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
             AND revoked_at IS NULL FOR UPDATE",
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
                 AND d.account_id = $3 AND d.revoked_at IS NULL) \
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
             WHERE id = $1 AND account_id = $2 AND revoked_at IS NULL FOR UPDATE",
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
        let response = self
            .inner
            .http
            .post("https://api.resend.com/emails")
            .bearer_auth(&self.inner.resend_api_key)
            .json(&serde_json::json!({
                "from": self.inner.resend_from_email,
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

#[async_trait]
impl DeviceAuthorizer for AccountDirectory {
    async fn authorize(
        &self,
        identity: IdentityPublicKey,
        device: &DeviceAddress,
    ) -> Result<(), ServerError> {
        device.validate()?;
        let row = sqlx::query(
            "SELECT 1 FROM account_devices WHERE user_id = $1 AND device_id = $2 \
             AND identity_public_key = $3 AND revoked_at IS NULL",
        )
        .bind(&device.user_id)
        .bind(&device.device_id)
        .bind(identity.as_bytes().as_slice())
        .fetch_optional(&self.inner.pool)
        .await
        .map_err(|_| ServerError::Internal)?;
        row.map(|_| ()).ok_or(ServerError::Unauthorized)
    }

    async fn authorize_recipient(&self, device: &DeviceAddress) -> Result<(), ServerError> {
        device.validate()?;
        let row = sqlx::query(
            "SELECT 1 FROM account_devices WHERE user_id = $1 AND device_id = $2 AND revoked_at IS NULL",
        )
        .bind(&device.user_id)
        .bind(&device.device_id)
        .fetch_optional(&self.inner.pool)
        .await
        .map_err(|_| ServerError::Internal)?;
        row.map(|_| ()).ok_or(ServerError::Unauthorized)
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
    decode_browser_secret(state)
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
        .and_then(|host| host.parse::<IpAddr>().ok())
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
        _ => Err(ServerError::InvalidConfiguration(name)),
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
    use super::{
        hash_token, normalize_tag, validate_email, validate_profile_update, validate_tag,
        AccountProfileUpdate,
    };

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
        pool.close().await;
    }
}
