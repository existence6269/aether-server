use axum::{
    extract::{Path, Query, State},
    http::{
        header::{AUTHORIZATION, CONTENT_TYPE},
        HeaderMap, HeaderValue, Method, StatusCode,
    },
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::Serialize;
use tower_http::cors::CorsLayer;
use uuid::Uuid;

use crate::{
    accounts::{
        AccountDirectory, DeviceChallengeFinish, DeviceChallengeStart, EmailVerifyRequest,
        FirstDeviceFinish, FirstDeviceStart, LinkComplete, LinkStart, RegistrationFinish,
        SessionExchange, SigninFinish, SigninStart, SignupRequest,
    },
    websocket, AppState, ServerError,
};

#[derive(Serialize)]
struct ServiceStatus {
    status: &'static str,
}

const EMAIL_VERIFICATION_ERROR_HTML: &str = r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>Email link unavailable — Void</title></head><body><main>
<h1>We couldn't verify that email address</h1>
<p>This link may be invalid, expired, or already used. Check the email and try the link again.</p>
<p><a href="/account">Return to the Void account portal</a></p>
</main></body></html>"#;

pub fn router(state: AppState) -> Router {
    let cors = state
        .accounts()
        .and_then(|directory| HeaderValue::from_str(directory.webauthn_origin()).ok())
        .map(|origin| {
            CorsLayer::new()
                .allow_origin(origin)
                .allow_methods([Method::GET, Method::POST, Method::PATCH, Method::DELETE])
                .allow_headers([AUTHORIZATION, CONTENT_TYPE])
        })
        .unwrap_or_else(CorsLayer::new);
    Router::new()
        .route("/healthz", get(health))
        .route("/readyz", get(readiness))
        .route("/ws", get(websocket::upgrade))
        .route("/account", get(account_portal))
        .route("/account/signin", get(system_browser_signin))
        .route("/account/signup", get(system_browser_signup))
        .route("/api/accounts/signup", post(signup))
        .route("/api/accounts/signup/finish", post(finish_signup))
        .route("/api/accounts/signin", post(start_signin))
        .route("/api/accounts/signin/finish", post(finish_signin))
        .route("/api/accounts/session/exchange", post(exchange_session))
        .route(
            "/api/accounts/email/verify",
            get(verify_email_link).post(verify_email),
        )
        .route("/api/accounts/logout", post(logout))
        .route(
            "/api/accounts/me",
            get(account_me).patch(update_account_profile),
        )
        .route("/api/directory/{tag}", get(directory_lookup))
        .route("/api/devices", get(devices))
        .route(
            "/api/devices/{device_id}",
            axum::routing::delete(revoke_device),
        )
        .route(
            "/api/devices/session/challenge",
            post(start_device_challenge),
        )
        .route("/api/devices/session/finish", post(finish_device_challenge))
        .route(
            "/api/devices/first-enrollment/challenge",
            post(start_first_device),
        )
        .route(
            "/api/devices/first-enrollment/finish",
            post(finish_first_device),
        )
        .route("/api/devices/link", post(start_link).get(pending_links))
        .route("/api/devices/link/{request_id}/approve", post(approve_link))
        .route(
            "/api/devices/link/{request_id}/complete",
            post(complete_link),
        )
        .layer(cors)
        .with_state(state)
}

fn directory(state: &AppState) -> Result<&AccountDirectory, ServerError> {
    state.accounts().ok_or(ServerError::Unavailable)
}

fn bearer(headers: &HeaderMap) -> Result<&str, ServerError> {
    let value = headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .filter(|token| !token.is_empty())
        .ok_or(ServerError::Unauthorized)?;
    Ok(value)
}

async fn account_from_headers(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<crate::accounts::AuthenticatedAccount, ServerError> {
    directory(state)?.authenticate(bearer(headers)?).await
}

async fn signup(
    State(state): State<AppState>,
    Json(request): Json<SignupRequest>,
) -> Result<Json<crate::accounts::SignupResponse>, ServerError> {
    Ok(Json(directory(&state)?.signup(request).await?))
}

async fn finish_signup(
    State(state): State<AppState>,
    Json(request): Json<RegistrationFinish>,
) -> Result<StatusCode, ServerError> {
    directory(&state)?.finish_signup(request).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn start_signin(
    State(state): State<AppState>,
    Json(request): Json<SigninStart>,
) -> Result<Json<crate::accounts::SigninStartResponse>, ServerError> {
    Ok(Json(directory(&state)?.start_signin(request).await?))
}

async fn finish_signin(
    State(state): State<AppState>,
    Json(request): Json<SigninFinish>,
) -> Result<Json<crate::accounts::SigninHandoffResponse>, ServerError> {
    Ok(Json(directory(&state)?.finish_signin(request).await?))
}

async fn exchange_session(
    State(state): State<AppState>,
    Json(request): Json<SessionExchange>,
) -> Result<Json<crate::accounts::SigninResponse>, ServerError> {
    Ok(Json(directory(&state)?.exchange_session(request).await?))
}

async fn account_portal(State(state): State<AppState>) -> Result<Response, ServerError> {
    directory(&state)?;
    let mut response = Html(ACCOUNT_PORTAL_HTML).into_response();
    set_account_page_headers(&mut response);
    Ok(response)
}

async fn system_browser_signin(State(state): State<AppState>) -> Result<Response, ServerError> {
    directory(&state)?;
    let mut response = Html(SYSTEM_BROWSER_SIGNIN_HTML).into_response();
    set_account_page_headers(&mut response);
    Ok(response)
}

async fn system_browser_signup(State(state): State<AppState>) -> Result<Response, ServerError> {
    directory(&state)?;
    let mut response = Html(SYSTEM_BROWSER_SIGNUP_HTML).into_response();
    set_account_page_headers(&mut response);
    Ok(response)
}

fn set_account_page_headers(response: &mut Response) {
    response.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        "no-store".parse().expect("valid static header"),
    );
    response.headers_mut().insert(
        axum::http::header::CONTENT_SECURITY_POLICY,
        "default-src 'none'; script-src 'unsafe-inline'; connect-src 'self'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'"
            .parse()
            .expect("valid static header"),
    );
    response.headers_mut().insert(
        axum::http::header::REFERRER_POLICY,
        "no-referrer".parse().expect("valid static header"),
    );
    response.headers_mut().insert(
        axum::http::header::X_CONTENT_TYPE_OPTIONS,
        "nosniff".parse().expect("valid static header"),
    );
}

const ACCOUNT_PORTAL_HTML: &str = r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>Void account</title><style>
body{font:16px system-ui,sans-serif;max-width:36rem;margin:10vh auto;padding:1rem;color:#222}
a{color:#164b80}li{margin:1rem 0}#notice{padding:1rem;background:#edf7ed}
</style></head><body><main><h1>Void account</h1>
<p>Use a passkey in this system browser to create your account. To sign in to the Void desktop app, start sign-in in the app; it opens this page with a one-time secure return to the app.</p>
<p id="notice" role="status" aria-live="polite" hidden>Email verified. Return to Void and choose “Sign in” to continue.</p>
<nav aria-label="Account actions"><ul>
<li><a id="signin" href="/account/signin">Sign in with a passkey</a></li>
<li><a href="/account/signup">Create an account with a passkey</a></li>
</ul></nav>
<p>Your passkey stays with your authenticator. This page keeps credential data only in memory and never stores a bearer token.</p>
</main><script>
const p=new URLSearchParams(location.search),notice=document.getElementById("notice");
if(p.get("verified")==="1")notice.hidden=false;
const callbackUri=p.get("callback_uri"),state=p.get("state"),codeChallenge=p.get("code_challenge");
if(callbackUri&&state&&codeChallenge){const u=new URL("/account/signin",location.origin);u.searchParams.set("callback_uri",callbackUri);u.searchParams.set("state",state);u.searchParams.set("code_challenge",codeChallenge);document.getElementById("signin").href=u.pathname+u.search}
</script></body></html>"#;

const SYSTEM_BROWSER_SIGNIN_HTML: &str = r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>Sign in to Void</title><style>
body{font:16px system-ui,sans-serif;max-width:28rem;margin:12vh auto;padding:1rem;color:#222}
label,input,button{display:block;width:100%;box-sizing:border-box;margin:.7rem 0}
input,button{font:inherit;padding:.75rem}button{cursor:pointer}
#status{min-height:3rem}
</style></head><body><h1>Sign in to Void</h1>
<form id="signin"><label for="tag">Void tag</label><input id="tag" autocomplete="username" required minlength="3" maxlength="24">
<button type="submit">Continue with passkey</button></form><p id="status" role="status" aria-live="polite"></p>
<script>
const form=document.getElementById("signin"),status=document.getElementById("status");
const params=new URLSearchParams(location.search),callbackUri=params.get("callback_uri"),state=params.get("state"),codeChallenge=params.get("code_challenge");
async function apiError(response,fallback){let code="";try{code=(await response.json()).error||""}catch(_){}const messages={invalid_request:"Check the account details and try again.",unauthorized:"The tag or passkey could not be verified. Check the tag and try again.",resource_limit:"Too many sign-in attempts are pending. Wait a moment and try again.",unavailable:"Account services are temporarily unavailable.",internal:"The server could not complete sign-in. Try again later."};return messages[code]||fallback}
function b64url(bytes){let s="";for(const b of new Uint8Array(bytes))s+=String.fromCharCode(b);return btoa(s).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"")}
function fromB64url(s){const p=s.replace(/-/g,"+").replace(/_/g,"/");return Uint8Array.from(atob(p+"=".repeat((4-p.length%4)%4)),c=>c.charCodeAt(0))}
function credentialJson(c){if(typeof c.toJSON==="function")return c.toJSON();const r=c.response,out={id:c.id,rawId:b64url(c.rawId),type:c.type,authenticatorAttachment:c.authenticatorAttachment,response:{clientDataJSON:b64url(r.clientDataJSON)}};if(r.attestationObject)out.response.attestationObject=b64url(r.attestationObject);if(r.authenticatorData)out.response.authenticatorData=b64url(r.authenticatorData);if(r.signature)out.response.signature=b64url(r.signature);if(r.userHandle)out.response.userHandle=b64url(r.userHandle);if(r.getTransports)out.response.transports=r.getTransports();return out}
if(!callbackUri||!state||!codeChallenge){form.hidden=true;status.textContent="This sign-in link is missing its secure desktop handoff. Return to the Void app and try again."}
form.addEventListener("submit",async e=>{e.preventDefault();status.textContent="Waiting for your passkey…";form.querySelector("button").disabled=true;try{
const start=await fetch("/api/accounts/signin",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({tag:document.getElementById("tag").value,callback_uri:callbackUri,state,code_challenge:codeChallenge})});
if(!start.ok)throw new Error(await apiError(start,"Could not start sign-in."));const ceremony=await start.json(),publicKey=ceremony.options.publicKey;
publicKey.challenge=fromB64url(publicKey.challenge);if(publicKey.allowCredentials)publicKey.allowCredentials=publicKey.allowCredentials.map(c=>({...c,id:fromB64url(c.id)}));
const assertion=await navigator.credentials.get({publicKey});
const finish=await fetch("/api/accounts/signin/finish",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({ceremony_id:ceremony.ceremony_id,credential:credentialJson(assertion)})});
if(!finish.ok)throw new Error(await apiError(finish,"Passkey sign-in failed."));const handoff=await finish.json();location.assign(handoff.redirect_uri);
}catch(error){status.textContent=error instanceof DOMException&&error.name==="NotAllowedError"?"Passkey sign-in was cancelled or timed out. You can try again.":error instanceof Error?error.message:"Sign-in could not be completed. Return to Void and try again.";form.querySelector("button").disabled=false}});
</script></body></html>"#;

const SYSTEM_BROWSER_SIGNUP_HTML: &str = r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>Create a Void account</title><style>
body{font:16px system-ui,sans-serif;max-width:28rem;margin:12vh auto;padding:1rem;color:#222}
label,input,button{display:block;width:100%;box-sizing:border-box;margin:.7rem 0}
input,button{font:inherit;padding:.75rem}button{cursor:pointer}
#status{min-height:3rem}
</style></head><body><h1>Create a Void account</h1>
<form id="signup"><label for="tag">Void tag</label><input id="tag" autocomplete="username" required minlength="3" maxlength="24">
<label for="email">Email</label><input id="email" type="email" autocomplete="email" required maxlength="320">
<button type="submit">Create account with passkey</button></form><p id="status" role="status" aria-live="polite"></p>
<script>
const form=document.getElementById("signup"),status=document.getElementById("status");
const signupParams=new URLSearchParams(location.search);
document.getElementById("tag").value=signupParams.get("tag")||"";
document.getElementById("email").value=signupParams.get("email")||"";
async function apiError(response,fallback){let code="";try{code=(await response.json()).error||""}catch(_){}const messages={invalid_request:"That tag or email may be invalid or already in use. Check the details and try again.",resource_limit:"Too many account requests are pending. Wait a moment and try again.",unavailable:"Account services are temporarily unavailable.",internal:"The server could not complete account creation. Try again later."};return messages[code]||fallback}
function b64url(bytes){let s="";for(const b of new Uint8Array(bytes))s+=String.fromCharCode(b);return btoa(s).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"")}
function fromB64url(s){const p=s.replace(/-/g,"+").replace(/_/g,"/");return Uint8Array.from(atob(p+"=".repeat((4-p.length%4)%4)),c=>c.charCodeAt(0))}
function credentialJson(c){if(typeof c.toJSON==="function")return c.toJSON();const r=c.response,out={id:c.id,rawId:b64url(c.rawId),type:c.type,authenticatorAttachment:c.authenticatorAttachment,response:{clientDataJSON:b64url(r.clientDataJSON)}};if(r.attestationObject)out.response.attestationObject=b64url(r.attestationObject);if(r.authenticatorData)out.response.authenticatorData=b64url(r.authenticatorData);if(r.signature)out.response.signature=b64url(r.signature);if(r.userHandle)out.response.userHandle=b64url(r.userHandle);if(r.getTransports)out.response.transports=r.getTransports();return out}
form.addEventListener("submit",async e=>{e.preventDefault();status.textContent="Waiting for your passkey…";form.querySelector("button").disabled=true;try{
const start=await fetch("/api/accounts/signup",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({tag:document.getElementById("tag").value,email:document.getElementById("email").value})});
if(!start.ok)throw new Error(await apiError(start,"Could not start account creation."));const ceremony=await start.json(),publicKey=ceremony.options.publicKey;
publicKey.challenge=fromB64url(publicKey.challenge);publicKey.user.id=fromB64url(publicKey.user.id);if(publicKey.excludeCredentials)publicKey.excludeCredentials=publicKey.excludeCredentials.map(c=>({...c,id:fromB64url(c.id)}));
const credential=await navigator.credentials.create({publicKey});
const finish=await fetch("/api/accounts/signup/finish",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({ceremony_id:ceremony.ceremony_id,credential:credentialJson(credential)})});
if(!finish.ok)throw new Error(await apiError(finish,"Passkey registration failed."));form.hidden=true;status.textContent="Account created. Check your email to verify it, then return to Void and sign in.";
}catch(error){status.textContent=error instanceof DOMException&&error.name==="NotAllowedError"?"Passkey registration was cancelled or timed out. You can try again.":error instanceof Error?error.message:"Account creation could not be completed. Check the tag and email, then try again.";form.querySelector("button").disabled=false}});
</script></body></html>"#;

async fn verify_email(
    State(state): State<AppState>,
    Json(request): Json<EmailVerifyRequest>,
) -> Result<StatusCode, ServerError> {
    directory(&state)?.verify_email(request).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn verify_email_link(
    State(state): State<AppState>,
    Query(request): Query<EmailVerifyRequest>,
) -> Result<Response, ServerError> {
    match directory(&state)?.verify_email(request).await {
        Ok(()) => {}
        Err(ServerError::Unauthorized | ServerError::InvalidRequest) => {
            let mut response = Html(EMAIL_VERIFICATION_ERROR_HTML).into_response();
            *response.status_mut() = StatusCode::BAD_REQUEST;
            set_account_page_headers(&mut response);
            return Ok(response);
        }
        Err(error) => return Err(error),
    }
    let mut response = axum::response::Redirect::to("/account?verified=1").into_response();
    set_account_page_headers(&mut response);
    Ok(response)
}

async fn logout(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<StatusCode, ServerError> {
    let directory = directory(&state)?;
    let account = directory.authenticate(bearer(&headers)?).await?;
    directory.logout(&account).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn account_me(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<crate::accounts::AccountSummary>, ServerError> {
    let directory = directory(&state)?;
    let account = account_from_headers(&state, &headers).await?;
    Ok(Json(directory.account_summary(&account).await?))
}

async fn update_account_profile(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<crate::accounts::AccountProfileUpdate>,
) -> Result<Json<crate::accounts::AccountSummary>, ServerError> {
    let directory = directory(&state)?;
    let account = account_from_headers(&state, &headers).await?;
    Ok(Json(
        directory.update_account_profile(&account, request).await?,
    ))
}

async fn directory_lookup(
    State(state): State<AppState>,
    Path(tag): Path<String>,
) -> Result<Json<crate::accounts::DirectoryEntry>, ServerError> {
    Ok(Json(directory(&state)?.lookup_tag(&tag).await?))
}

async fn devices(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<crate::accounts::DeviceEntry>>, ServerError> {
    let directory = directory(&state)?;
    let account = account_from_headers(&state, &headers).await?;
    Ok(Json(directory.devices(&account).await?))
}

async fn revoke_device(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(device_id): Path<Uuid>,
) -> Result<StatusCode, ServerError> {
    let directory = directory(&state)?;
    let account = account_from_headers(&state, &headers).await?;
    let address = directory.revoke_device(&account, device_id).await?;
    state.revoke_route_device(&address).await;
    Ok(StatusCode::NO_CONTENT)
}

async fn start_device_challenge(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<DeviceChallengeStart>,
) -> Result<Json<crate::accounts::DeviceChallengeResponse>, ServerError> {
    let directory = directory(&state)?;
    let account = account_from_headers(&state, &headers).await?;
    Ok(Json(
        directory.start_device_challenge(&account, request).await?,
    ))
}

async fn finish_device_challenge(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<DeviceChallengeFinish>,
) -> Result<StatusCode, ServerError> {
    let directory = directory(&state)?;
    let account = account_from_headers(&state, &headers).await?;
    directory.finish_device_challenge(&account, request).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn start_first_device(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<FirstDeviceStart>,
) -> Result<Json<crate::accounts::FirstDeviceStartResponse>, ServerError> {
    let directory = directory(&state)?;
    let account = account_from_headers(&state, &headers).await?;
    Ok(Json(directory.start_first_device(&account, request).await?))
}

async fn finish_first_device(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<FirstDeviceFinish>,
) -> Result<Json<crate::accounts::FirstDeviceResponse>, ServerError> {
    let directory = directory(&state)?;
    let account = account_from_headers(&state, &headers).await?;
    Ok(Json(
        directory.finish_first_device(&account, request).await?,
    ))
}

async fn start_link(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<LinkStart>,
) -> Result<Json<crate::accounts::LinkStartResponse>, ServerError> {
    let directory = directory(&state)?;
    let account = account_from_headers(&state, &headers).await?;
    Ok(Json(directory.start_link(&account, request).await?))
}

async fn pending_links(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<crate::accounts::LinkRequestEntry>>, ServerError> {
    let directory = directory(&state)?;
    let account = account_from_headers(&state, &headers).await?;
    Ok(Json(directory.pending_links(&account).await?))
}

async fn approve_link(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(request_id): Path<Uuid>,
) -> Result<StatusCode, ServerError> {
    let directory = directory(&state)?;
    let account = account_from_headers(&state, &headers).await?;
    directory.approve_link(&account, request_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn complete_link(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(request_id): Path<Uuid>,
    Json(request): Json<LinkComplete>,
) -> Result<Json<crate::accounts::DeviceEntry>, ServerError> {
    let directory = directory(&state)?;
    let account = account_from_headers(&state, &headers).await?;
    Ok(Json(
        directory
            .complete_link(&account, request_id, request)
            .await?,
    ))
}

async fn health() -> Json<ServiceStatus> {
    Json(ServiceStatus { status: "ok" })
}

async fn readiness(
    State(state): State<AppState>,
) -> Result<Json<ServiceStatus>, axum::http::StatusCode> {
    if state.is_ready() {
        Ok(Json(ServiceStatus { status: "ready" }))
    } else {
        Err(axum::http::StatusCode::SERVICE_UNAVAILABLE)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;

    use crate::{auth::RejectAllAuthenticator, config::ServerConfig, state::AppState};

    use super::router;

    #[tokio::test]
    async fn health_and_readiness_track_shutdown_state() {
        let state =
            AppState::new(ServerConfig::default(), Arc::new(RejectAllAuthenticator)).unwrap();
        let app = router(state.clone());

        let health = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/healthz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(health.status(), StatusCode::OK);

        let ready = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/readyz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(ready.status(), StatusCode::OK);

        state.stop_accepting();
        let not_ready = app
            .oneshot(
                Request::builder()
                    .uri("/readyz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(not_ready.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn account_api_stays_unavailable_without_a_configured_directory() {
        let state =
            AppState::new(ServerConfig::default(), Arc::new(RejectAllAuthenticator)).unwrap();
        let response = router(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/accounts/signup")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"tag":"alice","email":"alice@example.org"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[test]
    fn hosted_system_browser_pages_use_webauthn_and_do_not_persist_tokens() {
        assert!(ACCOUNT_PORTAL_HTML.contains("role=\"status\""));
        assert!(!ACCOUNT_PORTAL_HTML.contains("localStorage"));
        assert!(!ACCOUNT_PORTAL_HTML.contains("sessionStorage"));
        assert!(SYSTEM_BROWSER_SIGNIN_HTML.contains("navigator.credentials.get"));
        assert!(SYSTEM_BROWSER_SIGNIN_HTML.contains("code_challenge"));
        assert!(SYSTEM_BROWSER_SIGNUP_HTML.contains("navigator.credentials.create"));
        assert!(!SYSTEM_BROWSER_SIGNIN_HTML.contains("/api/accounts/session/exchange"));
        assert!(!SYSTEM_BROWSER_SIGNIN_HTML.contains("session_token"));
        assert!(ACCOUNT_PORTAL_HTML.contains("Create an account with a passkey"));
        assert!(ACCOUNT_PORTAL_HTML.contains("Sign in with a passkey"));
        assert!(EMAIL_VERIFICATION_ERROR_HTML.contains("may be invalid, expired"));
        assert!(!EMAIL_VERIFICATION_ERROR_HTML.contains("token"));
    }
}
