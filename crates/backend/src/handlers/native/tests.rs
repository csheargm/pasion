//! Integration tests: the native API end to end against a real database,
//! including the `/oauth2/token` exchange the desktop SDK performs next.

use hyper::{Request, StatusCode};
use oauth2_types::registration::ClientRegistrationResponse;
use pasion_data::{RepositoryAccess, SiteConfig};
use serde_json::{Value, json};

use crate::handlers::test_utils::{RequestBuilderExt, ResponseExt, TestState, setup, test_site_config};

/// RFC 7636 appendix B pair.
pub(super) const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
pub(super) const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
pub(super) const REDIRECT: &str = "http://127.0.0.1:43123/";
pub(super) const SCOPE: &str = "openid urn:matrix:client:api:* urn:matrix:client:device:NATIVEDEV";

/// A state whose `native_client_id` is a freshly registered public loopback client.
pub(super) async fn native_state() -> (TestState, String) {
    setup();
    let pool = pasion_data::test_utils::setup_test_pool().await;
    let bootstrap = TestState::from_pool(pool.clone()).await.unwrap();
    let response = bootstrap
        .request(Request::post("/oauth2/registration").json(json!({
            "client_uri": "https://example.com/",
            "application_type": "native",
            "token_endpoint_auth_method": "none",
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "redirect_uris": ["http://127.0.0.1/"],
        })))
        .await;
    response.assert_status(StatusCode::CREATED);
    let client_id = response.json::<ClientRegistrationResponse>().client_id;
    // As on the alpha/beta servers: sign-up needs no email.
    let config = SiteConfig {
        native_client_id: Some(client_id.clone()),
        password_registration_contact_required: false,
        ..test_site_config()
    };
    let state = TestState::from_pool_with_site_config(pool, config).await.unwrap();
    // `/oauth2/token` reads the system clock; align the mock clock with it.
    state.clock.advance(chrono::Utc::now() - pasion_data::Clock::now(state.clock.as_ref()));
    (state, client_id)
}

pub(super) fn body(client_id: &str, username: &str, password: &str) -> Value {
    json!({
        "client_id": client_id, "redirect_uri": REDIRECT, "scope": SCOPE, "state": "st-1",
        "code_challenge": CHALLENGE, "code_challenge_method": "S256",
        "username": username, "password": password,
    })
}

pub(super) async fn post(state: &TestState, path: &str, payload: Value) -> hyper::Response<String> {
    let response = state.request(Request::post(path).json(payload)).await;
    assert!(response.headers().get("set-cookie").is_none(), "native API must not set cookies");
    response
}

fn code_of(response: &hyper::Response<String>) -> String {
    let body: Value = response.json();
    let url = url::Url::parse(body["redirect_url"].as_str().unwrap()).unwrap();
    assert_eq!((url.host_str(), url.port()), (Some("127.0.0.1"), Some(43123)));
    let pairs: std::collections::HashMap<_, _> = url.query_pairs().into_owned().collect();
    assert_eq!(pairs["state"], "st-1");
    pairs["code"].clone()
}

pub(super) async fn provision(state: &TestState, username: &str) {
    use pasion_matrix::{HomeserverAdmin, ProvisionRequest};
    let mut repo = state.repository().await.unwrap();
    let user = repo.user().find_by_username(username).await.unwrap().unwrap();
    repo.cancel().await.unwrap();
    state.homeserver_admin.provision_user(&ProvisionRequest::new(&user.username, &user.sub)).await.unwrap();
}

pub(super) async fn exchange(state: &TestState, client_id: &str, code: &str) -> hyper::Response<String> {
    state
        .request(Request::post("/oauth2/token").form(json!({
            "grant_type": "authorization_code", "code": code, "redirect_uri": REDIRECT,
            "client_id": client_id, "code_verifier": VERIFIER,
        })))
        .await
}

#[tokio::test]
async fn register_then_login_yield_single_use_pkce_codes_and_lowercase_names() {
    let (state, client) = native_state().await;
    let created = post(&state, "/api/v1/native/register", body(&client, "Alice", "correct horse battery")).await;
    created.assert_status(StatusCode::OK);
    assert_eq!(created.json::<Value>()["username"], "alice");
    // Production provisions the Matrix account in a background job.
    provision(&state, "alice").await;
    let code = code_of(&created);
    exchange(&state, &client, &code).await.assert_status(StatusCode::OK);
    // Single use: a replayed code is refused.
    assert_eq!(exchange(&state, &client, &code).await.status(), StatusCode::BAD_REQUEST);

    let wrong = post(&state, "/api/v1/native/login", body(&client, "alice", "nope")).await;
    wrong.assert_status(StatusCode::UNAUTHORIZED);
    assert_eq!(wrong.json::<Value>()["error"], "invalid_credentials");
    let login = post(&state, "/api/v1/native/login", body(&client, "ALICE", "correct horse battery")).await;
    login.assert_status(StatusCode::OK);
    exchange(&state, &client, &code_of(&login)).await.assert_status(StatusCode::OK);

    let again = post(&state, "/api/v1/native/register", body(&client, "alice", "another long pass")).await;
    assert_eq!(again.json::<Value>()["error"], "username_exists");
}

#[tokio::test]
async fn only_the_desktop_client_with_loopback_pkce_and_device_scopes_is_served() {
    let (state, client) = native_state().await;
    let cases = [
        (json!({"client_id": "01J0000000000000000000000A"}), StatusCode::FORBIDDEN, "client_not_allowed"),
        (json!({"code_challenge_method": "plain"}), StatusCode::BAD_REQUEST, "pkce_s256_required"),
        (json!({"redirect_uri": "https://evil.example/"}), StatusCode::BAD_REQUEST, "redirect_uri_not_loopback"),
        (json!({"scope": "openid urn:pasion:admin"}), StatusCode::FORBIDDEN, "scope_not_allowed"),
        (json!({"state": ""}), StatusCode::BAD_REQUEST, "state_required"),
    ];
    for (patch, status, code) in cases {
        let mut payload = body(&client, "mallory", "correct horse battery");
        for (k, v) in patch.as_object().unwrap() {
            payload[k] = v.clone();
        }
        let response = post(&state, "/api/v1/native/register", payload).await;
        assert_eq!((response.status(), response.json::<Value>()["error"].clone()), (status, json!(code)));
    }
    // None of the refused requests created the account.
    let mut repo = state.repository().await.unwrap();
    assert!(!repo.user().exists("mallory").await.unwrap());
}

#[tokio::test]
async fn registration_that_needs_an_email_issues_no_code() {
    let (state, client) = native_state().await;
    let strict = SiteConfig { password_registration_contact_required: true, ..state.site_config.clone() };
    let pool = state.repository_factory.pool().clone();
    let state = TestState::from_pool_with_site_config(pool, strict).await.unwrap();
    let response = post(&state, "/api/v1/native/register", body(&client, "eve", "correct horse battery")).await;
    response.assert_status(StatusCode::BAD_REQUEST);
    assert_eq!(response.json::<Value>()["error"], "email_or_phone_required");
}

#[tokio::test]
async fn locked_accounts_get_no_code() {
    let (state, client) = native_state().await;
    post(&state, "/api/v1/native/register", body(&client, "pat", "correct horse battery")).await.assert_status(StatusCode::OK);
    let mut repo = state.repository().await.unwrap();
    let user = repo.user().find_by_username("pat").await.unwrap().unwrap();
    repo.user().lock(&state.clock, user).await.unwrap();
    repo.save().await.unwrap();
    let response = post(&state, "/api/v1/native/login", body(&client, "pat", "correct horse battery")).await;
    response.assert_status(StatusCode::FORBIDDEN);
    assert_eq!(response.json::<Value>()["error"], "account_locked");
}

#[tokio::test]
async fn username_availability_is_lowercased_and_reflects_registrations() {
    let (state, client) = native_state().await;
    let check = |name: &'static str| {
        let state = &state;
        async move {
            let response = state.request(Request::get(format!("/api/v1/native/username-available?username={name}")).empty()).await;
            response.assert_status(StatusCode::OK);
            response.json::<Value>()
        }
    };
    assert_eq!(check("Bob").await, json!({"username": "bob", "status": "available"}));
    assert_eq!(check("_bad").await["status"], "invalid");
    post(&state, "/api/v1/native/register", body(&client, "bob", "correct horse battery")).await.assert_status(StatusCode::OK);
    assert_eq!(check("BOB").await["status"], "taken");
}

#[tokio::test]
async fn config_names_the_client_and_is_absent_when_unconfigured() {
    let (state, client) = native_state().await;
    let response = state.request(Request::get("/api/v1/native/config").empty()).await;
    response.assert_status(StatusCode::OK);
    assert_eq!(response.json::<Value>()["client_id"], json!(client));

    let pool = pasion_data::test_utils::setup_test_pool().await;
    let plain = TestState::from_pool(pool).await.unwrap();
    plain.request(Request::get("/api/v1/native/config").empty()).await.assert_status(StatusCode::NOT_FOUND);
}
