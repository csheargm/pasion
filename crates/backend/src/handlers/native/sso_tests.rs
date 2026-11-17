//! Integration tests for the native SSO finish on `/consent/{grant}`.

use chrono::Duration;
use hyper::{Request, StatusCode};
use oauth2_types::requests::ResponseMode;
use pasion_data::{
    AuthorizationCode, Pkce, RepositoryAccess,
    oauth2::{OAuth2AuthorizationGrantRepository, OAuth2ClientRepository},
    user::{BrowserSessionRepository, UserPasswordRepository},
};
use pasion_iana::oauth::PkceCodeChallengeMethod;

use super::tests::{CHALLENGE, REDIRECT, SCOPE, body, exchange, native_state, post, provision};
use crate::{
    handlers::test_utils::{CookieHelper, RequestBuilderExt, ResponseExt, TestState},
    salvo_utils::session::SessionInfoExt,
};

/// A pending native grant with `login_hint`, and a browser session for
/// `username` authenticated `auth_offset` after the grant was created.
async fn grant_and_session(state: &TestState, client_id: &str, hint: &str, auth_offset: Duration) -> (ulid::Ulid, CookieHelper) {
    let mut repo = state.repository().await.unwrap();
    let mut rng = state.rng();
    let client = repo.oauth2_client().find_by_client_id(client_id).await.unwrap().unwrap();
    let grant = repo
        .oauth2_authorization_grant()
        .add(
            &mut rng,
            &state.clock,
            &client,
            REDIRECT.parse().unwrap(),
            REDIRECT.to_owned(),
            SCOPE.parse().unwrap(),
            Some(AuthorizationCode {
                code: format!("{}sso000", ulid::Ulid::new()),
                pkce: Some(Pkce { challenge_method: PkceCodeChallengeMethod::S256, challenge: CHALLENGE.to_owned() }),
            }),
            Some("st-1".to_owned()),
            None,
            ResponseMode::Query,
            false,
            Some(hint.to_owned()),
            None,
        )
        .await
        .unwrap();
    let user = repo.user().find_by_username("gina").await.unwrap().unwrap();
    let password = repo.user_password().active(&user).await.unwrap().unwrap();
    let session = repo.browser_session().add(&mut rng, &state.clock, &user, None).await.unwrap();
    state.clock.advance(auth_offset);
    repo.browser_session()
        .authenticate_with_password(&mut rng, &state.clock, &session, &password)
        .await
        .unwrap();
    repo.save().await.unwrap();
    let cookies = CookieHelper::new();
    cookies.import(state.cookie_jar().set_session(&session));
    (grant.id, cookies)
}

/// The hoop declined and the SPA consent page handler ran (the test depot
/// has no front-end script, so the page itself is not rendered).
fn assert_fell_through(response: &hyper::Response<String>) {
    assert_ne!(response.status(), StatusCode::SEE_OTHER);
    assert!(response.headers().get("location").is_none());
}

async fn signed_up() -> (TestState, String) {
    let (state, client) = native_state().await;
    post(&state, "/api/v1/native/register", body(&client, "gina", "correct horse battery")).await;
    provision(&state, "gina").await;
    (state, client)
}

#[tokio::test]
async fn fresh_upstream_sign_in_goes_once_to_the_loopback_and_ends_the_browser_session() {
    let (state, client) = signed_up().await;
    let (grant, cookies) = grant_and_session(&state, &client, "upstream:github", Duration::seconds(1)).await;
    let response = state.request(cookies.with_cookies(Request::get(format!("/consent/{grant}")).empty())).await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let location = response.headers()["location"].to_str().unwrap();
    assert!(location.starts_with(REDIRECT) && location.contains("code=") && location.contains("state=st-1"), "{location}");
    assert!(response.headers().get("set-cookie").is_some(), "the session cookie is replaced");
    let code = url::Url::parse(location).unwrap().query_pairs().find(|(k, _)| k == "code").unwrap().1.into_owned();
    exchange(&state, &client, &code).await.assert_status(StatusCode::OK);

    // The Pasion session is over: the same cookie no longer finishes anything.
    let (again, _) = grant_and_session(&state, &client, "upstream:github", Duration::seconds(1)).await;
    let reused = state.request(cookies.with_cookies(Request::get(format!("/consent/{again}")).empty())).await;
    assert_fell_through(&reused);
}

#[tokio::test]
async fn stale_sessions_and_password_grants_get_the_consent_page() {
    let (state, client) = signed_up().await;
    // Authenticated before the grant existed: a leftover session.
    let (stale, cookies) = grant_and_session(&state, &client, "upstream:github", Duration::seconds(-5)).await;
    let page = state.request(cookies.with_cookies(Request::get(format!("/consent/{stale}")).empty())).await;
    assert_fell_through(&page);
    // Not an upstream sign-in: never finished silently.
    let (plain, cookies) = grant_and_session(&state, &client, "mxid:@gina:example.com", Duration::seconds(1)).await;
    let page = state.request(cookies.with_cookies(Request::get(format!("/consent/{plain}")).empty())).await;
    assert_fell_through(&page);
}
