//! Native SSO finish: the desktop opens the system browser on an ordinary
//! authorization request with `login_hint=upstream:<provider>` and
//! `prompt=login`, so Pasion goes straight to GitHub/Google. When that
//! upstream sign-in lands back on `/consent/<grant>`, this hoop — for the
//! native client only, and only when the person authenticated after the
//! grant was created — fulfills the grant, ends the Pasion browser session,
//! clears its cookie and redirects once to the desktop's loopback callback.
//! Element and every other client still get the consent page, so the
//! browser is never left signed in as the desktop user. The desktop then
//! shows "Signed in as @x — not you?".

use pasion_data::{
    AuthorizationGrant, AuthorizationGrantStage, BrowserSession, RepositoryAccess,
    oauth2::{OAuth2AuthorizationGrantRepository, OAuth2ClientRepository},
    user::BrowserSessionRepository,
};
use salvo::prelude::*;
use ulid::Ulid;

use crate::{
    handlers::{
        common::{DepotExt, RouteError, extract_bound_activity_tracker, make_clock, make_rng},
        native::policy,
        oauth2::{
            access::accept_authorization_consent,
            authorization::upstream_hint::{parse_upstream_hint, selects_provider},
        },
    },
    salvo_utils::session::SessionInfoExt,
};

/// The grant id in a `/consent/<id>` path tail.
#[must_use]
pub fn grant_id_from_tail(tail: &str) -> Option<Ulid> {
    tail.split(['/', '?', '#']).next()?.parse().ok()
}

/// Whether this grant is a native upstream sign-in the hoop may finish: the
/// native client, still pending, an upstream hint, and the same loopback,
/// PKCE S256, state and Matrix-device-scope rules as the password API.
#[must_use]
pub fn is_native_sso_grant(grant: &AuthorizationGrant, client_id: &str, native: Option<&str>) -> bool {
    let pkce_ok = grant
        .code
        .as_ref()
        .and_then(|code| code.pkce.as_ref())
        .is_some_and(|pkce| policy::check_pkce(&pkce.challenge_method, &pkce.challenge).is_ok());
    native == Some(client_id)
        && matches!(grant.stage, AuthorizationGrantStage::Pending)
        && parse_upstream_hint(grant.login_hint.as_deref()).is_some()
        && policy::is_loopback(&grant.redirect_uri)
        && pkce_ok
        && grant.state.as_deref().is_some_and(|state| policy::check_state(state).is_ok())
        && policy::check_scope(&grant.scope).is_ok()
}

/// The fresh authentication must be an upstream sign-in with the provider
/// the grant's hint selected, started after the grant was created.
async fn upstream_auth_matches(repo: &mut pasion_data::BoxRepository, grant: &AuthorizationGrant, auth: &pasion_data::Authentication) -> Result<bool, RouteError> {
    let pasion_data::AuthenticationMethod::UpstreamOAuth2 { upstream_oauth2_session_id } = auth.authentication_method else {
        return Ok(false);
    };
    let Some(upstream) = repo.upstream_oauth_session().lookup(upstream_oauth2_session_id).await? else { return Ok(false) };
    let Some(provider) = repo.upstream_oauth_provider().lookup(upstream.provider_id).await? else { return Ok(false) };
    let selector = parse_upstream_hint(grant.login_hint.as_deref()).unwrap_or_default();
    Ok(upstream.created_at >= grant.created_at && selects_provider(selector, &provider))
}

/// Fresh authentication: after the grant was created, never a leftover one.
#[must_use]
pub fn authenticated_for_grant(grant: &AuthorizationGrant, last_auth: Option<chrono::DateTime<chrono::Utc>>) -> bool {
    last_auth.is_some_and(|at| at >= grant.created_at)
}

/// The loopback URL to send the browser to, or `None` to show the page.
async fn finish(req: &mut Request, depot: &Depot, grant_id: Ulid) -> Result<Option<(String, BrowserSession)>, RouteError> {
    let site_config = depot.site_config()?;
    let Some(native) = site_config.native_client_id.as_deref() else { return Ok(None) };
    let session_info = crate::handlers::common::extract_session_info(req, depot);
    let mut repo = depot.repo().await?;
    let Some(grant) = repo.oauth2_authorization_grant().lookup(grant_id).await? else {
        repo.cancel().await?;
        return Ok(None);
    };
    let client = repo.oauth2_client().lookup(grant.client_id).await?;
    let Some(session) = session_info.load_active_session(&mut repo).await? else {
        repo.cancel().await?;
        return Ok(None);
    };
    let last = repo.browser_session().get_last_authentication(&session).await?;
    let native_grant = client.is_some_and(|c| is_native_sso_grant(&grant, &c.client_id, Some(native)));
    let fresh = match last.as_ref() {
        Some(auth) if native_grant && authenticated_for_grant(&grant, Some(auth.created_at)) => {
            upstream_auth_matches(&mut repo, &grant, auth).await?
        }
        _ => false,
    };
    repo.cancel().await?;
    if !fresh {
        return Ok(None);
    }
    let (mut rng, clock) = (make_rng(), make_clock());
    let ip = extract_bound_activity_tracker(req, depot).ip();
    let decision = accept_authorization_consent(
        depot.repo().await?,
        &mut rng,
        &clock,
        &depot.key_store()?,
        &depot.url_builder()?,
        depot.policy_factory()?.as_ref(),
        &session,
        grant_id,
        ip,
        req.header::<String>("user-agent"),
    )
    .await
    .map_err(|error| RouteError::Internal(Box::new(error)))?;
    let url = decision.redirect_url().map_err(|error| RouteError::Internal(Box::new(error)))?;
    Ok(Some((url, session)))
}

/// Hoop on `/consent/{**rest}`: finish native SSO, else fall through to the
/// SPA consent page.
#[handler]
pub async fn native_consent(req: &mut Request, depot: &mut Depot, res: &mut Response, ctrl: &mut FlowCtrl) -> Result<(), RouteError> {
    let Some(grant_id) = req.param::<String>("rest").as_deref().and_then(grant_id_from_tail) else {
        return Ok(());
    };
    let Some((url, session)) = finish(req, depot, grant_id).await? else { return Ok(()) };
    // The code is issued: end the Pasion session so the browser (and an
    // Element tab in it) is not left signed in as this person.
    let mut repo = depot.repo().await?;
    repo.browser_session().finish(&make_clock(), session).await?;
    repo.save().await?;
    let (session_info, jar) = depot.cookie_jar(req)?.session_info();
    let jar = jar.update_session_info(&session_info.mark_session_ended());
    jar.write_to_response(res);
    res.render(Redirect::other(url));
    ctrl.skip_rest();
    Ok(())
}
