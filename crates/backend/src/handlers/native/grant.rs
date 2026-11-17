//! Turn an authenticated Pasion user into an authorization code for the
//! native client, without a browser or cookie: record a PKCE-bound grant,
//! then fulfill it through the same consent path the browser uses (policy
//! checks, session creation). The code is single-use: `/oauth2/token`
//! refuses a second exchange and revokes the session it issued.

use oauth2_types::{requests::ResponseMode, scope::Scope};
use pasion_data::{
    AuthorizationCode, BoxClock, BoxRng, BrowserSession, Pkce, RepositoryAccess,
    oauth2::{OAuth2AuthorizationGrantRepository, OAuth2ClientRepository},
};
use rand_core::RngCore;
use salvo::Depot;
use url::Url;

use super::{
    NativeRequest,
    policy::{self, NativeRefusal},
};
use crate::handlers::{
    common::{DepotExt, RouteError},
    oauth2::access::{OAuth2AccessError, accept_authorization_consent},
};

/// `login_hint` recorded on native password grants, for audit.
pub const NATIVE_PASSWORD_HINT: &str = "native:password";
/// Length of a generated authorization code (≈190 bits).
const CODE_LEN: usize = 32;
const CODE_CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

/// A request that passed every client/redirect/PKCE/scope rule.
pub struct ValidatedRequest {
    pub client: pasion_data::Client,
    pub redirect_uri: Url,
    pub raw_redirect_uri: String,
    pub scope: Scope,
}

/// Outcome a handler turns into a JSON error.
pub enum GrantError {
    Refused(NativeRefusal),
    Route(RouteError),
}

impl From<RouteError> for GrantError {
    fn from(error: RouteError) -> Self {
        Self::Route(error)
    }
}

impl From<pasion_data::RepositoryError> for GrantError {
    fn from(error: pasion_data::RepositoryError) -> Self {
        Self::Route(error.into())
    }
}

/// Apply every native rule before any password is checked.
pub async fn validate(depot: &Depot, request: &NativeRequest) -> Result<ValidatedRequest, GrantError> {
    let site_config = depot.site_config()?;
    policy::check_client(site_config.native_client_id.as_deref(), &request.client_id)
        .map_err(GrantError::Refused)?;
    policy::check_pkce(&request.code_challenge_method, &request.code_challenge)
        .map_err(GrantError::Refused)?;
    policy::check_state(&request.state).map_err(GrantError::Refused)?;
    let scope: Scope = request
        .scope
        .parse()
        .map_err(|_| GrantError::Refused(NativeRefusal::ScopeNotAllowed))?;
    policy::check_scope(&scope).map_err(GrantError::Refused)?;
    let redirect_uri = Url::parse(&request.redirect_uri)
        .map_err(|_| GrantError::Refused(NativeRefusal::RedirectNotLoopback))?;
    if !policy::is_loopback(&redirect_uri) {
        return Err(GrantError::Refused(NativeRefusal::RedirectNotLoopback));
    }
    let mut repo = depot.repo().await?;
    let client = repo.oauth2_client().find_by_client_id(&request.client_id).await?;
    repo.cancel().await?;
    let client = client.ok_or(GrantError::Refused(NativeRefusal::ClientNotAllowed))?;
    let wanted = Some(redirect_uri.clone());
    let resolved = client
        .resolve_redirect_uri(&wanted)
        .map_err(|_| GrantError::Refused(NativeRefusal::RedirectNotLoopback))?
        .clone();
    Ok(ValidatedRequest {
        client,
        redirect_uri: resolved,
        raw_redirect_uri: request.redirect_uri.clone(),
        scope,
    })
}

fn random_code(rng: &mut BoxRng) -> String {
    // Rejection sampling keeps the 62-character alphabet uniform.
    let limit = (256 - 256 % CODE_CHARSET.len()) as u16;
    let mut out = String::with_capacity(CODE_LEN);
    let mut buf = [0u8; 64];
    while out.len() < CODE_LEN {
        rng.fill_bytes(&mut buf);
        for &b in buf.iter().filter(|&&b| u16::from(b) < limit) {
            out.push(CODE_CHARSET[usize::from(b) % CODE_CHARSET.len()] as char);
            if out.len() == CODE_LEN {
                break;
            }
        }
    }
    out
}

/// Record and fulfill a grant for `session`; returns the loopback URL
/// carrying `code` and `state`.
pub async fn issue_code(
    depot: &Depot,
    rng: &mut BoxRng,
    clock: &BoxClock,
    validated: ValidatedRequest,
    request: &NativeRequest,
    session: &BrowserSession,
    ip: Option<std::net::IpAddr>,
    user_agent: Option<String>,
) -> Result<String, GrantError> {
    let mut repo = depot.repo().await?;
    let code = AuthorizationCode {
        code: random_code(rng),
        pkce: Some(Pkce {
            challenge_method: request.code_challenge_method.clone(),
            challenge: request.code_challenge.clone(),
        }),
    };
    let grant = repo
        .oauth2_authorization_grant()
        .add(
            rng,
            clock,
            &validated.client,
            validated.redirect_uri,
            validated.raw_redirect_uri,
            validated.scope,
            Some(code),
            Some(request.state.clone()),
            None,
            ResponseMode::Query,
            false,
            Some(NATIVE_PASSWORD_HINT.to_owned()),
            None,
        )
        .await?;
    repo.save().await?;
    let decision = accept_authorization_consent(
        depot.repo().await?,
        rng,
        clock,
        &depot.key_store()?,
        &depot.url_builder()?,
        depot.policy_factory()?.as_ref(),
        session,
        grant.id,
        ip,
        user_agent,
    )
    .await
    .map_err(map_access_error)?;
    decision.redirect_url().map_err(map_access_error)
}

pub fn map_access_error(error: OAuth2AccessError) -> GrantError {
    match error {
        OAuth2AccessError::PolicyViolation => GrantError::Refused(NativeRefusal::ScopeNotAllowed),
        OAuth2AccessError::Repository(error) => GrantError::Route(error.into()),
        other => GrantError::Route(RouteError::Internal(Box::new(other))),
    }
}
