//! Hagency native sign-in API (`/api/v1/native/*`): the desktop signs in or
//! creates an account with a username and password over plain JSON — no
//! Pasion page, no browser, no cookie — and receives an OAuth authorization
//! code for its own PKCE request, which it exchanges at `/oauth2/token`.
//!
//! Only the one public client named by `account.native_client_id`, with an
//! exact loopback redirect URI, PKCE S256, a `state` and Matrix device scopes,
//! is served. Password checks and registrations go through Pasion's normal
//! pipelines, so rate limits, password policy, locked and deactivated
//! accounts behave exactly as on the web pages.

use pasion_iana::oauth::PkceCodeChallengeMethod;
use salvo::{oapi::ToSchema, prelude::*};
use serde::{Deserialize, Serialize};

use self::{grant::GrantError, policy::NativeRefusal};
use crate::handlers::common::{DepotExt, RouteError};

pub mod grant;
pub mod password;
pub mod policy;
pub mod sso;
#[cfg(test)]
mod sso_tests;
#[cfg(test)]
mod tests;
pub mod username;

/// The SDK's authorization request plus the person's credentials.
#[derive(Deserialize, ToSchema)]
pub struct NativeRequest {
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: String,
    pub state: String,
    pub code_challenge: String,
    #[salvo(schema(value_type = String))]
    pub code_challenge_method: PkceCodeChallengeMethod,
    pub username: String,
    pub password: String,
}

/// `redirect_url` is the client's loopback callback with `code` and `state`.
#[derive(Serialize, ToSchema)]
pub struct NativeResponse {
    pub status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
}

impl NativeResponse {
    fn success(redirect_url: String, username: String) -> Self {
        Self { status: "success", error: None, redirect_url: Some(redirect_url), username: Some(username) }
    }

    fn error(code: impl Into<String>) -> Self {
        Self { status: "error", error: Some(code.into()), redirect_url: None, username: None }
    }
}

/// HTTP status for an API error code (credentials stay 401, abuse 429).
fn status_for(code: &str) -> StatusCode {
    match code {
        "native_auth_disabled" => StatusCode::NOT_FOUND,
        "client_not_allowed" | "scope_not_allowed" | "account_locked" | "account_deactivated" => {
            StatusCode::FORBIDDEN
        }
        "invalid_credentials" => StatusCode::UNAUTHORIZED,
        "rate_limited" => StatusCode::TOO_MANY_REQUESTS,
        _ => StatusCode::BAD_REQUEST,
    }
}

/// Write an error body with its status.
fn render_error(res: &mut Response, code: &str) {
    res.status_code(status_for(code));
    res.render(Json(NativeResponse::error(code)));
}

/// Render the outcome of a grant step: refusals become JSON errors, route
/// errors propagate.
fn render_grant(res: &mut Response, result: Result<NativeResponse, GrantError>) -> Result<(), RouteError> {
    match result {
        Ok(body) => {
            res.render(Json(body));
            Ok(())
        }
        Err(GrantError::Refused(refusal)) => {
            render_error(res, refusal.code());
            Ok(())
        }
        Err(GrantError::Route(error)) => Err(error),
    }
}

/// What the desktop needs before showing the sign-in screen.
#[derive(Serialize, ToSchema)]
pub struct NativeConfig {
    pub client_id: String,
    pub password_registration_enabled: bool,
    pub providers: Vec<NativeProvider>,
}

#[derive(Serialize, ToSchema)]
pub struct NativeProvider {
    pub id: String,
    pub brand_name: Option<String>,
    pub human_name: Option<String>,
}

/// `GET /api/v1/native/config`: 404 when the native API is not configured.
#[endpoint]
pub async fn get_config(depot: &Depot, res: &mut Response) -> Result<(), RouteError> {
    let site_config = depot.site_config()?;
    let Some(client_id) = site_config.native_client_id.clone() else {
        render_error(res, NativeRefusal::Disabled.code());
        return Ok(());
    };
    let mut repo = depot.repo().await?;
    let providers =
        crate::handlers::account::service::access::load_enabled_upstream_providers(&mut repo).await?;
    repo.cancel().await?;
    res.render(Json(NativeConfig {
        client_id,
        password_registration_enabled: site_config.password_registration_enabled,
        providers: providers
            .into_iter()
            .map(|p| NativeProvider { id: p.id.to_string(), brand_name: p.brand_name, human_name: p.human_name })
            .collect(),
    }));
    Ok(())
}

/// Routes mounted under `/api/v1`.
pub fn router() -> Router {
    Router::with_path("native")
        .push(Router::with_path("config").get(get_config))
        .push(Router::with_path("login").post(password::post_login))
        .push(Router::with_path("register").post(password::post_register))
        .push(Router::with_path("username-available").get(username::get_available))
}
