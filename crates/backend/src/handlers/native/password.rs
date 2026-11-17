//! `POST /api/v1/native/login` and `/register`: credentials in, an
//! authorization code for the caller's own PKCE request out. No session
//! cookie is ever set; the Pasion browser session created by the password
//! check exists only to fulfill this one grant.

use pasion_data::BrowserSession;
use salvo::prelude::*;
use zeroize::Zeroizing;

use super::{NativeRequest, NativeResponse, grant, render_error, render_grant};
use crate::handlers::{
    RequesterFingerprint,
    account::service::{
        access::{PasswordLoginError, PasswordLoginOutcome, PasswordLoginRequest, login_with_password},
        registration::{
            BeginPasswordRegistrationIssue, BeginPasswordRegistrationRequest, BeginPasswordRegistrationResult,
            RegistrationFinishOutcome, begin_password_registration, finish_registration,
            set_registration_display_name,
        },
    },
    common::{DepotExt, RouteError, extract_bound_activity_tracker, make_clock, make_rng},
};

/// Request context shared by both endpoints.
struct Caller {
    ip: Option<std::net::IpAddr>,
    requester: RequesterFingerprint,
    user_agent: Option<String>,
}

fn caller(req: &Request, depot: &Depot) -> Caller {
    let ip = extract_bound_activity_tracker(req, depot).ip();
    Caller {
        ip,
        requester: ip.map(RequesterFingerprint::new).unwrap_or(RequesterFingerprint::EMPTY),
        user_agent: req.header::<String>("user-agent"),
    }
}

async fn parse(req: &mut Request) -> Result<NativeRequest, RouteError> {
    req.parse_json().await.map_err(|_| RouteError::BadRequest("invalid json body".into()))
}

/// Finish with a code for `session`, or the refusal.
async fn respond_with_code(
    depot: &Depot,
    res: &mut Response,
    validated: grant::ValidatedRequest,
    input: &NativeRequest,
    session: &BrowserSession,
    caller: Caller,
) -> Result<(), RouteError> {
    let (mut rng, clock) = (make_rng(), make_clock());
    let username = session.user.username.clone();
    let result = grant::issue_code(depot, &mut rng, &clock, validated, input, session, caller.ip, caller.user_agent)
        .await
        .map(|url| NativeResponse::success(url, username));
    render_grant(res, result)
}

/// Map a password outcome to the authenticated session or an error code.
fn login_outcome(outcome: PasswordLoginOutcome) -> Result<BrowserSession, &'static str> {
    match outcome {
        PasswordLoginOutcome::Authenticated { user_session, .. } => Ok(user_session),
        PasswordLoginOutcome::Disabled => Err("password_login_disabled"),
        PasswordLoginOutcome::InvalidCredentials => Err("invalid_credentials"),
        PasswordLoginOutcome::RateLimited => Err("rate_limited"),
        PasswordLoginOutcome::AccountDeactivated => Err("account_deactivated"),
        // Locked covers accounts an administrator has not approved yet.
        PasswordLoginOutcome::AccountLocked => Err("account_locked"),
    }
}

#[endpoint]
pub async fn post_login(req: &mut Request, depot: &Depot, res: &mut Response) -> Result<(), RouteError> {
    let input = parse(req).await?;
    let caller = caller(req, depot);
    let validated = match grant::validate(depot, &input).await {
        Ok(v) => v,
        Err(error) => return render_grant(res, Err(error)),
    };
    let username = crate::util::normalize_username(&input.username).unwrap_or_else(|| input.username.clone());
    let outcome = login_with_password(
        depot.repo().await?,
        &mut make_rng(),
        &make_clock(),
        &depot.password_manager()?,
        &depot.limiter()?,
        depot.homeserver()?.as_ref(),
        &depot.site_config()?,
        PasswordLoginRequest {
            username_or_email: username,
            password: Zeroizing::new(input.password.clone()),
            user_agent: caller.user_agent.clone(),
            requester: caller.requester,
            skip_requester_limit: false,
        },
    )
    .await
    .map_err(|error| match error {
        PasswordLoginError::Repository(error) => RouteError::from(error),
        PasswordLoginError::Password(error) => RouteError::Internal(error.into()),
    })?;
    match login_outcome(outcome) {
        Ok(session) => respond_with_code(depot, res, validated, &input, &session, caller).await,
        Err(code) => {
            render_error(res, code);
            Ok(())
        }
    }
}

/// Create the account through Pasion's registration pipeline; returns the
/// signed-in session, or the API error code.
async fn register(depot: &Depot, input: &NativeRequest, caller: &Caller) -> Result<Result<BrowserSession, String>, RouteError> {
    let site_config = depot.site_config()?;
    let (mut rng, clock) = (make_rng(), make_clock());
    let begun = begin_password_registration(
        depot.repo().await?,
        &mut rng,
        &clock,
        &depot.password_manager()?,
        depot.homeserver()?.as_ref(),
        depot.policy_factory()?.as_ref(),
        &depot.limiter()?,
        BeginPasswordRegistrationRequest {
            username: input.username.clone(),
            email: None,
            phone: None,
            password: input.password.clone(),
            password_confirm: input.password.clone(),
            user_agent: caller.user_agent.clone(),
            ip_address: caller.ip,
            requester: caller.requester,
            notification_language: "en".to_owned(),
            post_auth_action: None,
            password_registration_enabled: site_config.password_registration_enabled,
            password_registration_contact_required: site_config.password_registration_contact_required,
            terms_url: site_config.tos_uri.clone(),
        },
    )
    .await
    .map_err(|error| RouteError::Internal(Box::new(error)))?;
    let started = match begun {
        BeginPasswordRegistrationResult::Started(started) => started,
        BeginPasswordRegistrationResult::Rejected { issues } => {
            return Ok(Err(register_issue_code(&issues)));
        }
    };
    // The desktop shows the username until the person picks a display name.
    let name = started.registration.username.clone();
    set_registration_display_name(depot.repo().await?, started.registration.id, Some(name), false)
        .await
        .map_err(|error| RouteError::Internal(Box::new(error)))?;
    let finished = finish_registration(
        depot.repo().await?,
        &mut rng,
        &clock,
        depot.homeserver()?.as_ref(),
        started.registration.id,
        None,
        site_config.registration_token_required,
        site_config.bootstrap_admin_token.as_deref(),
        None,
        caller.user_agent.clone(),
    )
    .await
    .map_err(|error| RouteError::Internal(Box::new(error)))?;
    Ok(match finished {
        RegistrationFinishOutcome::Completed(done) => Ok(done.user_session),
        // E.g. email verification or a registration token still required:
        // no account session, so no code.
        RegistrationFinishOutcome::Rejected { error } => Err(error.to_owned()),
    })
}

/// One stable error code for the desktop: abuse first, then the username,
/// then the rest in Pasion's own wording.
fn register_issue_code(issues: &[BeginPasswordRegistrationIssue]) -> String {
    use BeginPasswordRegistrationIssue as I;
    if issues.contains(&I::RateLimited) {
        "rate_limited".to_owned()
    } else if issues.contains(&I::UsernameInvalid) {
        "username_invalid".to_owned()
    } else {
        issues.first().map_or_else(|| "registration_rejected".to_owned(), I::as_api_error)
    }
}

#[endpoint]
pub async fn post_register(req: &mut Request, depot: &Depot, res: &mut Response) -> Result<(), RouteError> {
    let input = parse(req).await?;
    let caller = caller(req, depot);
    let validated = match grant::validate(depot, &input).await {
        Ok(v) => v,
        Err(error) => return render_grant(res, Err(error)),
    };
    match register(depot, &input, &caller).await? {
        Ok(session) => respond_with_code(depot, res, validated, &input, &session, caller).await,
        Err(code) => {
            render_error(res, &code);
            Ok(())
        }
    }
}
