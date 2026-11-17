//! `GET /api/v1/native/username-available?username=`: live availability for
//! the sign-up field. Public, so it is rate limited per IP and answers only
//! "available / taken / invalid" with the lowercased name it checked.

use pasion_data::RepositoryAccess;
use salvo::{oapi::ToSchema, prelude::*};
use serde::Serialize;

use crate::handlers::{
    RequesterFingerprint,
    common::{DepotExt, RouteError, extract_bound_activity_tracker},
};

#[derive(Serialize, ToSchema, Debug, PartialEq, Eq)]
pub struct Availability {
    /// The name as the server would register it (lowercased), if valid.
    pub username: Option<String>,
    /// `available`, `taken` or `invalid`.
    pub status: &'static str,
}

/// Pure part: normalize and judge syntax before any lookup.
#[must_use]
pub fn normalized(input: &str) -> Option<String> {
    crate::util::normalize_username(input)
}

#[endpoint]
pub async fn get_available(req: &mut Request, depot: &Depot, res: &mut Response) -> Result<(), RouteError> {
    let input: String = req.query("username").unwrap_or_default();
    let Some(username) = normalized(&input) else {
        res.render(Json(Availability { username: None, status: "invalid" }));
        return Ok(());
    };
    let requester = extract_bound_activity_tracker(req, depot)
        .ip()
        .map(RequesterFingerprint::new)
        .unwrap_or(RequesterFingerprint::EMPTY);
    if depot.limiter()?.check_username_lookup(requester).await.is_err() {
        res.status_code(StatusCode::TOO_MANY_REQUESTS);
        res.render(Json(serde_json::json!({"status": "error", "error": "rate_limited"})));
        return Ok(());
    }
    let mut repo = depot.repo().await?;
    let exists = repo.user().exists(&username).await?;
    repo.cancel().await?;
    let free = if exists {
        false
    } else {
        match depot.homeserver()?.is_localpart_available(&username).await {
            Ok(free) => free,
            Err(error) => {
                tracing::warn!(error = &*error as &dyn std::error::Error, "localpart availability check failed");
                res.status_code(StatusCode::SERVICE_UNAVAILABLE);
                res.render(Json(serde_json::json!({"status": "error", "error": "homeserver_unavailable"})));
                return Ok(());
            }
        }
    };
    res.render(Json(Availability {
        username: Some(username),
        status: if free { "available" } else { "taken" },
    }));
    Ok(())
}
