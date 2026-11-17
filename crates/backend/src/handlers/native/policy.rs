//! Pure checks for the native sign-in API: which client, redirect URI, PKCE
//! challenge and scopes it accepts. Kept free of I/O so each rule is unit
//! tested on its own.

use oauth2_types::scope::Scope;
use pasion_iana::oauth::PkceCodeChallengeMethod as CodeChallengeMethod;
use url::Url;

/// Scope tokens a native sign-in may ask for. Anything else (admin scopes,
/// other APIs) is refused: the desktop needs exactly a Matrix device.
const ALLOWED_EXACT_SCOPES: &[&str] = &[
    "openid",
    "urn:matrix:client:api:*",
    "urn:matrix:org.matrix.msc2967.client:api:*",
];
/// Prefixes of the per-device scope the Matrix SDK adds.
const DEVICE_SCOPE_PREFIXES: &[&str] = &[
    "urn:matrix:client:device:",
    "urn:matrix:org.matrix.msc2967.client:device:",
];
/// RFC 7636: a code challenge is 43–128 characters.
const PKCE_CHALLENGE_LEN: std::ops::RangeInclusive<usize> = 43..=128;
/// Hosts a native client may receive its code on (RFC 8252 loopback).
const LOOPBACK_HOSTS: &[&str] = &["127.0.0.1", "localhost", "[::1]"];

/// Why a native request was refused; `code()` is the stable API error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeRefusal {
    Disabled,
    ClientNotAllowed,
    RedirectNotLoopback,
    PkceRequired,
    StateRequired,
    ScopeNotAllowed,
}

impl NativeRefusal {
    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            Self::Disabled => "native_auth_disabled",
            Self::ClientNotAllowed => "client_not_allowed",
            Self::RedirectNotLoopback => "redirect_uri_not_loopback",
            Self::PkceRequired => "pkce_s256_required",
            Self::StateRequired => "state_required",
            Self::ScopeNotAllowed => "scope_not_allowed",
        }
    }
}

/// The configured native client must be the one asking.
pub fn check_client(configured: Option<&str>, client_id: &str) -> Result<(), NativeRefusal> {
    match configured {
        None => Err(NativeRefusal::Disabled),
        Some(id) if id == client_id => Ok(()),
        Some(_) => Err(NativeRefusal::ClientNotAllowed),
    }
}

/// An `http` loopback URL without credentials or fragment.
#[must_use]
pub fn is_loopback(url: &Url) -> bool {
    url.scheme() == "http"
        && url.username().is_empty()
        && url.password().is_none()
        && url.fragment().is_none()
        && url.host_str().is_some_and(|host| LOOPBACK_HOSTS.contains(&host))
}

/// Only S256 with a well-formed challenge.
pub fn check_pkce(method: &CodeChallengeMethod, challenge: &str) -> Result<(), NativeRefusal> {
    let well_formed = PKCE_CHALLENGE_LEN.contains(&challenge.len())
        && challenge.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    if *method == CodeChallengeMethod::S256 && well_formed {
        Ok(())
    } else {
        Err(NativeRefusal::PkceRequired)
    }
}

/// A non-empty `state` the client correlates its response with.
pub fn check_state(state: &str) -> Result<(), NativeRefusal> {
    if state.trim().is_empty() { Err(NativeRefusal::StateRequired) } else { Ok(()) }
}

/// Every scope token must be a Matrix client API or device scope.
pub fn check_scope(scope: &Scope) -> Result<(), NativeRefusal> {
    let allowed = |token: &str| {
        ALLOWED_EXACT_SCOPES.contains(&token)
            || DEVICE_SCOPE_PREFIXES
                .iter()
                .any(|prefix| token.strip_prefix(prefix).is_some_and(|rest| !rest.is_empty()))
    };
    if scope.iter().all(|token| allowed(token)) {
        Ok(())
    } else {
        Err(NativeRefusal::ScopeNotAllowed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    #[test]
    fn only_the_configured_client_is_accepted() {
        assert_eq!(check_client(None, "a"), Err(NativeRefusal::Disabled));
        assert_eq!(check_client(Some("a"), "b"), Err(NativeRefusal::ClientNotAllowed));
        assert_eq!(check_client(Some("a"), "a"), Ok(()));
    }

    #[test]
    fn redirect_must_be_plain_http_loopback() {
        for ok in ["http://127.0.0.1:5000/", "http://localhost/cb", "http://[::1]:9/"] {
            assert!(is_loopback(&Url::parse(ok).unwrap()), "{ok}");
        }
        for bad in [
            "https://127.0.0.1/",
            "http://example.com/",
            "http://127.0.0.1.example.com/",
            "http://u:p@127.0.0.1/",
            "http://127.0.0.1/#x",
        ] {
            assert!(!is_loopback(&Url::parse(bad).unwrap()), "{bad}");
        }
    }

    #[test]
    fn pkce_must_be_s256_and_well_formed() {
        assert_eq!(check_pkce(&CodeChallengeMethod::S256, CHALLENGE), Ok(()));
        assert!(check_pkce(&CodeChallengeMethod::Plain, CHALLENGE).is_err());
        assert!(check_pkce(&CodeChallengeMethod::S256, "short").is_err());
        assert!(check_pkce(&CodeChallengeMethod::S256, &format!("{}!", &CHALLENGE[1..])).is_err());
    }

    #[test]
    fn state_is_required() {
        assert!(check_state(" ").is_err());
        assert_eq!(check_state("s1"), Ok(()));
    }

    #[test]
    fn only_matrix_device_scopes_pass() {
        let ok: Scope = "openid urn:matrix:client:api:* urn:matrix:client:device:ABC".parse().unwrap();
        assert_eq!(check_scope(&ok), Ok(()));
        let msc: Scope = "openid urn:matrix:org.matrix.msc2967.client:api:* urn:matrix:org.matrix.msc2967.client:device:X"
            .parse()
            .unwrap();
        assert_eq!(check_scope(&msc), Ok(()));
        for bad in ["urn:pasion:admin", "openid urn:matrix:client:device:", "urn:synapse:admin:*"] {
            assert!(check_scope(&bad.parse().unwrap()).is_err(), "{bad}");
        }
    }
}
