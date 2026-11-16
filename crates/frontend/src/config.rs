/// A server-injected error state, rendered instead of the normal SPA when
/// the backend detects an account-level problem during session loading.
#[derive(Debug, Clone, PartialEq)]
pub struct AppError {
    /// One of: `account_deactivated`, `account_locked`, `session_ended`,
    /// `generic`.
    pub kind: String,
    /// The local username (without `@` prefix or `:server` suffix), if known.
    pub username: Option<String>,
    /// Human-readable error description, if any.
    pub description: Option<String>,
}

/// Application configuration, loaded from `window.APP_CONFIG` or defaults.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct AppConfig {
    pub root: String,
    pub api_endpoint: String,
    /// If set, the backend wants the frontend to display an error page
    /// instead of the normal router.
    pub error: Option<AppError>,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            root: "/".to_owned(),
            api_endpoint: "/api/v1".to_owned(),
            error: None,
        }
    }
}

thread_local! {
    /// Cached, lazily-resolved app configuration. The underlying source
    /// (`window.APP_CONFIG`) never changes during a session, so we parse it
    /// once.
    static CONFIG_CACHE: std::cell::RefCell<Option<AppConfig>> =
        const { std::cell::RefCell::new(None) };
    /// Cached resolved API base URL.
    static API_BASE_URL_CACHE: std::cell::RefCell<Option<String>> =
        const { std::cell::RefCell::new(None) };
}

/// Get the app configuration.
/// In WASM, this reads from `window.APP_CONFIG`. Otherwise uses defaults.
/// The result is cached per thread (WASM is single-threaded) so repeated
/// calls don't re-parse the JS config.
pub fn get_config() -> AppConfig {
    if let Some(cfg) = CONFIG_CACHE.with(|c| c.borrow().clone()) {
        return cfg;
    }
    let cfg = resolve_config();
    CONFIG_CACHE.with(|c| *c.borrow_mut() = Some(cfg.clone()));
    cfg
}

fn resolve_config() -> AppConfig {
    #[cfg(target_arch = "wasm32")]
    {
        use web_sys::window;

        if let Some(win) = window() {
            if let Ok(val) = js_sys::Reflect::get(&win, &"APP_CONFIG".into()) {
                if !val.is_undefined() && !val.is_null() {
                    let root = js_sys::Reflect::get(&val, &"root".into())
                        .ok()
                        .and_then(|v| v.as_string())
                        .unwrap_or_else(|| "/".to_string());
                    let api_endpoint = js_sys::Reflect::get(&val, &"api_endpoint".into())
                        .ok()
                        .and_then(|v| v.as_string())
                        .or_else(|| {
                            js_sys::Reflect::get(&val, &"apiEndpoint".into())
                                .ok()
                                .and_then(|v| v.as_string())
                        })
                        .unwrap_or_else(|| "/api/v1".to_string());

                    let error = read_error_from_js(&val);

                    return AppConfig {
                        root,
                        api_endpoint,
                        error,
                    };
                }
            }
        }
    }

    AppConfig::default()
}

/// Try to read the optional `error` object from the JS config.
#[cfg(target_arch = "wasm32")]
fn read_error_from_js(config: &web_sys::wasm_bindgen::JsValue) -> Option<AppError> {
    let err = js_sys::Reflect::get(config, &"error".into()).ok()?;
    if err.is_undefined() || err.is_null() {
        return None;
    }

    let kind = js_sys::Reflect::get(&err, &"kind".into())
        .ok()
        .and_then(|v| v.as_string())?;

    let username = js_sys::Reflect::get(&err, &"username".into())
        .ok()
        .and_then(|v| v.as_string());

    let description = js_sys::Reflect::get(&err, &"description".into())
        .ok()
        .and_then(|v| v.as_string());

    Some(AppError {
        kind,
        username,
        description,
    })
}

/// Resolve the full API base URL based on the current location.
/// Cached per thread since neither the configured endpoint nor the document
/// origin change during a session.
pub fn api_base_url() -> String {
    if let Some(url) = API_BASE_URL_CACHE.with(|c| c.borrow().clone()) {
        return url;
    }
    let url = resolve_api_base_url();
    API_BASE_URL_CACHE.with(|c| *c.borrow_mut() = Some(url.clone()));
    url
}

fn resolve_api_base_url() -> String {
    let config = get_config();

    #[cfg(target_arch = "wasm32")]
    {
        if let Some(win) = web_sys::window() {
            if let Ok(location) = win.location().href() {
                if let Ok(base) = web_sys::Url::new_with_base(&config.api_endpoint, &location) {
                    return base.href();
                }
            }
        }
    }

    config.api_endpoint
}

/// Resolve an application-local path under the runtime mount point.
pub fn app_path(path: &str) -> String {
    let root = get_config().root;
    let prefix = root.trim_end_matches('/');
    if !prefix.is_empty() && (path == prefix || path.starts_with(&format!("{prefix}/"))) {
        path.to_owned()
    } else {
        format!("{prefix}/{}", path.trim_start_matches('/'))
    }
}

/// Turn a server-relative URL from the backend (e.g. `/auth/register/steps/1`)
/// into a path relative to the router's mount point (`/register/steps/1`).
///
/// The router's history already prepends the mount point, so pushing the
/// backend URL unchanged produced `/auth/auth/...` and a "Page not found".
/// Absolute URLs and paths outside the mount point are returned unchanged.
pub fn router_path(url: &str) -> String {
    strip_mount_point(&get_config().root, url)
}

fn strip_mount_point(root: &str, url: &str) -> String {
    let prefix = root.trim_end_matches('/');
    if prefix.is_empty() || !url.starts_with('/') {
        return url.to_owned();
    }
    match url.strip_prefix(prefix) {
        Some("") => "/".to_owned(),
        Some(rest) if rest.starts_with(['/', '?', '#']) => {
            if rest.starts_with('/') {
                rest.to_owned()
            } else {
                format!("/{rest}")
            }
        }
        _ => url.to_owned(),
    }
}

#[cfg(test)]
mod router_path_tests {
    use super::strip_mount_point;

    #[test]
    fn backend_redirect_under_mount_point_is_not_doubled() {
        assert_eq!(
            strip_mount_point("/auth/", "/auth/register/steps/01J"),
            "/register/steps/01J"
        );
        assert_eq!(
            strip_mount_point("/auth", "/auth/consent/7?x=1"),
            "/consent/7?x=1"
        );
        assert_eq!(strip_mount_point("/auth/", "/auth"), "/");
        assert_eq!(strip_mount_point("/auth/", "/auth?next=1"), "/?next=1");
    }

    #[test]
    fn other_urls_are_left_alone() {
        assert_eq!(
            strip_mount_point("/", "/register/steps/1"),
            "/register/steps/1"
        );
        assert_eq!(strip_mount_point("/auth/", "/authority"), "/authority");
        assert_eq!(
            strip_mount_point("/auth/", "https://example.com/auth/x"),
            "https://example.com/auth/x"
        );
        assert_eq!(strip_mount_point("/auth/", "/other/x"), "/other/x");
    }
}
