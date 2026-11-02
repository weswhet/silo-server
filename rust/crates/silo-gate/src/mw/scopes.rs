//! `api_key_scopes.go` and the route half of `remote_playback.go`.

use std::collections::HashMap;
use std::sync::LazyLock;

use silo_gocompat::regexp::GoRegex as Regexp;
use silo_http::Request;

use super::route_tables::{API_KEY_SCOPE_ROUTES, REMOTE_PLAYBACK_ROUTES};

type Compiled = Vec<(&'static str, Regexp)>;

static SCOPE_ROUTES: LazyLock<HashMap<&'static str, Compiled>> = LazyLock::new(|| {
    let mut map: HashMap<&'static str, Compiled> = HashMap::new();
    for (scope, method, pattern) in API_KEY_SCOPE_ROUTES {
        map.entry(scope)
            .or_default()
            .push((method, Regexp::must_compile(pattern)));
    }
    map
});

static PLAYBACK_ROUTES: LazyLock<Compiled> = LazyLock::new(|| {
    REMOTE_PLAYBACK_ROUTES
        .iter()
        .map(|(method, pattern)| (*method, Regexp::must_compile(pattern)))
        .collect()
});

/// `path.Clean(p) == p`.
fn is_clean(path: &str) -> bool {
    silo_gocompat::path::clean(path) == path
}

/// `unambiguousRequestPath`.
pub fn unambiguous_request_path(r: &Request) -> Option<&str> {
    if !r.url.raw_path.is_empty() || r.url.path.is_empty() {
        return None;
    }
    let path = std::str::from_utf8(&r.url.path).ok()?;
    is_clean(path).then_some(path)
}

/// `apiKeyScopesAllow`.
pub fn api_key_scopes_allow(scopes: &[String], r: &Request) -> bool {
    if scopes.is_empty() {
        return true;
    }
    let Some(path) = unambiguous_request_path(r) else {
        return false;
    };
    scopes_allow_path(scopes, &r.method, path)
}

/// The match half of `apiKeyScopesAllow`, for `RevalidateCurrent`'s synthetic request.
pub fn scopes_allow_path(scopes: &[String], method: &str, path: &str) -> bool {
    scopes.iter().any(|scope| {
        SCOPE_ROUTES.get(scope.as_str()).is_some_and(|routes| {
            routes
                .iter()
                .any(|(m, pattern)| *m == method && pattern.match_string(path))
        })
    })
}

/// `remotePlaybackAllowsRoute`.
pub fn remote_playback_allows_route(method: &str, path: &str) -> bool {
    if path.is_empty() || !is_clean(path) {
        return false;
    }
    PLAYBACK_ROUTES
        .iter()
        .any(|(m, pattern)| *m == method && pattern.match_string(path))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_scoped_key_reaches_only_listed_routes() {
        let scopes = ["libraries:read".to_owned()];
        assert!(scopes_allow_path(&scopes, "GET", "/api/v2/user/libraries"));
        assert!(!scopes_allow_path(&scopes, "GET", "/api/v2/account/me"));
        assert!(!scopes_allow_path(
            &scopes,
            "POST",
            "/api/v2/user/libraries"
        ));
    }

    #[test]
    fn a_handoff_refuses_v1_and_unclean_paths() {
        assert!(remote_playback_allows_route("GET", "/api/v2/account/me"));
        assert!(!remote_playback_allows_route("GET", "/api/v1/auth/me"));
        assert!(!remote_playback_allows_route("GET", "/api/v2//account/me"));
        assert!(!remote_playback_allows_route(
            "GET",
            "/api/v2/x/../account/me"
        ));
        assert!(!remote_playback_allows_route(
            "GET",
            "/api/v2/admin/sessions"
        ));
    }
}
