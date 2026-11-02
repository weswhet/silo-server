//! Sign-in flows that take several requests: each later step uses what an earlier answer gave each side,
//! so the rows behind them reach a success, not only their refusals.

use crate::model::*;
use crate::plan::Builder;

/// One step. A path is the route's template; `at` fills it in with each side's facts.
pub(crate) struct Step<'a> {
    pub(crate) surface: Surface,
    pub(crate) method: &'a str,
    pub(crate) route: &'a str,
    pub(crate) name: &'a str,
    pub(crate) identity: Identity,
    pub(crate) at: Option<&'a str>,
    pub(crate) bearer: Option<&'a str>,
    pub(crate) profile: Option<&'a str>,
    pub(crate) headers: &'a [(&'a str, &'a str)],
    pub(crate) query: &'a [(&'a str, &'a str)],
    pub(crate) body: Option<&'a str>,
    pub(crate) capture: &'a [(&'a str, &'a str)],
    pub(crate) empty_users: bool,
}

impl<'a> Step<'a> {
    pub(crate) fn new(surface: Surface, method: &'a str, route: &'a str, name: &'a str) -> Self {
        Self {
            surface,
            method,
            route,
            name,
            identity: Identity::Anon,
            at: None,
            bearer: None,
            profile: None,
            headers: &[],
            query: &[],
            body: None,
            capture: &[],
            empty_users: false,
        }
    }
}

pub(crate) struct Flows<'b, 'c> {
    pub(crate) b: &'b mut Builder<'c>,
    pub(crate) seq: usize,
    /// Sorts these steps among the run's flows.
    pub(crate) prefix: &'static str,
}

impl Flows<'_, '_> {
    pub(crate) fn step(&mut self, s: Step) {
        let key = (s.surface, s.method.to_string(), s.route.to_string());
        let Some(&idx) = self.b.index.get(&key) else {
            self.b.skip(
                format!("{} {} {}", s.surface.name(), s.method, s.route),
                "auth flow step's route is not in the sources",
            );
            return;
        };
        self.seq += 1;
        let mut c = self.b.blank(
            idx,
            &format!("flow:{}", s.name),
            Phase::MutateScenarios,
            s.identity,
        );
        // After every scenario, so the flows see the seed's accounts and passwords.
        c.sort_key = format!("{}/{:04}", self.prefix, self.seq);
        c.may_mutate = is_mutating(s.method);
        // A required parameter's example would make a second header field beside the case's own.
        c.headers.clear();
        c.query = s
            .query
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        if let Some(at) = s.at {
            c.path = at.to_string();
        }
        if let Some(token) = s.bearer {
            c.headers
                .push(("Authorization".to_string(), format!("Bearer ${{{token}}}")));
        }
        if let Some(profile) = s.profile {
            c.headers
                .push(("X-Profile-Id".to_string(), profile.to_string()));
        }
        c.headers.extend(
            s.headers
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string())),
        );
        if let Some(body) = s.body {
            c.body = Some(body.as_bytes().to_vec());
            c.content_type = Some("application/json".to_string());
        }
        c.capture_facts = s
            .capture
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        c.needs_empty_users = s.empty_users;
        // The session's last-seen write is asynchronous, and the step before this one caused it.
        if s.name.ends_with(":sessions") {
            c.wait_ms = LAST_SEEN_WAIT_MS;
        }
        // Nothing can log in afterwards until the next stage's reset, which restores the seed.
        if s.empty_users || s.route.contains("/auth/setup") || s.name == "v1:setup_owner" {
            c.may_mutate = false;
        }
        self.b.push(c);
    }
}

const LAST_SEEN_WAIT_MS: u64 = 500;
const USER_LOGIN: &str =
    "{\"username\":\"${member_username}\",\"password\":\"${member_password}\"}";
const USER_PROFILE: &str = "${user_profile_id}";
const ADMIN_PROFILE: &str = "${admin_profile_id}";

fn sessions(f: &mut Flows) {
    use Surface::{ApiV1, ApiV2};
    for (surface, login, refresh, logout, sessions, one) in [
        (
            ApiV1,
            "/api/v1/auth/login",
            "/api/v1/auth/refresh",
            "/api/v1/auth/logout",
            "/api/v1/auth/sessions",
            "/api/v1/auth/sessions/{id}",
        ),
        (
            ApiV2,
            "/api/v2/auth/login",
            "/api/v2/auth/refresh",
            "/api/v2/auth/logout",
            "/api/v2/auth/sessions",
            "/api/v2/auth/sessions/{id}",
        ),
    ] {
        let v = surface.name();
        let tag = |what: &str| format!("{v}:{what}");
        let mut s = Step::new(surface, "POST", login, "");
        let n = tag("login");
        s.name = &n;
        s.body = Some(USER_LOGIN);
        s.headers = &[
            ("User-Agent", "conformance-flow"),
            ("X-Silo-Device-Id", "flow-device-1"),
            ("X-Silo-Device-Name", "Flow Device"),
            ("X-Silo-Device-Platform", "flowos"),
        ];
        s.capture = &[
            ("flow_access", "/access_token"),
            ("flow_refresh", "/refresh_token"),
        ];
        f.step(s);

        let n = tag("login_email");
        let mut s = Step::new(surface, "POST", login, &n);
        s.body = Some("{\"username\":\"${member_email}\",\"password\":\"${member_password}\"}");
        s.capture = &[("flow_other_access", "/access_token")];
        f.step(s);

        let n = tag("login_wrong_password");
        let mut s = Step::new(surface, "POST", login, &n);
        s.body = Some("{\"username\":\"${member_username}\",\"password\":\"wrong-password\"}");
        f.step(s);

        let n = tag("login_unknown_provider");
        let mut s = Step::new(surface, "POST", login, &n);
        s.body = Some(
            "{\"username\":\"${member_username}\",\"password\":\"${member_password}\",\"provider\":\"nope\"}",
        );
        f.step(s);

        let n = tag("refresh");
        let mut s = Step::new(surface, "POST", refresh, &n);
        s.body = Some("{\"refresh_token\":\"${flow_refresh}\"}");
        s.capture = &[("flow_access", "/access_token")];
        f.step(s);

        let n = tag("refresh_access_token");
        let mut s = Step::new(surface, "POST", refresh, &n);
        s.body = Some("{\"refresh_token\":\"${flow_access}\"}");
        f.step(s);

        let n = tag("touch");
        let mut s = Step::new(ApiV2, "GET", "/api/v2/account/me", &n);
        s.bearer = Some("flow_other_access");
        f.step(s);

        // The list holds the login above, and it is the newest row of the other token's session.
        let n = tag("sessions");
        let mut s = Step::new(surface, "GET", sessions, &n);
        s.bearer = Some("flow_other_access");
        s.capture = &[
            ("flow_other_id", "/current_session/id"),
            ("flow_other_id", "/sessions/0/id"),
        ];
        f.step(s);

        let n = tag("delete_session");
        let mut s = Step::new(surface, "DELETE", one, &n);
        let at = format!("{}/${{flow_other_id}}", sessions);
        s.at = Some(&at);
        s.bearer = Some("flow_access");
        f.step(s);

        let n = tag("deleted_session_refused");
        let mut s = Step::new(surface, "GET", sessions, &n);
        s.bearer = Some("flow_other_access");
        f.step(s);

        let n = tag("delete_session_again");
        let mut s = Step::new(surface, "DELETE", one, &n);
        s.at = Some(&at);
        s.bearer = Some("flow_access");
        f.step(s);

        let n = tag("logout");
        let mut s = Step::new(surface, "POST", logout, &n);
        s.bearer = Some("flow_access");
        f.step(s);

        let n = tag("refresh_revoked");
        let mut s = Step::new(surface, "POST", refresh, &n);
        s.body = Some("{\"refresh_token\":\"${flow_refresh}\"}");
        f.step(s);

        // A Go-served row reads what the native rows wrote.
        let n = tag("logged_out_token_on_go");
        let mut s = Step::new(ApiV2, "GET", "/api/v2/user/libraries", &n);
        s.bearer = Some("flow_access");
        f.step(s);
    }
}

fn plugin_launch(f: &mut Flows) {
    use Surface::{ApiV1, ApiV2};
    let mut s = Step::new(
        ApiV2,
        "POST",
        "/api/v2/auth/plugin-launch",
        "v2:plugin_launch",
    );
    s.identity = Identity::UserJwt;
    s.profile = Some(USER_PROFILE);
    f.step(s);
    let mut s = Step::new(
        ApiV2,
        "POST",
        "/api/v2/auth/plugin-launch",
        "v2:plugin_launch_secure",
    );
    s.identity = Identity::UserJwt;
    s.headers = &[("X-Forwarded-Proto", "https")];
    f.step(s);
    let mut s = Step::new(
        ApiV1,
        "POST",
        "/api/v1/auth/plugin-launch",
        "v1:plugin_launch_profile",
    );
    s.identity = Identity::UserJwt;
    s.profile = Some(USER_PROFILE);
    f.step(s);
}

fn device(f: &mut Flows) {
    use Surface::{ApiV1, ApiV2};
    const CODES: &[(&str, &str)] = &[
        ("flow_device", "/device_code"),
        ("flow_user_code", "/user_code"),
    ];
    let start = "{\"device_name\":\"Flow TV\",\"device_platform\":\"tvos\"}";
    let code_body = "{\"code\":\"${flow_user_code}\"}";
    let poll_body = "{\"device_code\":\"${flow_device}\"}";

    // Approved, collected, then read as consumed.
    let mut s = Step::new(ApiV2, "POST", "/api/v2/auth/device/start", "v2:start");
    s.body = Some(start);
    s.capture = CODES;
    f.step(s);
    let mut s = Step::new(ApiV2, "POST", "/api/v2/auth/device/poll", "v2:poll_pending");
    s.body = Some(poll_body);
    f.step(s);
    let mut s = Step::new(ApiV2, "GET", "/api/v2/auth/device", "v2:lookup");
    s.query = &[("code", "${flow_user_code}")];
    f.step(s);
    let mut s = Step::new(ApiV2, "POST", "/api/v2/auth/device/poll", "v2:poll_opened");
    s.body = Some(poll_body);
    f.step(s);
    let mut s = Step::new(
        ApiV2,
        "POST",
        "/api/v2/auth/device/approve",
        "v2:approve_api_key",
    );
    s.identity = Identity::User;
    s.body = Some(code_body);
    f.step(s);
    let mut s = Step::new(ApiV2, "POST", "/api/v2/auth/device/approve", "v2:approve");
    s.identity = Identity::UserJwt;
    s.body = Some(code_body);
    f.step(s);
    let mut s = Step::new(
        ApiV2,
        "POST",
        "/api/v2/auth/device/approve",
        "v2:approve_again",
    );
    s.identity = Identity::UserJwt;
    s.body = Some(code_body);
    f.step(s);
    let mut s = Step::new(
        ApiV2,
        "POST",
        "/api/v2/auth/device/approve",
        "v2:approve_other_account",
    );
    s.identity = Identity::AdminJwt;
    s.body = Some(code_body);
    f.step(s);
    let mut s = Step::new(ApiV2, "POST", "/api/v2/auth/device/poll", "v2:poll_collect");
    s.headers = &[("X-Silo-Device-Id", "flow-tv"), ("User-Agent", "flow-tv")];
    s.body = Some(poll_body);
    s.capture = &[("flow_device_access", "/tokens/access_token")];
    f.step(s);
    let mut s = Step::new(
        ApiV2,
        "POST",
        "/api/v2/auth/device/poll",
        "v2:poll_consumed",
    );
    s.body = Some(poll_body);
    f.step(s);
    let mut s = Step::new(ApiV2, "GET", "/api/v2/account/me", "v2:device_token_works");
    s.bearer = Some("flow_device_access");
    f.step(s);
    let mut s = Step::new(
        ApiV2,
        "POST",
        "/api/v2/auth/device/deny",
        "v2:deny_consumed",
    );
    s.identity = Identity::UserJwt;
    s.body = Some(code_body);
    f.step(s);

    // Denied.
    let mut s = Step::new(ApiV2, "POST", "/api/v2/auth/device/start", "v2:start_deny");
    s.body = Some("{}");
    s.capture = CODES;
    f.step(s);
    let mut s = Step::new(ApiV2, "POST", "/api/v2/auth/device/deny", "v2:deny");
    s.identity = Identity::UserJwt;
    s.body = Some(code_body);
    f.step(s);
    let mut s = Step::new(
        ApiV2,
        "POST",
        "/api/v2/auth/device/approve",
        "v2:approve_denied",
    );
    s.identity = Identity::UserJwt;
    s.body = Some(code_body);
    f.step(s);
    let mut s = Step::new(ApiV2, "POST", "/api/v2/auth/device/poll", "v2:poll_denied");
    s.body = Some(poll_body);
    f.step(s);

    // Withdrawn by the device.
    let mut s = Step::new(
        ApiV2,
        "POST",
        "/api/v2/auth/device/start",
        "v2:start_cancel",
    );
    s.body = Some("{}");
    s.capture = CODES;
    f.step(s);
    let mut s = Step::new(ApiV2, "POST", "/api/v2/auth/device/cancel", "v2:cancel");
    s.body = Some(poll_body);
    f.step(s);
    let mut s = Step::new(
        ApiV2,
        "POST",
        "/api/v2/auth/device/cancel",
        "v2:cancel_again",
    );
    s.body = Some(poll_body);
    f.step(s);
    let mut s = Step::new(
        ApiV2,
        "POST",
        "/api/v2/auth/device/poll",
        "v2:poll_canceled",
    );
    s.body = Some(poll_body);
    f.step(s);

    // The profile handoff.
    let remote = "{\"client_purpose\":\"remote_playback\",\"temporary\":true}";
    let mut s = Step::new(
        ApiV2,
        "POST",
        "/api/v2/auth/device/start",
        "v2:start_remote",
    );
    s.body = Some(remote);
    s.capture = CODES;
    f.step(s);
    let mut s = Step::new(
        ApiV2,
        "POST",
        "/api/v2/auth/device/approve",
        "v2:approve_wrong_purpose",
    );
    s.identity = Identity::UserJwt;
    s.body = Some(code_body);
    f.step(s);
    let mut s = Step::new(
        ApiV2,
        "POST",
        "/api/v2/auth/device/approve-handoff",
        "v2:handoff",
    );
    s.identity = Identity::UserJwt;
    s.profile = Some(USER_PROFILE);
    s.body = Some(code_body);
    f.step(s);
    let mut s = Step::new(ApiV2, "POST", "/api/v2/auth/device/poll", "v2:poll_handoff");
    s.body = Some(poll_body);
    s.capture = &[("flow_remote_refresh", "/tokens/refresh_token")];
    f.step(s);
    let mut s = Step::new(ApiV2, "POST", "/api/v2/auth/refresh", "v2:refresh_handoff");
    s.body = Some("{\"refresh_token\":\"${flow_remote_refresh}\"}");
    f.step(s);

    // A Quick Connect code needs a signed-in session.
    let mut s = Step::new(
        ApiV2,
        "GET",
        "/api/v2/auth/device",
        "v2:lookup_six_digits_anon",
    );
    s.query = &[("code", "123456")];
    f.step(s);
    let mut s = Step::new(
        ApiV2,
        "GET",
        "/api/v2/auth/device",
        "v2:lookup_six_digits_key",
    );
    s.identity = Identity::User;
    s.query = &[("code", "123456")];
    f.step(s);
    let mut s = Step::new(
        ApiV2,
        "GET",
        "/api/v2/auth/device",
        "v2:lookup_six_digits_session",
    );
    s.identity = Identity::UserJwt;
    s.query = &[("code", "123456")];
    f.step(s);

    // v1.
    let mut s = Step::new(ApiV1, "POST", "/api/v1/auth/device/start", "v1:start");
    s.body = Some(start);
    s.capture = CODES;
    f.step(s);
    let mut s = Step::new(ApiV1, "GET", "/api/v1/auth/device", "v1:lookup");
    s.query = &[("code", "${flow_user_code}")];
    f.step(s);
    let mut s = Step::new(ApiV1, "POST", "/api/v1/auth/device/poll", "v1:poll_pending");
    s.body = Some(poll_body);
    f.step(s);
    let mut s = Step::new(ApiV1, "POST", "/api/v1/auth/device/approve", "v1:approve");
    s.identity = Identity::UserJwt;
    s.body = Some(code_body);
    f.step(s);
    let mut s = Step::new(ApiV1, "POST", "/api/v1/auth/device/poll", "v1:poll_collect");
    s.body = Some(poll_body);
    f.step(s);
    let mut s = Step::new(ApiV1, "POST", "/api/v1/auth/device/start", "v1:start_deny");
    s.body = Some("{}");
    s.capture = CODES;
    f.step(s);
    let mut s = Step::new(ApiV1, "POST", "/api/v1/auth/device/deny", "v1:deny");
    s.identity = Identity::UserJwt;
    s.body = Some(code_body);
    f.step(s);
    let mut s = Step::new(
        ApiV1,
        "POST",
        "/api/v1/auth/device/start",
        "v1:start_remote",
    );
    s.body = Some(remote);
    s.capture = CODES;
    f.step(s);
    let mut s = Step::new(
        ApiV1,
        "POST",
        "/api/v1/auth/device/approve-handoff",
        "v1:handoff",
    );
    s.identity = Identity::UserJwt;
    s.profile = Some(USER_PROFILE);
    s.body = Some(code_body);
    f.step(s);
    let mut s = Step::new(ApiV1, "POST", "/api/v1/auth/device/poll", "v1:poll_handoff");
    s.body = Some(poll_body);
    f.step(s);
}

fn impersonation(f: &mut Flows) {
    use Surface::{ApiV1, ApiV2};
    for (surface, start, end, name_start, name_end, name_after) in [
        (
            ApiV1,
            "/api/v1/admin/users/{id}/impersonate",
            "/api/v1/auth/impersonation/end",
            "v1:impersonate",
            "v1:end_impersonation",
            "v1:end_impersonation_again",
        ),
        (
            ApiV2,
            "/api/v2/admin/users/{id}/impersonate",
            "/api/v2/auth/impersonation/end",
            "v2:impersonate",
            "v2:end_impersonation",
            "v2:end_impersonation_again",
        ),
    ] {
        let mut s = Step::new(surface, "POST", start, name_start);
        s.identity = Identity::AdminJwt;
        s.profile = Some(ADMIN_PROFILE);
        let at = start.replace("{id}", "${member_user_id}");
        s.at = Some(&at);
        s.body = Some("{}");
        s.capture = &[("flow_view_as", "/access_token")];
        f.step(s);
        let mut s = Step::new(surface, "POST", end, name_end);
        s.bearer = Some("flow_view_as");
        f.step(s);
        let mut s = Step::new(surface, "POST", end, name_after);
        s.bearer = Some("flow_view_as");
        f.step(s);
    }
}

fn passwords(f: &mut Flows) {
    use Surface::{Abs, ApiV1, ApiV2};
    let mut s = Step::new(ApiV1, "POST", "/api/v1/auth/login", "password:login");
    s.body = Some(USER_LOGIN);
    s.capture = &[("flow_pw_access", "/access_token")];
    f.step(s);
    let mut s = Step::new(
        ApiV1,
        "POST",
        "/api/v1/auth/account/password",
        "v1:password_wrong",
    );
    s.bearer = Some("flow_pw_access");
    s.profile = Some(USER_PROFILE);
    s.body = Some("{\"current_password\":\"nope\",\"new_password\":\"conformance-new-password\"}");
    f.step(s);
    let mut s = Step::new(
        ApiV1,
        "POST",
        "/api/v1/auth/account/password",
        "v1:password_short",
    );
    s.bearer = Some("flow_pw_access");
    s.profile = Some(USER_PROFILE);
    s.body = Some("{\"current_password\":\"${member_password}\",\"new_password\":\"short\"}");
    f.step(s);
    let mut s = Step::new(
        ApiV1,
        "POST",
        "/api/v1/auth/account/password",
        "v1:password",
    );
    s.bearer = Some("flow_pw_access");
    s.profile = Some(USER_PROFILE);
    s.body = Some("{\"current_password\":\"${member_password}\",\"new_password\":\"conformance-new-password\"}");
    f.step(s);
    // Go's own compatibility sign-in reads the hash Rust wrote, and the old password no longer works.
    let mut s = Step::new(Abs, "POST", "/login", "password:go_reads_new_hash");
    s.body =
        Some("{\"username\":\"${member_username}\",\"password\":\"conformance-new-password\"}");
    f.step(s);
    let mut s = Step::new(ApiV2, "POST", "/api/v2/auth/login", "password:old_refused");
    s.body = Some(USER_LOGIN);
    f.step(s);
    let mut s = Step::new(
        ApiV2,
        "POST",
        "/api/v2/account/password",
        "v2:password_secondary_profile",
    );
    s.bearer = Some("flow_pw_access");
    s.profile = Some("${kid_profile_id}");
    s.body = Some("{\"current_password\":\"conformance-new-password\",\"new_password\":\"${member_password}\"}");
    f.step(s);
    let mut s = Step::new(
        ApiV2,
        "POST",
        "/api/v2/account/password",
        "v2:password_wrong",
    );
    s.bearer = Some("flow_pw_access");
    s.profile = Some(USER_PROFILE);
    s.body = Some("{\"current_password\":\"nope\",\"new_password\":\"${member_password}\"}");
    f.step(s);
    let mut s = Step::new(
        ApiV2,
        "POST",
        "/api/v2/account/password",
        "v2:password_too_long",
    );
    s.bearer = Some("flow_pw_access");
    s.profile = Some(USER_PROFILE);
    s.body = Some("{\"current_password\":\"conformance-new-password\",\"new_password\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}");
    f.step(s);
    // Signs the seeded login out; the harness logs in again.
    let mut s = Step::new(ApiV2, "POST", "/api/v2/account/password", "v2:password");
    s.bearer = Some("flow_pw_access");
    s.profile = Some(USER_PROFILE);
    s.body = Some("{\"current_password\":\"conformance-new-password\",\"new_password\":\"${member_password}\",\"sign_out_other_sessions\":true}");
    f.step(s);
    let mut s = Step::new(
        ApiV2,
        "GET",
        "/api/v2/auth/sessions",
        "password:kept_session",
    );
    s.bearer = Some("flow_pw_access");
    f.step(s);
}

fn signup(f: &mut Flows) {
    use Surface::{ApiV1, ApiV2};
    let mut s = Step::new(
        ApiV1,
        "PUT",
        "/api/v1/admin/settings/{key}",
        "signup:enable",
    );
    s.identity = Identity::Admin;
    s.at = Some("/api/v1/admin/settings/signup.enabled");
    s.body = Some("{\"value\":\"true\"}");
    f.step(s);
    let mut s = Step::new(ApiV1, "GET", "/api/v1/auth/signup", "v1:signup_status_on");
    f.step(s);
    s = Step::new(ApiV2, "GET", "/api/v2/auth/signup", "v2:signup_status_on");
    f.step(s);
    let mut s = Step::new(ApiV2, "POST", "/api/v2/admin/invite-codes", "signup:invite");
    s.identity = Identity::Admin;
    s.body = Some("{\"code\":\"FLOW-INVITE\",\"label\":\"flow\",\"max_uses\":2}");
    f.step(s);
    let v1 = "{\"username\":\"flow-signup-v1\",\"email\":\"flow-v1@silo.example.test\",\"password\":\"conformance-signup\",\"invite_code\":\"FLOW-INVITE\",\"create_default_profile\":true}";
    let mut s = Step::new(ApiV1, "POST", "/api/v1/auth/signup", "v1:signup");
    s.body = Some(v1);
    f.step(s);
    let mut s = Step::new(ApiV1, "POST", "/api/v1/auth/signup", "v1:signup_duplicate");
    s.body = Some(v1);
    f.step(s);
    let mut s = Step::new(ApiV1, "POST", "/api/v1/auth/signup", "v1:signup_bad_code");
    s.body = Some("{\"username\":\"flow-signup-x\",\"email\":\"flow-x@silo.example.test\",\"password\":\"conformance-signup\",\"invite_code\":\"nope\"}");
    f.step(s);
    let mut s = Step::new(ApiV2, "POST", "/api/v2/auth/signup", "v2:signup");
    s.body = Some("{\"username\":\"flow-signup-v2\",\"email\":\"flow-v2@silo.example.test\",\"password\":\"conformance-signup\",\"invite_code\":\"FLOW-INVITE\",\"default_profile_name\":\"Flow\",\"create_default_profile\":true}");
    s.capture = &[("flow_signup_access", "/access_token")];
    f.step(s);
    let mut s = Step::new(ApiV2, "POST", "/api/v2/auth/signup", "v2:signup_exhausted");
    s.body = Some("{\"username\":\"flow-signup-y\",\"email\":\"flow-y@silo.example.test\",\"password\":\"conformance-signup\",\"invite_code\":\"FLOW-INVITE\"}");
    f.step(s);
    let mut s = Step::new(ApiV2, "POST", "/api/v2/auth/signup", "v2:signup_bad_email");
    s.body = Some("{\"username\":\"flow-signup-z\",\"email\":\"nope\",\"password\":\"conformance-signup\",\"invite_code\":\"FLOW-INVITE\"}");
    f.step(s);
    // What the new account looks like through Go.
    let mut s = Step::new(ApiV2, "GET", "/api/v2/profiles", "signup:profile_on_go");
    s.bearer = Some("flow_signup_access");
    s.capture = &[("flow_signup_profile", "/items/0/id")];
    f.step(s);
    let mut s = Step::new(
        ApiV1,
        "PUT",
        "/api/v1/admin/settings/{key}",
        "signup:disable",
    );
    s.identity = Identity::Admin;
    s.at = Some("/api/v1/admin/settings/signup.enabled");
    s.body = Some("{\"value\":\"false\"}");
    f.step(s);
}

fn api_keys(f: &mut Flows) {
    use Surface::{ApiV1, ApiV2};
    // Personal keys need a login session on the primary profile.
    let mut s = Step::new(ApiV1, "POST", "/api/v1/api-keys/", "v1:key_create");
    s.identity = Identity::AdminJwt;
    s.profile = Some(ADMIN_PROFILE);
    s.body = Some("{\"label\":\"flow-v1\",\"scopes\":[\"admin:users\"]}");
    s.capture = &[("flow_key_id", "/id")];
    f.step(s);
    let mut s = Step::new(ApiV1, "POST", "/api/v1/api-keys/", "v1:key_bad_scope");
    s.identity = Identity::AdminJwt;
    s.profile = Some(ADMIN_PROFILE);
    s.body = Some("{\"label\":\"flow-v1\",\"scopes\":[\"nope\"]}");
    f.step(s);
    let mut s = Step::new(ApiV1, "POST", "/api/v1/api-keys/", "v1:key_no_label");
    s.identity = Identity::AdminJwt;
    s.profile = Some(ADMIN_PROFILE);
    s.body = Some("{}");
    f.step(s);
    let mut s = Step::new(ApiV1, "GET", "/api/v1/api-keys/", "v1:key_list");
    s.identity = Identity::AdminJwt;
    f.step(s);
    let mut s = Step::new(ApiV1, "GET", "/api/v1/admin/api-keys", "v1:admin_key_list");
    s.identity = Identity::AdminJwt;
    s.profile = Some(ADMIN_PROFILE);
    f.step(s);
    let mut s = Step::new(ApiV1, "PUT", "/api/v1/admin/api-keys/{id}/tier", "v1:tier");
    s.identity = Identity::Admin;
    s.at = Some("/api/v1/admin/api-keys/${flow_key_id}/tier");
    s.body = Some("{\"tier\":\"elevated\"}");
    f.step(s);
    let mut s = Step::new(
        ApiV1,
        "PUT",
        "/api/v1/admin/api-keys/{id}/tier",
        "v1:tier_bad",
    );
    s.identity = Identity::Admin;
    s.at = Some("/api/v1/admin/api-keys/${flow_key_id}/tier");
    s.body = Some("{\"tier\":\"gold\"}");
    f.step(s);
    let mut s = Step::new(ApiV1, "DELETE", "/api/v1/api-keys/{id}", "v1:key_delete");
    s.identity = Identity::AdminJwt;
    s.at = Some("/api/v1/api-keys/${flow_key_id}");
    f.step(s);
    let mut s = Step::new(
        ApiV1,
        "DELETE",
        "/api/v1/api-keys/{id}",
        "v1:key_delete_again",
    );
    s.identity = Identity::AdminJwt;
    s.at = Some("/api/v1/api-keys/${flow_key_id}");
    f.step(s);

    let mut s = Step::new(ApiV2, "POST", "/api/v2/api-keys", "v2:key_create");
    s.identity = Identity::AdminJwt;
    s.profile = Some(ADMIN_PROFILE);
    s.body = Some("{\"label\":\"flow-v2\",\"scopes\":[\"libraries:read\"]}");
    s.capture = &[("flow_key_id", "/id")];
    f.step(s);
    let mut s = Step::new(ApiV2, "POST", "/api/v2/api-keys", "v2:key_bad_scope");
    s.identity = Identity::AdminJwt;
    s.profile = Some(ADMIN_PROFILE);
    s.body = Some("{\"label\":\"flow-v2\",\"scopes\":[\"nope\"]}");
    f.step(s);
    let mut s = Step::new(ApiV2, "POST", "/api/v2/api-keys", "v2:key_member");
    s.identity = Identity::UserJwt;
    s.profile = Some(USER_PROFILE);
    s.body = Some("{\"label\":\"flow-v2\"}");
    f.step(s);
    let mut s = Step::new(ApiV2, "GET", "/api/v2/api-keys", "v2:key_list");
    s.identity = Identity::AdminJwt;
    s.query = &[("limit", "1")];
    s.capture = &[("flow_key_cursor", "/page/next_cursor")];
    f.step(s);
    let mut s = Step::new(ApiV2, "GET", "/api/v2/api-keys", "v2:key_list_cursor");
    s.identity = Identity::AdminJwt;
    s.query = &[("limit", "1"), ("cursor", "${flow_key_cursor}")];
    f.step(s);
    let mut s = Step::new(ApiV2, "GET", "/api/v2/api-keys", "v2:key_list_limit_over");
    s.identity = Identity::AdminJwt;
    s.query = &[("limit", "201")];
    f.step(s);
    let mut s = Step::new(ApiV2, "GET", "/api/v2/admin/api-keys", "v2:admin_key_page");
    s.identity = Identity::Admin;
    s.query = &[("limit", "1")];
    s.capture = &[("flow_admin_cursor", "/page/next_cursor")];
    f.step(s);
    let mut s = Step::new(
        ApiV2,
        "GET",
        "/api/v2/admin/api-keys",
        "v2:admin_key_page_cursor",
    );
    s.identity = Identity::Admin;
    s.query = &[("limit", "1"), ("cursor", "${flow_admin_cursor}")];
    f.step(s);
    let mut s = Step::new(
        ApiV2,
        "GET",
        "/api/v2/admin/api-keys/{id}",
        "v2:admin_key_get",
    );
    s.identity = Identity::Admin;
    s.at = Some("/api/v2/admin/api-keys/${flow_key_id}");
    s.capture = &[("flow_key_etag", "header:etag")];
    f.step(s);
    let mut s = Step::new(
        ApiV2,
        "PUT",
        "/api/v2/admin/api-keys/{id}/tier",
        "v2:tier_no_guard",
    );
    s.identity = Identity::Admin;
    s.at = Some("/api/v2/admin/api-keys/${flow_key_id}/tier");
    s.body = Some("{\"rate_tier\":\"elevated\"}");
    f.step(s);
    let mut s = Step::new(ApiV2, "PUT", "/api/v2/admin/api-keys/{id}/tier", "v2:tier");
    s.identity = Identity::Admin;
    s.at = Some("/api/v2/admin/api-keys/${flow_key_id}/tier");
    s.headers = &[("If-Match", "${flow_key_etag}")];
    s.body = Some("{\"rate_tier\":\"elevated\"}");
    f.step(s);
    let mut s = Step::new(
        ApiV2,
        "PUT",
        "/api/v2/admin/api-keys/{id}/tier",
        "v2:tier_stale",
    );
    s.identity = Identity::Admin;
    s.at = Some("/api/v2/admin/api-keys/${flow_key_id}/tier");
    s.headers = &[("If-Match", "${flow_key_etag}")];
    s.body = Some("{\"rate_tier\":\"standard\"}");
    f.step(s);
    let mut s = Step::new(
        ApiV2,
        "PUT",
        "/api/v2/admin/api-keys/{id}/tier",
        "v2:tier_star_same",
    );
    s.identity = Identity::Admin;
    s.at = Some("/api/v2/admin/api-keys/${flow_key_id}/tier");
    s.headers = &[("If-Match", "*")];
    s.body = Some("{\"rate_tier\":\"elevated\"}");
    f.step(s);
    let mut s = Step::new(
        ApiV2,
        "DELETE",
        "/api/v2/api-keys/{id}",
        "v2:key_delete_other_account",
    );
    s.identity = Identity::UserJwt;
    s.at = Some("/api/v2/api-keys/${flow_key_id}");
    f.step(s);
    let mut s = Step::new(ApiV2, "DELETE", "/api/v2/api-keys/{id}", "v2:key_delete");
    s.identity = Identity::AdminJwt;
    s.at = Some("/api/v2/api-keys/${flow_key_id}");
    f.step(s);
    let mut s = Step::new(
        ApiV2,
        "POST",
        "/api/v2/admin/api-keys",
        "v2:admin_key_for_member",
    );
    s.identity = Identity::Admin;
    s.body = Some("{\"label\":\"flow-admin\",\"user_id\":\"${member_user_id}\"}");
    s.capture = &[("flow_key_id", "/id")];
    f.step(s);
    let mut s = Step::new(
        ApiV2,
        "POST",
        "/api/v2/admin/api-keys",
        "v2:admin_key_bad_account",
    );
    s.identity = Identity::Admin;
    s.body = Some("{\"label\":\"flow-admin\",\"user_id\":\"007\"}");
    f.step(s);
    let mut s = Step::new(
        ApiV2,
        "GET",
        "/api/v2/admin/users/{id}/api-keys",
        "v2:user_keys",
    );
    s.identity = Identity::Admin;
    s.at = Some("/api/v2/admin/users/${member_user_id}/api-keys");
    f.step(s);
    let mut s = Step::new(
        ApiV1,
        "GET",
        "/api/v1/admin/users/{userId}/api-keys",
        "v1:user_keys",
    );
    s.identity = Identity::Admin;
    s.at = Some("/api/v1/admin/users/${member_user_id}/api-keys");
    f.step(s);
    let mut s = Step::new(
        ApiV1,
        "DELETE",
        "/api/v1/admin/api-keys/{id}",
        "v1:admin_key_delete",
    );
    s.identity = Identity::Admin;
    s.at = Some("/api/v1/admin/api-keys/${flow_key_id}");
    f.step(s);
    // The key the seed gave the member, spent through Go's audit view of the writes above.
    let mut s = Step::new(ApiV2, "GET", "/api/v2/admin/logs/audit", "keys:audit_on_go");
    s.identity = Identity::Admin;
    f.step(s);
}

/// Last in the stage: setup needs an empty `users` table, and the liveness check then resets.
fn setup(f: &mut Flows) {
    use Surface::{ApiV1, ApiV2};
    let body = "{\"username\":\"flow-owner\",\"email\":\"flow-owner@silo.example.test\",\"password\":\"conformance-owner\",\"create_default_profile\":true,\"default_profile_name\":\"Owner\"}";
    let mut s = Step::new(ApiV1, "GET", "/api/v1/auth/setup", "v1:setup_status_empty");
    s.empty_users = true;
    f.step(s);
    let mut s = Step::new(ApiV1, "POST", "/api/v1/auth/setup", "v1:setup");
    s.empty_users = true;
    s.body = Some(body);
    s.capture = &[("flow_owner_access", "/access_token")];
    f.step(s);
    let mut s = Step::new(ApiV1, "GET", "/api/v1/auth/me", "v1:setup_owner");
    s.bearer = Some("flow_owner_access");
    f.step(s);
    let mut s = Step::new(ApiV2, "POST", "/api/v2/auth/setup", "v2:setup");
    s.empty_users = true;
    s.body = Some(body);
    f.step(s);
}

pub(crate) fn add(b: &mut Builder) {
    let mut f = Flows {
        b,
        seq: 0,
        prefix: "zflow",
    };
    sessions(&mut f);
    plugin_launch(&mut f);
    device(&mut f);
    impersonation(&mut f);
    passwords(&mut f);
    signup(&mut f);
    api_keys(&mut f);
    setup(&mut f);
}
