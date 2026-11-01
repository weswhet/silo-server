//! Fills path templates. Known seed objects first, then objects this run created,
//! then the contract's own examples. Everything is per server, because a value one
//! server generated is meaningless to the other.

use crate::model::{Case, Identity, Route, Surface, INVALID_ID};
use regex::Regex;
use std::collections::BTreeMap;
use std::sync::OnceLock;

#[derive(Clone, Debug, Default)]
pub struct SideState {
    pub facts: BTreeMap<String, String>,
    /// Template prefix of a create route -> the id its response returned.
    pub created: BTreeMap<String, String>,
}

impl SideState {
    pub fn fact(&self, name: &str) -> Option<&str> {
        self.facts.get(name).map(String::as_str)
    }
}

fn param_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\{([^}]+)\}").unwrap())
}

fn placeholder_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#""?\$\{([a-zA-Z_]+)(:int)?\}"?"#).unwrap())
}

/// Replaces `${fact}` with its value, and `"${fact:int}"` with a bare integer.
pub fn fill(text: &str, facts: &BTreeMap<String, String>) -> String {
    placeholder_re()
        .replace_all(text, |c: &regex::Captures| {
            let whole = c.get(0).unwrap().as_str();
            let Some(value) = facts.get(&c[1]) else {
                return whole.to_string();
            };
            let (open, close) = (whole.starts_with('"'), whole.ends_with('"'));
            if c.get(2).is_some() {
                value.clone()
            } else {
                format!(
                    "{}{}{}",
                    if open { "\"" } else { "" },
                    value,
                    if close { "\"" } else { "" }
                )
            }
        })
        .into_owned()
}

fn encode_segment(v: &str) -> String {
    let mut out = String::new();
    for b in v.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~:".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

pub fn self_suffix(identity: Identity) -> &'static str {
    match identity {
        Identity::Admin | Identity::AdminJwt | Identity::AdminNoProfile => "admin",
        _ => "user",
    }
}

/// Ids that must not be deleted out from under the rest of the run. A DELETE only
/// uses one of these when this run created the object.
const PROTECTED_DELETE: [&str; 5] = [
    "library_id",
    "member_user_id",
    "self_profile_id",
    "member_api_key_id",
    "file_id",
];

fn seed_fact_for(surface: Surface, route: &str, prev: &str, name: &str) -> Option<&'static str> {
    let n = name.to_ascii_lowercase();
    if matches!(surface, Surface::Jellycompat) {
        return Some(match n.as_str() {
            "userid" => "jf_self_user_id",
            "itemid" | "id" | "routeitemid" | "routemediasourceid" | "boxsetid" => "jf_movie_id",
            "episodeid" => "jf_episode_id",
            "seriesid" => "jf_series_id",
            "seasonid" => "jf_season_id",
            "libraryid" | "viewid" => "jf_library_id",
            _ => return None,
        });
    }
    if matches!(surface, Surface::Abs) {
        return None;
    }
    Some(match n.as_str() {
        "content_id" | "contentid" | "item_id" | "media_item_id" => "movie_id",
        "series_id" => "series_id",
        "file_id" | "fileid" | "media_file_id" => "file_id",
        "library_id" | "libraryid" => "library_id",
        "user_id" | "userid" => "member_user_id",
        "profile_id" => "self_profile_id",
        "id" if prev == "items" && route.ends_with("/episodes") => "series_id",
        "id" => match prev {
            "items" | "watched" | "watch" | "catalog" | "unmatched-items" => "movie_id",
            "users" | "accounts" => "member_user_id",
            "libraries" | "library" => "library_id",
            "profiles" => "self_profile_id",
            "people" => "person_id",
            "series" => "series_id",
            "api-keys" => "member_api_key_id",
            _ => return None,
        },
        _ => return None,
    })
}

fn literal_for(surface: Surface, prev: &str, name: &str) -> Option<&'static str> {
    let n = name.to_ascii_lowercase();
    if matches!(surface, Surface::Jellycompat | Surface::Abs) {
        return Some(match n.as_str() {
            "container" | "routeformat" => "mp4",
            "imagetype" | "type" => "Primary",
            "index" | "routeindex" | "idx" | "segmentid" | "routestartpositionticks" | "time" => {
                "0"
            }
            "segmentcontainer" => "ts",
            "displaypreferencesid" => "usersettings",
            "width" => "100",
            "year" => "2001",
            "name" => "Fixture Actor",
            "key" => "encoding",
            _ => return None,
        });
    }
    Some(match n.as_str() {
        "num" | "version" => "1",
        "media_type" => "movie",
        "tmdb_id" => "9000001",
        "track" => "0",
        "segment" => "intro",
        "surface" => "home",
        "slug" => "drama",
        "section" => "trending",
        "type" => "genre",
        "name" => "master.m3u8",
        "provider" => match prev {
            "network-access" => "tailscale",
            _ => "tmdb",
        },
        "kind" => match prev {
            "assets" | "artwork" => "logo",
            "check" => "ffmpeg",
            _ => "trending",
        },
        "key" => match prev {
            "tasks" => "scan-all",
            _ => "branding.server_name",
        },
        _ => return None,
    })
}

fn schema_example(route: &Route, name: &str) -> Option<String> {
    let op = route.op.as_ref()?;
    let param = op
        .params
        .iter()
        .find(|p| p.location == "path" && p.name.eq_ignore_ascii_case(name))?;
    let s = &param.schema;
    let value = s["enum"]
        .as_array()
        .and_then(|e| e.first())
        .or_else(|| s["examples"].as_array().and_then(|e| e.first()))?;
    Some(match value {
        serde_json::Value::String(v) => v.clone(),
        other => other.to_string(),
    })
}

pub fn resolve_path(case: &Case, route: &Route, state: &SideState) -> String {
    let template = case.path.as_str();
    let mut out = String::with_capacity(template.len() + 16);
    let mut last = 0;
    for m in param_re().captures_iter(template) {
        let whole = m.get(0).unwrap();
        let name = &m[1];
        let before = &template[..whole.start()];
        out.push_str(&template[last..whole.start()]);
        last = whole.end();
        if let Some(v) = &case.path_override {
            out.push_str(&encode_segment(v));
            continue;
        }
        let prefix = before.trim_end_matches('/');
        let prev = prefix.rsplit('/').next().unwrap_or("").to_ascii_lowercase();
        let value = one_param(case, route, state, prefix, &prev, name);
        out.push_str(&encode_segment(&value));
    }
    out.push_str(&template[last..]);
    if out.ends_with("/*") {
        out.truncate(out.len() - 1);
        out.push_str("conformance-unmatched");
    }
    out
}

fn one_param(
    case: &Case,
    route: &Route,
    state: &SideState,
    prefix: &str,
    prev: &str,
    name: &str,
) -> String {
    // Writes target what this run created, so the seed stays intact. Reads prefer
    // the seed, whose objects have real content behind them.
    let created = state.created.get(prefix);
    if crate::model::is_mutating(&case.method) {
        if let Some(v) = created {
            return v.clone();
        }
    }
    if let Some(fact) = seed_fact_for(route.surface, &route.path, prev, name) {
        let fact_key = match fact {
            "self_profile_id" => format!("{}_profile_id", self_suffix(case.identity)),
            "jf_self_user_id" => format!("jf_{}_user_id", self_suffix(case.identity)),
            other => other.to_string(),
        };
        if case.method == "DELETE" && PROTECTED_DELETE.contains(&fact) {
            return INVALID_ID.to_string();
        }
        if let Some(v) = state.fact(&fact_key) {
            return v.to_string();
        }
    }
    if let Some(v) = created {
        return v.clone();
    }
    if let Some(v) = literal_for(route.surface, prev, name) {
        return v.to_string();
    }
    if let Some(v) = schema_example(route, name) {
        return v;
    }
    "1".to_string()
}

pub fn has_params(template: &str) -> bool {
    template.contains('{') || template.ends_with('*')
}
