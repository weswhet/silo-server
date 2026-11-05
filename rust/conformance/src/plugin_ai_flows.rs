//! Static capability reads and guarded database-only plugin catalog updates.
use crate::auth_flows::{Flows, Step};
use crate::model::{Identity, Surface::ApiV2};
use crate::plan::Builder;

const CONTENT: &str = "/api/v2/plugin-content/capabilities";
const AI: &str = "/api/v2/admin/ai/capabilities";
const SETTINGS: &str = "/api/v2/admin/plugins/catalog-settings";
const REPOSITORIES: &str = "/api/v2/admin/plugins/repositories";

fn admin<'a>(method: &'a str, route: &'a str, name: &'a str) -> Step<'a> {
    Step {
        identity: Identity::Admin,
        profile: Some("${admin_profile_id}"),
        ..Step::new(ApiV2, method, route, name)
    }
}

pub(crate) fn add(b: &mut Builder) {
    let mut f = Flows {
        b,
        seq: 0,
        prefix: "xflow-plugin-ai",
    };
    f.step(Step {
        capture: &[("plugin_content_capability_etag", "header:etag")],
        ..Step::new(ApiV2, "GET", CONTENT, "plugin_ai:content")
    });
    f.step(Step {
        headers: &[("If-None-Match", "${plugin_content_capability_etag}")],
        ..Step::new(ApiV2, "GET", CONTENT, "plugin_ai:content_unchanged")
    });
    for model in [
        "",
        "chat-latest",
        "gpt-6-sol-chat-latest",
        "gpt-4.1",
        "gpt-3.5-turbo",
        "OPENAI/GPT-6.1-SOL",
        "gpt-6-astra",
        "gpt-6-sol",
        "gpt-6-luna",
        "gpt-5.6",
        "gpt-5-pro",
        "gpt-5.2-pro",
        "gpt-5.4-pro",
        "gpt-5.5-pro",
        "gpt-5.2",
        "gpt-5.4",
        "gpt-5.5",
        "gpt-5.1",
        "gpt-5",
        "gpt-5-mini",
        "gpt-5-nano",
        "gpt-5-2025",
        "o1",
        "o3",
        "o4-mini",
        "custom-model",
    ] {
        let name = format!("plugin_ai:ai:{model}");
        f.step(Step {
            query: &[("model", model)],
            ..admin("GET", AI, &name)
        });
    }
    f.step(Step {
        capture: &[("plugin_ai_capability_etag", "header:etag")],
        ..admin("GET", AI, "plugin_ai:ai_capture")
    });
    f.step(Step {
        headers: &[("If-None-Match", "${plugin_ai_capability_etag}")],
        ..admin("GET", AI, "plugin_ai:ai_unchanged")
    });
    f.step(Step {
        capture: &[("plugin_catalog_initial_etag", "header:etag")],
        ..admin("GET", SETTINGS, "plugin_ai:catalog_initial")
    });
    f.step(Step {
        headers: &[("If-None-Match", "${plugin_catalog_initial_etag}")],
        ..admin("GET", SETTINGS, "plugin_ai:catalog_unchanged")
    });
    f.step(admin("GET", REPOSITORIES, "plugin_ai:repositories_initial"));
    for (name, body) in [
        ("enable", r#"{"include_approved_community_plugins":true}"#),
        ("disable", r#"{"include_approved_community_plugins":false}"#),
    ] {
        f.step(Step {
            body: Some(body),
            headers: &[("If-Match", "*")],
            ..admin("PUT", SETTINGS, &format!("plugin_ai:catalog_{name}"))
        });
        f.step(admin(
            "GET",
            SETTINGS,
            &format!("plugin_ai:catalog_after_{name}"),
        ));
        f.step(admin(
            "GET",
            REPOSITORIES,
            &format!("plugin_ai:repositories_after_{name}"),
        ));
    }
    for (name, headers, body) in [
        (
            "no_precondition",
            &[][..],
            r#"{"include_approved_community_plugins":true}"#,
        ),
        (
            "stale",
            &[("If-Match", "\"stale\"")][..],
            r#"{"include_approved_community_plugins":true}"#,
        ),
        (
            "invalid",
            &[("If-Match", "*")][..],
            r#"{"include_approved_community_plugins":null}"#,
        ),
    ] {
        f.step(Step {
            body: Some(body),
            headers,
            ..admin("PUT", SETTINGS, &format!("plugin_ai:catalog_{name}"))
        });
        f.step(admin(
            "GET",
            SETTINGS,
            &format!("plugin_ai:catalog_after_{name}"),
        ));
    }
    f.step(Step {
        query: &[("limit", "1")],
        capture: &[("plugin_repository_cursor", "/page/next_cursor")],
        ..admin("GET", REPOSITORIES, "plugin_ai:repositories_page")
    });
    f.step(Step {
        query: &[("limit", "1"), ("cursor", "${plugin_repository_cursor}")],
        ..admin("GET", REPOSITORIES, "plugin_ai:repositories_next")
    });
    f.step(Step {
        query: &[("cursor", "bad-cursor")],
        ..admin("GET", REPOSITORIES, "plugin_ai:repositories_bad_cursor")
    });
}
