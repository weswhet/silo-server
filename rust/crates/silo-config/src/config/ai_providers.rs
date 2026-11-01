//! The AI provider registry stored in `ai.providers`.

use super::admin_settings::normalize_admin_url;
use super::{SettingsMap, admin_setting_enabled, m_get};
use crate::gonet::Url;
use serde::Serialize;
use silo_gocompat::regexp::GoRegex;
use silo_gocompat::strconv::quote;
use silo_gocompat::strings::{equal_fold, to_lower, trim_space};
use std::sync::OnceLock;

/// Holds the registry, API keys included, as one encrypted value. Do not rename it: the ciphertext
/// is bound to this name.
pub const AI_PROVIDERS_SETTING_KEY: &str = "ai.providers";
pub const AI_TEXT_PROVIDER_SETTING_KEY: &str = "ai.text_provider_id";
pub const AI_SERVICE_TIER_SETTING_KEY: &str = "ai.service_tier";
pub const AI_SPEECH_PROVIDER_SETTING_KEY: &str = "ai.speech_provider_id";
pub const EMBEDDING_PROVIDER_SETTING_KEY: &str = "recommendations.embedding_provider_id";

const OPENAI_BASE_URL: &str = "https://api.openai.com";
const OPENROUTER_BASE_URL: &str = "https://openrouter.ai/api/v1";
const GEMINI_BASE_URL: &str = "https://generativelanguage.googleapis.com";
const GROQ_BASE_URL: &str = "https://api.groq.com/openai";
const OLLAMA_BASE_URL: &str = "http://ollama:11434";
const SPEACHES_BASE_URL: &str = "http://speaches:8000";

pub(crate) const AI_AUTH_MODE_CHATGPT: &str = "chatgpt";
const AI_PROVIDERS_VERSION: i64 = 2;
const MAX_AI_PROVIDERS: usize = 32;
const MAX_AI_PROVIDER_NAME_RUNES: usize = 80;
const MAX_AI_PROVIDER_KEY_BYTES: usize = 4096;

pub const AI_CAPABILITY_CHAT: &str = "chat";
pub const AI_CAPABILITY_EMBEDDINGS: &str = "embeddings";
pub const AI_CAPABILITY_SPEECH: &str = "speech";
/// Every capability in display order.
pub const AI_CAPABILITIES: [&str; 3] = [
    AI_CAPABILITY_CHAT,
    AI_CAPABILITY_EMBEDDINGS,
    AI_CAPABILITY_SPEECH,
];

pub const AI_PROVIDER_OPENAI: &str = "openai";
pub const AI_PROVIDER_GEMINI: &str = "gemini";
pub const AI_PROVIDER_OPENROUTER: &str = "openrouter";
pub const AI_PROVIDER_GROQ: &str = "groq";
pub const AI_PROVIDER_OLLAMA: &str = "ollama";
pub const AI_PROVIDER_WHISPER: &str = "whisper";
pub const AI_PROVIDER_CUSTOM: &str = "custom";

/// A provider type.
#[derive(Debug, Clone, Copy)]
pub struct AIProviderTypeSpec {
    pub type_: &'static str,
    pub label: &'static str,
    pub default_base_url: &'static str,
    /// The fixed set a known type serves. `None` for custom.
    pub capabilities: Option<&'static [&'static str]>,
    pub key_required: bool,
    chat_path: &'static str,
}

/// Every provider type in display order.
pub const AI_PROVIDER_TYPES: &[AIProviderTypeSpec] = &[
    AIProviderTypeSpec {
        type_: AI_PROVIDER_OPENAI,
        label: "OpenAI",
        default_base_url: OPENAI_BASE_URL,
        capabilities: Some(&[
            AI_CAPABILITY_CHAT,
            AI_CAPABILITY_EMBEDDINGS,
            AI_CAPABILITY_SPEECH,
        ]),
        key_required: true,
        chat_path: "",
    },
    AIProviderTypeSpec {
        type_: AI_PROVIDER_GEMINI,
        label: "Google Gemini",
        default_base_url: GEMINI_BASE_URL,
        capabilities: Some(&[AI_CAPABILITY_CHAT, AI_CAPABILITY_EMBEDDINGS]),
        key_required: true,
        chat_path: "/v1beta/openai",
    },
    AIProviderTypeSpec {
        type_: AI_PROVIDER_OPENROUTER,
        label: "OpenRouter",
        default_base_url: OPENROUTER_BASE_URL,
        capabilities: Some(&[
            AI_CAPABILITY_CHAT,
            AI_CAPABILITY_EMBEDDINGS,
            AI_CAPABILITY_SPEECH,
        ]),
        key_required: true,
        chat_path: "",
    },
    AIProviderTypeSpec {
        type_: AI_PROVIDER_GROQ,
        label: "Groq",
        default_base_url: GROQ_BASE_URL,
        capabilities: Some(&[AI_CAPABILITY_CHAT, AI_CAPABILITY_SPEECH]),
        key_required: true,
        chat_path: "",
    },
    AIProviderTypeSpec {
        type_: AI_PROVIDER_OLLAMA,
        label: "Ollama",
        default_base_url: OLLAMA_BASE_URL,
        capabilities: Some(&[AI_CAPABILITY_CHAT, AI_CAPABILITY_EMBEDDINGS]),
        key_required: false,
        chat_path: "",
    },
    AIProviderTypeSpec {
        type_: AI_PROVIDER_WHISPER,
        label: "Self-hosted Whisper",
        default_base_url: SPEACHES_BASE_URL,
        capabilities: Some(&[AI_CAPABILITY_SPEECH]),
        key_required: false,
        chat_path: "",
    },
    AIProviderTypeSpec {
        type_: AI_PROVIDER_CUSTOM,
        label: "OpenAI-compatible",
        default_base_url: "",
        capabilities: None,
        key_required: false,
        chat_path: "",
    },
];

/// The spec for a type.
pub fn lookup_ai_provider_type(t: &str) -> Option<AIProviderTypeSpec> {
    AI_PROVIDER_TYPES.iter().find(|s| s.type_ == t).copied()
}

impl AIProviderTypeSpec {
    fn endpoint(&self, base_url: &str, capability: &str) -> String {
        if capability == AI_CAPABILITY_CHAT {
            format!("{base_url}{}", self.chat_path)
        } else {
            base_url.to_owned()
        }
    }

    fn supports(&self, capability: &str) -> bool {
        self.capabilities.is_none_or(|c| c.contains(&capability))
    }
}

/// One connected provider.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct AIProvider {
    pub id: String,
    #[serde(rename = "type")]
    pub type_: String,
    pub name: String,
    pub base_url: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub api_key: String,
    /// `None` encodes as null, as a nil slice does in Go.
    pub capabilities: Option<Vec<String>>,
}

impl AIProvider {
    pub fn supports(&self, capability: &str) -> bool {
        self.capabilities.iter().flatten().any(|c| c == capability)
    }

    pub fn endpoint(&self, capability: &str) -> String {
        match lookup_ai_provider_type(&self.type_) {
            Some(spec) => spec.endpoint(&self.base_url, capability),
            None => self.base_url.clone(),
        }
    }
}

/// The decoded `ai.providers` value.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct AIProviderRegistry {
    pub version: i64,
    pub providers: Vec<AIProvider>,
}

/// `ParseAIProviderRegistry`: an empty value is an empty registry no conversion has seen.
pub fn parse_ai_provider_registry(raw: &str) -> Result<AIProviderRegistry, String> {
    use crate::gojson::{self, Node, Value};
    let mut registry = AIProviderRegistry::default();
    if trim_space(raw).is_empty() {
        return Ok(registry);
    }
    let wrap = |e: String| format!("{AI_PROVIDERS_SETTING_KEY} is not valid JSON: {e}");
    let node = gojson::parse(raw.as_bytes()).map_err(wrap)?;
    fn eq_key(a: &str, b: &str) -> bool {
        equal_fold(a, b)
    }
    fn string_field(v: &Node, field: &str, ty: &str) -> Result<String, String> {
        match &v.value {
            Value::String(s) => Ok(s.clone()),
            Value::Null => Ok(String::new()),
            _ => Err(format!(
                "json: cannot unmarshal {} into Go struct field AIProvider.providers.{field} of type {ty}",
                v.kind_name()
            )),
        }
    }
    let decode_err = |e: String| format!("{AI_PROVIDERS_SETTING_KEY} is not valid JSON: {e}");
    match &node.value {
        Value::Object(members) => {
            for (k, v) in members {
                if eq_key(k, "version") {
                    match &v.value {
                        Value::Number(n) => {
                            registry.version = crate::goparse::parse_int(n, 10, 64).map_err(|_| {
                                decode_err(format!(
                                    "json: cannot unmarshal number {n} into Go struct field AIProviderRegistry.version of type int"
                                ))
                            })?;
                        }
                        Value::Null => {}
                        _ => {
                            return Err(decode_err(format!(
                                "json: cannot unmarshal {} into Go struct field AIProviderRegistry.version of type int",
                                v.kind_name()
                            )));
                        }
                    }
                } else if eq_key(k, "providers") {
                    let items: &[Node] = match &v.value {
                        Value::Array(a) => a,
                        Value::Null => &[],
                        _ => {
                            return Err(decode_err(format!(
                                "json: cannot unmarshal {} into Go struct field AIProviderRegistry.providers of type []config.AIProvider",
                                v.kind_name()
                            )));
                        }
                    };
                    for item in items {
                        let mut p = AIProvider::default();
                        match &item.value {
                            Value::Object(fields) => {
                                for (fk, fv) in fields {
                                    if eq_key(fk, "id") {
                                        p.id =
                                            string_field(fv, "id", "string").map_err(decode_err)?;
                                    } else if eq_key(fk, "type") {
                                        p.type_ = string_field(fv, "type", "config.AIProviderType")
                                            .map_err(decode_err)?;
                                    } else if eq_key(fk, "name") {
                                        p.name = string_field(fv, "name", "string")
                                            .map_err(decode_err)?;
                                    } else if eq_key(fk, "base_url") {
                                        p.base_url = string_field(fv, "base_url", "string")
                                            .map_err(decode_err)?;
                                    } else if eq_key(fk, "api_key") {
                                        p.api_key = string_field(fv, "api_key", "string")
                                            .map_err(decode_err)?;
                                    } else if eq_key(fk, "capabilities") {
                                        if let Value::Array(caps) = &fv.value {
                                            let mut list = Vec::with_capacity(caps.len());
                                            for c in caps {
                                                list.push(
                                                    string_field(
                                                        c,
                                                        "capabilities",
                                                        "config.AICapability",
                                                    )
                                                    .map_err(decode_err)?,
                                                );
                                            }
                                            p.capabilities = Some(list);
                                        } else if !matches!(fv.value, Value::Null) {
                                            return Err(decode_err(format!(
                                                "json: cannot unmarshal {} into Go struct field AIProvider.providers.capabilities of type []config.AICapability",
                                                fv.kind_name()
                                            )));
                                        }
                                    }
                                }
                            }
                            Value::Null => {}
                            _ => {
                                return Err(decode_err(format!(
                                    "json: cannot unmarshal {} into Go struct field AIProviderRegistry.providers of type config.AIProvider",
                                    item.kind_name()
                                )));
                            }
                        }
                        registry.providers.push(p);
                    }
                }
            }
        }
        Value::Null => {}
        _ => {
            return Err(decode_err(format!(
                "json: cannot unmarshal {} into Go value of type config.AIProviderRegistry",
                node.kind_name()
            )));
        }
    }
    for provider in &mut registry.providers {
        if let Some(spec) = lookup_ai_provider_type(&provider.type_)
            && let Some(caps) = spec.capabilities
        {
            provider.capabilities = Some(caps.iter().map(|c| (*c).to_owned()).collect());
        }
    }
    Ok(registry)
}

impl AIProviderRegistry {
    /// The stored form of the registry.
    pub fn encode(&self) -> String {
        silo_gocompat::json::marshal_to_string(self).unwrap_or_default()
    }

    pub fn find(&self, id: &str) -> Option<&AIProvider> {
        if id.is_empty() {
            return None;
        }
        self.providers.iter().find(|p| p.id == id)
    }

    /// The endpoint and key the provider with `id` serves `capability` from.
    pub fn resolve(&self, id: &str, capability: &str) -> Option<(String, String)> {
        let provider = self.find(id)?;
        if !provider.supports(capability) {
            return None;
        }
        Some((provider.endpoint(capability), provider.api_key.clone()))
    }

    /// Checks every provider and that ids and names are unique.
    pub fn validate(&self) -> Result<(), String> {
        if self.providers.len() > MAX_AI_PROVIDERS {
            return Err(format!(
                "at most {MAX_AI_PROVIDERS} AI providers can be connected"
            ));
        }
        let mut ids = std::collections::HashSet::new();
        let mut names = std::collections::HashSet::new();
        for provider in &self.providers {
            let normalized = normalize_ai_provider(provider.clone())?;
            if !ids.insert(normalized.id.clone()) {
                return Err(format!(
                    "AI provider id {} is used twice",
                    quote(&normalized.id)
                ));
            }
            if !names.insert(to_lower(&normalized.name)) {
                return Err(format!(
                    "another AI provider is already named {}",
                    quote(&normalized.name)
                ));
            }
        }
        Ok(())
    }
}

/// `ResolveAIEndpoint`: the provider bound by `binding_key`. An unreadable registry resolves nothing.
pub fn resolve_ai_endpoint(
    values: &SettingsMap,
    binding_key: &str,
    capability: &str,
) -> (String, String) {
    parse_ai_provider_registry(m_get(values, AI_PROVIDERS_SETTING_KEY))
        .ok()
        .and_then(|r| r.resolve(trim_space(m_get(values, binding_key)), capability))
        .unwrap_or_default()
}

/// `ResolveAIServiceTier`: the saved tier applies only to an OpenAI API-key text provider.
pub fn resolve_ai_service_tier(values: &SettingsMap) -> String {
    if m_get(values, "ai.auth_mode") == AI_AUTH_MODE_CHATGPT {
        return String::new();
    }
    let Ok(registry) = parse_ai_provider_registry(m_get(values, AI_PROVIDERS_SETTING_KEY)) else {
        return String::new();
    };
    match registry.find(trim_space(m_get(values, AI_TEXT_PROVIDER_SETTING_KEY))) {
        Some(p) if p.type_ == AI_PROVIDER_OPENAI && p.supports(AI_CAPABILITY_CHAT) => {
            m_get(values, AI_SERVICE_TIER_SETTING_KEY).to_owned()
        }
        _ => String::new(),
    }
}

fn ai_provider_id_pattern() -> &'static GoRegex {
    static RE: OnceLock<GoRegex> = OnceLock::new();
    RE.get_or_init(|| GoRegex::must_compile("^[a-z0-9][a-z0-9-]{0,63}$"))
}

/// `NewAIProviderID`: a fresh id for a provider of type `t`.
pub fn new_ai_provider_id(t: &str) -> String {
    use std::io::Read;
    let mut b = [0u8; 3];
    // crypto/rand in Go, whose error it ignores. The id is not a secret, only unique in one registry.
    let _ = std::fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut b));
    format!("{t}-{:02x}{:02x}{:02x}", b[0], b[1], b[2])
}

/// `NormalizeAIProvider`: trims the editable fields, fills a known type's capabilities, and reports
/// the first problem with the provider.
pub fn normalize_ai_provider(mut p: AIProvider) -> Result<AIProvider, String> {
    let Some(spec) = lookup_ai_provider_type(&p.type_) else {
        return Err(format!("unknown AI provider type {}", quote(&p.type_)));
    };
    if !ai_provider_id_pattern().match_string(&p.id) {
        return Err(format!(
            "AI provider id {} must be lowercase letters, digits, and hyphens",
            quote(&p.id)
        ));
    }
    p.name = trim_space(&p.name).to_owned();
    if p.name.is_empty() || p.name.chars().count() > MAX_AI_PROVIDER_NAME_RUNES {
        return Err(format!(
            "AI provider name must be 1 to {MAX_AI_PROVIDER_NAME_RUNES} characters"
        ));
    }
    let base_url = normalize_admin_url("AI provider base URL", trim_space(&p.base_url))?;
    if base_url.is_empty() {
        return Err("AI provider base URL is required".to_owned());
    }
    if let Ok(parsed) = Url::parse(&base_url)
        && (parsed.user.is_some() || !parsed.raw_query.is_empty() || !parsed.fragment.is_empty())
    {
        return Err(
            "AI provider base URL cannot carry credentials, a query, or a fragment".to_owned(),
        );
    }
    p.base_url = base_url;
    p.api_key = trim_space(&p.api_key).to_owned();
    if p.api_key.len() > MAX_AI_PROVIDER_KEY_BYTES {
        return Err(format!(
            "AI provider API key must be at most {MAX_AI_PROVIDER_KEY_BYTES} bytes"
        ));
    }
    if spec.key_required && p.api_key.is_empty() {
        return Err(format!("{} requires an API key", spec.label));
    }
    if let Some(caps) = spec.capabilities {
        p.capabilities = Some(caps.iter().map(|c| (*c).to_owned()).collect());
        return Ok(p);
    }
    let given = p.capabilities.take().unwrap_or_default();
    let capabilities: Vec<String> = AI_CAPABILITIES
        .iter()
        .filter(|c| given.iter().any(|x| x == *c))
        .map(|c| (*c).to_owned())
        .collect();
    for capability in &given {
        if !AI_CAPABILITIES.contains(&capability.as_str()) {
            return Err(format!("unknown AI capability {}", quote(capability)));
        }
    }
    if capabilities.is_empty() {
        return Err("choose at least one thing the provider serves".to_owned());
    }
    p.capabilities = Some(capabilities);
    Ok(p)
}

pub const AI_JOB_TEXT: &str = "text";
pub const AI_JOB_SPEECH: &str = "speech";
pub const AI_JOB_EMBEDDINGS: &str = "embeddings";

const AI_PROVIDER_BINDINGS: [(&str, &str, &str, &str); 3] = [
    (
        AI_JOB_TEXT,
        AI_TEXT_PROVIDER_SETTING_KEY,
        AI_CAPABILITY_CHAT,
        "text model",
    ),
    (
        AI_JOB_SPEECH,
        AI_SPEECH_PROVIDER_SETTING_KEY,
        AI_CAPABILITY_SPEECH,
        "speech-to-text",
    ),
    (
        AI_JOB_EMBEDDINGS,
        EMBEDDING_PROVIDER_SETTING_KEY,
        AI_CAPABILITY_EMBEDDINGS,
        "recommendation embeddings",
    ),
];

/// `AIJob.Label`.
pub fn ai_job_label(job: &str) -> String {
    AI_PROVIDER_BINDINGS
        .iter()
        .find(|b| b.0 == job)
        .map_or_else(|| job.to_owned(), |b| b.3.to_owned())
}

/// `AIProviderBindingKeys`.
pub fn ai_provider_binding_keys() -> Vec<String> {
    AI_PROVIDER_BINDINGS
        .iter()
        .map(|b| b.1.to_owned())
        .collect()
}

/// `ValidateAIProviderBindings`.
pub fn validate_ai_provider_bindings(values: &SettingsMap) -> Result<(), String> {
    let registry = parse_ai_provider_registry(m_get(values, AI_PROVIDERS_SETTING_KEY))?;
    for (_, key, capability, label) in AI_PROVIDER_BINDINGS {
        let id = trim_space(m_get(values, key));
        if id.is_empty() {
            continue;
        }
        let Some(provider) = registry.find(id) else {
            return Err(format!(
                "the {label} provider {} is not connected",
                quote(id)
            ));
        };
        if !provider.supports(capability) {
            return Err(format!("{} cannot serve the {label}", provider.name));
        }
    }
    Ok(())
}

/// `AIProviderUsers`: the jobs that send requests to provider `id`.
pub fn ai_provider_users(values: &SettingsMap, id: &str) -> Vec<String> {
    let mut users = Vec::new();
    for (job, key, _, _) in AI_PROVIDER_BINDINGS {
        if id.is_empty() || trim_space(m_get(values, key)) != id {
            continue;
        }
        if job == AI_JOB_TEXT && trim_space(m_get(values, "ai.auth_mode")) == AI_AUTH_MODE_CHATGPT {
            continue;
        }
        users.push(job.to_owned());
    }
    users
}

pub(crate) const LEGACY_AI_TEXT_URL_SETTING: &str = "ai.base_url";
pub(crate) const LEGACY_AI_TEXT_KEY_SETTING: &str = "ai.api_key";
pub(crate) const LEGACY_AI_SPEECH_URL_SETTING: &str = "ai.asr_base_url";
pub(crate) const LEGACY_AI_SPEECH_KEY_SETTING: &str = "ai.asr_api_key";
pub(crate) const LEGACY_SUBTITLE_URL_SETTING: &str = "subtitle_ai.base_url";
pub(crate) const LEGACY_SUBTITLE_KEY_SETTING: &str = "subtitle_ai.api_key";
pub(crate) const LEGACY_EMBEDDING_URL_SETTING: &str = "recommendations.embedding_base_url";
pub(crate) const LEGACY_EMBEDDING_TOKEN_SETTING: &str = "recommendations.embedding_auth_token";
const LEGACY_EMBEDDING_MODEL_SETTING: &str = "recommendations.embedding_model";
pub(crate) const LEGACY_OPENAI_EMBEDDING_MODEL: &str = "recommendations.openai_model";
pub(crate) const LEGACY_OPENAI_EMBEDDING_TOKEN: &str = "recommendations.openai_api_key";
pub(crate) const LEGACY_EMBEDDING_PROVIDER_SETTING: &str = "recommendations.embedding_provider";
const LEGACY_DEFAULT_EMBEDDING_MODEL: &str = "all-minilm";
const OPENAI_DEFAULT_EMBEDDING_MODEL: &str = "text-embedding-3-small";

struct Conversion<'a> {
    registry: &'a mut AIProviderRegistry,
    stored: &'a SettingsMap,
    writes: SettingsMap,
    unconverted: Vec<String>,
    new_id: &'a mut dyn FnMut(&str) -> String,
}

impl Conversion<'_> {
    fn bind(&mut self, key: &str, id: &str) {
        if !id.is_empty() && trim_space(m_get(self.stored, key)).is_empty() {
            self.writes.insert(key.to_owned(), id.to_owned());
        }
    }

    fn adopt(&mut self, setting: &str, base_url: &str, api_key: &str, capability: &str) -> String {
        match adopt_ai_provider(self.registry, base_url, api_key, capability, self.new_id) {
            Ok(id) => id,
            Err(_) => {
                if !self.unconverted.iter().any(|s| s == setting) {
                    self.unconverted.push(setting.to_owned());
                }
                String::new()
            }
        }
    }
}

fn first_non_empty<'a>(a: &'a str, b: &'a str) -> &'a str {
    if a.is_empty() { b } else { a }
}

/// What [`plan_ai_provider_conversion`] found to do.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AIProviderConversionPlan {
    /// The writes for one atomic settings update, or `None` when every conversion has run.
    pub writes: Option<SettingsMap>,
    /// Legacy settings whose endpoint the registry refuses.
    pub unconverted: Vec<String>,
}

/// `PlanAIProviderConversion`: moves endpoints stored by older builds into the registry, once.
pub fn plan_ai_provider_conversion(
    stored: &SettingsMap,
) -> Result<AIProviderConversionPlan, String> {
    plan_ai_provider_conversion_with_ids(stored, &mut new_ai_provider_id)
}

/// [`plan_ai_provider_conversion`] with a chosen id source, so a vector can pin the ids.
pub fn plan_ai_provider_conversion_with_ids(
    stored: &SettingsMap,
    new_id: &mut dyn FnMut(&str) -> String,
) -> Result<AIProviderConversionPlan, String> {
    let mut registry = parse_ai_provider_registry(m_get(stored, AI_PROVIDERS_SETTING_KEY))?;
    if registry.version >= AI_PROVIDERS_VERSION {
        return Ok(AIProviderConversionPlan::default());
    }
    let version = registry.version;
    let mut c = Conversion {
        registry: &mut registry,
        stored,
        writes: SettingsMap::new(),
        unconverted: Vec::new(),
        new_id,
    };
    if version < 1 {
        convert_legacy_text_and_speech(&mut c);
    }
    if version < 2 {
        convert_legacy_embeddings(&mut c);
    }
    let mut writes = std::mem::take(&mut c.writes);
    let unconverted = std::mem::take(&mut c.unconverted);
    registry.version = AI_PROVIDERS_VERSION;
    writes.insert(AI_PROVIDERS_SETTING_KEY.to_owned(), registry.encode());
    Ok(AIProviderConversionPlan {
        writes: Some(writes),
        unconverted,
    })
}

fn convert_legacy_text_and_speech(c: &mut Conversion<'_>) {
    let stored = c.stored;
    let stored_text_url = first_non_empty(
        m_get(stored, LEGACY_AI_TEXT_URL_SETTING),
        m_get(stored, LEGACY_SUBTITLE_URL_SETTING),
    );
    let text_url_setting = if m_get(stored, LEGACY_AI_TEXT_URL_SETTING).is_empty()
        && !m_get(stored, LEGACY_SUBTITLE_URL_SETTING).is_empty()
    {
        LEGACY_SUBTITLE_URL_SETTING
    } else {
        LEGACY_AI_TEXT_URL_SETTING
    };
    let text_key = first_non_empty(
        m_get(stored, LEGACY_AI_TEXT_KEY_SETTING),
        m_get(stored, LEGACY_SUBTITLE_KEY_SETTING),
    );
    let text_base_url = first_non_empty(stored_text_url, OPENAI_BASE_URL)
        .trim_end_matches('/')
        .to_owned();
    if !stored_text_url.is_empty() || !text_key.is_empty() {
        let id = c.adopt(
            text_url_setting,
            &text_base_url,
            text_key,
            AI_CAPABILITY_CHAT,
        );
        c.bind(AI_TEXT_PROVIDER_SETTING_KEY, &id);
    }
    let speech_base_url = trim_space(m_get(stored, LEGACY_AI_SPEECH_URL_SETTING)).to_owned();
    let speech_key = first_non_empty(m_get(stored, LEGACY_AI_SPEECH_KEY_SETTING), text_key);
    if !speech_base_url.is_empty() {
        let id = c.adopt(
            LEGACY_AI_SPEECH_URL_SETTING,
            &speech_base_url,
            speech_key,
            AI_CAPABILITY_SPEECH,
        );
        c.bind(AI_SPEECH_PROVIDER_SETTING_KEY, &id);
        return;
    }
    if stored_text_url.is_empty() && speech_key.is_empty() {
        return;
    }
    let (provider_type, _) =
        detect_ai_provider_type(&text_base_url, speech_key, AI_CAPABILITY_SPEECH);
    if provider_type == AI_PROVIDER_CUSTOM
        && !admin_setting_enabled(
            "subtitle_ai.transcribe_enabled",
            m_get(stored, "subtitle_ai.transcribe_enabled"),
        )
    {
        return;
    }
    let id = c.adopt(
        text_url_setting,
        &text_base_url,
        speech_key,
        AI_CAPABILITY_SPEECH,
    );
    c.bind(AI_SPEECH_PROVIDER_SETTING_KEY, &id);
}

fn convert_legacy_embeddings(c: &mut Conversion<'_>) {
    let stored = c.stored;
    if !trim_space(m_get(stored, EMBEDDING_PROVIDER_SETTING_KEY)).is_empty() {
        return;
    }
    let legacy_openai = !m_get(stored, LEGACY_OPENAI_EMBEDDING_MODEL).is_empty()
        || !m_get(stored, LEGACY_OPENAI_EMBEDDING_TOKEN).is_empty()
        || m_get(stored, LEGACY_EMBEDDING_PROVIDER_SETTING) == AI_PROVIDER_OPENAI;
    let mut base_url = trim_space(m_get(stored, LEGACY_EMBEDDING_URL_SETTING)).to_owned();
    let mut model = first_non_empty(
        m_get(stored, LEGACY_EMBEDDING_MODEL_SETTING),
        m_get(stored, LEGACY_OPENAI_EMBEDDING_MODEL),
    )
    .to_owned();
    if base_url.is_empty() {
        if legacy_openai {
            base_url = OPENAI_BASE_URL.to_owned();
        } else if !trim_space(m_get(stored, "recommendations.embedding_lock")).is_empty()
            || admin_setting_enabled(
                "recommendations.enabled",
                m_get(stored, "recommendations.enabled"),
            )
        {
            base_url = OLLAMA_BASE_URL.to_owned();
        } else {
            return;
        }
    }
    if model.is_empty() {
        model = LEGACY_DEFAULT_EMBEDDING_MODEL.to_owned();
        if base_url == OPENAI_BASE_URL
            || m_get(stored, LEGACY_EMBEDDING_PROVIDER_SETTING) == AI_PROVIDER_OPENAI
        {
            model = OPENAI_DEFAULT_EMBEDDING_MODEL.to_owned();
        }
    }
    let token = first_non_empty(
        m_get(stored, LEGACY_EMBEDDING_TOKEN_SETTING),
        m_get(stored, LEGACY_OPENAI_EMBEDDING_TOKEN),
    );
    let id = c.adopt(
        LEGACY_EMBEDDING_URL_SETTING,
        &base_url,
        token,
        AI_CAPABILITY_EMBEDDINGS,
    );
    if id.is_empty() {
        return;
    }
    c.writes
        .insert(EMBEDDING_PROVIDER_SETTING_KEY.to_owned(), id);
    if trim_space(m_get(stored, LEGACY_EMBEDDING_MODEL_SETTING)) != model {
        c.writes
            .insert(LEGACY_EMBEDDING_MODEL_SETTING.to_owned(), model);
    }
}

fn adopt_ai_provider(
    r: &mut AIProviderRegistry,
    base_url: &str,
    api_key: &str,
    capability: &str,
    new_id: &mut dyn FnMut(&str) -> String,
) -> Result<String, String> {
    let base_url = trim_space(base_url).trim_end_matches('/').to_owned();
    let api_key = trim_space(api_key).to_owned();
    let (provider_type, provider_base_url) =
        detect_ai_provider_type(&base_url, &api_key, capability);
    if provider_type.is_empty() {
        return Ok(String::new());
    }
    if let Some(existing) = r
        .providers
        .iter()
        .find(|p| {
            p.type_ == provider_type && p.base_url == provider_base_url && p.api_key == api_key
        })
        .map(|p| p.id.clone())
    {
        add_ai_provider_capability(r, &existing, capability);
        return Ok(existing);
    }
    let spec = lookup_ai_provider_type(&provider_type);
    let mut name = spec.map_or("", |s| s.label).to_owned();
    let mut capabilities: Option<Vec<String>> = spec
        .and_then(|s| s.capabilities)
        .map(|c| c.iter().map(|x| (*x).to_owned()).collect());
    if provider_type == AI_PROVIDER_CUSTOM {
        if let Ok(parsed) = Url::parse(&provider_base_url)
            && !parsed.host.is_empty()
        {
            name = parsed.host;
        }
        capabilities = Some(vec![capability.to_owned()]);
    }
    if name.chars().count() > MAX_AI_PROVIDER_NAME_RUNES - 5 {
        name = name.chars().take(MAX_AI_PROVIDER_NAME_RUNES - 5).collect();
    }
    let provider = normalize_ai_provider(AIProvider {
        id: new_id(&provider_type),
        type_: provider_type,
        name: unique_ai_provider_name(r, &name),
        base_url: provider_base_url,
        api_key,
        capabilities,
    })?;
    let id = provider.id.clone();
    r.providers.push(provider);
    Ok(id)
}

fn add_ai_provider_capability(r: &mut AIProviderRegistry, id: &str, capability: &str) {
    for provider in &mut r.providers {
        if provider.id != id || provider.supports(capability) {
            continue;
        }
        if provider.type_ == AI_PROVIDER_CUSTOM {
            let caps = provider.capabilities.get_or_insert_with(Vec::new);
            caps.push(capability.to_owned());
            caps.sort_by_key(|c| AI_CAPABILITIES.iter().position(|x| x == c));
        }
    }
}

fn unique_ai_provider_name(r: &AIProviderRegistry, name: &str) -> String {
    let taken = |candidate: &str| r.providers.iter().any(|p| equal_fold(&p.name, candidate));
    if !taken(name) {
        return name.to_owned();
    }
    let mut n = 2;
    loop {
        let candidate = format!("{name} ({n})");
        if !taken(&candidate) {
            return candidate;
        }
        n += 1;
    }
}

fn api_version_segment() -> &'static GoRegex {
    static RE: OnceLock<GoRegex> = OnceLock::new();
    RE.get_or_init(|| GoRegex::must_compile(API_VERSION_SEGMENT))
}

// internal/ai/llm's apiVersionSegment.
const API_VERSION_SEGMENT: &str = r"^v[0-9]+(?:(?:alpha|beta)[0-9]*)?$";

/// `llm.HasAPIVersion`.
pub fn has_api_version(base_url: &str) -> bool {
    let Ok(parsed) = Url::parse(trim_space(base_url)) else {
        return false;
    };
    parsed
        .path
        .split('/')
        .any(|segment| api_version_segment().match_string(segment))
}

fn same_request_endpoint(a: &str, b: &str, capability: &str) -> bool {
    if capability == AI_CAPABILITY_EMBEDDINGS {
        return a == b;
    }
    let with_version = |base: &str| {
        if has_api_version(base) {
            base.to_owned()
        } else {
            format!("{base}/v1")
        }
    };
    with_version(a) == with_version(b)
}

fn detect_ai_provider_type(base_url: &str, api_key: &str, capability: &str) -> (String, String) {
    if normalize_admin_url("AI provider base URL", base_url).is_err() || base_url.is_empty() {
        return (String::new(), String::new());
    }
    for spec in AI_PROVIDER_TYPES {
        if spec.default_base_url.is_empty()
            || spec.type_ == AI_PROVIDER_OLLAMA
            || spec.type_ == AI_PROVIDER_WHISPER
            || !spec.supports(capability)
        {
            continue;
        }
        if !same_request_endpoint(
            &spec.endpoint(spec.default_base_url, capability),
            base_url,
            capability,
        ) {
            continue;
        }
        if spec.key_required && api_key.is_empty() {
            return (String::new(), String::new());
        }
        return (spec.type_.to_owned(), spec.default_base_url.to_owned());
    }
    if let Ok(parsed) = Url::parse(base_url)
        && parsed.port() == "11434"
        && parsed.path.is_empty()
        && capability != AI_CAPABILITY_SPEECH
    {
        return (AI_PROVIDER_OLLAMA.to_owned(), base_url.to_owned());
    }
    (AI_PROVIDER_CUSTOM.to_owned(), base_url.to_owned())
}
