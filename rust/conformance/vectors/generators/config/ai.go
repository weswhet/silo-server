//go:build silo_config_vectors

package main

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/Silo-Server/silo-server/internal/ai/llm"
	"github.com/Silo-Server/silo-server/internal/ai/reasoning"
	"github.com/Silo-Server/silo-server/internal/config"
)

type registryVector struct {
	Raw      string `json:"raw"`
	Encoded  string `json:"encoded,omitempty"`
	Error    string `json:"error,omitempty"`
	Validate string `json:"validate,omitempty"`
}

type providerVector struct {
	In    string `json:"in"`
	Out   string `json:"out,omitempty"`
	Error string `json:"error,omitempty"`
}

type planVector struct {
	Stored      map[string]string `json:"stored"`
	Writes      map[string]string `json:"writes"`
	Unconverted []string          `json:"unconverted"`
	Error       string            `json:"error,omitempty"`
	NilWrites   bool              `json:"nil_writes"`
}

type bindingVector struct {
	Values   map[string]string    `json:"values"`
	Validate string               `json:"validate,omitempty"`
	Tier     string               `json:"tier"`
	Users    map[string][]string  `json:"users"`
	Endpoint map[string][2]string `json:"endpoint"`
}

var randomProviderID = regexp.MustCompile(`(openai|gemini|openrouter|groq|ollama|whisper|custom)-[0-9a-f]{6}`)

// stableIDs numbers NewAIProviderID's random suffixes, so regenerating changes nothing. The Rust side
// numbers both sides by first appearance before comparing.
func stableIDs(writes map[string]string) map[string]string {
	if writes == nil {
		return nil
	}
	seen := map[string]string{}
	out := map[string]string{}
	for _, k := range sortedKeys(writes) {
		out[k] = randomProviderID.ReplaceAllStringFunc(writes[k], func(id string) string {
			if _, ok := seen[id]; !ok {
				seen[id] = fmt.Sprintf("%s-%06x", id[:len(id)-7], len(seen))
			}
			return seen[id]
		})
	}
	return out
}

func writeAIVectors() {
	raws := []string{
		"", " ", "{}", "null", "[]", "1", "{", `{"version":1}`, `{"VERSION":2,"PROVIDERS":[]}`, `{"version":"2"}`, `{"version":1.5}`, `{"providers":null}`, `{"providers":{}}`, `{"providers":[null]}`, `{"providers":[1]}`,
		`{"providers":[{"id":"a","type":"openai","name":"A","base_url":"https://api.openai.com","api_key":"k","capabilities":["speech"]}]}`,
		`{"providers":[{"id":"b","type":"openrouter","name":"B","base_url":"https://openrouter.ai/api/v1","api_key":"k"}]}`,
		`{"providers":[{"id":"c","type":"custom","name":"C","base_url":"http://c","capabilities":["speech","chat"]},{"id":"d","type":"nope","name":"D","base_url":"http://d","capabilities":["x"]}]}`,
		`{"providers":[{"id":"e","type":"gemini","name":"E","base_url":"https://g","api_key":"<&>"}]}`,
		`{"providers":[{"ID":"f","Type":"ollama","Name":"F","Base_URL":"http://o:11434"}]}`,
		`{"providers":[{"id":1}]}`, `{"providers":[{"capabilities":"chat"}]}`, `{"providers":[{"capabilities":[1]}]}`,
		`{"providers":[{"id":"x","type":"groq","name":"X","base_url":"http://x","api_key":"k"},{"id":"x","type":"groq","name":"Y","base_url":"http://y","api_key":"k"}]}`,
		`{"providers":[{"id":"x","type":"groq","name":"Same","base_url":"http://x","api_key":"k"},{"id":"y","type":"groq","name":"same","base_url":"http://y","api_key":"k"}]}`,
	}
	regs := make([]registryVector, 0, len(raws))
	for _, r := range raws {
		reg, err := config.ParseAIProviderRegistry(r)
		vec := registryVector{Raw: r}
		if err != nil {
			vec.Error = err.Error()
		} else {
			vec.Encoded = reg.Encode()
			if verr := reg.Validate(); verr != nil {
				vec.Validate = verr.Error()
			}
		}
		regs = append(regs, vec)
	}
	providers := []string{
		`{"id":"a","type":"openai","name":" OpenAI ","base_url":" https://api.openai.com/ ","api_key":" k ","capabilities":[]}`,
		`{"id":"a","type":"openai","name":"O","base_url":"https://api.openai.com"}`,
		`{"id":"a","type":"ollama","name":"O","base_url":"http://o:11434"}`,
		`{"id":"a","type":"nope","name":"O","base_url":"http://o"}`,
		`{"id":"A!","type":"ollama","name":"O","base_url":"http://o"}`,
		`{"id":"-a","type":"ollama","name":"O","base_url":"http://o"}`,
		`{"id":"a","type":"ollama","name":"  ","base_url":"http://o"}`,
		`{"id":"a","type":"ollama","name":"` + strings.Repeat("n", 81) + `","base_url":"http://o"}`,
		`{"id":"a","type":"ollama","name":"` + strings.Repeat("n", 80) + `","base_url":"http://o"}`,
		`{"id":"a","type":"ollama","name":"O","base_url":""}`,
		`{"id":"a","type":"ollama","name":"O","base_url":"ftp://o"}`,
		`{"id":"a","type":"ollama","name":"O","base_url":"o"}`,
		`{"id":"a","type":"ollama","name":"O","base_url":"http://u:p@o"}`,
		`{"id":"a","type":"ollama","name":"O","base_url":"http://o?q=1"}`,
		`{"id":"a","type":"ollama","name":"O","base_url":"http://o#f"}`,
		`{"id":"a","type":"ollama","name":"O","base_url":"http://o","api_key":"` + strings.Repeat("k", 4097) + `"}`,
		`{"id":"a","type":"custom","name":"C","base_url":"http://c","capabilities":[]}`,
		`{"id":"a","type":"custom","name":"C","base_url":"http://c","capabilities":["speech","chat","speech"]}`,
		`{"id":"a","type":"custom","name":"C","base_url":"http://c","capabilities":["bogus"]}`,
	}
	provs := make([]providerVector, 0, len(providers))
	for _, p := range providers {
		var in config.AIProvider
		if err := json.Unmarshal([]byte(p), &in); err != nil {
			panic(err)
		}
		out, err := config.NormalizeAIProvider(in)
		vec := providerVector{In: p}
		if err != nil {
			vec.Error = err.Error()
		} else {
			vec.Out = goJSON(out)
		}
		provs = append(provs, vec)
	}
	stored := []map[string]string{
		{},
		{"ai.providers": `{"version":2,"providers":[]}`},
		{"ai.providers": `{`},
		{"ai.base_url": "https://api.openai.com/", "ai.api_key": "k"},
		{"ai.api_key": "k"},
		{"ai.base_url": "https://api.openai.com/v1", "ai.api_key": "k"},
		{"ai.base_url": "https://api.openai.com"},
		{"subtitle_ai.base_url": "https://openrouter.ai/api", "subtitle_ai.api_key": "k"},
		{"subtitle_ai.base_url": "http://my.host/v1", "subtitle_ai.api_key": "k", "subtitle_ai.transcribe_enabled": "true"},
		{"ai.base_url": "http://my.host/v1", "ai.asr_base_url": "http://w:9000/", "ai.asr_api_key": "s"},
		{"ai.base_url": "http://u:p@my.host"},
		{"ai.base_url": "http://ollama:11434"},
		{"ai.base_url": "https://generativelanguage.googleapis.com/v1beta/openai", "ai.api_key": "k"},
		{"ai.base_url": "https://api.groq.com/openai/v1", "ai.api_key": "k", "ai.asr_base_url": "https://api.groq.com/openai", "ai.asr_api_key": "k"},
		{"ai.text_provider_id": "already", "ai.base_url": "http://x", "ai.providers": `{"version":0,"providers":[{"id":"already","type":"custom","name":"x","base_url":"http://x","capabilities":["speech"]}]}`},
		{"ai.providers": `{"version":1,"providers":[]}`, "ai.base_url": "http://ignored"},
		{"recommendations.enabled": "true"},
		{"recommendations.embedding_lock": "x"},
		{"recommendations.embedding_base_url": "http://e:1/", "recommendations.embedding_auth_token": "t", "recommendations.embedding_model": "m"},
		{"recommendations.openai_model": "o"},
		{"recommendations.openai_api_key": "k"},
		{"recommendations.embedding_provider": "openai", "recommendations.openai_api_key": "k"},
		{"recommendations.embedding_base_url": "https://api.openai.com", "recommendations.openai_api_key": "k"},
		{"recommendations.embedding_provider_id": "set", "recommendations.embedding_base_url": "http://e"},
		{"recommendations.embedding_base_url": "http://u:p@e"},
		{"ai.base_url": "http://same", "recommendations.embedding_base_url": "http://same"},
		{"ai.base_url": "http://same", "subtitle_ai.transcribe_enabled": "true", "recommendations.embedding_base_url": "http://same"},
		{"ai.base_url": "http://a", "ai.asr_base_url": "http://a", "subtitle_ai.base_url": "http://b"},
		{"ai.providers": `{"version":0,"providers":[{"id":"c1","type":"custom","name":"h","base_url":"http://h2","capabilities":["chat"]}]}`, "ai.base_url": "http://h"},
	}
	plans := make([]planVector, 0, len(stored))
	for _, s := range stored {
		w, u, err := config.PlanAIProviderConversion(s)
		vec := planVector{Stored: s, Writes: stableIDs(w), Unconverted: u, NilWrites: w == nil}
		if err != nil {
			vec.Error = err.Error()
		}
		if vec.Unconverted == nil {
			vec.Unconverted = []string{}
		}
		plans = append(plans, vec)
	}
	registry := `{"version":2,"providers":[{"id":"o","type":"openai","name":"OpenAI","base_url":"https://api.openai.com","api_key":"ko"},{"id":"g","type":"gemini","name":"Gem","base_url":"https://g","api_key":"kg"},{"id":"w","type":"whisper","name":"Wh","base_url":"http://w"},{"id":"c","type":"custom","name":"Cu","base_url":"http://c","capabilities":["embeddings"]}]}`
	values := []map[string]string{
		{},
		{"ai.providers": registry, "ai.text_provider_id": " o ", "ai.speech_provider_id": "w", "recommendations.embedding_provider_id": "c", "ai.service_tier": "ultrafast"},
		{"ai.providers": registry, "ai.text_provider_id": "g", "ai.service_tier": "priority"},
		{"ai.providers": registry, "ai.text_provider_id": "o", "ai.auth_mode": "chatgpt", "ai.service_tier": "priority"},
		{"ai.providers": registry, "ai.text_provider_id": "w"},
		{"ai.providers": registry, "ai.speech_provider_id": "g"},
		{"ai.providers": registry, "recommendations.embedding_provider_id": "w"},
		{"ai.providers": registry, "ai.text_provider_id": "missing"},
		{"ai.providers": "{", "ai.text_provider_id": "o"},
	}
	bindings := make([]bindingVector, 0, len(values))
	for _, v := range values {
		vec := bindingVector{Values: v, Tier: config.ResolveAIServiceTier(v), Users: map[string][]string{}, Endpoint: map[string][2]string{}}
		if err := config.ValidateAIProviderBindings(v); err != nil {
			vec.Validate = err.Error()
		}
		for _, id := range []string{"", "o", "g", "w", "c"} {
			users := []string{}
			for _, j := range config.AIProviderUsers(v, id) {
				users = append(users, string(j))
			}
			vec.Users[id] = users
		}
		for _, key := range config.AIProviderBindingKeys() {
			for _, capability := range config.AICapabilities {
				u, k := config.ResolveAIEndpoint(v, key, capability)
				vec.Endpoint[key+"|"+string(capability)] = [2]string{u, k}
			}
		}
		bindings = append(bindings, vec)
	}
	versions := map[string]bool{}
	for _, u := range []string{"https://h/v1", "https://h/v1beta/openai", "https://h/v2alpha1", "https://v1.h", "https://h/v1-router", "https://h", "", " https://h/v1 ", "https://h/V1", "https://h/v1/", "://bad", "https://h/x/v12/y", "https://h/v", "https://h/v1beta2x"} {
		versions[u] = llm.HasAPIVersion(u)
	}
	efforts := []map[string]any{}
	for _, m := range []string{"", "gpt-6-luna", "gpt-6-sol", "gpt-6.1-sol", "gpt-6-astra", "gpt-5.6", "gpt-5-pro", "gpt-5.2-pro", "gpt-5.4-pro", "gpt-5.5-pro", "gpt-5.2", "gpt-5.4", "gpt-5.5", "gpt-5.1", "gpt-5", "gpt-5-mini", "gpt-5-nano", "gpt-5-2025", "o1", "o3-mini", "o4", "gpt-4o", "gpt-3.5", "chat-latest", "gpt-5-chat-latest", "openai/GPT-5.2-Chat-Latest", "openai/GPT-5.4-Pro", "custom-model"} {
		for _, e := range []string{"", "none", "minimal", "low", "medium", "high", "xhigh", "max", "bogus"} {
			msg := ""
			if err := reasoning.Validate(m, e); err != nil {
				msg = err.Error()
			}
			efforts = append(efforts, map[string]any{"model": m, "effort": e, "error": msg})
		}
	}
	write("ai_providers.json", map[string]any{"registries": regs, "providers": provs, "plans": plans, "bindings": bindings, "versions": versions, "efforts": efforts})
}
