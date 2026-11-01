# Assistant setup

Docklight Assistant is an optional provider-backed feature. It starts off and has no model, endpoint, or key configured. Provider setup and a connection check are available to administrators under **Manage → Assistant**. Saving provider details does not turn the Assistant on.

## Configure a provider

Choose one of the supported providers, enter the model identifier from that provider, and save. Docklight supplies these default base URLs; an administrator may replace any default with an HTTP(S) endpoint:

| Provider | Default URL | Request format |
| --- | --- | --- |
| Anthropic | `https://api.anthropic.com` | Anthropic Messages API |
| OpenAI | `https://api.openai.com/v1` | OpenAI-compatible chat completions |
| OpenRouter | `https://openrouter.ai/api/v1` | OpenAI-compatible chat completions |
| DeepSeek | `https://api.deepseek.com/v1` | OpenAI-compatible chat completions |
| Mistral | `https://api.mistral.ai/v1` | OpenAI-compatible chat completions |
| Ollama | `http://127.0.0.1:11434/v1` | OpenAI-compatible chat completions |
| Custom | None | OpenAI-compatible chat completions |

Request shapes follow the [Anthropic Messages API](https://docs.anthropic.com/en/api/messages) and [OpenAI Chat Completions API](https://platform.openai.com/docs/api-reference/chat/create). OpenAI-compatible providers use the chat completions format.

The model name is required. A key is required for hosted providers before testing; Ollama and custom endpoints can be tested without one. The key is encrypted with the panel's `auth.secret_key`. The API returns a fixed mask and a configured flag, never the clear key. Leave the key field blank or send the returned mask to keep the saved key, or check **Remove the saved API key** to clear it.

HTTPS is required for public endpoints. Plain HTTP is accepted for loopback and private-network endpoints, including local Ollama deployments. Provider URLs cannot contain user information, query strings, or fragments. Connection requests have a 12-second timeout, do not follow redirects, and read at most 1 MiB of response data.

## Test the connection

Save the provider settings first. **Test connection** sends only `Reply with the word connected.` and checks for a non-empty text response. Docklight discards that response and does not include server, event, log, player, or configuration data. Test calls work while Assistant is off and are not written to audit history. Failures show the HTTP status when available, without returning the provider's response body or saved key.

The current slice covers provider storage and connection tests. It does not yet provide assistant chat, operations or daily digests, log/config advisors, panel data lookups, proposals, proactive actions, or the MCP connector. Those remain separate implementation work; keep Assistant off until those controls are present and reviewed.
