# Optional AI summaries

AI is off by default. It never decides whether an asset is affected, changes the
CVSS/EPSS/KEV metrics, or blocks a notification. When enabled, the worker asks for a
short summary **after** deterministic matching and rule evaluation. The alert
labels the result as AI-generated and unverified and retains the original source
links and matching explanation. If AI fails or the daily quota is exhausted, the
source-based alert still sends. Model output can be inaccurate or influenced by
untrusted descriptions; check primary sources before acting.

## Setup

1. Add your API credential to the server's private `.env` as `VULNRELAY_AI_KEY=...`. Multiple keys can use names starting with `VULNRELAY_AI_KEY`, such as `VULNRELAY_AI_KEY_TEAM`. Never enter the secret itself in the browser or commit it. Some self-hosted compatible servers do not require a key.
2. Select **AI** in the web interface. Choose the OpenAI Responses API, Anthropic Messages API, or an OpenAI-compatible Chat Completions API, and enter the exact model ID offered by your provider. Model availability and compatible parameters differ by provider.
3. For the compatible option, set `VULNRELAY_AI_BASE_URL` in `.env` to the provider's API base URL, including its version path when required, e.g. `https://your-provider.example/v1`. VulnRelay appends `/chat/completions`. The base URL is a trusted server setting, not a browser input. HTTPS and publicly routed addresses are required by default. The application resolves and pins the outgoing IP while retaining TLS hostname validation, and does not follow redirects.
4. Optional self-hosted servers, for example an Ollama OpenAI-compatible endpoint, can be explicitly allowed with `VULNRELAY_AI_ALLOW_PRIVATE_HOSTS=true`. For Docker, a server on the VPS host needs an address reachable **from the container**; `localhost` inside the container refers to that container. Use this setting only with endpoints you trust. Link-local and metadata addresses are still blocked; plain HTTP is allowed only for explicitly enabled private hosts.
5. After editing `.env`, recreate both containers with `docker compose up -d --force-recreate`; a simple restart does not reload their environment. Save the AI settings. **Test connection** makes a real provider request with a fictional description and may cost money. Automated tests use mock responses and do not use an API key.
6. Select the summary language, daily request limit and maximum output tokens. The daily request counter resets at UTC midnight and persists through restarts; failures and connection tests count. Cached summaries do not. This is not a monetary spending limit: configure a separate billing limit with your provider. Then enable summaries and save.

Only a public CVE identifier and its public source description (up to 4,000 characters) are sent after a rule matches. Asset names, inventory, rules, connector details and metrics are not sent. A short result cache is stored locally for up to 1,000 summaries. Remote providers may have their own retention and privacy policies. OpenAI requests explicitly set `store: false`.

The custom protocol supports providers that implement the standard Chat Completions message and response shape; it cannot guarantee compatibility with every provider or model. Ollama requires its compatible API mode and network reachability. There is currently one active AI configuration per instance, and summaries are available for alerts, not independent digests or vulnerability-page chat. Translation is an instruction to the model, not a verified translation.

References: [OpenAI Responses API](https://developers.openai.com/api/reference/resources/responses/methods/create), [Anthropic Messages API](https://platform.claude.com/docs/en/api/messages/create), [Ollama OpenAI compatibility](https://docs.ollama.com/api/openai-compatibility).
