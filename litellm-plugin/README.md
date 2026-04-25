# AIAuth LiteLLM Plugin

API-level attestation for any model that runs through a [LiteLLM](https://docs.litellm.ai/) proxy. Every call gets a signed attestation record with input/output hashes — content never leaves your infrastructure.

## What it does

- Captures a SHA-256 fingerprint of the prompt and response on every LiteLLM call.
- Stores a structured attestation record locally in SQLite with a versioned schema and review fields.
- Supports multi-model chains (e.g. ChatGPT plans → Claude implements → review) so the attestations link.
- Fields beyond the core schema land in a `metadata` JSON envelope — additive, never breaking.

This is the third surface alongside the Chrome extension and the desktop agent. The Chrome extension covers browser-based AI tools, the desktop agent covers everything else on the OS, and this plugin covers programmatic API traffic — internal pipelines, agentic workflows, batch jobs.

## Files

- `attestation_callback.py` — `CustomLogger` implementation. Drop next to your LiteLLM config.
- `multi_model_chain.py` — helpers for linking attestations from chained model calls.
- `config.yaml` — example LiteLLM proxy config showing how to wire the callback.

## Install

```bash
pip install 'litellm[proxy]'
```

Place the three files in a directory:

```
my-proxy/
  attestation_callback.py
  multi_model_chain.py
  config.yaml
```

## Configure

Edit `config.yaml` to add your model providers and API keys, then activate the callback:

```yaml
litellm_settings:
  callbacks: attestation_callback.proxy_handler_instance
  enforce_user_param: true
```

Required environment variables:

| Variable | Purpose |
|---|---|
| `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` / etc. | Whatever providers you list in `model_list` |
| `LITELLM_MASTER_KEY` | LiteLLM admin key (any value you choose) |
| `ATTESTATION_DB_PATH` | Optional. SQLite DB path. Defaults to `attestations.db` in cwd. |
| `AIAUTH_SIGN_ENDPOINT` | Optional. If set (e.g. `https://aiauth.app/v1/sign`), input/output hashes are also registered with the public AIAuth chain. Without it, attestations stay local — useful for air-gapped pipelines. |

## Run

```bash
litellm --config config.yaml
```

Proxy starts on `http://localhost:4000`. Point any OpenAI-compatible client at it. Every completion produces one row in `attestations.db`.

## Attestation record

Each row carries the LiteLLM call's identity plus AIAuth-style receipt fields:

- `id` — UUID, the receipt ID
- `schema_version` — currently `0.2.0`. Additive only.
- `model`, `provider`, `user_id`, `api_key_alias`
- `input_hash`, `output_hash` — SHA-256 over normalized text. No raw content stored.
- `review_status` — `pending` / `approved` / `modified` / `rejected`
- `parent_id` — links chained attestations (multi-model workflows)
- `metadata` — JSON envelope for additional fields (cost, tokens, classification, etc.)

The schema is intentionally a superset of the v0.5.0 receipt schema so records can be exported into the public AIAuth chain or imported into the enterprise attestation store.

## Multi-model chains

`multi_model_chain.py` provides a helper to mark a call as derived from a previous attestation:

```python
from multi_model_chain import attest_chained

plan_id = call_chatgpt(...)             # logs its own attestation
impl_id = call_claude(parent=plan_id)    # parent_id set automatically
```

Each downstream call carries the parent's hash forward, producing a queryable chain. The compliance dashboard renders these as a single workflow rather than disconnected events.

## Notes

- The plugin never blocks the LiteLLM call. If signing or DB write fails, the call still returns to the user; the failure is logged.
- The DB schema is created on first run via `init_db()`; no migrations needed for additive field additions.
- `metadata` is the right place for org-specific fields. Don't fork the schema.
