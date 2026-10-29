# AI Agent Detections

Detection rules for **AI agent / LLM threats** — prompt injection, excessive agency,
tool poisoning, runaway loops — in [Sigma](https://sigmahq.io/) format, mapped to the
**OWASP LLM Top 10** and **MITRE ATLAS**.

The rules are the commodity. **What makes this different: every rule ships with
benign + malicious fixtures and a test that actually fires them** — not a folder of
untested YAML. If a rule can't tell an attack from normal traffic in CI, it isn't done.
Every rule also passes `sigma check` with zero issues and ships pre-converted to
Splunk, Microsoft Sentinel and Elastic.

> Status: **v0 / seed set** (15 rules). Public knowledge only (OWASP, MITRE ATLAS,
> published research, own lab) — no proprietary or employer data.

## Rules in this set

OWASP mapping lives in each rule's `x_owasp_llm` field (OWASP is not a standard Sigma
tag namespace); MITRE ATLAS technique ids are in each rule's `references`.

| Rule | Threat | OWASP |
|------|--------|-------|
| `agent_tool_invocation_outside_allowlist` | Agent calls a tool outside its allowlist | LLM06 Excessive Agency |
| `agent_runaway_tool_loop` | Agent stuck in a runaway tool-call loop (denial-of-wallet) | LLM10 Unbounded Consumption |
| `agent_indirect_prompt_injection_in_tool_output` | Injection instructions arriving via tool/retrieval output | LLM01 Prompt Injection, LLM05 Improper Output Handling |
| `agent_sensitive_data_exfil_egress` | Egress tool sends data externally after a sensitive read | LLM02 Sensitive Information Disclosure |
| `agent_secrets_in_model_output` | API key / token pattern appears in model output | LLM02 Sensitive Information Disclosure |
| `agent_pii_in_tool_output_cross_boundary` | Email / card PII in tool output crossing a trust boundary | LLM02 Sensitive Information Disclosure |
| `agent_ssrf_via_tool_to_internal` | Fetch tool steered at metadata / loopback / internal host | LLM06 Excessive Agency |
| `agent_direct_jailbreak_in_user_input` | Direct jailbreak / guardrail-bypass phrases in the user turn | LLM01 Prompt Injection |
| `agent_insecure_output_handling` | Executable payload in model output routed to an HTML/Markdown/shell sink | LLM05 Improper Output Handling |
| `agent_memory_poisoning_untrusted_write` | Agent memory written from an untrusted source (tool/retrieval/web) | LLM04 Data and Model Poisoning |
| `agent_mcp_tool_poisoning_schema_change` | MCP tool schema/description changed since registration (rug pull) | LLM03 Supply Chain |
| `agent_destructive_action_without_approval` | Agent runs a destructive action (delete/drop/terminate…) with no human approval | LLM06 Excessive Agency |
| `agent_subagent_spawn_beyond_autonomy_tier` | Agent spawns sub-agents past its allowed nesting depth | LLM06 Excessive Agency |
| `agent_unbounded_single_completion` | A single model completion emits an abnormally large token count | LLM10 Unbounded Consumption |
| `agent_unexpected_model_or_provider` | Completion served by a model/provider outside the approved list | LLM03 Supply Chain |

## Telemetry schema

Rules target a **flat agent-runtime event** (dotted keys, OpenTelemetry GenAI style).
Minimum fields the rules read:

| Field | Meaning |
|-------|---------|
| `event_type` | `tool_call` \| `tool_result` \| `model_completion` \| `memory_write` \| `user_prompt` |
| `session_id` | agent session (correlation) |
| `agent` | agent name/id |
| `tool.name` | tool invoked |
| `tool.allowed` | was the tool in the agent's allowlist (bool) |
| `tool.call_count_window` | tool calls by this session in the trailing window (computed at ingest) |
| `cost_usd_window` | spend by this session in the window |
| `content.source` | origin of `content`: `user` \| `model` \| `tool_output` \| `retrieval` \| `web_fetch` |
| `content` | text payload |
| `content.scanner_verdict` | output-scanner verdict, e.g. `benign_confirmed` |
| `tool.args` | serialized tool arguments (string) |
| `dest.host` | destination host of an egress tool call |
| `dest.is_external` | destination is outside the trust boundary (bool, computed at ingest) |
| `dest.trust_boundary_crossed` | the result/output left the boundary it was collected in (bool, computed at ingest) |
| `prior_sensitive_read` | this session already read sensitive data before the current call (bool, computed at ingest) |
| `tool.action` | semantic action of a tool call, e.g. `delete` \| `drop` \| `terminate` \| `revoke` \| `wipe` |
| `approval.human_confirmed` | a human confirmed this (destructive) action (bool); absent = not confirmed |
| `agent.spawn_depth` | sub-agent nesting depth of a spawn (0 = root session), computed at ingest |
| `gen_ai.usage.output_tokens` | output tokens emitted by a model completion |
| `model.approved` | resolved model/provider is on the approved registry (bool), stamped at ingest |
| `output.rendered_as` | sink the model completion is routed to, e.g. `html` \| `markdown` \| `shell` \| `plain_text` |
| `memory.key` | key written into agent persistent memory on a `memory_write` |
| `mcp.server` | MCP server providing the tool |
| `mcp.tool_schema_changed` | the MCP tool's schema/description changed vs the registered baseline (bool) |

Your ingestion pipeline maps your own agent/LLM logs onto these fields.

## Run the tests

```bash
pip install -r requirements.txt
PYTHONPATH=tests pytest -q
```

`tests/sigma_eval.py` is a minimal Sigma-subset evaluator (stdlib + PyYAML) that runs
each rule against its fixtures. The tests prove that **every malicious event fires and
every benign one stays quiet**, not merely that the YAML parses. The evaluator follows
Sigma semantics on case: plain values and `contains` are case-insensitive, `re` is
case-sensitive unless `|re|i`, the same as Splunk and KQL.

## SIEM queries

Pre-generated in `conversions/` with the OSS [sigma-cli](https://github.com/SigmaHQ/sigma-cli):

| Target | Folder | Notes |
|--------|--------|-------|
| Splunk SPL | `conversions/splunk/` | Dotted field names as-is (JSON extraction). Add your `index=`/`sourcetype=`. |
| Microsoft Sentinel KQL | `conversions/sentinel/` | `pipelines/sentinel.yml` maps dotted fields to underscore columns and scopes to `AIAgentRuntime_CL`; rename to your table. |
| Elastic ES\|QL | `conversions/elastic-esql/` | `pipelines/elastic-esql.yml` aligns case, null and regex semantics with Sigma. Replace `from *` with your index pattern; dotted fields need `subobjects: false` in the mapping. |

Regenerate after editing a rule: `./convert.sh`.

**End-to-end lab (`lab/`)**: `lab/run.sh` starts Elastic, the Azure Data Explorer
emulator (the KQL engine behind Sentinel) and Splunk in Docker, loads every fixture event
into each, runs the shipped queries from `conversions/`, and requires each engine to return
exactly the events the reference evaluator matches over the whole corpus (misses and false
positives on other rules' traffic both fail).

**Known limitations (honest status):**
- Elastic ES|QL, 2 of 15 rules do not run as shipped. RLIKE uses Lucene regex:
  `agent_direct_jailbreak_in_user_input` needs a word boundary (`\bDAN\b`), which Lucene
  regex lacks, and `agent_secrets_in_model_output` exceeds Lucene's regex determinization
  limit (`.*sk-[...]{20,}.*`). Adapt them in Elastic (e.g. a tokenized keyword match or an
  ingest-time flag). The other 13 match the reference evaluator.
- Splunk and Sentinel KQL: all 15 match the reference evaluator in the lab.
- Sentinel was exercised on the Kusto emulator, not a live workspace; Splunk on Splunk
  Enterprise 9.3 in Docker.

## Roadmap (not built yet)

- Elastic-native versions of the 2 rules above.

## Pro feed (waitlist)

A paid feed with 40+ more rules and monthly updates is planned, and gets built only if
enough teams ask. Join the free waitlist: https://javito-gc.github.io/ai-agent-detections/

## License

MIT. Rules derived from public frameworks and the author's own lab/book
*Securing Autonomous AI*.
