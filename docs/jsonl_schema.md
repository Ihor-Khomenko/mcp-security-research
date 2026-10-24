# MCP Attack Scenario JSONL Schema (v1.0)

Export attack scenarios and (optionally) live simulation traces as **JSON Lines**
for evaluation of an external guard — **MCP-Sentinel** (developed in
[LLM-tester-tool](https://github.com/Ihor-Khomenko/LLM-tester-tool) as
`llm_tester.sentinel`). This repository does **not** implement the guard; it
only produces labelled scenarios/traces and an optional `GuardHook` plug-in point.

## Export

```bash
python -m scenarios.export --out exports/mcp_attack_scenarios.jsonl --lang en
python -m scenarios.export --list
python -m scenarios.export --id mcp-indirect-injection-exfil-001 --lang uk
```

Each line is one JSON object (`ScenarioRecord`).

## Required fields

| Field | Type | Description |
|-------|------|-------------|
| `schema_version` | string | Always `"1.0"` for this format |
| `id` | string | Stable scenario id (e.g. `mcp-indirect-injection-exfil-001`) |
| `attack_class` | string | Primary class (see below) |
| `title` | string | Short title (language selected at export) |
| `description` | string | What the scenario demonstrates |
| `simulation` | string | Script name (`attack_sim`, …) or `catalog_only` |
| `defense` | string | Control under test (`none`, `session_path_whitelist`, …) |
| `labels` | object | Evaluation labels (`guard_should_block`, …) |
| `trace` | array | Ordered events (user / tool_call / tool_result / guard_decision / …) |
| `source` | string | `"mcp-security-research"` |
| `timestamp` | string | ISO-8601 UTC |

## Optional fields

| Field | Type | Description |
|-------|------|-------------|
| `secondary_classes` | string[] | Additional attack tags |
| `tools` / `tools_before` / `tools_after` | object[] | Tool schemas (rug-pull uses before/after) |
| `user_prompt` | string | Benign user task that triggers the chain |
| `payload_files` | string[] | Filenames under `test_vault/` |
| `payloads` | object | Inline file contents keyed by filename |
| `attack_class_definition` | object | EN/UK definition of the primary class |
| `language` | string | `en` or `uk` |
| `provider` / `model` | string | Filled for live runs |
| `guard_hook` | string | Hook id used during the run (`none`, or `module:attr`) |
| `outcome` | string | Live outcome summary |

## Attack classes

- `indirect_prompt_injection`
- `tool_poisoning`
- `rug_pull`
- `data_exfiltration`
- `malicious_write`
- `path_traversal`
- `guard_prefix_bypass`
- `judge_evasion`

## Trace events

Each `trace[]` element has at least `event`. Common shapes:

```json
{"event": "user_message", "role": "user", "content": "..."}
{"event": "tool_call", "role": "assistant", "tool_name": "read_text_file", "arguments": {"path": "..."}, "attack_step": true}
{"event": "tool_result", "role": "tool", "tool_name": "read_text_file", "content": "...", "untrusted": true}
{"event": "guard_decision", "guard": "session_path_whitelist", "allowed": false, "reason": "..."}
{"event": "tools_listed", "tools": [...], "schema_hash": "benign"}
{"event": "tools_mutated", "tools": [...], "schema_hash": "poisoned", "attack_step": true}
{"event": "assistant_message", "role": "assistant", "content": "...", "attack_success_indicator": true}
```

## Compatibility with MCP-Sentinel

Sentinel (in LLM-tester-tool) can load this JSONL as evaluation data:

1. Treat `labels.guard_should_block` as the ground-truth expectation.
2. Replay `trace` tool_call / tool_result events through the guard.
3. Compare decisions to `expected_block_stage` when present.

Live simulations can append rows via `scenarios.export.append_live_trace(...)`
using the same schema.
