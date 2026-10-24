# MCP Security Research Lab

PhD research playground for **attack and defense simulations** against agentic AI systems that use the [Model Context Protocol (MCP)](https://modelcontextprotocol.io/). Gradio UI (`app.py`), unified LLM providers, JSONL scenario export for an external guard (**MCP-Sentinel**, developed only in [LLM-tester-tool](https://github.com/Ihor-Khomenko/LLM-tester-tool) as `llm_tester.sentinel`).

This repo focuses on **attack scenarios + traces + local defense demos**. It does **not** reimplement Sentinel; simulations expose an optional `GuardHook` so Sentinel can be plugged in later.

---

## EN — What the simulations demonstrate

### Attack classes

| Class | Demo | Mechanism |
|-------|------|-----------|
| **Indirect prompt injection** | `attack_sim.py` + `test_vault/report_steal.txt` | Benign “summarise report” task; file content overrides the agent to read `secret_data.txt` and leak it. |
| **Data exfiltration** | same | Coerced `read_text_file` outside the user’s intended scope. |
| **Tool poisoning / malicious write** | `report_malware.txt` + bypass/advanced sims | Returned tool text instructs `write_file` with a ransomware *simulation* payload. |
| **Rug pull** | catalog scenario `mcp-rug-pull-tool-desc-001` | Tool description mutates after `list_tools` trust — evaluation data for schema-integrity guards. |
| **Path traversal** | coerced reads of secrets | Access outside a session allow-list. |
| **Guard prefix bypass** | `defense_bypass_sim.py` | Naive `path.startswith(ALLOWED_DIR)` allows malicious *writes* inside the vault (content blind spot). |
| **Judge evasion** | catalog `mcp-judge-evasion-benign-framing-001` | Destructive logic framed as a “backup unit test” to probe LLM-judge false negatives. |

### Defenses (local demos — not Sentinel)

| Control | Script | Behaviour |
|---------|--------|-----------|
| **None** | `attack_sim.py` | Unrestricted MCP tool loop — baseline exploit. |
| **Session path whitelist** | `defense_sim.py` | Only `SESSION_ALLOWED_FILES` may be read; others blocked before MCP. |
| **Path prefix only** | `defense_bypass_sim.py` | `startswith(ALLOWED_DIR)` — shows bypass via in-vault malicious write. |
| **LLM-as-a-Judge** | `advanced_defense_sim.py` | Semantic DENY/ALLOW on `write_file` content (second model). |
| **Optional GuardHook** | all sims via `GUARD_HOOK` | Thin interface for plugging MCP-Sentinel later (`module:attr`). |

### LLM providers (shared design with LLM-tester-tool)

OpenAI-compatible clients with configurable `base_url`:

- **ollama** — `http://localhost:11434/v1`
- **openai** — API / ChatGPT
- **openrouter** — including `:free` model ids (quota-friendly)
- **xai** — Grok
- **groq**

Keys from environment / `.env` (see `.env.example`). Selectable in Gradio UI, env vars (`ATTACK_PROVIDER`, …), and programmatically via `providers.LLMProvider` (API aligned with `llm_tester.providers` for later shared packaging).

**Rate limits:** `LLM_MAX_REQUESTS`, `LLM_REQUEST_DELAY`, `LLM_MAX_RETRIES` — max calls per run, inter-request delay, exponential backoff on HTTP 429 (OpenRouter free ≈ 50 req/day).

### JSONL export for MCP-Sentinel evaluation

```bash
python -m scenarios.export --out exports/mcp_attack_scenarios.jsonl --lang en
python -m scenarios.export --list
```

Schema: [`docs/jsonl_schema.md`](docs/jsonl_schema.md). Labelled traces (tool calls, untrusted tool results, guard decisions) are usable as evaluation data in LLM-tester-tool’s Sentinel package.

### Run

```bash
cp .env.example .env   # add keys as needed
chmod +x run.sh && ./run.sh
# or: python app.py
```

Windows: `run.bat`.

```bash
# CLI simulation example
ATTACK_PROVIDER=ollama ATTACK_MODEL_CMD=qwen2.5:7b python attack_sim.py

# Tests (mocked; network guard blocks real API hosts)
pip install -r requirements-dev.txt
python -m pytest -q
```

### Profiles & TLS

Remote MCP settings can be stored password-encrypted under `mcp_saved_profiles/` (gitignored). TLS: use a CA bundle `.pem` or disable verify only for local/dev.

---

## UK — Що демонструють симуляції

### Класи атак

| Клас | Демо | Суть |
|------|------|------|
| **Непряма ін'єкція промпту** | `attack_sim.py` + `report_steal.txt` | Завдання «підсумуй звіт»; вміст файлу змушує прочитати `secret_data.txt` і витікти дані. |
| **Ексфільтрація** | те саме | Примусовий `read_text_file` поза межами наміру користувача. |
| **Отруєння інструментів / шкідливий запис** | `report_malware.txt` | Текст інструменту наказує `write_file` з симуляцією ransomware. |
| **Rug pull** | сценарій у каталозі | Опис інструменту змінюється після discovery — дані для сторожів цілісності схем. |
| **Path traversal** | читання секретів | Доступ поза whitelist сесії. |
| **Обхід prefix-гарду** | `defense_bypass_sim.py` | `startswith(ALLOWED_DIR)` пропускає шкідливий *запис* усередині vault. |
| **Обхід LLM-судді** | сценарій judge-evasion | Деструктивний код під виглядом «backup unit test». |

### Захисти (локальні демо — не Sentinel)

| Контроль | Скрипт | Поведінка |
|----------|--------|-----------|
| **Немає** | `attack_sim.py` | Базовий експлойт без обмежень. |
| **Whitelist шляхів** | `defense_sim.py` | Лише `SESSION_ALLOWED_FILES`. |
| **Лише prefix** | `defense_bypass_sim.py` | Сліпа зона за вмістом запису. |
| **LLM-as-a-Judge** | `advanced_defense_sim.py` | Семантичний DENY/ALLOW для `write_file`. |
| **Опційний GuardHook** | `GUARD_HOOK` | Точка інтеграції для MCP-Sentinel з LLM-tester-tool. |

### Провайдери LLM

Єдиний шар OpenAI-compatible (`providers/`), сумісний за дизайном із `llm_tester` у LLM-tester-tool: ollama, openai, openrouter (`:free`), xai, groq. Ключі з `.env` / UI. Ліміти: `LLM_MAX_REQUESTS`, `LLM_REQUEST_DELAY`, `LLM_MAX_RETRIES`.

### Експорт JSONL

```bash
python -m scenarios.export --out exports/mcp_attack_scenarios.jsonl --lang uk
```

Формат: [`docs/jsonl_schema.md`](docs/jsonl_schema.md) — оцінка зовнішнього MCP-Sentinel.

### Запуск

```bash
cp .env.example .env
chmod +x run.sh && ./run.sh
```

Тести без реальних API-викликів: `python -m pytest -q`.

---

## Demo screenshots

![Demo 1](docs/demo/demo-1.png)
![Demo 2](docs/demo/demo-2.png)

## Architecture note

| Component | Where |
|-----------|--------|
| Attack/defense simulations, Gradio UI, JSONL scenarios | **this repo** |
| MCP-Sentinel guard implementation | **LLM-tester-tool** (`llm_tester.sentinel`) |
| Shared OpenAI-compatible provider shape | `providers/` here ↔ `llm_tester.providers` there |
