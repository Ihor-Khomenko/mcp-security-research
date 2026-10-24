---
name: mcp-security-research
description: Guides agents in running diagnostics, executing attack/defense simulations, managing password-encrypted MCP profiles, and auditing security logs in the MCP Security Research Lab.
---

# MCP Security Research Lab Skill Guide

This skill provides step-by-step guidance, command references, and architecture details for testing, simulating, and auditing Model Context Protocol (MCP) integrations using the files in this workspace.

---

## 🛠️ Environment Setup & Bootstrapping

To set up or run the environment, perform the following tasks:
* **Bootstrap Virtual Env**: Ensure python packages from [requirements.txt](file:///Users/ihkh/Documents/University/MCP/requirements.txt) are installed in the `ui-env/` virtual environment.
* **Launch UI**: Run [app.py](file:///Users/ihkh/Documents/University/MCP/app.py) using the `ui-env/` python executable to access the Gradio interface:
  ```bash
  source ui-env/bin/activate
  python app.py
  ```
  Alternatively, use the convenience scripts:
  * macOS / Linux: `./run.sh`
  * Windows: `run.bat`

---

## 🚀 Simulation Commands & Environment Variables

All simulation scripts read configuration parameters via environment variables and utilize the unified client helper [llm_client.py](file:///Users/ihkh/Documents/University/MCP/llm_client.py).

### Common Environment Variables
* `ATTACK_PROVIDER`: The LLM engine for the attacker role (`"Ollama"`, `"Unsloth Studio"`, `"ChatGPT"`, `"Claude API"`, `"Codex API"`, `"Claude Code CLI"`, `"Copilot CLI"`, `"Agy CLI"`, `"Codex CLI"`).
* `ATTACK_MODEL_CMD`: Model name or CLI command to execute (e.g. `qwen2.5:7b` or `/usr/local/bin/claude`).
* `ATTACK_API_KEY`: API token/key for the attack provider.
* `ATTACK_BASE_URL`: Custom base URL for remote endpoints (like Unsloth Studio / ChatGPT).
* `DEFEND_PROVIDER` / `DEFEND_MODEL_CMD` / `DEFEND_API_KEY` / `DEFEND_BASE_URL`: Configuration for the Defender role (LLM-as-a-Judge).
* `MCP_TYPE`: `"Local Filesystem"` or `"Remote URL"`.
* `MCP_URL`: Absolute URL of the remote MCP SSE server (if type is `"Remote URL"`).
* `MCP_AUTH_METHOD`: `"api_token"` or `"oauth_client_credentials"`.
* `MCP_TOKEN`: Bearer token for remote server.
* `MCP_OAUTH_CLIENT_ID` / `MCP_OAUTH_CLIENT_SECRET` / `MCP_OAUTH_TOKEN_URL` / `MCP_OAUTH_SCOPE`: OAuth details.
* `MCP_SSL_VERIFY`: `"1"` (verify TLS, default) or `"0"` (skip validation).
* `MCP_SSL_CA_BUNDLE`: Path to a custom `.pem` trust bundle (optional).
* `CUSTOM_PROMPT`: The query for the agent. If empty, scripts fall back to defaults.
* `UI_LANGUAGE`: `"uk"` (default) or `"en"`.

### Run Diagnostics
Verify standard Node-based filesystem MCP server connectivity:
```bash
python mcp-test.py
```

### Run Attack Simulation
Demonstrate indirect prompt injection. The LLM reads `report_steal.txt` and is coerced to read `secret_data.txt`:
```bash
ATTACK_PROVIDER="Ollama" ATTACK_MODEL_CMD="qwen2.5:7b" python attack_sim.py
```

### Run Basic Defense
Applies whitelist checking. Access to paths outside `SESSION_ALLOWED_FILES` is blocked:
```bash
ATTACK_PROVIDER="Ollama" ATTACK_MODEL_CMD="qwen2.5:7b" python defense_sim.py
```

### Run Defense Bypass
Demonstrates naive path prefix validation constraints (`startswith` traversal bypass):
```bash
ATTACK_PROVIDER="Ollama" ATTACK_MODEL_CMD="qwen2.5:7b" python defense_bypass_sim.py
```

### Run Advanced Defense
Implements a semantic payload evaluator (LLM-as-a-Judge) protecting `write_file` calls:
```bash
ATTACK_PROVIDER="Ollama" ATTACK_MODEL_CMD="qwen2.5:7b" DEFEND_PROVIDER="Ollama" DEFEND_MODEL_CMD="qwen2.5:7b" python advanced_defense_sim.py
```

---

## 📂 Data Vault & Payloads

The directory [test_vault/](file:///Users/ihkh/Documents/University/MCP/test_vault) contains files used for testing injections:
* **[report_steal.txt](file:///Users/ihkh/Documents/University/MCP/test_vault/report_steal.txt)**: Contains indirect injection commanding the agent to leak secrets from `secret_data.txt`.
* **[report_malware.txt](file:///Users/ihkh/Documents/University/MCP/test_vault/report_malware.txt)**: Commands the agent to execute a `write_file` operation saving a ransomware script.
* **[secret_data.txt](file:///Users/ihkh/Documents/University/MCP/test_vault/secret_data.txt)**: Simulates protected, high-value data.
* **[allowed_output.txt](file:///Users/ihkh/Documents/University/MCP/test_vault/allowed_output.txt)**: Target file containing benign summaries or safe data.

---

## 🔑 Profile Encryption & Credentials

Saved credentials profiles and vaults are handled by [mcp_profile_store.py](file:///Users/ihkh/Documents/University/MCP/mcp_profile_store.py).
* Profiles and vaults are stored locally inside `mcp_saved_profiles/` (gitignored).
* Credentials, model API keys, and MCP servers lists are encrypted using **Fernet (AES 128 in CBC mode with HMAC)**.
* Encryption keys are derived from user passwords using **PBKDF2 HMAC SHA-256** (480,000 iterations).
* Verification file `_vault_verify.enc` is used to check if the entered password matches the initialized vault password.
* Never save client secrets or API tokens in plaintext in any scripts. Always load them through the encrypted vault manager or environment variables.

---

## 🤖 AI Log Auditing

When a simulation finishes, a log file is saved to [research_logs/](file:///Users/ihkh/Documents/University/MCP/research_logs).
* System prompts for the audits reside in [prompts/system_audit_uk.txt](file:///Users/ihkh/Documents/University/MCP/prompts/system_audit_uk.txt) and [prompts/system_audit_en.txt](file:///Users/ihkh/Documents/University/MCP/prompts/system_audit_en.txt).
* Auditing is executed via `UnifiedLLMClient` using the specified **Analyzer** role configuration.
* Recommendations must adhere to the structured order: **Configuration**, **Permissions**, **Scope**, and **DLP/Output control**.

---

## 🧪 Testing & Verification

The project includes a comprehensive unit test suite to verify vault cryptography, unified LLM client mappings, and dashboard helper helpers.

* **Run all tests**: Execute the following command from the virtual environment:
  ```bash
  ui-env/bin/python3 -m unittest discover -s tests -p "test_*.py"
  ```
* **Development Rule**: When developing new modules, features, or UI helpers, you **MUST** add corresponding tests in the `tests/` directory and verify they all pass before completing tasks.


