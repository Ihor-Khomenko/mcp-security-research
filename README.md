# MCP Security Research Lab

## EN
Simple MCP security testing playground with Gradio UI.

**Saved MCP profiles:** Remote MCP settings (URL, auth, OAuth fields, TLS verify, optional CA bundle path) can be saved under `mcp_saved_profiles/` as password-encrypted files (PBKDF2 + Fernet). The folder is gitignored. This protects secrets on disk from casual exposure; it does not stop a compromised machine or someone with your password.

**TLS with a private/dev CA:** If “Verify TLS” is on but the server uses a certificate your OS does not trust, either point “TLS CA bundle” to a `.pem` file (e.g. mkcert or your org’s root CA) or turn off verify for local dev only.

**Run (macOS / Linux):**
```bash
chmod +x run.sh
./run.sh
```

**Run (Windows):** double-click `run.bat` or from Command Prompt in this folder:
```bat
run.bat
```
Requires Python 3 on `PATH`. Creates `ui-env` and installs dependencies like `run.sh`.

## UK
Простий полігон для тестування безпеки MCP з Gradio UI.

**Збережені профілі MCP:** налаштування віддаленого MCP (URL, авторизація, OAuth, TLS, опційно шлях до CA) можна зберігати в `mcp_saved_profiles/` у вигляді файлів, зашифрованих паролем (PBKDF2 + Fernet). Тека в `.gitignore`. Це захищає секрети на диску від випадкового витоку; не рятує від скомпрометованого ПК або людини з вашим паролем.

**TLS і приватний CA:** якщо «Перевіряти SSL» увімкнено, але сертифікат не довіряється ОС, вкажіть у полі CA шлях до `.pem` (наприклад mkcert) або для локального dev тимчасово вимкніть перевірку.

**Запуск (macOS / Linux):**
```bash
chmod +x run.sh
./run.sh
```

**Запуск (Windows):** подвійний клік на `run.bat` або з командного рядка в каталозі проєкту:
```bat
run.bat
```
Потрібен Python 3 у `PATH`. Створює `ui-env` і ставить залежності, як `run.sh`.

## Demo
![Demo 1](docs/demo/demo-1.png)
![Demo 2](docs/demo/demo-2.png)
