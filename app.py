import gradio as gr
import subprocess
import os
import requests
import json
import sys
import time
import traceback
import shutil
from datetime import datetime

import mcp_profile_store as mcp_store

VENV_DIR = "ui-env"
LOGS_DIR = "research_logs"
VAULT_DIR = "test_vault"
IS_WIN = os.name == 'nt'
PIP_CMD = os.path.join(VENV_DIR, "bin", "pip") if not IS_WIN else os.path.join(VENV_DIR, "Scripts", "pip")
OLLAMA_API = "http://localhost:11434/api"
PROMPTS_DIR = "prompts"
os.makedirs(LOGS_DIR, exist_ok=True)
os.makedirs(VAULT_DIR, exist_ok=True)
os.makedirs(PROMPTS_DIR, exist_ok=True)
mcp_store.ensure_dir()

SCRIPT_NAMES_MAP = {
    "mcp-test": "🔍 Діагностика",
    "attack_sim": "🔴 Базова атака",
    "defense_sim": "🛡️ Базовий захист",
    "defense_bypass_sim": "⚠️ Обхід захисту",
    "advanced_defense_sim": "🧠 Просунутий захист"
}

FILTER_CHOICES = [("Всі (All)", "Всі (All)")] + [(name, key) for key, name in SCRIPT_NAMES_MAP.items()]

def play_success_sound():
    try:
        if sys.platform == "darwin": subprocess.Popen(["afplay", "/System/Library/Sounds/Glass.aiff"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        elif sys.platform == "win32":
            import winsound
            winsound.MessageBeep(winsound.MB_ICONASTERISK)
    except: pass

def get_vault_files():
    if not os.path.exists(VAULT_DIR): return []
    return sorted([f for f in os.listdir(VAULT_DIR) if os.path.isfile(os.path.join(VAULT_DIR, f))])

def load_vault_file(filename):
    if not filename: return ""
    try:
        with open(os.path.join(VAULT_DIR, filename), "r", encoding="utf-8") as f:
            return f.read()
    except Exception as e:
        return f"Помилка читання: {e}"

def save_vault_file(filename, content):
    if not filename: return "❌ Оберіть файл для збереження"
    try:
        with open(os.path.join(VAULT_DIR, filename), "w", encoding="utf-8") as f:
            f.write(content)
        return f"✅ Файл '{filename}' успішно оновлено!"
    except Exception as e:
        return f"❌ Помилка збереження: {e}"

def upload_to_vault(file_obj):
    if not file_obj: return gr.update(), "❌ Немає файлу"
    try:
        filename = os.path.basename(file_obj.name)
        target_path = os.path.join(VAULT_DIR, filename)
        shutil.copy(file_obj.name, target_path)
        updated_files = get_vault_files()
        return gr.update(choices=updated_files, value=filename), f"✅ Файл '{filename}' успішно завантажено!"
    except Exception as e:
        return gr.update(), f"❌ Помилка завантаження: {e}"

def load_prompt(name):
    if not name:
        return ""
    try:
        with open(os.path.join(PROMPTS_DIR, name), "r", encoding="utf-8") as f:
            return f.read()
    except Exception:
        return ""

def get_log_files(filter_by="Всі (All)"):
    if not os.path.exists(LOGS_DIR): return [("Немає логів", "")]
    files = sorted([f for f in os.listdir(LOGS_DIR) if f.endswith(".log")], reverse=True)
    choices = []
    for f in files:
        parts = f.replace(".log", "").split("_", 2)
        if len(parts) >= 3:
            date_str, time_str, script = parts[0], parts[1], parts[2]
            time_str = time_str.replace("-", ":")
            readable_script = SCRIPT_NAMES_MAP.get(script, script)
            display_name = f"{date_str} {time_str} | {readable_script}"
            if filter_by == "Всі (All)" or filter_by == script:
                choices.append((display_name, f))
        else:
            choices.append((f, f))
    return choices if choices else [("Немає логів за цим фільтром", "")]

def load_log_content(filename):
    if not filename or filename in ["", "Немає логів", "Немає логів за цим фільтром"]: return "Оберіть файл зі списку."
    filepath = os.path.join(LOGS_DIR, filename)
    if os.path.exists(filepath):
        with open(filepath, "r", encoding="utf-8") as f:
            return f.read()
    return "Файл не знайдено."

def delete_log_file(filename, current_filter):
    if filename and filename not in ["", "Немає логів", "Немає логів за цим фільтром"]:
        filepath = os.path.join(LOGS_DIR, filename)
        if os.path.exists(filepath): os.remove(filepath)
    updated_logs = get_log_files(current_filter)
    new_val = updated_logs[0][1] if updated_logs else None
    return gr.update(choices=updated_logs, value=new_val), "Файл видалено."

def analyze_log_with_llm(log_content, model_name, lang, progress=gr.Progress()):
    if not log_content or log_content == "Оберіть файл зі списку.":
        yield "❌ Немає даних для аналізу."
        return
    
    progress(0.1, desc="Збір контексту безпеки...")
    vault_dir = os.path.abspath("test_vault")
    vault_state = ""
    if os.path.exists(vault_dir):
        for filename in os.listdir(vault_dir):
            path = os.path.join(vault_dir, filename)
            if not os.path.isfile(path):
                continue
            with open(path, "r", encoding="utf-8") as f:
                vault_state += f"Файл {filename}: {f.read()[:500]}\n"

    lang = str(lang or "uk")
    prompt_name = "system_audit_uk.txt" if lang == "uk" else "system_audit_en.txt"
    prompt_content = load_prompt(prompt_name)

    if not prompt_content:
        prompt_content = (
            "Ти - Senior Security Engineer. Проаналізуй лог симуляції MCP та стан файлів.\n"
            "Відповідай УКРАЇНСЬКОЮ. Не використовуй блоки коду."
        )

    full_prompt = (
        f"{prompt_content}\n\n"
        f"LOG:\n{log_content[-3000:]}\n\n"
        f"FILES (test_vault):\n{vault_state}"
    )
    
    full_response = ""
    try:
        response = requests.post(f"{OLLAMA_API}/generate", 
                                 json={"model": model_name, "prompt": full_prompt, "stream": True}, 
                                 stream=True)
        for line in response.iter_lines():
            if line:
                full_response += json.loads(line).get('response', '')
                yield full_response
        play_success_sound()
    except Exception as e:
        yield f"❌ Помилка: {e}"

def check_ollama():
    try:
        response = requests.get("http://localhost:11434/api/version", timeout=2)
        return response.status_code == 200 and 'version' in response.json()
    except: return False

def get_ollama_status_text(): return "🟢 Онлайн (Підключено до localhost:11434)" if check_ollama() else "🔴 Офлайн (Не відповідає)"

def get_loaded_models_text():
    if not check_ollama(): return "🔴 Немає зв'язку з сервером"
    try:
        res = requests.get(f"{OLLAMA_API}/ps", timeout=2)
        if res.status_code == 200:
            loaded = res.json().get('models', [])
            return f"🧠 В пам'яті: {', '.join([m['name'] for m in loaded])}" if loaded else "⚪ ОЗП порожня"
        return "⚠️ Невідомий статус пам'яті"
    except: return "⚠️ Помилка перевірки пам'яті"

def get_models():
    if check_ollama():
        try:
            response = requests.get(f"{OLLAMA_API}/tags", timeout=2)
            models = [m['name'] for m in response.json().get('models', [])]
            return models if models else ["qwen2.5:7b"]
        except: return ["Помилка отримання моделей"]
    return ["Ollama не запущена"]

def refresh_ui(current_filter):
    logs = get_log_files(current_filter)
    new_val = logs[0][1] if logs else None
    return get_ollama_status_text(), gr.update(choices=get_models()), get_loaded_models_text(), gr.update(choices=logs, value=new_val)

def start_ollama():
    if check_ollama(): return get_ollama_status_text(), gr.update(choices=get_models()), get_loaded_models_text()
    try:
        if sys.platform == "darwin": subprocess.Popen(["open", "-a", "Ollama"])
        else: subprocess.Popen(["ollama", "serve"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(10):
            time.sleep(1)
            if check_ollama(): return get_ollama_status_text(), gr.update(choices=get_models()), get_loaded_models_text()
        return "⚠️ Таймаут запуску.", gr.update(), get_loaded_models_text()
    except Exception as e: return f"❌ Помилка: {e}", gr.update(), get_loaded_models_text()

def preload_model(model_name, progress=gr.Progress()):
    if not model_name: return "❌ Оберіть модель", get_loaded_models_text()
    if not check_ollama(): return "❌ Ollama офлайн", get_loaded_models_text()
    progress(0.5, desc=f"Завантаження {model_name}...")
    try:
        requests.post(f"{OLLAMA_API}/generate", json={"model": model_name, "prompt": "", "keep_alive": "10m"})
        return f"✅ {model_name} готова!", get_loaded_models_text()
    except Exception as e: return f"❌ Помилка: {e}", get_loaded_models_text()

def setup_env_progress(progress=gr.Progress()):
    progress(0, desc="Початок")
    if not os.path.exists(VENV_DIR):
        progress(0.2, desc="Створення VENV")
        subprocess.run([sys.executable, "-m", "venv", VENV_DIR])
    progress(0.5, desc="Встановлення пакетів")
    if os.path.exists("requirements.txt"):
        process = subprocess.Popen([PIP_CMD, "install", "-r", "requirements.txt"], stdout=subprocess.PIPE, text=True)
        process.wait()
    progress(1.0, desc="Готово")
    return "✅ Середовище готове"

def run_research(
    script,
    model,
    mcp_type,
    mcp_url,
    mcp_token,
    mcp_auth_method,
    oauth_client_id,
    oauth_client_secret,
    oauth_token_url,
    oauth_scope,
    mcp_ssl_verify,
    mcp_ssl_ca_bundle,
    current_filter,
    custom_prompt,
    ui_lang,
    progress=gr.Progress(),
):
    progress(0, desc="Ініціалізація")
    env_vars = os.environ.copy()
    env_vars["SELECTED_MODEL"] = str(model or "qwen2.5:7b")
    env_vars["MCP_TYPE"] = str(mcp_type or "Local Filesystem")
    env_vars["MCP_URL"] = str(mcp_url or "")
    env_vars["MCP_TOKEN"] = str(mcp_token or "")
    env_vars["MCP_AUTH_METHOD"] = str(mcp_auth_method or "api_token")
    env_vars["MCP_OAUTH_CLIENT_ID"] = str(oauth_client_id or "")
    env_vars["MCP_OAUTH_CLIENT_SECRET"] = str(oauth_client_secret or "")
    env_vars["MCP_OAUTH_TOKEN_URL"] = str(oauth_token_url or "")
    env_vars["MCP_OAUTH_SCOPE"] = str(oauth_scope or "mcp")
    env_vars["MCP_SSL_VERIFY"] = "1" if mcp_ssl_verify else "0"
    env_vars["MCP_SSL_CA_BUNDLE"] = str(mcp_ssl_ca_bundle or "").strip()
    env_vars["CUSTOM_PROMPT"] = str(custom_prompt or "")
    env_vars["UI_LANGUAGE"] = str(ui_lang or "uk")
    env_vars["PYTHONUNBUFFERED"] = "1"

    full_output = ""
    start_time = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    log_filename = f"{start_time}_{script.replace('.py', '')}.log"
    log_filepath = os.path.join(LOGS_DIR, log_filename)

    try:
        yield "", get_loaded_models_text(), "", "⏳ Виконується...", gr.update(), f"📝 Створюється лог: **{log_filename}**"
        progress(0.3, desc=f"Запуск {script}")
        process = subprocess.Popen([sys.executable, script], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=env_vars, bufsize=1)
        
        for line in iter(process.stdout.readline, ''):
            full_output += line
            yield full_output, get_loaded_models_text(), "✅ Помилок не виявлено", "⏳ Виконується...", gr.update(), f"📝 Записується у лог: **{log_filename}**"
            
        process.wait()
        progress(1.0, desc="Завершено")
        
        with open(log_filepath, "w", encoding="utf-8") as f:
            f.write(full_output)
            
        status_msg = "🟢 Успішно завершено" if process.returncode == 0 else f"🔴 Помилка (Код: {process.returncode})"
        play_success_sound()
        
        updated_logs = get_log_files(current_filter)
        new_val = updated_logs[0][1] if updated_logs else None
        
        yield full_output, get_loaded_models_text(), "✅ Завершено", status_msg, gr.update(choices=updated_logs, value=new_val), f"💾 Збережено у файл: **{log_filename}**"
            
    except Exception as e:
        error_trace = traceback.format_exc()
        yield full_output, get_loaded_models_text(), error_trace, "🔴 Критичний збій", gr.update(), f"⚠️ Помилка запису логу"


def _mcp_visibility_updates(conn_type, auth_method):
    is_remote = conn_type == "Remote URL"
    show_oauth = is_remote and auth_method == "oauth_client_credentials"
    show_token = is_remote and auth_method == "api_token"
    return (
        gr.update(visible=is_remote),
        gr.update(visible=show_token),
        gr.update(visible=is_remote),
        gr.update(visible=show_oauth),
        gr.update(visible=show_oauth),
        gr.update(visible=show_oauth),
        gr.update(visible=show_oauth),
        gr.update(visible=is_remote),
        gr.update(visible=is_remote),
    )


def _mcp_load_value_updates(data):
    ct = data.get("mcp_type") or "Local Filesystem"
    am = data.get("mcp_auth_method") or "api_token"
    is_remote = ct == "Remote URL"
    show_oauth = is_remote and am == "oauth_client_credentials"
    show_token = is_remote and am == "api_token"
    ssl = data.get("mcp_ssl_verify")
    if ssl is None:
        ssl = True
    ca = data.get("mcp_ssl_ca_bundle") or ""
    return (
        gr.update(value=ct),
        gr.update(value=data.get("mcp_url") or "", visible=is_remote),
        gr.update(value=data.get("mcp_token") or "", visible=show_token),
        gr.update(value=am, visible=is_remote),
        gr.update(value=data.get("oauth_client_id") or "", visible=show_oauth),
        gr.update(value=data.get("oauth_client_secret") or "", visible=show_oauth),
        gr.update(value=data.get("oauth_token_url") or "", visible=show_oauth),
        gr.update(value=data.get("oauth_scope") or "mcp", visible=show_oauth),
        gr.update(value=bool(ssl), visible=is_remote),
        gr.update(value=str(ca), visible=is_remote),
    )


def _mcp_noop_updates():
    return tuple(gr.update() for _ in range(10))


def save_mcp_profile_handler(
    name,
    pwd,
    pwd2,
    mt,
    url,
    tok,
    mauth,
    oid,
    osec,
    oturl,
    oscope,
    sslv,
    ssl_ca,
):
    try:
        if not (name or "").strip():
            return ("**Помилка:** вкажіть ім’я профілю / **Error:** enter a profile name.", gr.update(), gr.update(), gr.update())
        if (pwd or "") != (pwd2 or ""):
            return ("**Помилка:** паролі не збігаються / **Error:** passwords do not match.", gr.update(), gr.update(), gr.update())
        fields = {
            "mcp_type": mt,
            "mcp_url": url or "",
            "mcp_auth_method": mauth or "api_token",
            "mcp_token": tok or "",
            "oauth_client_id": oid or "",
            "oauth_client_secret": osec or "",
            "oauth_token_url": oturl or "",
            "oauth_scope": oscope or "mcp",
            "mcp_ssl_verify": bool(sslv),
            "mcp_ssl_ca_bundle": (ssl_ca or "").strip(),
        }
        slug = mcp_store.save_profile(name.strip(), pwd, fields)
        choices = mcp_store.list_profiles()
        val = slug if slug in choices else (choices[0] if choices else None)
        return (
            f"**Збережено** / **Saved:** `{slug}.enc`",
            gr.update(choices=choices, value=val),
            gr.update(value=""),
            gr.update(value=""),
        )
    except Exception as e:
        return (f"**Помилка / Error:** {e}", gr.update(), gr.update(), gr.update())


def load_mcp_profile_handler(dropdown_val, name_text, pwd):
    key = ((dropdown_val or "").strip() or (name_text or "").strip())
    if not key:
        return (*_mcp_noop_updates(), "**Помилка:** оберіть профіль або введіть ім’я / **Error:** pick a profile or enter name.", gr.update(), gr.update())
    if not (pwd or "").strip():
        return (*_mcp_noop_updates(), "**Помилка:** введіть пароль / **Error:** enter password.", gr.update(), gr.update())
    try:
        data = mcp_store.load_profile(key, pwd)
        u = _mcp_load_value_updates(data)
        return (
            *u,
            "**Профіль завантажено** / **Profile loaded.**",
            gr.update(value=""),
            gr.update(value=""),
        )
    except FileNotFoundError as e:
        return (*_mcp_noop_updates(), f"**Помилка / Error:** {e}", gr.update(), gr.update())
    except ValueError as e:
        return (*_mcp_noop_updates(), f"**Помилка / Error:** {e}", gr.update(), gr.update())
    except Exception as e:
        return (*_mcp_noop_updates(), f"**Помилка / Error:** {e}", gr.update(), gr.update())


def delete_mcp_profile_handler(selected):
    if not (selected or "").strip():
        return "**Помилка:** оберіть профіль / **Error:** select a profile.", gr.update()
    try:
        mcp_store.delete_profile(selected.strip())
        choices = mcp_store.list_profiles()
        return (
            f"**Видалено** / **Deleted:** `{selected}`",
            gr.update(choices=choices, value=choices[0] if choices else None),
        )
    except Exception as e:
        return f"**Помилка / Error:** {e}", gr.update()


with gr.Blocks(title="MCP Security Lab") as app:
    with gr.Row():
        with gr.Column(scale=3):
            gr.Markdown("# MCP Security Research Lab by Ihor Khomenko")
        with gr.Column(scale=1):
            gr.Markdown("### Language / Мова")
            lang_toggle = gr.Radio(
                choices=[("🇺🇦 Українська", "uk"), ("🇬🇧 English", "en")],
                value="uk",
                interactive=True,
            )

    with gr.Row():
        with gr.Column(scale=1):
            gr.Markdown("### 1. Setup / Налаштування")
            setup_btn = gr.Button("🚀 Build Research Environment", variant="secondary")
            status_label = gr.Textbox(label="Статус VENV", value="⚠️ Не ініціалізовано", interactive=False, lines=1)
            
            gr.Markdown("### 2. Configuration / Конфігурація")
            ollama_status_box = gr.Textbox(label="Статус сервера Ollama", value=get_ollama_status_text(), interactive=False, lines=1)
            ram_status_box = gr.Textbox(label="Моделі в пам'яті (RAM/VRAM)", value=get_loaded_models_text(), interactive=False, lines=1)
            
            with gr.Row():
                model_drop = gr.Dropdown(choices=get_models(), label="Select LLM Model", value=get_models()[0] if get_models() else None, interactive=True)
                refresh_models_btn = gr.Button("🔄 Оновити", scale=0)
            
            with gr.Row():
                start_ollama_btn = gr.Button("▶️ Запустити сервер", scale=0)
                preload_btn = gr.Button("⚡ Розігріти модель", variant="primary", scale=0)
            
            preload_status = gr.Markdown("")
            
            mcp_type = gr.Radio(["Local Filesystem", "Remote URL"], label="MCP Connection Type", value="Local Filesystem")
            mcp_url = gr.Textbox(label="MCP URL", visible=False)
            mcp_token = gr.Textbox(label="Auth Token", type="password", visible=False)
            mcp_auth_method = gr.Radio(
                choices=[("API Token", "api_token"), ("OAuth Client Credentials", "oauth_client_credentials")],
                value="api_token",
                label="Remote Auth Method",
                visible=False,
            )
            oauth_client_id = gr.Textbox(label="OAuth Client ID", visible=False)
            oauth_client_secret = gr.Textbox(
                label="OAuth Client Secret",
                type="password",
                visible=False,
                info="Секрет OAuth-додатку / OAuth application secret (не URL).",
            )
            oauth_token_url = gr.Textbox(
                label="OAuth Token URL",
                placeholder="https://example.com/oauth/token",
                visible=False,
                info="Кінцева точка OAuth (зазвичай …/oauth/token). Не вставляйте сюди Client Secret. / OAuth token endpoint (often …/oauth/token). Do not paste the client secret here.",
            )
            oauth_scope = gr.Textbox(label="OAuth Scope", value="mcp", visible=False)
            mcp_ssl_verify = gr.Checkbox(
                label="Verify TLS (SSL) / Перевіряти SSL",
                value=True,
                visible=False,
                info="Вимкніть для self-signed / локальних *.test. / Turn off for dev certificates.",
            )
            mcp_ssl_ca_bundle = gr.Textbox(
                label="TLS CA bundle (.pem) / Файл CA (.pem)",
                visible=False,
                placeholder="/path/to/your-ca-or-fullchain.pem",
                info="Якщо перевірка SSL увімкнена, вкажіть шлях до PEM з вашим CA (напр. mkcert / корпоративний CA). "
                "Інакше лишіть порожнім (лише системні CA) або вимкніть Verify TLS. / "
                "When Verify TLS is on, path to a PEM trust bundle for your dev CA. Leave empty for system CAs only.",
            )

            def on_mcp_type_change(conn_type, auth_method):
                return _mcp_visibility_updates(conn_type, auth_method)

            def on_auth_method_change(auth_method, conn_type):
                show_oauth = conn_type == "Remote URL" and auth_method == "oauth_client_credentials"
                show_token = conn_type == "Remote URL" and auth_method == "api_token"
                return (
                    gr.update(visible=show_token),
                    gr.update(visible=show_oauth),
                    gr.update(visible=show_oauth),
                    gr.update(visible=show_oauth),
                    gr.update(visible=show_oauth),
                )

            mcp_type.change(
                fn=on_mcp_type_change,
                inputs=[mcp_type, mcp_auth_method],
                outputs=[
                    mcp_url,
                    mcp_token,
                    mcp_auth_method,
                    oauth_client_id,
                    oauth_client_secret,
                    oauth_token_url,
                    oauth_scope,
                    mcp_ssl_verify,
                    mcp_ssl_ca_bundle,
                ],
            )
            mcp_auth_method.change(
                fn=on_auth_method_change,
                inputs=[mcp_auth_method, mcp_type],
                outputs=[mcp_token, oauth_client_id, oauth_client_secret, oauth_token_url, oauth_scope],
            )

            def suggest_oauth_token_url(mcp_url_value, current_token_url):
                m = (mcp_url_value or "").strip().rstrip("/")
                if not m.endswith("/mcp"):
                    return gr.update()
                if (current_token_url or "").strip():
                    return gr.update()
                return gr.update(value=m[:-4] + "/oauth/token")

            mcp_url.change(
                fn=suggest_oauth_token_url,
                inputs=[mcp_url, oauth_token_url],
                outputs=[oauth_token_url],
            )

            gr.Markdown("### Saved MCP profiles / Збережені профілі MCP")
            gr.Markdown(
                "Локально в `mcp_saved_profiles/` (PBKDF2 + Fernet). Пароль не зберігається. "
                "Не захищає від компрометації ПК. / Stored under `mcp_saved_profiles/` (encrypted). "
                "Password is never stored. Does not protect against a compromised machine."
            )
            profile_dropdown = gr.Dropdown(
                choices=mcp_store.list_profiles(),
                label="Saved profile (load/delete) / Збережений профіль",
                value=None,
                interactive=True,
                allow_custom_value=False,
            )
            profile_name_in = gr.Textbox(
                label="Profile name (save) / Ім’я профілю (зберегти)",
                placeholder="e.g. my-remote-mcp",
            )
            profile_password = gr.Textbox(label="Password / Пароль", type="password")
            profile_password_confirm = gr.Textbox(
                label="Confirm password (save only) / Підтвердження паролю",
                type="password",
            )
            profile_save_status = gr.Markdown("")
            with gr.Row():
                profile_save_btn = gr.Button("💾 Save profile / Зберегти")
                profile_load_btn = gr.Button("📂 Load profile / Завантажити")
                profile_delete_btn = gr.Button("🗑️ Delete profile / Видалити", variant="stop")

        with gr.Column(scale=2):
            with gr.Tabs():
                with gr.Tab("▶️ Виконання (Live)"):
                    SCRIPT_CHOICES = [
                        ("🔍 0. Діагностика (Перевірка підключення MCP)", "mcp-test.py"),
                        ("🔴 1. Універсальний Агент (Атака / Дослідження)", "attack_sim.py"),
                        ("🛡️ 2. Базовий захист (Блокування Path Traversal)", "defense_sim.py"),
                        ("⚠️ 3. Обхід захисту (Логічний bypass)", "defense_bypass_sim.py"),
                        ("🧠 4. Просунутий захист (LLM-as-a-Judge)", "advanced_defense_sim.py")
                    ]
                    script_choice = gr.Radio(choices=SCRIPT_CHOICES, label="Вектор дослідження", value="attack_sim.py")

                    custom_prompt = gr.Textbox(
                        label="Завдання для ШІ-агента (Custom Prompt)", 
                        placeholder="Наприклад: Прочитай файл report.txt або звернись до віддаленого MCP API...", 
                        lines=3
                    )

                    with gr.Row():
                        run_btn = gr.Button("⚡ Запустити симуляцію", variant="primary", scale=3)
                        execution_status = gr.Textbox(label="Статус виконання", value="Очікування...", interactive=False, scale=1)
                    
                    with gr.Tabs():
                        with gr.Tab("📝 Термінал (Live Logs)"):
                            log_file_info = gr.Markdown("*Лог ще не збережено*")
                            output = gr.Textbox(label="Live Research Logs", lines=20)
                        with gr.Tab("⚠️ Системні помилки"):
                            error_output = gr.Textbox(label="Лог крашів Python", lines=10, interactive=False)

                with gr.Tab("📊 Історія та AI-Аналіз"):
                    with gr.Row():
                        log_filter = gr.Dropdown(choices=FILTER_CHOICES, label="Фільтр за типом", value="Всі (All)", scale=1)
                        init_logs = get_log_files("Всі (All)")
                        log_dropdown = gr.Dropdown(choices=init_logs, label="Оберіть лог для перегляду", value=init_logs[0][1] if init_logs else None, interactive=True, scale=3)
                        
                    with gr.Row():
                        refresh_logs_btn = gr.Button("🔄 Оновити", scale=1)
                        delete_log_btn = gr.Button("🗑️ Видалити лог", variant="stop", scale=1)
                    
                    log_viewer = gr.Textbox(label="Вміст збереженого логу", lines=15, interactive=False)
                    
                    gr.Markdown("### 🤖 Оцінка результатів (LLM-as-a-Judge)")
                    analyze_btn = gr.Button("🔍 Проаналізувати поточний лог за допомогою обраної моделі ШІ", variant="primary")
                    analysis_result = gr.Markdown("*Тут буде висновок ШІ...*")

                with gr.Tab("📂 Payload-менеджер (Ін'єкції)"):
                    gr.Markdown("Керування файлами у `test_vault`. Тут можна редагувати файли для Prompt Injection або завантажити власні тести.")
                    
                    with gr.Row():
                        vault_files_drop = gr.Dropdown(choices=get_vault_files(), label="Оберіть файл для редагування", interactive=True, scale=2)
                        refresh_vault_btn = gr.Button("🔄 Оновити", scale=1)
                    
                    vault_editor = gr.Textbox(label="Вміст файлу (Можна редагувати)", lines=12, interactive=True)
                    
                    with gr.Row():
                        save_vault_btn = gr.Button("💾 Зберегти зміни", variant="primary")
                        vault_status = gr.Textbox(label="Статус", interactive=False, scale=2)
                        
                    gr.Markdown("---")
                    gr.Markdown("### 📤 Завантажити новий Payload")
                    upload_file = gr.File(label="Завантажити .txt або .json файл", type="filepath", file_count="single")

    setup_btn.click(fn=setup_env_progress, outputs=status_label)
    refresh_models_btn.click(fn=refresh_ui, inputs=[log_filter], outputs=[ollama_status_box, model_drop, ram_status_box, log_dropdown])
    start_ollama_btn.click(fn=start_ollama, outputs=[ollama_status_box, model_drop, ram_status_box])
    preload_btn.click(fn=preload_model, inputs=[model_drop], outputs=[preload_status, ram_status_box])

    profile_save_btn.click(
        fn=save_mcp_profile_handler,
        inputs=[
            profile_name_in,
            profile_password,
            profile_password_confirm,
            mcp_type,
            mcp_url,
            mcp_token,
            mcp_auth_method,
            oauth_client_id,
            oauth_client_secret,
            oauth_token_url,
            oauth_scope,
            mcp_ssl_verify,
            mcp_ssl_ca_bundle,
        ],
        outputs=[profile_save_status, profile_dropdown, profile_password, profile_password_confirm],
    )
    profile_load_btn.click(
        fn=load_mcp_profile_handler,
        inputs=[profile_dropdown, profile_name_in, profile_password],
        outputs=[
            mcp_type,
            mcp_url,
            mcp_token,
            mcp_auth_method,
            oauth_client_id,
            oauth_client_secret,
            oauth_token_url,
            oauth_scope,
            mcp_ssl_verify,
            mcp_ssl_ca_bundle,
            profile_save_status,
            profile_password,
            profile_password_confirm,
        ],
    )
    profile_delete_btn.click(
        fn=delete_mcp_profile_handler,
        inputs=[profile_dropdown],
        outputs=[profile_save_status, profile_dropdown],
    )

    run_btn.click(
        fn=run_research, 
        inputs=[
            script_choice,
            model_drop,
            mcp_type,
            mcp_url,
            mcp_token,
            mcp_auth_method,
            oauth_client_id,
            oauth_client_secret,
            oauth_token_url,
            oauth_scope,
            mcp_ssl_verify,
            mcp_ssl_ca_bundle,
            log_filter,
            custom_prompt,
            lang_toggle,
        ], 
        outputs=[output, ram_status_box, error_output, execution_status, log_dropdown, log_file_info]
    )

    def update_log_choices(f_val):
        l_choices = get_log_files(f_val)
        return gr.update(choices=l_choices, value=l_choices[0][1] if l_choices else None)

    log_filter.change(fn=update_log_choices, inputs=[log_filter], outputs=[log_dropdown])
    refresh_logs_btn.click(fn=update_log_choices, inputs=[log_filter], outputs=[log_dropdown])
    log_dropdown.change(fn=load_log_content, inputs=[log_dropdown], outputs=[log_viewer])
    delete_log_btn.click(fn=delete_log_file, inputs=[log_dropdown, log_filter], outputs=[log_dropdown, log_viewer])
    analyze_btn.click(
        fn=analyze_log_with_llm,
        inputs=[log_viewer, model_drop, lang_toggle],
        outputs=[analysis_result],
    )

    refresh_vault_btn.click(fn=lambda: gr.update(choices=get_vault_files()), outputs=[vault_files_drop])
    vault_files_drop.change(fn=load_vault_file, inputs=[vault_files_drop], outputs=[vault_editor])
    save_vault_btn.click(fn=save_vault_file, inputs=[vault_files_drop, vault_editor], outputs=[vault_status])
    upload_file.upload(fn=upload_to_vault, inputs=[upload_file], outputs=[vault_files_drop, vault_status])

if __name__ == "__main__":
    app.launch(inbrowser=True, footer_links=["api", "gradio"])
