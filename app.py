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

VENV_DIR = "mcp-env"
LOGS_DIR = "research_logs"
VAULT_DIR = "test_vault"
IS_WIN = os.name == 'nt'
PYTHON_CMD = os.path.join(VENV_DIR, "bin", "python") if not IS_WIN else os.path.join(VENV_DIR, "Scripts", "python")
PIP_CMD = os.path.join(VENV_DIR, "bin", "pip") if not IS_WIN else os.path.join(VENV_DIR, "Scripts", "pip")
OLLAMA_API = "http://localhost:11434/api"
PROMPTS_DIR = "prompts"
DEBUG_LANGUAGE_SWITCH = True  # temporary diagnostics

os.makedirs(LOGS_DIR, exist_ok=True)
os.makedirs(VAULT_DIR, exist_ok=True)
os.makedirs(PROMPTS_DIR, exist_ok=True)

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
    """Повертає список файлів з тестового сховища"""
    if not os.path.exists(VAULT_DIR): return []
    return sorted([f for f in os.listdir(VAULT_DIR) if os.path.isfile(os.path.join(VAULT_DIR, f))])

def load_vault_file(filename):
    """Читає вміст payload-файлу для прев'ю"""
    if not filename: return ""
    try:
        with open(os.path.join(VAULT_DIR, filename), "r", encoding="utf-8") as f:
            return f.read()
    except Exception as e:
        return f"Помилка читання: {e}"

def save_vault_file(filename, content):
    """Зберігає відредагований payload-файл"""
    if not filename: return "❌ Оберіть файл для збереження"
    try:
        with open(os.path.join(VAULT_DIR, filename), "w", encoding="utf-8") as f:
            f.write(content)
        return f"✅ Файл '{filename}' успішно оновлено!"
    except Exception as e:
        return f"❌ Помилка збереження: {e}"

def upload_to_vault(file_obj):
    """Копіює завантажений файл у test_vault"""
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
    if DEBUG_LANGUAGE_SWITCH:
        print(f"[LANG_SWITCH_DEBUG] lang={lang!r} prompt_name={prompt_name!r}")
    prompt_content = load_prompt(prompt_name)

    if not prompt_content:
        prompt_content = (
            "Ти - Senior Security Engineer. Проаналізуй лог симуляції MCP та стан файлів.\n"
            "Відповідай УКРАЇНСЬКОЮ. Не використовуй блоки коду."
        )

    if DEBUG_LANGUAGE_SWITCH:
        preview = (prompt_content or "")[:120].replace("\n", " ")
        print(f"[LANG_SWITCH_DEBUG] prompt_preview={preview!r}")
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

def run_research(script, model, mcp_type, mcp_url, mcp_token, current_filter, custom_prompt, ui_lang, progress=gr.Progress()):
    if not os.path.exists(PYTHON_CMD):
        yield "❌ Немає середовища", get_loaded_models_text(), "⚠️ VENV не знайдено", "🔴 Зупинено", gr.update(), ""
        return
    
    progress(0, desc="Ініціалізація")
    env_vars = os.environ.copy()
    env_vars["SELECTED_MODEL"] = str(model or "qwen2.5:7b")
    env_vars["MCP_TYPE"] = str(mcp_type or "Local Filesystem")
    env_vars["MCP_URL"] = str(mcp_url or "")
    env_vars["MCP_TOKEN"] = str(mcp_token or "")
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
        process = subprocess.Popen([PYTHON_CMD, script], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=env_vars, bufsize=1)
        
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
            mcp_type.change(lambda c: (gr.update(visible=c=="Remote URL"), gr.update(visible=c=="Remote URL")), inputs=mcp_type, outputs=[mcp_url, mcp_token])

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
                        placeholder="Наприклад: Прочитай файл report.txt АБО Знайди всі work packages в OpenProject...", 
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
    
    run_btn.click(
        fn=run_research, 
        inputs=[script_choice, model_drop, mcp_type, mcp_url, mcp_token, log_filter, custom_prompt, lang_toggle], 
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
