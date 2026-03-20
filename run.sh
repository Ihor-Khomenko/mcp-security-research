#!/bin/bash

# [EN] Name of the environment for the UI launcher
# [UK] Назва середовища для запуску інтерфейсу
UI_ENV="ui-env"

echo "--- [EN] Checking dependencies / [UK] Перевірка залежностей ---"

# [EN] Create UI environment if it doesn't exist
# [UK] Створення UI-середовища, якщо воно не існує
if [ ! -d "$UI_ENV" ]; then
    python3 -m venv $UI_ENV
    source $UI_ENV/bin/activate
    pip install gradio requests
else
    source $UI_ENV/bin/activate
fi

# [EN] Check if Ollama is running
# [UK] Перевірка, чи запущена Ollama
if ! curl -s http://localhost:11434/api/tags > /dev/null; then
    echo "--- [EN] Warning: Ollama is not running! / [UK] Увага: Ollama не запущена! ---"
fi

echo "--- [EN] Launching App / [UK] Запуск застосунку ---"
python3 app.py