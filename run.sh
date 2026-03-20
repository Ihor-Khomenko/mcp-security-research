#!/bin/bash
set -e
UI_ENV="ui-env"
cd "$(dirname "$0")"
echo "--- Checking dependencies ---"
if [ ! -d "$UI_ENV" ]; then
    python3 -m venv "$UI_ENV"
fi
source "$UI_ENV/bin/activate"
pip install -q -r requirements.txt
if ! curl -sf http://localhost:11434/api/tags > /dev/null; then
    echo "--- Warning: Ollama may not be running ---"
fi
echo "--- Launching app ---"
python3 app.py
