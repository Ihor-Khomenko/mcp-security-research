@echo off
setlocal
cd /d "%~dp0"
set UI_ENV=ui-env
echo --- Checking dependencies ---
if not exist "%UI_ENV%\Scripts\python.exe" (
    python -m venv "%UI_ENV%"
    if errorlevel 1 (
        echo Failed to create venv. Install Python 3 and ensure it is on PATH.
        exit /b 1
    )
)
call "%UI_ENV%\Scripts\activate.bat"
pip install -q -r requirements.txt
if errorlevel 1 exit /b 1
python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:11434/api/tags', timeout=2)" 2>nul
if errorlevel 1 echo --- Warning: Ollama may not be running ---
echo --- Launching app ---
python app.py
endlocal
