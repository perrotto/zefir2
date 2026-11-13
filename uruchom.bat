@echo off
cd /d "%~dp0"
if not exist .venv (
  echo Pierwsze uruchomienie - instaluje biblioteki...
  py -m venv .venv || python -m venv .venv
  .venv\Scripts\pip install -r requirements.txt
)
.venv\Scripts\python app.py
pause
