@echo off
rem Starts the Pegasus Console AI helper. Keep this window open while you use Console AI in Pegasus.
cd /d "%~dp0"
if not exist .venv\Scripts\python.exe (
  echo First run: setting up, this takes a minute...
  py -3 -m venv .venv || python -m venv .venv
  .venv\Scripts\python -m pip install -q -r requirements.txt
  .venv\Scripts\python -m playwright install chromium
)
.venv\Scripts\python -m pegasus_console_ai %*
pause
