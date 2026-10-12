@echo off
cd /d %~dp0
set /p PSDASH_PASSWORD=Dashboard password: 
"C:\Users\spanda\AppData\Local\Programs\Python\Python312\python.exe" app.py
pause
