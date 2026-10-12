@echo off
rem Pegasus updater: copies the newest ps-admin-dashboard.zip from Downloads over this folder,
rem keeping data\ (inventory, saved settings, cached patches) and logs\ untouched.
set "DEST=%~dp0"
set "ZIP=%USERPROFILE%\Downloads\ps-admin-dashboard.zip"
set "PY=C:\Users\spanda\AppData\Local\Programs\Python\Python312\python.exe"
if not exist "%ZIP%" (echo No update found at %ZIP% & pause & exit /b 1)
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$t=Join-Path $env:TEMP 'pegasus_update'; Remove-Item $t -Recurse -Force -EA SilentlyContinue;" ^
  "Expand-Archive -LiteralPath '%ZIP%' -DestinationPath $t -Force;" ^
  "Get-ChildItem (Join-Path $t 'ps-admin-dashboard') | Where-Object { $_.Name -notin 'data','logs' } |" ^
  "  ForEach-Object { Copy-Item $_.FullName '%DEST%' -Recurse -Force };" ^
  "Remove-Item $t -Recurse -Force; Write-Host 'Files updated.'"
"%PY%" -m pip install -q -r "%DEST%requirements.txt"
echo.
echo Update done. Start Pegasus again with start.bat.
pause
