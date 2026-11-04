@echo off
rem Starts the MalWeight Canary (Openweight Canary) page. Nothing is started until you run this file.
rem Usage: run-canary.bat [config-file] [port]
setlocal
set "HERE=%~dp0"
set "CONFIG=%~1"
if "%CONFIG%"=="" set "CONFIG=canary.json"
set "PORT=%~2"
if "%PORT%"=="" set "PORT=8765"
if "%PORT%"=="8080" (
  echo Port 8080 is not allowed; choose another.
  exit /b 1
)
where python >nul 2>nul
if errorlevel 1 (
  echo Python 3.10 or later was not found in PATH.
  exit /b 1
)
set "PYTHONPATH=%HERE%"
cd /d "%HERE%"
if not exist "%CONFIG%" (
  echo No %CONFIG% yet: writing a starting one.
  python -m canary init --dir .
)
python -m canary gui -c "%CONFIG%" --port %PORT%
endlocal
