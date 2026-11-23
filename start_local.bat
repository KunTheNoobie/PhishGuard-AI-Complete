@echo off
setlocal
title PhishGuard-AI (local, logo detector on)
cd /d "%~dp0"
echo ========================================================
echo  PhishGuard-AI local server  (BERT + YOLOv8n logo detector)
echo  Dashboard: http://127.0.0.1:8000/dashboard/   key 12345678
echo ========================================================
rem Prefer an explicit interpreter, then the project's own environments.
set "PYTHON_EXE=%PHISHGUARD_PYTHON%"
if defined PYTHON_EXE goto :interpreter_ready
if exist "venv\Scripts\python.exe" set "PYTHON_EXE=%~dp0venv\Scripts\python.exe"
if defined PYTHON_EXE goto :interpreter_ready
if exist ".venv\Scripts\python.exe" set "PYTHON_EXE=%~dp0.venv\Scripts\python.exe"
if defined PYTHON_EXE goto :interpreter_ready
rem A user-local path can reuse already installed packages without downloading them again.
if exist ".local-python-path" set /p "PYTHON_EXE="<".local-python-path"
:interpreter_ready
if not defined PYTHON_EXE (echo Run setup.bat first or set PHISHGUARD_PYTHON. & pause & exit /b 1)
if not exist "%PYTHON_EXE%" (echo The configured Python interpreter is missing. Run setup.bat or update .local-python-path. & pause & exit /b 1)
set PHISHGUARD_ENABLE_VISUAL=true
if /i "%~1"=="--check" goto :check_only
"%PYTHON_EXE%" -m uvicorn main:app --host 127.0.0.1 --port 8000
pause
exit /b

:check_only
"%PYTHON_EXE%" -c "import uvicorn; from services.visual_detector import VisualLogoDetector; detector=VisualLogoDetector(); model=detector._load_model(); assert model is not None, detector._load_error; print('Local startup check passed: 29-bank model loaded.')"
exit /b %ERRORLEVEL%
