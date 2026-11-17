@echo off
setlocal
title PhishGuard-AI one-click setup
cd /d "%~dp0"
echo ========================================================
echo  PhishGuard-AI setup  (Git LFS, virtual environment, .env)
echo  The first run downloads about 4 GB of packages.
echo ========================================================

where git >nul 2>&1 || (echo [ERROR] Git is not installed. Get it from https://git-scm.com & goto :fail)

echo.
echo [1/5] Git LFS: downloading the model weights (about 430 MB)...
git lfs install
git lfs pull
if errorlevel 1 (echo [ERROR] git lfs pull failed. Install Git LFS from https://git-lfs.com and run again. & goto :fail)

echo.
echo [2/5] Creating the virtual environment...
where py >nul 2>&1 && (set "PY=py -3") || (set "PY=python")
if not exist venv (%PY% -m venv venv || (echo [ERROR] Python 3.11 or newer is required. & goto :fail))

echo.
echo [3/5] Installing requirements.txt (PyTorch, Transformers, YOLO, FastAPI...)...
call venv\Scripts\activate.bat
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
if errorlevel 1 (echo [ERROR] Package installation failed. & goto :fail)

echo.
echo [4/5] Creating .env from .env.example (admin key 12345678)...
if not exist .env (copy /y .env.example .env >nul && echo .env created.) else (echo .env already exists - left unchanged.)

echo.
echo [5/5] Checking the model files...
if not exist phishguard_custom_model\model.safetensors (echo [WARNING] BERT weights missing - the AI URL model will be off.) else (echo BERT weights found.)

echo.
echo ========================================================
echo  Setup finished.  Start the server with run_server.bat
echo  Dashboard: http://127.0.0.1:8000/dashboard/   (admin key 12345678)
echo ========================================================
pause
exit /b 0

:fail
echo.
echo Setup stopped. Fix the message above and run setup.bat again.
pause
exit /b 1
