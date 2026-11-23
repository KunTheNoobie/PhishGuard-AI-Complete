@echo off
setlocal
title PhishGuard-AI one-click setup
cd /d "%~dp0"
echo ========================================================
echo  PhishGuard-AI setup  (Git LFS, virtual environment, .env)
echo  The first run downloads about 4 GB of packages.
echo ========================================================

echo.
echo [1/5] Checking the included model weights...
call :verify_models
if not errorlevel 1 goto :models_ready
if /i "%~1"=="--check-models" exit /b 1
if not exist .git (echo [ERROR] This ZIP is missing complete models. Obtain the complete release ZIP. & goto :fail)
where git >nul 2>&1 || (echo [ERROR] Git is required to fetch missing model weights. & goto :fail)
git lfs install
git lfs pull
if errorlevel 1 goto :fail
call :verify_models
if errorlevel 1 (echo [ERROR] Model weights are still missing or incomplete. & goto :fail)
:models_ready
echo Complete model weights found. No model download is needed.
if /i "%~1"=="--check-models" exit /b 0
echo.
echo [2/5] Creating the virtual environment...
where py >nul 2>&1 && (set "PY=py -3") || (set "PY=python")
if not exist venv (%PY% -m venv venv || (echo [ERROR] Python 3.11 or newer is required. & goto :fail))

echo.
echo [3/5] Installing requirements.txt (PyTorch, Transformers, YOLO, FastAPI...)...
venv\Scripts\python.exe -m pip install --upgrade pip
venv\Scripts\python.exe -m pip install -r requirements.txt
if errorlevel 1 (echo [ERROR] Package installation failed. & goto :fail)

echo.
echo [4/5] Creating .env from .env.example (admin key 12345678)...
if not exist .env (copy /y .env.example .env >nul && echo .env created.) else (echo .env already exists - left unchanged.)

echo.
echo [5/5] Checking the model files...
if not exist phishguard_custom_model\model.safetensors (echo [WARNING] BERT weights missing - the AI URL model will be off.) else (echo BERT weights found.)

echo.
echo ========================================================
echo  Setup finished.  Start the server with start_local.bat
echo  Dashboard: http://127.0.0.1:8000/dashboard/   (admin key 12345678)
echo ========================================================
pause
exit /b 0

:fail
echo.
echo Setup stopped. Fix the message above and run setup.bat again.
pause
exit /b 1

:verify_models
if not exist "phishguard_custom_model\model.safetensors" exit /b 1
if not exist "phishguard_custom_model\tokenizer.json" exit /b 1
if not exist "visual_identity\models\best.pt" exit /b 1
for %%F in ("phishguard_custom_model\model.safetensors") do if %%~zF LSS 1000000 exit /b 1
for %%F in ("phishguard_custom_model\tokenizer.json") do if %%~zF LSS 10000 exit /b 1
for %%F in ("visual_identity\models\best.pt") do if %%~zF LSS 10000 exit /b 1
exit /b 0
