@echo off
title PhishGuard-AI (local, logo detector on)
cd /d "%~dp0"
echo ========================================================
echo  PhishGuard-AI local server  (BERT + YOLOv8n logo detector)
echo  Dashboard: http://127.0.0.1:8000/dashboard/   key 12345678
echo ========================================================
if not exist venv\Scripts\python.exe (echo Run setup.bat first. & pause & exit /b 1)
rem The venv interpreter is called directly: activate.bat breaks on folder names that contain "&".
set PHISHGUARD_ENABLE_VISUAL=true
venv\Scripts\python.exe -m uvicorn main:app --host 127.0.0.1 --port 8000
pause
