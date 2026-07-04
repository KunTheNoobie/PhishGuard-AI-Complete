@echo off
title PhishGuard-AI Server
echo ========================================================
echo PhishGuard-AI Backend Server Startup
echo ========================================================
echo.
echo Activating Virtual Environment...
call .\venv\Scripts\activate.bat

echo Starting FastAPI Server...
.\venv\Scripts\python.exe -m uvicorn main:app --host 127.0.0.1 --port 8000
pause
