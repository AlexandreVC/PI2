@echo off
title VulnAI - Web Interface
echo.
echo ========================================
echo   VulnAI - Vulnerability Analysis Platform
echo ========================================
echo.
echo Installing dependencies...
pip install -q fastapi uvicorn[standard] python-multipart
echo.
echo Starting web server...
echo.
echo   Web Interface: http://localhost:8000
echo   API Docs:      http://localhost:8000/docs
echo.
echo Press CTRL+C to stop
echo.
python run_web.py
pause
