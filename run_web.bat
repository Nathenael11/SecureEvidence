@echo off
cd /d "%~dp0"
echo Starting SecureEvidence Web Server...
echo Press CTRL+C to stop.
echo.
echo URL: http://localhost:8000
echo Docs: http://localhost:8000/docs
echo.
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
pause
