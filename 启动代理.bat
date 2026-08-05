@echo off
cd /d "%~dp0"
python dpi_proxy.py
if errorlevel 1 (
  echo.
  echo Failed to start. Is Python installed and on PATH?
  pause
)
