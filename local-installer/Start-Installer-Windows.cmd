@echo off
setlocal
cd /d "%~dp0.."
py -3 local-installer\start.py
if errorlevel 1 pause
