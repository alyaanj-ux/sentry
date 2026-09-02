@echo off
REM Prints what Sentry currently scans, and what it excludes.
REM %~dp0 is Sentry\scripts\ -- step up to the project root.
cd /d "%~dp0.."
python -m sentry scope
pause
