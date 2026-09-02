@echo off
REM Runs a one-off scan of your configured scope and prints results.
REM %~dp0 is Sentry\scripts\ -- step up to the project root.
cd /d "%~dp0.."
python -m sentry scan
pause
