@echo off
REM Starts the Sentry dashboard and opens it in your browser.
REM %~dp0 is Sentry\scripts\ -- step up to the project root.
cd /d "%~dp0.."
python -m sentry serve
pause
