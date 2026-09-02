@echo off
REM Runs a full scan of your configured scope, writes an HTML report, and opens
REM it if anything needs review. This is the same thing the weekly scheduled
REM task runs. Safe to double-click from anywhere -- it fixes its own directory.
REM %~dp0 is Sentry\scripts\ -- step up to the project root.
cd /d "%~dp0.."
echo Scanning... this can take a few minutes on a large scope.
echo.
python -m sentry weekly --open-report
echo.
echo Reports are saved in: %LOCALAPPDATA%\Sentry\reports
pause
