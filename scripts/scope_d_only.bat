@echo off
REM Restricts Sentry to drive D: only. Every preset (which all point at C:) is
REM turned off and D:\ becomes the single scan root. This is what the weekly
REM scheduled task will use from now on.
REM %~dp0 is Sentry\scripts\ -- step up to the project root.
cd /d "%~dp0.."
python -m sentry scope --only D:\
echo.
echo Run weekly_report.bat to scan with the new scope.
pause
