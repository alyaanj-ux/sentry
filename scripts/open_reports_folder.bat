@echo off
REM Opens the folder where Sentry saves its HTML reports.
if not exist "%LOCALAPPDATA%\Sentry\reports" (
  echo No reports folder yet -- run weekly_report.bat first.
  pause
  exit /b 1
)
start "" "%LOCALAPPDATA%\Sentry\reports"
