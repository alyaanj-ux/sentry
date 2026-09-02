@echo off
REM Sentry -- main launcher. Everything else lives in scripts\.
cd /d "%~dp0"

:menu
cls
echo.
echo   SENTRY -- local heuristic file scanner
echo   =======================================
echo.
echo    1   Open the Sentry app  (review flagged files)
echo    2   Open the dashboard  (findings, quarantine, restore)
echo    3   Run a scan now and write a report
echo    4   Show what gets scanned
echo    5   Scan only drive D:
echo    6   Open the reports folder
echo    7   Run the test suite
echo    8   Install the weekly scheduled task
echo    9   Install the app shortcut (Start menu + toast opens the app)
echo    0   Exit
echo.
set /p choice="  Choose: "

if "%choice%"=="1" ( start "" pythonw -m sentry app & goto menu )
if "%choice%"=="2" ( python -m sentry serve & goto done )
if "%choice%"=="3" ( python -m sentry weekly --open-report & goto done )
if "%choice%"=="4" ( python -m sentry scope & goto done )
if "%choice%"=="5" ( python -m sentry scope --only D:\ & goto done )
if "%choice%"=="6" ( start "" "%LOCALAPPDATA%\Sentry\reports" & goto menu )
if "%choice%"=="7" ( python tests\run_tests.py & goto done )
if "%choice%"=="8" ( powershell -ExecutionPolicy Bypass -File "scripts\install_schedule.ps1" & goto done )
if "%choice%"=="9" ( powershell -ExecutionPolicy Bypass -File "scripts\install_app_shortcut.ps1" & goto done )
if "%choice%"=="0" exit /b 0
goto menu

:done
echo.
pause
goto menu
