<#
    Registers a weekly Sentry scan with Windows Task Scheduler.

    Runs as the current user, at normal priority, waking the machine if needed
    and catching up on a missed run if the PC was off at the scheduled time.

    Usage (from the sentry folder):
        powershell -ExecutionPolicy Bypass -File .\install_schedule.ps1
        powershell -ExecutionPolicy Bypass -File .\install_schedule.ps1 -Day SAT -Time 21:30
        powershell -ExecutionPolicy Bypass -File .\install_schedule.ps1 -Remove
#>
param(
    [ValidateSet('SUN','MON','TUE','WED','THU','FRI','SAT')]
    [string]$Day = 'SUN',
    [string]$Time = '12:00',
    [switch]$Remove,
    [switch]$RunNow
)

$ErrorActionPreference = 'Stop'
$TaskName = 'Sentry Weekly Scan'
# This script lives in Sentry\scripts, so the project root -- the folder that
# contains the `sentry` package and is therefore the task's working directory --
# is one level up.
$ScriptDir = if ($PSScriptRoot) { $PSScriptRoot }
             elseif ($MyInvocation.MyCommand.Path) { Split-Path -Parent $MyInvocation.MyCommand.Path }
             else { (Get-Location).Path }
$ProjectDir = Split-Path -Parent $ScriptDir

function Test-StoreAlias {
    # Microsoft Store Python installs an "App Execution Alias": a zero-length
    # reparse point under WindowsApps. Task Scheduler cannot launch one -- the
    # task fails with 0x2 / 0xC0000135 -- so it must never be used as -Execute.
    param([string]$Path)
    if (-not $Path) { return $false }
    return ($Path -like '*\WindowsApps\*')
}

function Resolve-Interpreter {
    <#
      Returns @{ Exe; Pre; Note } where Exe is a real .exe on disk.

      Three cases the old code got wrong:
        * py launcher  -> pythonw.exe is NOT next to py.exe (py.exe lives in
          C:\Windows). The windowless launcher is pyw.exe, in the same folder.
        * python.exe   -> pythonw.exe IS next to it; use it.
        * Store shim   -> WindowsApps alias; unusable from Task Scheduler.
          Ask the real interpreter for sys.prefix and use the exe there, or
          fail loudly rather than registering a task that can never run.
    #>
    # 1. A real python.exe on PATH (not a Store alias).
    $cmd = Get-Command 'python.exe' -ErrorAction SilentlyContinue |
           Where-Object { -not (Test-StoreAlias $_.Source) } | Select-Object -First 1
    if ($cmd) {
        $dir = Split-Path -Parent $cmd.Source
        $pyw = Join-Path $dir 'pythonw.exe'
        if (Test-Path -LiteralPath $pyw) {
            return @{ Exe = $pyw; Pre = @(); Note = 'pythonw.exe (no console window)' }
        }
        return @{ Exe = $cmd.Source; Pre = @(); Note = 'python.exe (a console window will flash)' }
    }

    # 2. The py launcher. pyw.exe is its windowless twin, NOT pythonw.exe.
    $pyCmd = Get-Command 'py.exe' -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($pyCmd -and -not (Test-StoreAlias $pyCmd.Source)) {
        $dir = Split-Path -Parent $pyCmd.Source
        $pyw = Join-Path $dir 'pyw.exe'
        # pyw.exe accepts the same -3 version selector as py.exe.
        if (Test-Path -LiteralPath $pyw) {
            return @{ Exe = $pyw; Pre = @('-3'); Note = 'pyw.exe launcher (no console window)' }
        }
        return @{ Exe = $pyCmd.Source; Pre = @('-3'); Note = 'py.exe launcher (a console window will flash)' }
    }

    # 3. Only a Store alias is on PATH: resolve through it to the real install.
    $alias = Get-Command 'python.exe','python3.exe' -ErrorAction SilentlyContinue |
             Select-Object -First 1
    if ($alias) {
        try {
            $prefix = (& $alias.Source -c "import sys;print(sys.prefix)" 2>$null).Trim()
        } catch { $prefix = '' }
        foreach ($n in @('pythonw.exe', 'python.exe')) {
            if ($prefix) {
                $c = Join-Path $prefix $n
                if ((Test-Path -LiteralPath $c) -and -not (Test-StoreAlias $c)) {
                    return @{ Exe = $c; Pre = @(); Note = "resolved out of the Store alias to $c" }
                }
            }
        }
        throw ("Only the Microsoft Store Python app-execution alias was found " +
               "($($alias.Source)). Task Scheduler cannot launch it. Install " +
               "Python from python.org (or 'winget install Python.Python.3.12') " +
               "and re-run this script.")
    }

    throw "Python not found on PATH. Install Python 3.10+ from python.org and re-run."
}

if ($Remove) {
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        Write-Host "Removed scheduled task '$TaskName'." -ForegroundColor Green
    } else {
        Write-Host "No scheduled task named '$TaskName' found." -ForegroundColor Yellow
    }
    return
}

$py  = Resolve-Interpreter
$exe = $py.Exe

$argList = @()
$argList += $py.Pre
$argList += @('-m', 'sentry', 'weekly')
$arguments = ($argList -join ' ')

if (-not (Test-Path -LiteralPath $exe)) {
    throw "Resolved interpreter '$exe' does not exist on disk."
}

Write-Host "Project folder : $ProjectDir"
Write-Host "Interpreter    : $exe"
Write-Host "                 ($($py.Note))"
Write-Host "Command        : $exe $arguments"
Write-Host "Schedule       : every $Day at $Time"
Write-Host ""

$action = New-ScheduledTaskAction -Execute $exe -Argument $arguments -WorkingDirectory $ProjectDir

$trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek $Day -At $Time

$settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -StartWhenAvailable `
    -RunOnlyIfNetworkAvailable:$false `
    -ExecutionTimeLimit (New-TimeSpan -Hours 3) `
    -MultipleInstances IgnoreNew `
    -RunOnlyIfIdle:$false `
    -WakeToRun

# LogonType Interactive is deliberate and has a real consequence: the task runs
# only while this user is logged on (a locked screen is fine, a logged-off or
# signed-out session is not). It is required for the toast/balloon notification
# to reach a desktop at all -- a task registered with -LogonType S4U or as
# SYSTEM runs in session 0 and its notification is never displayed.
#
# Because of that, -WakeToRun only achieves anything when the machine is asleep
# *with the user still logged on*. If nobody is logged on, Windows may still wake
# the machine at $Time, find no eligible session, and go back to sleep without
# running the scan; StartWhenAvailable then runs the missed occurrence after the
# next logon (Windows applies its own delay, typically up to 10 minutes).
#
# RunLevel Limited means the scan runs unelevated, so files that only
# Administrators or SYSTEM can read (parts of C:\Windows, other users' profiles,
# System Volume Information) are silently unreadable. That is the intended
# trade-off: a weekly unattended task should not hold admin rights.
$principal = New-ScheduledTaskPrincipal `
    -UserId "$env:USERDOMAIN\$env:USERNAME" `
    -LogonType Interactive `
    -RunLevel Limited

if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    Write-Host "Replaced existing task." -ForegroundColor Yellow
}

Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger `
    -Settings $settings -Principal $principal `
    -Description ("Weekly Sentry heuristic file scan. Writes an HTML report and " +
                  "shows a notification. Never moves or deletes files on its own.") | Out-Null

Write-Host "Registered '$TaskName'." -ForegroundColor Green
Write-Host ""
Write-Host "This task runs only while you are signed in (a locked screen counts)."
Write-Host "If the PC is off or signed out at $Time on $Day, StartWhenAvailable runs the"
Write-Host "missed scan shortly after your next sign-in -- not at boot, and not while"
Write-Host "signed out. Reports land in:"
Write-Host "  $env:LOCALAPPDATA\Sentry\reports" -ForegroundColor Cyan
Write-Host ""
Write-Host "Verify with : Get-ScheduledTask -TaskName '$TaskName' | Get-ScheduledTaskInfo"
Write-Host "Remove with : powershell -ExecutionPolicy Bypass -File .\install_schedule.ps1 -Remove"

if ($RunNow) {
    Write-Host ""
    Write-Host "Starting a run now..." -ForegroundColor Cyan
    Start-ScheduledTask -TaskName $TaskName
}
