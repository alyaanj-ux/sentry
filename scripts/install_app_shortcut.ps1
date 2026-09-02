<#
    Installs the Sentry desktop app integration for the current user:
      * a Start-menu shortcut ("Sentry") that opens the review app
      * the sentry-app: URL protocol, so the weekly toast can open the app
    No admin rights needed - everything lives in HKCU / the user profile.
    Remove with -Remove.
#>
param([switch]$Remove)

$ErrorActionPreference = 'Stop'
$ProjectDir = Split-Path -Parent $PSScriptRoot
$Launcher   = Join-Path $PSScriptRoot 'launch_app.py'
$Shortcut   = Join-Path ([Environment]::GetFolderPath('Programs')) 'Sentry.lnk'
$ProtoKey   = 'HKCU:\Software\Classes\sentry-app'

if ($Remove) {
    if (Test-Path $Shortcut) { Remove-Item $Shortcut }
    if (Test-Path $ProtoKey) { Remove-Item $ProtoKey -Recurse }
    Write-Host 'Removed the Sentry shortcut and protocol handler.'
    return
}

# The windowless interpreter, resolved the same way install_schedule.ps1 does:
# a console window must not flash when the toast or shortcut opens the app.
$pyw = $null
$cmd = Get-Command 'pythonw.exe' -ErrorAction SilentlyContinue |
       Where-Object { $_.Source -notlike '*\WindowsApps\*' } | Select-Object -First 1
if ($cmd) { $pyw = $cmd.Source }
if (-not $pyw) {
    $py = Get-Command 'python.exe' -ErrorAction SilentlyContinue |
          Where-Object { $_.Source -notlike '*\WindowsApps\*' } | Select-Object -First 1
    if ($py) {
        $candidate = Join-Path (Split-Path -Parent $py.Source) 'pythonw.exe'
        if (Test-Path -LiteralPath $candidate) { $pyw = $candidate }
    }
}
if (-not $pyw) { throw 'Could not find pythonw.exe (python.org install required).' }

# Start-menu shortcut.
$ws = New-Object -ComObject WScript.Shell
$lnk = $ws.CreateShortcut($Shortcut)
$lnk.TargetPath = $pyw
$lnk.Arguments = "`"$Launcher`""
$lnk.WorkingDirectory = $ProjectDir
$lnk.Description = 'Sentry - review flagged files'
$icon = Join-Path $ProjectDir 'assets\sentry.ico'
if (Test-Path -LiteralPath $icon) {
    $lnk.IconLocation = "$icon, 0"
} else {
    $lnk.IconLocation = "$env:SystemRoot\System32\imageres.dll, 73"  # shield
}
$lnk.Save()

# sentry-app: protocol so a toast click can open the app.
New-Item -Path "$ProtoKey\shell\open\command" -Force | Out-Null
Set-ItemProperty -Path $ProtoKey -Name '(Default)' -Value 'URL:Sentry review app'
Set-ItemProperty -Path $ProtoKey -Name 'URL Protocol' -Value ''
Set-ItemProperty -Path "$ProtoKey\shell\open\command" -Name '(Default)' `
    -Value "`"$pyw`" `"$Launcher`""

Write-Host "Shortcut   : $Shortcut"
Write-Host "Opens with : $pyw `"$Launcher`""
Write-Host "Protocol   : sentry-app: registered (toast clicks open the app)"
