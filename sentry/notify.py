"""Desktop notification after a scheduled scan. Best-effort, never fatal."""
from __future__ import annotations

import base64
import re
import subprocess
from urllib.parse import quote

from . import config

# A toast notifier needs an AppUserModelID that is actually registered with the
# shell, otherwise Show() succeeds silently and nothing is ever displayed.
# 'Microsoft.WindowsPowerShell' is NOT registered on a stock Windows 10/11
# install. This GUID\path form is the AppUserModelID of the Start Menu's
# Windows PowerShell shortcut, which does exist on every desktop SKU.
POWERSHELL_AUMID = (r"{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}"
                    r"\WindowsPowerShell\v1.0\powershell.exe")


def notify(title: str, message: str, report_path: str | None = None) -> None:
    # Always leave a durable record: a toast can silently fail to appear and a
    # scheduled run has nobody watching.
    try:
        from . import store
        store.log_event("notify", f"{title} — {message}")
    except Exception:  # noqa: BLE001
        pass
    try:
        if config.IS_WINDOWS:
            _windows_toast(title, message, report_path)
        else:
            subprocess.run(["notify-send", title, message],
                           capture_output=True, timeout=10, check=False)
    except Exception:  # noqa: BLE001
        pass


def launch_uri(report_path: str | None) -> str | None:
    """file:/// URI for the report, or None when there is nothing safe to open.

    Built by hand rather than via Path.as_uri() so the result does not depend
    on the host the code happens to run on (tests simulate Windows on Linux).
    Only an absolute drive-letter path qualifies: a relative path would be
    resolved against whatever cwd the shell has, and UNC is left alone.
    """
    p = config.strip_long_prefix(str(report_path or "")).strip().replace("\\", "/")
    if not re.match(r"^[A-Za-z]:/", p):
        return None
    return "file:///" + quote(p, safe="/:")


APP_PROTOCOL = "sentry-app:review"


def app_uri() -> str | None:
    """The desktop review app's protocol URI, when its handler is installed.

    scripts/install_app_shortcut.ps1 registers HKCU\\Software\\Classes\\
    sentry-app for the current user. When that key exists, clicking the toast
    opens the review app instead of the static HTML report.
    """
    if not config.IS_WINDOWS:
        return None
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                            r"Software\Classes\sentry-app\shell\open\command"):
            return APP_PROTOCOL
    except (ImportError, OSError):
        return None


def build_toast_script(title: str, message: str,
                       report_path: str | None = None,
                       app_link: str | None = None) -> str:
    """The PowerShell source used for the toast. Separated out so it is testable.

    A toast with no `launch` target does nothing when clicked, which is what
    the first Windows run showed: the notification appeared, the click went
    nowhere. Protocol activation needs no COM activator registration -- the
    shell simply opens the URI. When the desktop app is installed (`app_link`,
    resolved by the caller via app_uri()), the toast body opens the review app
    and the HTML report stays available as a second button; otherwise the
    report is the click target, opened in the default browser.
    """
    report = launch_uri(report_path)
    launch = app_link or report
    buttons = ([("Review now", app_link)] if app_link else []) \
        + ([("Open report", report)] if report else [])
    body = "".join(f"""
  $b{n} = $tpl.CreateElement('action')
  $b{n}.SetAttribute('content', {_q(label)})
  $b{n}.SetAttribute('activationType', 'protocol')
  $b{n}.SetAttribute('arguments', {_q(uri)})
  $actions.AppendChild($b{n}) | Out-Null""" for n, (label, uri) in enumerate(buttons))
    activation = f"""
  $tpl.DocumentElement.SetAttribute('activationType', 'protocol')
  $tpl.DocumentElement.SetAttribute('launch', {_q(launch)})
  $actions = $tpl.CreateElement('actions'){body}
  $tpl.DocumentElement.AppendChild($actions) | Out-Null""" if launch else ""
    return f"""
$ErrorActionPreference = 'Stop'
$shown = $false
try {{
  [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType=WindowsRuntime] | Out-Null
  [Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom, ContentType=WindowsRuntime] | Out-Null
  $tpl = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent(
            [Windows.UI.Notifications.ToastTemplateType]::ToastText02)
  $texts = $tpl.GetElementsByTagName('text')
  $texts.Item(0).AppendChild($tpl.CreateTextNode({_q(title)})) | Out-Null
  $texts.Item(1).AppendChild($tpl.CreateTextNode({_q(message)})) | Out-Null{activation}
  $toast = [Windows.UI.Notifications.ToastNotification]::new($tpl)
  $notifier = [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier(
     {_q(POWERSHELL_AUMID)})
  # Show() does not throw when the AppID is unregistered or notifications are
  # turned off — it just does nothing. Setting is the only way to tell.
  if ("$($notifier.Setting)" -eq 'Enabled') {{
    $notifier.Show($toast)
    $shown = $true
  }}
}} catch {{ $shown = $false }}

if (-not $shown) {{
  # Fallback: a tray balloon, which auto-dismisses. Deliberately not a modal
  # dialog — one of those blocks until a human clicks it, and this runs from
  # Task Scheduler where there may be nobody at the keyboard.
  try {{
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    $ni = New-Object System.Windows.Forms.NotifyIcon
    $ni.Icon = [System.Drawing.SystemIcons]::Information
    $ni.BalloonTipTitle = {_q(title)}
    $ni.BalloonTipText = {_q(message)}
    $ni.Visible = $true
    $ni.ShowBalloonTip(10000)
    Start-Sleep -Seconds 8
    $ni.Dispose()
  }} catch {{ }}
}}
"""


def powershell_exe() -> str:
    """Full path to powershell.exe.

    A task launched by Task Scheduler can inherit a PATH that does not contain
    the PowerShell directory, in which case a bare "powershell" is a
    FileNotFoundError and the notification silently never happens.
    """
    import os
    import shutil
    return shutil.which("powershell") or os.path.join(
        os.environ.get("SystemRoot", r"C:\Windows"),
        "System32", "WindowsPowerShell", "v1.0", "powershell.exe")


def _windows_toast(title: str, message: str,
                   report_path: str | None = None) -> None:
    ps = build_toast_script(title, message, report_path, app_link=app_uri())
    subprocess.run(
        [powershell_exe(), "-NoProfile", "-NonInteractive",
         "-WindowStyle", "Hidden",
         "-ExecutionPolicy", "Bypass", "-EncodedCommand", encode_command(ps)],
        capture_output=True, timeout=45, check=False)


def encode_command(script: str) -> str:
    """UTF-16LE base64, as -EncodedCommand expects.

    Passing a multi-line script via -Command means the newlines and quotes have
    to survive CreateProcess command-line parsing intact; -EncodedCommand takes
    quoting out of the picture entirely.
    """
    return base64.b64encode(script.encode("utf-16-le")).decode("ascii")


def _q(s: str) -> str:
    """Quote for a PowerShell single-quoted string literal."""
    return "'" + str(s).replace("'", "''") + "'"
