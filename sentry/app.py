"""Desktop app: the review queue in a native window.

Wraps the existing local dashboard with pywebview (WebView2 on Windows), so
the whole engine, store and web UI are reused — this module only puts a
window in front of them. If a Sentry server is already running it is reused;
otherwise one is started on a background thread and dies with the window.
"""
from __future__ import annotations

import socket
import threading
import time
import urllib.request

from . import config, store

WINDOW_TITLE = "Sentry"


def _is_sentry(url: str, timeout: float = 0.8) -> bool:
    """True when `url` is answering as a Sentry dashboard."""
    try:
        with urllib.request.urlopen(f"{url}/api/state", timeout=timeout) as r:
            return b"quarantine_dir" in r.read(4096)
    except Exception:  # noqa: BLE001
        return False


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _ensure_server() -> str:
    """Return the base URL of a running Sentry server, starting one if needed."""
    from . import webui

    cfg = config.load_config()
    port = int(cfg.get("web_port", 8787))
    url = f"http://127.0.0.1:{port}"
    if _is_sentry(url):
        return url  # reuse the dashboard the user already has running

    # The configured port may be taken by something that is not Sentry.
    with socket.socket() as probe:
        if probe.connect_ex(("127.0.0.1", port)) == 0:
            port = _free_port()
            url = f"http://127.0.0.1:{port}"

    t = threading.Thread(
        target=lambda: webui.app.run(host="127.0.0.1", port=port,
                                     debug=False, threaded=True),
        daemon=True)  # daemon: closing the window must end the process
    t.start()
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if _is_sentry(url, timeout=0.3):
            return url
        time.sleep(0.1)
    raise RuntimeError(f"The Sentry server did not come up on {url}.")


def _icon_path() -> str | None:
    import os
    p = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                     "assets", "sentry.ico")
    return p if os.path.exists(p) else None


def _brand_window(window) -> None:
    """Best-effort: give the native window/taskbar entry the Sentry icon.

    pywebview's Windows backend is WinForms via pythonnet, so window.native is
    a Form once shown. Anything failing here (other backend, no pythonnet,
    missing icon) just leaves the default icon.
    """
    try:
        import ctypes
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(
            "Sentry.Scanner")
    except Exception:  # noqa: BLE001
        pass
    icon = _icon_path()
    if not icon:
        return
    try:
        import System.Drawing  # type: ignore[import-not-found]  # pythonnet
        window.native.Icon = System.Drawing.Icon(icon)
    except Exception:  # noqa: BLE001
        pass


def main(page: str = "review") -> int:
    store.init_db()
    config.ensure_dirs()
    url = f"{_ensure_server()}/{page.lstrip('/')}"

    try:
        import webview
    except ImportError:
        # No pywebview: fall back to the browser rather than failing.
        print("  pywebview is not installed (pip install pywebview) — "
              "opening the browser instead.")
        import webbrowser
        webbrowser.open(url)
        # Keep the process alive so the just-started server survives.
        try:
            while True:
                time.sleep(3600)
        except KeyboardInterrupt:
            return 0

    window = webview.create_window(
        WINDOW_TITLE, url,
        width=880, height=760, min_size=(680, 560),
        background_color="#0f1115")
    webview.start(_brand_window, window)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
