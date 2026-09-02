"""Launch the Sentry desktop app from anywhere.

The Start-menu shortcut and the sentry-app: protocol handler both point at
this file via pythonw.exe. Neither sets a working directory, so the project
root is put on sys.path here instead of relying on cwd.

If the app is already open, a second launch just brings up another window on
the same server (the server is probed and reused, never duplicated).
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sentry.app import main  # noqa: E402

raise SystemExit(main())
