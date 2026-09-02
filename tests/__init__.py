"""Unit test package for Sentry.

Run from the project root:

    python3 -m unittest discover -s tests -v
    python3 run_tests.py
"""
import os
import sys

# Make the project root importable regardless of how the tests are launched.
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
