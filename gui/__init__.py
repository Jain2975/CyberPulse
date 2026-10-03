# gui/__init__.py
"""
CyberPulse web dashboard package.

A local-only Flask GUI that visualizes the same pipeline the CLI runs.
The CLI experience is unchanged — see gui/app.py.
"""

from gui.app import create_app

__all__ = ["create_app"]
