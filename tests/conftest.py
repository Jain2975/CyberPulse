"""
conftest.py — pytest configuration for CyberPulse test suite.
Ensures the project root is on sys.path so agent imports resolve correctly.
"""

import sys
from pathlib import Path

# Add the project root (D:\CyberPulse) to sys.path
sys.path.insert(0, str(Path(__file__).parent.parent))
