"""
reset_state.py — CyberPulse State Reset Utility
Clears all JSON state files and resets vulnapp_patched/ for a fresh run.
"""
import shutil
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
STATE_DIR = PROJECT_ROOT / "state"
PATCHED_DIR = PROJECT_ROOT / "vulnapp_patched"

def reset():
    # Clear state files
    if STATE_DIR.exists():
        for f in STATE_DIR.glob("*.json"):
            f.unlink()
            print(f"Deleted: {f}")
        for f in STATE_DIR.glob("*.md"):
            f.unlink()
            print(f"Deleted: {f}")
    else:
        STATE_DIR.mkdir(parents=True)
        print(f"Created: {STATE_DIR}")

    # Remove patched dir
    if PATCHED_DIR.exists():
        shutil.rmtree(PATCHED_DIR)
        print(f"Removed: {PATCHED_DIR}")

    print("\n✓ State reset complete. Ready for fresh run.")

if __name__ == "__main__":
    reset()
