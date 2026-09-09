"""Unified test runner script for backend and frontend test suites."""

import subprocess
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent


def main() -> None:
    print("=" * 60)
    print("Multi-Agent Cyber AI - Test Suite Runner")
    print("=" * 60)

    venv_pytest = ROOT_DIR / ".venv" / "Scripts" / "pytest.exe"
    if not venv_pytest.exists():
        venv_pytest = ROOT_DIR / ".venv" / "bin" / "pytest"

    if not venv_pytest.exists():
        print("[!] Pytest not found in virtual environment.")
        sys.exit(1)

    print("\n---> Running Pytest Suite:")
    res = subprocess.run([str(venv_pytest), "tests", "-v", "--cov=backend/app"], cwd=ROOT_DIR)
    if res.returncode != 0:
        print("[!] Backend tests failed.")
        sys.exit(res.returncode)

    print("\n[OK] ALL TESTS PASSED.")


if __name__ == "__main__":
    main()
