"""Unified linting and code quality validation script."""

import subprocess
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent


def run_command(cmd: list[str], cwd: Path | None = None, desc: str = "") -> bool:
    print(f"\n---> Running: {desc} ({' '.join(cmd)})")
    res = subprocess.run(cmd, cwd=cwd or ROOT_DIR, shell=True)
    if res.returncode != 0:
        print(f"[!] FAILED: {desc}")
        return False
    print(f"[OK] PASSED: {desc}")
    return True


def main() -> None:
    print("=" * 60)
    print("Multi-Agent Cyber AI - Full Monorepo Quality Check")
    print("=" * 60)

    # Detect python executable in venv
    venv_ruff = ROOT_DIR / ".venv" / "Scripts" / "ruff.exe"
    if not venv_ruff.exists():
        venv_ruff = ROOT_DIR / ".venv" / "bin" / "ruff"

    venv_mypy = ROOT_DIR / ".venv" / "Scripts" / "mypy.exe"
    if not venv_mypy.exists():
        venv_mypy = ROOT_DIR / ".venv" / "bin" / "mypy"

    success = True

    # 1. Python Ruff Check
    if venv_ruff.exists():
        success &= run_command([str(venv_ruff), "check", "backend", "tests"], desc="Python Ruff Linting")
        success &= run_command([str(venv_ruff), "format", "--check", "backend", "tests"], desc="Python Ruff Formatting")
    else:
        print("[!] Ruff not found in virtual environment.")
        success = False

    # 2. Python Mypy
    if venv_mypy.exists():
        success &= run_command([str(venv_mypy), "backend", "tests"], desc="Python Mypy Type Checking")
    else:
        print("[!] Mypy not found in virtual environment.")
        success = False

    # 3. Frontend Type Check & Lint
    frontend_dir = ROOT_DIR / "frontend"
    if frontend_dir.exists():
        success &= run_command(["npm", "run", "type-check"], cwd=frontend_dir, desc="Frontend TypeScript Check")
        success &= run_command(["npm", "run", "lint"], cwd=frontend_dir, desc="Frontend ESLint")

    if success:
        print("\n[OK] ALL QUALITY CHECKS PASSED.")
        sys.exit(0)
    else:
        print("\n[!] SOME CHECKS FAILED.")
        sys.exit(1)


if __name__ == "__main__":
    main()
