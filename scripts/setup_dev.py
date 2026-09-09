"""Development environment initialization script."""

import shutil
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent


def setup_env_file() -> None:
    """Create .env file from .env.example if missing."""
    env_file = ROOT_DIR / ".env"
    example_file = ROOT_DIR / ".env.example"

    if not env_file.exists() and example_file.exists():
        print("[+] Creating .env from .env.example...")
        shutil.copy(example_file, env_file)
    else:
        print("[*] .env file already exists.")


def create_required_directories() -> None:
    """Ensure data and logging directories exist."""
    dirs = [
        ROOT_DIR / "data" / "raw",
        ROOT_DIR / "data" / "processed",
        ROOT_DIR / "data" / "indexes",
        ROOT_DIR / "datasets" / "samples",
        ROOT_DIR / "reports" / "generated",
        ROOT_DIR / "logs",
    ]
    for d in dirs:
        d.mkdir(parents=True, exist_ok=True)
    print("[+] Verified all data directories.")


def main() -> None:
    print("=" * 60)
    print("Multi-Agent Cyber AI - Environment Setup")
    print("=" * 60)
    setup_env_file()
    create_required_directories()
    print("\n[OK] Environment setup completed successfully.")


if __name__ == "__main__":
    main()
