"""Command-line interface for secure-review."""

import argparse

from secure_review import __version__


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="secure-review",
        description="Run security scanners over a codebase.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.parse_args()
    print("secure-review: no scanners configured yet (install scanners separately)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
