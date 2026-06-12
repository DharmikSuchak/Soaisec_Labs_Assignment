# cli.py
"""
SentraGuard Lite CLI — single command: analyze

Usage:
    python cli.py analyze --input sample_request.json --output out.json

Reads a JSON file, calls POST /analyze on the running API (localhost:8000),
and writes the JSON response to the output file.

Authentication: reads X-API-Key from CLI_API_KEY environment variable.
API base URL: reads from CLI_API_BASE_URL env var (default: http://localhost:8000).
"""

import argparse    # Built-in library to parse command-line arguments
import json        # Built-in library to read/write JSON files
import os          # To read environment variables (API key, base URL)
import sys         # To exit with error codes (sys.exit(1))

import requests    # To make HTTP POST calls to the API



# ─── Constants ────────────────────────────────────────────────────────────────
DEFAULT_BASE_URL = "http://localhost:8000"


def cmd_analyze(args: argparse.Namespace) -> None:
    """Read input JSON, POST to /analyze, write response JSON."""
    # ── Load input file ───────────────────────────────────────────────────────
    try:
        with open(args.input, "r", encoding="utf-8") as fh:
            payload = json.load(fh)
    except FileNotFoundError:
        print(f"[ERROR] Input file not found: {args.input}", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as exc:
        print(f"[ERROR] Invalid JSON in input file: {exc}", file=sys.stderr)
        sys.exit(1)

    # ── Read API key from environment ─────────────────────────────────────────
    api_key = os.environ.get("CLI_API_KEY", os.environ.get("API_KEY", "")).strip()
    if not api_key:
        print(
            "[ERROR] No API key found. Set CLI_API_KEY (or API_KEY) environment variable.",
            file=sys.stderr,
        )
        sys.exit(1)

    # ── Determine API base URL ────────────────────────────────────────────────
    base_url = os.environ.get("CLI_API_BASE_URL", DEFAULT_BASE_URL).rstrip("/")
    endpoint = f"{base_url}/analyze"

    # ── Call the API ──────────────────────────────────────────────────────────
    try:
        response = requests.post(
            endpoint,
            json=payload,
            headers={"X-API-Key": api_key, "Content-Type": "application/json"},
            timeout=30,
        )
    except requests.ConnectionError:
        print(
            f"[ERROR] Could not connect to API at {endpoint}. Is it running?",
            file=sys.stderr,
        )
        sys.exit(1)
    except requests.Timeout:
        print("[ERROR] Request timed out after 30 seconds.", file=sys.stderr)
        sys.exit(1)

    # ── Handle non-2xx ───────────────────────────────────────────────────────
    if not response.ok:
        print(
            f"[ERROR] API returned HTTP {response.status_code}: {response.text}",
            file=sys.stderr,
        )
        sys.exit(1)

    # ── Write output ──────────────────────────────────────────────────────────
    result = response.json()
    try:
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump(result, fh, indent=2)
    except OSError as exc:
        print(f"[ERROR] Could not write output file: {exc}", file=sys.stderr)
        sys.exit(1)

    print(f"[OK] Response written to {args.output}")
    print(f"     decision={result.get('decision')}  risk_score={result.get('risk_score')}")


# ─── Argument parser ──────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cli.py",
        description="SentraGuard Lite CLI — analyze a prompt via the guardrails API",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    analyze_parser = subparsers.add_parser(
        "analyze",
        help="Analyze a prompt JSON file and write the result",
    )
    analyze_parser.add_argument(
        "--input",
        required=True,
        metavar="FILE",
        help="Path to the input JSON file (e.g. sample_request.json)",
    )
    analyze_parser.add_argument(
        "--output",
        required=True,
        metavar="FILE",
        help="Path where the response JSON will be written (e.g. out.json)",
    )

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "analyze":
        cmd_analyze(args)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
