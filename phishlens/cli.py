from __future__ import annotations

import argparse
import json
from pathlib import Path
from .analyzer import analyze_email, analyze_url


def main():
    parser = argparse.ArgumentParser(description="PhishLens — offline phishing indicator analyzer")
    sub = parser.add_subparsers(dest="command", required=True)
    url = sub.add_parser("url", help="Analyze a URL without opening it")
    url.add_argument("value", help="URL or hostname to analyze")
    email = sub.add_parser("email", help="Analyze email text from a file")
    email.add_argument("file", type=Path, help="UTF-8 text file containing email content")
    for item in (url, email):
        item.add_argument("--json", dest="json_path", type=Path, help="Optional path to save JSON output")
    args = parser.parse_args()
    try:
        result = analyze_url(args.value) if args.command == "url" else analyze_email(args.file.read_text(encoding="utf-8"))
    except (ValueError, OSError) as exc:
        parser.error(str(exc))
    rendered = json.dumps(result, indent=2, ensure_ascii=False)
    print(rendered)
    if args.json_path:
        args.json_path.parent.mkdir(parents=True, exist_ok=True)
        args.json_path.write_text(rendered + "\n", encoding="utf-8")
        print(f"\nJSON report saved: {args.json_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
