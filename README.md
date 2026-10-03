# PhishLens 🔎🛡️

**Explainable, offline phishing URL and email indicator analyzer** — Day 04 of the *100 Days • 100 Cybersecurity Projects* challenge.

PhishLens applies transparent, rule-based heuristics to URL structure and email text. It returns a bounded risk score, risk band, and the exact indicators behind the result. It is designed for learning and defensive triage, not as a definitive phishing verdict.

## Features

- URL checks: IP-address hosts, `@` confusion, punycode labels, many subdomains, common URL shorteners, credential-related path/query keywords, non-standard ports, and HTTP.
- Email text checks: urgency language, sensitive-information requests, action-link prompts, and generic greetings.
- JSON output and optional JSON report files.
- Python standard library only; no API key or external service required.
- Does **not** visit URLs, resolve DNS, follow redirects, download content, or send submitted text anywhere.
- Unit tests for benign, suspicious, and invalid inputs.

## Requirements

- Python 3.10+
- No third-party packages

## Setup and test

Open a terminal in the repository root:

```powershell
python -m unittest discover -s tests -v
```

## Usage

Analyze a URL (the tool never opens it):

```powershell
python -m phishlens.cli url "https://example.com/account/login"
```

Save URL analysis to JSON:

```powershell
python -m phishlens.cli url "http://192.0.2.10/verify" --json .\reports\url-analysis.json
```

Analyze an email saved as UTF-8 text:

```powershell
python -m phishlens.cli email .\samples\suspicious-email.txt --json .\reports\email-analysis.json
```

## Scoring

Each matched rule contributes documented points. The total is capped at 100 and mapped to `low` (0–19), `moderate` (20–44), or `high` (45–100). This is a transparent heuristic score, **not** a calibrated probability that a URL or email is malicious.

## Limitations

- No threat-intelligence feed, reputation checks, DNS, TLS certificate inspection, redirect analysis, HTML parsing, attachment scanning, or machine learning.
- Rules can produce false positives and false negatives; attackers can evade keyword and structure-based checks.
- Punycode is flagged for review, not automatically treated as malicious.
- The score is not a probability or a substitute for analyst judgment.
- The URL-shortener list and keyword rules are small and intentionally transparent.

## Responsible use

Use this project for defensive education and authorized analysis. Do not click suspicious links to test them. For real incidents, preserve evidence and use an isolated, approved analysis environment. Avoid submitting confidential email content to tools or services without authorization.

## Project status

Starter implementation published for local verification. Record test and manual verification results before describing the project as fully tested or complete.
