# PhishLens 🔎🛡️

### Explainable Phishing URL & Email Analyzer
**Day 04 · 100 Days • 100 Cybersecurity Projects**

PhishLens is an offline-first Python command-line tool that analyzes URL structure and email text for common phishing indicators. It returns a bounded risk score, a risk band, and human-readable explanations for triggered rules.

> **Important:** PhishLens is a heuristic triage aid, not a verdict engine. A low score does not prove content is safe, and a high score does not prove malicious intent.

## Table of contents
- [Why PhishLens?](#why-phishlens)
- [Features](#features)
- [How it works](#how-it-works)
- [Requirements](#requirements)
- [Installation](#installation)
- [Run tests](#run-tests)
- [Usage](#usage)
- [Project structure](#project-structure)
- [Security and privacy](#security-and-privacy)
- [Limitations](#limitations)
- [Roadmap](#roadmap)

## Why PhishLens?

Phishing messages can combine urgency, requests for credentials, and links that encourage immediate action. PhishLens surfaces these indicators so a learner or analyst can review the evidence instead of relying on an unexplained safe/malicious label.

## Features

### URL analysis
- IP-address hosts
- The @ character, which can create URL user-info confusion
- Punycode labels that may warrant inspection
- Excessive subdomains
- Common URL-shortening services
- Account, credential, or payment-related path/query keywords
- Non-standard ports
- Plain HTTP rather than HTTPS

### Email-text analysis
- Urgency and pressure language
- References to passwords and sensitive information
- Prompts to follow a link, button, or attachment
- Generic greetings

### Practical design
- Explainable findings with rule codes and point contributions
- Capped score from 0–100 and low, moderate, or high risk bands
- JSON output and optional report-file export
- Python standard library only; no API keys or third-party packages
- Unit tests for benign, suspicious, and invalid inputs

## How it works

1. Provide a URL or a local UTF-8 text file containing an email.
2. PhishLens applies transparent, locally executed heuristic rules.
3. Each triggered rule contributes points to a capped score.
4. The CLI prints structured JSON with findings and a disclaimer.
5. Review the evidence and make the final decision.

Risk bands: **low** = 0–19 · **moderate** = 20–44 · **high** = 45–100.

The score is a rule-based indicator score, not a probability that content is malicious.

## Requirements

- Python 3.10 or newer
- Git to clone the repository
- No third-party Python packages required

## Installation

Clone the repository and enter the project directory:

    git clone https://github.com/devanshshukla-3004/PhishLens-Explainable-Phishing-URL-Email-Analyzer.git
    cd PhishLens-Explainable-Phishing-URL-Email-Analyzer

## Run tests

Run from the repository root:

    python -m unittest discover -s tests -v

**Local verification:** all 8 unit tests passed during the Day 04 verification run.

## Usage

### 1. Analyze a URL

    python -m phishlens.cli url "https://example.com/account/login"

The output includes the input, normalized URL, hostname, score, risk level, findings, and a disclaimer. A legitimate URL may trigger a weak heuristic such as an account-related keyword; review findings in context.

### 2. Save URL analysis as JSON

    python -m phishlens.cli url "http://192.0.2.10/verify" --json .\reports\url-analysis.json

The example IP is from a documentation-only range. PhishLens does not visit the URL.

### 3. Analyze the included sample email

    python -m phishlens.cli email .\samples\suspicious-email.txt

### 4. Save email analysis as JSON

    python -m phishlens.cli email .\samples\suspicious-email.txt --json .\reports\email-analysis.json

Reports are generated locally. Avoid committing real messages or sensitive analysis data.

## Understanding results

Each finding provides a rule code, explanation, and point contribution. Email findings may also include the matched text that triggered a rule. Several weak signals together may justify a closer look, but none is independently conclusive.

## Project structure

    PhishLens-Explainable-Phishing-URL-Email-Analyzer/
    ├── phishlens/
    │   ├── __init__.py
    │   ├── analyzer.py       # URL and email heuristic analysis
    │   └── cli.py            # Command-line interface
    ├── samples/
    │   └── suspicious-email.txt
    ├── tests/
    │   └── test_analyzer.py
    ├── reports/
    │   └── .gitkeep
    ├── .gitignore
    └── README.md

## Security and privacy

- URL analysis is structural only: the program does not open URLs, resolve DNS, follow redirects, download web content, or contact threat-intelligence services.
- Email analysis reads the local text file supplied; this tool does not send it to an external service.
- Use synthetic or authorized sample data.
- Do not click suspicious links just to investigate them. Follow your organization's incident-response process for real incidents.

## Limitations

- No domain-reputation or threat-intelligence lookups.
- No DNS, TLS certificate, redirect-chain, webpage HTML, attachment, or malware analysis.
- No machine-learning classifier.
- Rules can produce false positives and false negatives, and attackers can evade simple indicators.
- Punycode, HTTP, shorteners, and keywords are signals to review—not proof of phishing.
- Results should not replace analyst judgment.

## Roadmap

- Expand tests with more benign and suspicious edge cases.
- Refine keyword weighting to reduce false positives.
- Add configurable rules and thresholds.
- Consider optional reputation integrations in a future version.
- Consider a local web interface after the CLI detection logic is further validated.

## Project information

- **Project:** PhishLens — Explainable Phishing URL & Email Analyzer
- **Challenge:** Day 04 of 100 Days • 100 Cybersecurity Projects
- **Language:** Python
- **Category:** Defensive security · Phishing analysis · Security awareness

Built for cybersecurity learning and defensive triage. Contributions and constructive feedback are welcome.