# PhishLens Demo & Presentation Guide

Use this checklist to capture authentic screenshots and record a short project walkthrough for the Day 04 portfolio entry.

## Recommended screenshot set

Capture these from your own terminal after running the commands. Do not present mockups or generated artwork as real application screenshots.

1. **Test results:** Run `python -m unittest discover -s tests -v` and capture the terminal showing all 8 tests passing.
2. **URL analysis:** Run `python -m phishlens.cli url "https://example.com/account/login"` and capture the JSON output.
3. **Email analysis:** Run `python -m phishlens.cli email .\samples\suspicious-email.txt` and capture the findings and risk level.
4. **Repository overview:** Capture the GitHub repository page showing the README, source, tests, and sample file.

## 60–90 second demo script

**Opening (0–10 sec)**

“This is PhishLens, my Day 04 project for the 100 Days • 100 Cybersecurity Projects challenge. It is a Python CLI tool for explainable phishing URL and email-text triage.”

**Show the tests (10–25 sec)**

Run:

    python -m unittest discover -s tests -v

“The current test suite has eight tests covering benign inputs, suspicious indicators, and invalid input handling.”

**Show URL analysis (25–45 sec)**

Run:

    python -m phishlens.cli url "https://example.com/account/login"

“The tool returns structured JSON and explains which heuristic fired. This example receives a low score because an account-related keyword is present. That also demonstrates a limitation: legitimate URLs can trigger heuristics.”

**Show email analysis (45–65 sec)**

Run:

    python -m phishlens.cli email .\samples\suspicious-email.txt

“The sample email receives a high heuristic score because it contains urgency language, a password reference, and a prompt to follow a link. The output explains each finding.”

**Close (65–90 sec)**

“PhishLens runs locally and does not visit submitted URLs or send email text to an external service. Its score is not a probability or a definitive verdict; the findings support human review.”

## Presentation notes

- Use a readable terminal font and zoom so the output is legible in screenshots.
- Keep screenshots free of personal file paths, usernames, tokens, and unrelated windows where possible.
- Do not use real confidential email content. The included sample is intended for demonstration.
- Label screenshots accurately; do not claim a web dashboard exists because this version is a command-line tool.
- Do not describe heuristic results as confirmed phishing detections.

## Suggested LinkedIn project caption

**Day 04/100 — PhishLens | Explainable Phishing URL & Email Analyzer**

Built a lightweight Python CLI that applies transparent heuristics to URL structure and email text, returning risk bands and human-readable findings.

Highlights:
- URL and email-text analysis
- Explainable rule-based indicators
- JSON output and local report export
- Eight passing unit tests
- No third-party packages or external analysis service required

One important lesson: a heuristic flag is an indicator to investigate—not proof of maliciousness. Legitimate URLs can trigger weak rules, and suspicious content can evade simple checks.

Repository: https://github.com/devanshshukla-3004/PhishLens-Explainable-Phishing-URL-Email-Analyzer

#CyberSecurity #Python #BlueTeam #PhishingAwareness #100DaysOfCybersecurity