# Automated Phishing Email Analyzer

A Python tool that parses EML files, extracts Indicators of Compromise (IOCs), cross-references them with threat intelligence feeds, and generates a risk assessment report.

## Features

- Parses raw EML email files.
- Extracts URLs, domains, IPv4 addresses, and attachment names.
- Checks IOCs against VirusTotal and AlienVault OTX.
- Generates a detailed JSON report with risk scores.
- Calculates an overall risk level (Low/Medium/High).

## Prerequisites

- Python 3.x
- API keys for:
  - [VirusTotal](https://www.virustotal.com/gui/join-us) (Free tier available)
  - [AlienVault OTX](https://otx.alienvault.com/) (Free tier available)

## Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/YOUR_USERNAME/automated-phishing-analyzer.git
   cd automated-phishing-analyzer
