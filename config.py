"""
Configuration file for the Phishing Email Analyzer.
Store sensitive information like API keys here.
"""

# --- API Configuration ---
VT_API_KEY = "Virus_total_API_Key"  # Replace with your VT API key
OTX_API_KEY = "Alien_Valut_OTX_API_Key"  # Replace with your OTX API key

# --- Threat Intel Endpoints ---
VT_BASE_URL = "https://www.virustotal.com/api/v3"
OTX_BASE_URL = "https://otx.alienvault.com/api/v1"

# --- File Paths ---
SAMPLE_EMAILS_DIR = "sample_emails"
REPORTS_OUTPUT_DIR = "reports"

# --- IOC Patterns (Regex) ---
import re
URL_PATTERN = re.compile(r'https?://[^\s\'\"<>]+', re.IGNORECASE)
DOMAIN_PATTERN = re.compile(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b')
IPV4_PATTERN = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
# Attachment pattern in email headers/structure
ATTACHMENT_PATTERN = re.compile(r'Content-Disposition:.*attachment|filename=', re.IGNORECASE)

# --- Report Formatting ---
RISK_SCORE_THRESHOLD_HIGH = 70
RISK_SCORE_THRESHOLD_MEDIUM = 30
