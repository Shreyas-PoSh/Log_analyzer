import os
import sys
import json
import hashlib
import requests
from email import message_from_string
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from urllib.parse import urlparse
import config  #This imports the config.py file


def extract_iocs(email_content):          #Extracts IPs, Domains, URLs, and attachment info from raw email string.
    iocs = {
        'urls': list(set(config.URL_PATTERN.findall(email_content))),
        'domains': [],
        'ips': list(set(config.IPV4_PATTERN.findall(email_content))),
        'attachments': []  # Placeholder; logic below handles attachments better
    }

    for url in iocs['urls']:    # Extract domains from URLs
        try:
            parsed_url = urlparse(url)
            domain = parsed_url.netloc.split(':')[0]  # Remove port if present
            if domain and '.' in domain:
                iocs['domains'].append(domain)
        except Exception as e:
            print(f"Error parsing URL {url}: {e}")

    all_domains = set(config.DOMAIN_PATTERN.findall(email_content))    #Extract domains from the main body text (not just URLs)
    for domain in all_domains:   #Filter out IPs and already found domains from URLs
        if not config.IPV4_PATTERN.match(domain) and domain not in iocs['domains']:
            iocs['domains'].append(domain)

    if config.ATTACHMENT_PATTERN.search(email_content):               #Attempt to find attachments via Content-Disposition
        iocs['attachments'] = ["Potential attachment detected in headers/body"]

    msg = message_from_string(email_content)  #More robust attachment extraction using email library
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_disposition() == 'attachment':
                filename = part.get_filename()
                if filename:
                    iocs['attachments'].append(filename)

    return iocs


def check_vt(url_or_hash):  #Checks fir the objects against the VT and assign the score based on VT 
    if len(url_or_hash) == 64:  #Assume it's a SHA256 hash
        endpoint = f"{config.VT_BASE_URL}/analyses/{url_or_hash}"
    else:  #Assume it's a URL or domain
        submit_url = f"{config.VT_BASE_URL}/urls"         #For URL scan, we need to submit it first
        headers = {"x-apikey": config.VT_API_KEY}
        data = {"url": url_or_hash}
        try:
            res = requests.post(submit_url, data=data, headers=headers)
            if res.status_code == 200:
                analysis_id = res.json().get('data', {}).get('id')
                endpoint = f"{config.VT_BASE_URL}/analyses/{analysis_id}"
            else:
                print(f"VT URL submission failed: {res.status_code}")
                return 0
        except Exception as e:
            print(f"Error submitting URL to VT: {e}")
            return 0

    headers = {"x-apikey": config.VT_API_KEY}
    try:
        res = requests.get(endpoint, headers=headers)
        if res.status_code == 200:
            data = res.json().get('data', {})
            attributes = data.get('attributes', {})
            stats = attributes.get('stats', {}) #For URL/Domain reports
            malicious_count = stats.get('malicious', 0)
            total_count = sum(stats.values())

            if 'last_analysis_stats' in attributes:             #For File (hash) reports
                stats = attributes['last_analysis_stats']
                malicious_count = stats.get('malicious', 0)
                total_count = sum(stats.values())

            if total_count > 0:
                return int((malicious_count / total_count) * 100)
    except Exception as e:
        print(f"Error checking VT for {url_or_hash}: {e}")

    return 0 #Default score if check fails


def check_otx(ioc):   #Checks for the IOC details on AlienVault OTX
    if '.' in ioc and ':' not in ioc and not ioc.startswith(('http://', 'https://')): 
        endpoint = f"{config.OTX_BASE_URL}/indicators/domain/{ioc}/general"
    elif ioc.count('.') == 3 and all(part.isdigit() for part in ioc.split('.')):
        endpoint = f"{config.OTX_BASE_URL}/indicators/IPv4/{ioc}/general"
    elif ioc.startswith(('http://', 'https://')):
        parsed = urlparse(ioc)
        host = parsed.netloc.split(':')[0]
        endpoint = f"{config.OTX_BASE_URL}/indicators/domain/{host}/general"
    else:
        print(f"Unsupported IOC type for OTX: {ioc}")
        return 0

    params = {'api_key': config.OTX_API_KEY}
    try:
        res = requests.get(endpoint, params=params)
        if res.status_code == 200:
            data = res.json()
            pulse_count = len(data.get('pulse_info', {}).get('pulses', []))
            return pulse_count
    except Exception as e:
        print(f"Error checking OTX for {ioc}: {e}")

    return 0


def generate_report(iocs, vt_results, otx_results, original_email_path):
    """
    Generates a JSON report based on collected IOCs and API results.
    """
    total_score = 0
    report_details = {}

    for category, items in iocs.items():
        category_score = 0
        category_details = {}
        for item in items:
            vt_score = vt_results.get(item, 0)
            otx_score = otx_results.get(item, 0)
            combined_score = max(vt_score, otx_score) #Take the highest score as a conservative measure

            category_score += combined_score
            category_details[item] = {
                "virustotal_score": vt_score,
                "otx_pulse_count": otx_score,
                "combined_risk_score": combined_score
            }

        total_score += category_score
        report_details[category] = {
            "items_found": items,
            "details": category_details,
            "category_risk_score": category_score
        }

    # Determine overall risk level
    if total_score >= config.RISK_SCORE_THRESHOLD_HIGH:
        risk_level = "High"
    elif total_score >= config.RISK_SCORE_THRESHOLD_MEDIUM:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    report = {
        "original_email_file": original_email_path,
        "summary": {
            "total_risk_score": total_score,
            "risk_level": risk_level,
            "total_iocs_found": sum(len(items) for items in iocs.values())
        },
        "details": report_details
    }

    return report


def main():
    if len(sys.argv) != 2:
        print("Usage: python analyzer.py <path_to_email.eml>")
        sys.exit(1)

    email_path = sys.argv[1]
    if not os.path.exists(email_path):
        print(f"Error: Email file '{email_path}' not found.")
        sys.exit(1)

    try: #Read the EML file
        with open(email_path, 'r', encoding='utf-8', errors='ignore') as f:
            email_content = f.read()
    except Exception as e:
        print(f"Error reading email file: {e}")
        sys.exit(1)

    print("Extracting IOCs...")
    iocs = extract_iocs(email_content)
    print(f"Found {sum(len(v) for v in iocs.values())} IOCs.")

    print("Checking IOCs against threat intelligence...")     #Check IOCs against threat intel
    vt_results = {}
    otx_results = {}

    all_iocs_flat = []
    for category, items in iocs.items():
        all_iocs_flat.extend(items)

    for ioc in all_iocs_flat:
        print(f"  Checking: {ioc}")
        # Skip empty strings
        if not ioc.strip(): continue

        # Check VirusTotal
        vt_score = check_vt(ioc)
        vt_results[ioc] = vt_score

        # Check OTX
        otx_score = check_otx(ioc)
        otx_results[ioc] = otx_score

    print("\nGenerating report...")
    report = generate_report(iocs, vt_results, otx_results, email_path)

    os.makedirs(config.REPORTS_OUTPUT_DIR, exist_ok=True)
    report_filename = os.path.join(
        config.REPORTS_OUTPUT_DIR,
        f"report_{os.path.basename(email_path)}.json"
    )
    with open(report_filename, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=4)

    print(f"\nReport saved to: {report_filename}")
    print(json.dumps(report["summary"], indent=2))


if __name__ == "__main__":
    main()
