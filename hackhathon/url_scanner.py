from urllib.parse import urlparse
import ipaddress
import re


SHORTENERS = [
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "is.gd",
    "cutt.ly",
    "rb.gy"
]


SUSPICIOUS_WORDS = [
    "login",
    "verify",
    "password",
    "account",
    "banking",
    "secure",
    "update",
    "payment"
]


def scan_url(url):

    findings = []

    original_url = url.strip()

    if not original_url:
        return {
            "url": original_url,
            "risk_score": 0,
            "status": "Invalid URL",
            "findings": [{
                "severity": "high",
                "title": "Empty URL",
                "description": "Please enter a URL."
            }]
        }

    if len(original_url) > 2048:
        return {
            "url": original_url[:100],
            "risk_score": 0,
            "status": "Invalid URL",
            "findings": [{
                "severity": "high",
                "title": "URL too long",
                "description": "The submitted URL exceeds the allowed length."
            }]
        }

    # Add HTTPS if the user doesn't provide a scheme
    if "://" not in original_url:
        original_url = "https://" + original_url

    parsed = urlparse(original_url)

    # Validate scheme
    if parsed.scheme not in ["http", "https"] or not parsed.hostname:

        return {
            "url": original_url,
            "risk_score": 0,
            "status": "Invalid URL",
            "findings": [{
                "severity": "high",
                "title": "Invalid URL format",
                "description": "Enter a valid HTTP or HTTPS URL."
            }]
        }

    hostname = parsed.hostname.lower()

    # 1. Check HTTPS
    if parsed.scheme != "https":

        findings.append({
            "severity": "medium",
            "title": "Unencrypted connection",
            "description": "This URL uses HTTP instead of HTTPS."
        })

    # 2. Check raw IP address
    try:
        ipaddress.ip_address(hostname)

        findings.append({
            "severity": "high",
            "title": "IP address used",
            "description": "The URL uses an IP address instead of a domain name."
        })

    except ValueError:
        pass

    # 3. Check URL shorteners
    if hostname in SHORTENERS:

        findings.append({
            "severity": "medium",
            "title": "URL shortener detected",
            "description": "Shortened URLs hide their final destination."
        })

    # 4. Check punycode
    if "xn--" in hostname:

        findings.append({
            "severity": "high",
            "title": "Punycode domain",
            "description": "The domain uses an internationalized encoding that can conceal lookalike characters."
        })

    # 5. Check suspicious words
    for word in SUSPICIOUS_WORDS:

        if word in original_url.lower():

            findings.append({
                "severity": "low",
                "title": "Suspicious keyword",
                "description": f"The URL contains the keyword: {word}"
            })

            break

    # 6. Check @ symbol
    if "@" in parsed.netloc:

        findings.append({
            "severity": "high",
            "title": "Misleading URL structure",
            "description": "The URL contains an @ symbol in its authority section."
        })

    # 7. Check excessive subdomains
    if len(hostname.split(".")) > 4:

        findings.append({
            "severity": "medium",
            "title": "Unusual domain structure",
            "description": "The domain contains many subdomain levels."
        })

    # 8. Check suspicious file extensions in URL path
    if re.search(r"\.(exe|scr|bat|cmd|msi)(?:$|\?)", parsed.path, re.I):

        findings.append({
            "severity": "medium",
            "title": "Executable download path",
            "description": "The URL path appears to reference an executable file."
        })

    # Calculate risk
    score = 0

    for finding in findings:

        if finding["severity"] == "high":
            score += 30

        elif finding["severity"] == "medium":
            score += 15

        else:
            score += 5

    score = min(score, 100)

    if score >= 60:
        status = "High Risk"

    elif score >= 25:
        status = "Suspicious"

    else:
        status = "Low Risk"

    return {
        "url": original_url,
        "domain": hostname,
        "risk_score": score,
        "status": status,
        "findings": findings
    }