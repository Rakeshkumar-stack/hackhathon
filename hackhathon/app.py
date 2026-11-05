from flask import Flask, render_template, request, jsonify
import requests
import os
import base64

from scanner import scan_file
from url_scanner import scan_url


app = Flask(__name__)

app.config["MAX_CONTENT_LENGTH"] = 20 * 1024 * 1024

VT_API_KEY = os.environ.get("VT_API_KEY")

VT_BASE_URL = "https://www.virustotal.com/api/v3"


def virustotal_request(endpoint):

    if not VT_API_KEY:
        return None

    headers = {
        "x-apikey": VT_API_KEY
    }

    try:

        response = requests.get(
            VT_BASE_URL + endpoint,
            headers=headers,
            timeout=15
        )

        if response.status_code == 200:
            return response.json()

        return {
            "error": f"VirusTotal returned HTTP {response.status_code}"
        }

    except requests.RequestException:

        return {
            "error": "VirusTotal connection failed."
        }


def check_file_reputation(sha256):

    result = virustotal_request("/files/" + sha256)

    if not result or "error" in result:
        return result

    stats = result.get("data", {}).get(
        "attributes", {}
    ).get("last_analysis_stats", {})

    return {
        "source": "VirusTotal",
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0)
    }


def check_url_reputation(url):

    # VirusTotal identifies a URL using URL-safe Base64.
    url_id = base64.urlsafe_b64encode(
        url.encode()
    ).decode().rstrip("=")

    result = virustotal_request("/urls/" + url_id)

    if not result or "error" in result:
        return result

    stats = result.get("data", {}).get(
        "attributes", {}
    ).get("last_analysis_stats", {})

    return {
        "source": "VirusTotal",
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0)
    }


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/api/scan-file", methods=["POST"])
def file_scan():

    if "file" not in request.files:
        return jsonify({"error": "Please select a file."}), 400

    uploaded_file = request.files["file"]

    if not uploaded_file.filename:
        return jsonify({"error": "No file selected."}), 400

    file_data = uploaded_file.read()

    if not file_data:
        return jsonify({"error": "The file is empty."}), 400

    # Run our detection algorithm
    result = scan_file(
        file_data,
        uploaded_file.filename
    )

    # Check VirusTotal using the hash
    vt_result = check_file_reputation(
        result["sha256"]
    )

    result["virustotal"] = vt_result

    # Add VirusTotal information to the risk score
    if vt_result and "malicious" in vt_result:

        malicious = vt_result["malicious"]
        suspicious = vt_result["suspicious"]

        if malicious > 0:

            result["findings"].append({
                "severity": "high",
                "title": "VirusTotal detections",
                "description": f"{malicious} security engine(s) detected this file as malicious."
            })

        if suspicious > 0:

            result["findings"].append({
                "severity": "medium",
                "title": "VirusTotal suspicious detections",
                "description": f"{suspicious} security engine(s) flagged this file."
            })

        result["risk_score"] = max(
            result["risk_score"],
            min(100, malicious * 15 + suspicious * 10)
        )

        if result["risk_score"] >= 60:
            result["status"] = "High Risk"

        elif result["risk_score"] >= 25:
            result["status"] = "Suspicious"

        else:
            result["status"] = "Low Risk"

    return jsonify(result)


@app.route("/api/scan-url", methods=["POST"])
def url_scan():

    data = request.get_json(silent=True) or {}

    url = data.get("url", "")

    result = scan_url(url)

    if result["status"] == "Invalid URL":
        return jsonify(result), 400

    # Check URL reputation using VirusTotal
    vt_result = check_url_reputation(
        result["url"]
    )

    result["virustotal"] = vt_result

    if vt_result and "malicious" in vt_result:

        malicious = vt_result["malicious"]
        suspicious = vt_result["suspicious"]

        if malicious > 0:

            result["findings"].append({
                "severity": "high",
                "title": "VirusTotal detections",
                "description": f"{malicious} security engine(s) detected this URL as malicious."
            })

        if suspicious > 0:

            result["findings"].append({
                "severity": "medium",
                "title": "VirusTotal suspicious detections",
                "description": f"{suspicious} security engine(s) flagged this URL."
            })

        result["risk_score"] = max(
            result["risk_score"],
            min(100, malicious * 15 + suspicious * 10)
        )

        if result["risk_score"] >= 60:
            result["status"] = "High Risk"

        elif result["risk_score"] >= 25:
            result["status"] = "Suspicious"

        else:
            result["status"] = "Low Risk"

    return jsonify(result)


@app.errorhandler(413)
def file_too_large(error):
    return jsonify({
        "error": "File is too large. Maximum size is 20 MB."
    }), 413


if __name__ == "__main__":
    app.run(debug=True)