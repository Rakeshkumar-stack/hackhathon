import hashlib
import os
import re
import zipfile
import io


# File extensions and their expected signatures
FILE_SIGNATURES = {
    ".pdf": [b"%PDF"],
    ".png": [b"\x89PNG\r\n\x1a\n"],
    ".jpg": [b"\xff\xd8\xff"],
    ".jpeg": [b"\xff\xd8\xff"],
    ".gif": [b"GIF87a", b"GIF89a"],
    ".exe": [b"MZ"],
    ".dll": [b"MZ"],
    ".zip": [b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"]
}


def calculate_hash(file_data):
    return hashlib.sha256(file_data).hexdigest()


def add_finding(findings, severity, title, description):
    findings.append({
        "severity": severity,
        "title": title,
        "description": description
    })


def scan_file(file_data, filename):

    findings = []

    extension = os.path.splitext(filename)[1].lower()

    sha256 = calculate_hash(file_data)

    # 1. Check file size
    if len(file_data) == 0:
        add_finding(
            findings,
            "high",
            "Empty file",
            "The uploaded file contains no data."
        )

    # 2. Check file signature
    expected_signatures = FILE_SIGNATURES.get(extension)

    if expected_signatures:
        signature_matches = any(
            file_data.startswith(signature)
            for signature in expected_signatures
        )

        if not signature_matches:
            add_finding(
                findings,
                "high",
                "File signature mismatch",
                "The file extension does not match its expected file signature."
            )

    # 3. Look for suspicious strings
    suspicious_patterns = {
        "powershell -enc": "Encoded PowerShell command indicator",
        "cmd.exe": "Windows command interpreter reference",
        "wscript.shell": "Windows scripting interface reference",
        "createobject": "Object creation command indicator",
        "virtualalloc": "Memory allocation API reference",
        "writeprocessmemory": "Process memory writing API reference",
        "winexec": "Windows execution API reference",
        "eval(": "Dynamic code evaluation indicator",
        "base64_decode": "Base64 decoding function reference"
    }

    sample = file_data[:5 * 1024 * 1024].lower()

    for pattern, description in suspicious_patterns.items():

        if pattern.encode() in sample:

            add_finding(
                findings,
                "medium",
                "Suspicious content indicator",
                description
            )

    # 4. Extract embedded URLs
    urls = re.findall(
        rb'https?://[^\s<>"\']+',
        sample,
        re.IGNORECASE
    )

    if urls:
        add_finding(
            findings,
            "low",
            "Embedded URLs detected",
            f"The file contains {len(urls)} URL reference(s)."
        )

    # 5. Check ZIP and Office archive contents
    if extension in [".zip", ".docx", ".xlsx", ".pptx"]:

        try:
            with zipfile.ZipFile(io.BytesIO(file_data)) as archive:

                entries = archive.infolist()

                if len(entries) > 1000:
                    add_finding(
                        findings,
                        "medium",
                        "Large archive",
                        "The archive contains an unusually large number of entries."
                    )

                for entry in entries:

                    name = entry.filename.replace("\\", "/")

                    if ".." in name.split("/"):

                        add_finding(
                            findings,
                            "high",
                            "Suspicious archive path",
                            "An archive entry contains a path traversal pattern."
                        )

                    if name.lower().endswith("vbaproject.bin"):

                        add_finding(
                            findings,
                            "medium",
                            "Macro project detected",
                            "The Office archive contains a VBA project."
                        )

        except (zipfile.BadZipFile, OSError):
            add_finding(
                findings,
                "medium",
                "Archive inspection failed",
                "The file could not be inspected as a valid ZIP archive."
            )

    # 6. Calculate risk score
    score = 0

    for finding in findings:

        if finding["severity"] == "high":
            score += 30

        elif finding["severity"] == "medium":
            score += 15

        elif finding["severity"] == "low":
            score += 5

    score = min(score, 100)

    if score >= 60:
        status = "High Risk"

    elif score >= 25:
        status = "Suspicious"

    else:
        status = "Low Risk"

    return {
        "filename": filename,
        "sha256": sha256,
        "file_size": len(file_data),
        "risk_score": score,
        "status": status,
        "findings": findings
    }