
import re


def normalize_script(script: str) -> str:
    """
    Normalize script text for static analysis.
    """
    return script.strip()


def detect_network_activity(script: str) -> list[dict]:
    """
    Detect potential network communication indicators.
    Does not execute the script.
    """

    findings = []

    patterns = [
        (r"\bcurl\b", "curl command detected"),
        (r"\bwget\b", "wget command detected"),
        (r"\brequests\.(get|post|put)\b",
         "Python HTTP request detected"),
        (r"\burllib\.request\b",
         "Python urllib network access detected"),
        (r"\bfetch\s*\(", "JavaScript fetch call detected"),
    ]

    for pattern, description in patterns:
        if re.search(pattern, script, re.IGNORECASE):
            findings.append({
                "category": "network_activity",
                "description": description,
                "severity": "medium"
            })

    return findings



def detect_environment_access(script: str) -> list[dict]:
    """
    Detect environment-variable access patterns
    without executing the script.
    """

    findings = []

    patterns = [
        (r"\bos\.environ\b", "Python environment access"),
        (r"\bos\.getenv\s*\(", "Python getenv access"),
        (r"\bprocess\.env\b", "Node.js environment access"),
    ]

    for pattern, description in patterns:
        if re.search(pattern, script, re.IGNORECASE):
            findings.append({
                "category": "environment_access",
                "description": description,
                "severity": "medium"
            })

    return findings



def detect_ssh_access(script: str) -> list[dict]:
    """
    Detect references to sensitive SSH files
    and directories through static analysis.
    """

    findings = []

    patterns = [
        (
            r"\.ssh[/\\]",
            "SSH directory reference detected"
        ),
        (
            r"\bid_rsa\b",
            "SSH private-key filename reference detected"
        ),
        (
            r"\bauthorized_keys\b",
            "SSH authorized_keys reference detected"
        ),
        (
            r"\bknown_hosts\b",
            "SSH known_hosts reference detected"
        ),
    ]

    for pattern, description in patterns:
        if re.search(pattern, script, re.IGNORECASE):
            findings.append({
                "category": "ssh_access",
                "description": description,
                "severity": "high"
            })

    return findings
