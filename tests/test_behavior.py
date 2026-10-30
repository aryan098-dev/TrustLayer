from trustlayer.behavior_analyzer import detect_environment_access
from trustlayer.behavior_analyzer import (
    detect_network_activity,
    normalize_script
)


def test_normalize_script():
    assert normalize_script("  print('hello')  ") == "print('hello')"


def test_detect_curl():
    script = "curl https://example.com"

    findings = detect_network_activity(script)

    assert any(
        item["category"] == "network_activity"
        for item in findings
    )


def test_detect_python_requests():
    script = "requests.get('https://example.com')"

    findings = detect_network_activity(script)

    assert any(
        "Python HTTP request" in item["description"]
        for item in findings
    )


def test_clean_script_has_no_network_findings():
    script = "print('Hello TrustLayer')"

    findings = detect_network_activity(script)

    assert findings == []


def test_detect_python_environment_access():
    script = "import os\nos.environ.get('API_KEY')"

    findings = detect_environment_access(script)

    assert any(
        item["category"] == "environment_access"
        for item in findings
    )


def test_detect_node_environment_access():
    script = "const token = process.env.API_KEY"

    findings = detect_environment_access(script)

    assert len(findings) == 1


def test_clean_script_has_no_environment_findings():
    script = "print('Hello TrustLayer')"

    findings = detect_environment_access(script)

    assert findings == []
