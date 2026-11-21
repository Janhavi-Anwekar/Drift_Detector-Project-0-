
"""
Drift Detector - Security Configuration Evaluator

Parses uploaded Ubuntu, SSH and NGINX configuration files.
This module is separate from core.py to preserve existing comparisons.
"""

import re
from pathlib import Path


class SecurityEvaluationError(ValueError):
    """Raised when uploaded security configuration cannot be parsed."""


def detect_platform(filename: str, content: str) -> str:
    """Identify the platform represented by an uploaded file."""

    name = Path(filename).name.lower()
    text = content.lower()

    # SSH configuration
    if (
        name in {"sshd_config", "ssh_config"}
        or "permitrootlogin" in text
        or "passwordauthentication" in text
        or "kexalgorithms" in text
    ):
        return "ssh"

    # NGINX configuration
    if (
        name.endswith(".conf") and (
            "server_tokens" in text
            or "fastcgi_hide_header" in text
            or "proxy_hide_header" in text
            or "nginx" in name
        )
    ):
        return "nginx"

    # Ubuntu sysctl configuration
    if (
        name == "sysctl.conf"
        or name.endswith(".sysctl")
        or "net.ipv4." in text
        or "net.ipv6." in text
        or "kernel.randomize_va_space" in text
    ):
        return "ubuntu_22_04"

    # CPU information
    if name == "cpuinfo":
        return "ubuntu_22_04"

    return "unknown"


def parse_sysctl(text: str) -> dict:
    """Parse sysctl configuration key-value pairs."""

    settings = {}

    for raw_line in text.splitlines():
        line = raw_line.strip()

        if not line or line.startswith("#"):
            continue

        line = line.split("#", 1)[0].strip()

        if "=" not in line:
            continue

        key, value = line.split("=", 1)

        key = key.strip()
        value = value.strip()

        if key:
            settings[key] = value

    return settings


def parse_ssh_security(text: str) -> dict:
    """
    Parse SSH directives while preserving their original names.

    Only global directives before the first Match block are used.
    First occurrence is retained for ordinary SSH directives.
    """

    settings = {}
    multi_value = {
        "ciphers",
        "kexalgorithms",
        "macs",
        "hostkey",
        "listenaddress",
    }

    for raw_line in text.splitlines():
        line = raw_line.strip()

        if not line or line.startswith("#"):
            continue

        match = re.match(
            r"^([A-Za-z][A-Za-z0-9]*)(?:\s*=\s*|\s+)(.+)$",
            line,
        )

        if not match:
            continue

        key = match.group(1)
        value = match.group(2).strip()

        if key.lower() == "match":
            break

        value = re.sub(r"\s+#.*$", "", value).strip()
        value = value.strip('"')

        normalized_key = key.lower()

        if normalized_key in multi_value:
            settings.setdefault(key, []).append(value)

        elif key not in settings:
            settings[key] = value

    return settings



def parse_nginx_security(text: str) -> dict:
    """
    Extract security-related NGINX directives.

    Extracts directive values instead of storing complete lines.
    This remains a conservative text parser, not a complete
    NGINX configuration interpreter.
    """

    settings = {
        "server_tokens": [],
        "error_page": [],
        "location": [],
        "proxy_hide_header": [],
        "fastcgi_hide_header": [],
    }

    for raw_line in text.splitlines():
        line = raw_line.strip()

        if not line or line.startswith("#"):
            continue

        line = re.sub(r'\s+#.*$', '', line).strip()

        if not line:
            continue

        match = re.match(
            r"^(server_tokens|error_page|location|"
            r"proxy_hide_header|fastcgi_hide_header)\s+(.+?)\s*;?$",
            line,
            re.IGNORECASE,
        )

        if not match:
            continue

        directive = match.group(1).lower()
        value = match.group(2).strip().rstrip(";").strip()

        if value:
            settings[directive].append(value)

    return {
        key: values
        for key, values in settings.items()
        if values
    }



def parse_security_file(filename: str, data: bytes) -> dict:
    """Detect and parse one uploaded security configuration file."""

    if len(data) > 2_000_000:
        raise SecurityEvaluationError(
            f"{filename} exceeds the 2 MB file limit."
        )

    try:
        text = data.decode("utf-8-sig")

    except UnicodeDecodeError:
        raise SecurityEvaluationError(
            f"{filename} is not a supported text configuration file."
        )

    if "\x00" in text:
        raise SecurityEvaluationError(
            f"{filename} contains binary data."
        )

    if not text.strip():
        raise SecurityEvaluationError(
            f"{filename} is empty."
        )

    platform = detect_platform(filename, text)

    if platform == "ubuntu_22_04":
        settings = (
            {"cpuinfo": text}
            if Path(filename).name.lower() == "cpuinfo"
            else parse_sysctl(text)
        )

    elif platform == "ssh":
        settings = parse_ssh_security(text)

    elif platform == "nginx":
        settings = parse_nginx_security(text)

    else:
        raise SecurityEvaluationError(
            f"Could not identify the configuration type of {filename}."
        )

    if not settings:
        raise SecurityEvaluationError(
            f"No supported security settings were found in {filename}."
        )

    return {
        "filename": filename,
        "platform": platform,
        "settings": settings,
    }

# ---------------------------------------------------------------------
# SECURITY RULE EVALUATION
# ---------------------------------------------------------------------

from security_baseline import get_all_rules


PLATFORM_NAMES = {
    "Ubuntu 22.04": "ubuntu_22_04",
    "SSH": "ssh",
    "NGINX": "nginx",
}


def _normalize_value(value):
    """Normalize values for safe comparison."""

    if isinstance(value, bool):
        return str(value).lower()

    return str(value).strip().lower()


def _evaluate_rule(rule, settings):
    """Evaluate one rule using only available evidence."""

    rule_id = rule["id"]
    setting = rule["setting"]
    expected = rule["expected"]
    check_type = rule["check_type"]

    def result(status, actual=None, reason=""):
        return {
            "id": rule_id,
            "platform": rule["platform"],
            "category": rule["category"],
            "title": rule["title"],
            "setting": setting,
            "expected": expected,
            "actual": actual,
            "severity": rule["severity"],
            "status": status,
            "reason": reason,
        }

    if not rule["automatic"] or check_type == "manual":
        return result(
            "Manual Review",
            reason="This rule requires human verification.",
        )

    if check_type in {"custom", "file_permission"}:
        return result(
            "Not Checkable",
            reason="This check requires additional validation or file metadata.",
        )

    if setting not in settings:
        return result(
            "Not Checkable",
            reason="The uploaded evidence does not contain this setting.",
        )

    actual = settings[setting]

    if check_type == "equals":
        passed = _normalize_value(actual) == _normalize_value(expected)

    elif check_type == "one_of":
        allowed = expected if isinstance(expected, list) else [expected]

        passed = any(
            _normalize_value(actual) == _normalize_value(item)
            for item in allowed
        )

  
    elif check_type == "contains":
        passed = _normalize_value(expected) in _normalize_value(actual)

    elif check_type == "value":
        allowed = expected if isinstance(expected, list) else [expected]
        actual_values = actual if isinstance(actual, list) else [actual]

        passed = any(
            _normalize_value(actual_value) == _normalize_value(item)
            for actual_value in actual_values
            for item in allowed
        )

    


    elif check_type == "regex":
        try:
            passed = re.search(expected, str(actual)) is not None

        except re.error:
            return result(
                "Not Checkable",
                actual,
                "The baseline contains an invalid regular expression.",
            )

    else:
        return result(
            "Not Checkable",
            actual,
            "This check type is not supported yet.",
        )

    if passed:
        return result(
            "Pass",
            actual,
            "The available configuration matches the expected value.",
        )

    return result(
        "Fail",
        actual,
        "The available configuration does not match the expected value.",
    )




def evaluate_security_baseline(
    parsed_files,
    platforms_only=None,
    include_unavailable_platforms=False,
):
    """
    Evaluate built-in security rules.

    By default, evaluates rules only for uploaded platforms.
    Set include_unavailable_platforms=True to include all 106 rules,
    marking unavailable platform checks as Not Checkable or Manual Review.

    platforms_only can restrict evaluation to selected platforms,
    such as {"ssh"} for an SSH-only comparison.
    """

    platform_settings = {
        "ubuntu_22_04": {},
        "ssh": {},
        "nginx": {},
    }

    available_platforms = set()

    for parsed in parsed_files:
        platform = parsed["platform"]
        settings = parsed["settings"]

        if platform not in platform_settings:
            continue

        available_platforms.add(platform)
        platform_settings[platform].update(settings)

    results = []

    for rule in get_all_rules():
        platform = PLATFORM_NAMES.get(rule["platform"])

        # Skip rules belonging to platforms not requested.
        if platforms_only is not None and platform not in platforms_only:
            continue

        # Preserve the original behaviour unless all platforms
        # have explicitly been requested for assessment.
        if (
            not include_unavailable_platforms
            and platform not in available_platforms
        ):
            continue

        evaluated = _evaluate_rule(
            rule,
            platform_settings[platform],
        )

        results.append(evaluated)

    counts = {
        "total": len(results),
        "pass": sum(r["status"] == "Pass" for r in results),
        "fail": sum(r["status"] == "Fail" for r in results),
        "not_checkable": sum(
            r["status"] == "Not Checkable" for r in results
        ),
        "manual_review": sum(
            r["status"] == "Manual Review" for r in results
        ),
    }

    return {
        "results": results,
        "counts": counts,
        "platforms_checked": sorted(available_platforms),
    }
