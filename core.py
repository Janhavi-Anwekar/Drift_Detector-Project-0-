
"""Core logic (no UI): parsing, drift detection, risk scoring and reports."""

import csv
import hashlib
import io
import json
import re
from datetime import datetime


# ---------------------------------------------------------------------
# RULES AND LABELS
# ---------------------------------------------------------------------

SETTING_LABELS = {
    "firewall_enabled": "Firewall",
    "ssh_password_login": "SSH password login",
    "ssh_root_login": "SSH root login",
    "open_ports": "Open ports",
    "password_min_length": "Minimum password length",
    "auto_updates": "Automatic updates",
    "log_level": "Log level",
    "telnet_enabled": "Telnet service",
    "permit_empty_passwords": "Empty passwords allowed",
    "x11_forwarding": "X11 forwarding",
    "max_auth_tries": "Max authentication attempts",
    "ssh_port": "SSH port",
}

# Existing dashboard risk classifications.
RISK_RULES = {
    "firewall_enabled": "High",
    "ssh_password_login": "High",
    "ssh_root_login": "High",
    "open_ports": "High",
    "telnet_enabled": "High",
    "permit_empty_passwords": "High",
    "password_min_length": "Medium",
    "auto_updates": "Medium",
    "max_auth_tries": "Medium",
    "log_level": "Low",
    "x11_forwarding": "Low",
    "ssh_port": "Low",
}

# Original weighted scoring parameters from main.py.
SECURITY_RISK_RULES = {
    "firewall_enabled": {
        "unsafe_value": False,
        "severity": 100,
        "impact": 90,
        "exposure": 80,
        "compliance": 90,
        "reason": "Firewall protection is disabled.",
    },
    "ssh_password_login": {
        "unsafe_value": True,
        "severity": 85,
        "impact": 80,
        "exposure": 85,
        "compliance": 75,
        "reason": "SSH password login is enabled.",
    },
    "logging_enabled": {
        "unsafe_value": False,
        "severity": 75,
        "impact": 65,
        "exposure": 40,
        "compliance": 80,
        "reason": "Security logging is disabled.",
    },
    "security_updates": {
        "unsafe_value": False,
        "severity": 90,
        "impact": 85,
        "exposure": 70,
        "compliance": 85,
        "reason": "Security updates are disabled.",
    },
}

RISK_ORDER = {
    "High": 0,
    "Medium": 1,
    "Low": 2,
    "None": 3,
}

PENALTY = {
    "High": 15,
    "Medium": 7,
    "Low": 2,
}

DOT = {
    "High": "#FF3B30",
    "Medium": "#FF9F0A",
    "Low": "#34C759",
    "None": "#34C759",
}

TYPE_LABEL = {
    "modified": "Modified",
    "added": "Added",
    "removed": "Removed",
    "same": "Unchanged",
}

# Existing standard comparison baseline.
# Used only when no custom baseline is uploaded.
STANDARD_BASELINE = {
    "firewall_enabled": True,
    "open_ports": [22, 443],
    "telnet_enabled": False,

    "ssh_password_login": False,
    "ssh_root_login": False,
    "permit_empty_passwords": False,
    "max_auth_tries": 4,
    "password_min_length": 12,
    "pubkey_authentication": True,
    "strict_modes": True,
    "ignore_rhosts": True,

    "x11_forwarding": False,
    "allow_tcp_forwarding": False,
    "client_alive_interval": 300,
    "client_alive_count_max": 3,
    "compression": False,

    "auto_updates": True,
    "log_level": "info",

    "port": 22,
    "protocol": 2,
}


def label(key: str) -> str:
    return SETTING_LABELS.get(key) or key.replace("_", " ").capitalize()


# ---------------------------------------------------------------------
# FILE PARSING
# ---------------------------------------------------------------------

class ConfigError(ValueError):
    """A problem with an uploaded configuration file."""


MAX_BYTES = 2_000_000

BOOL = {
    "yes": True,
    "no": False,
    "true": True,
    "false": False,
    "on": True,
    "off": False,
}

SSH_ALIASES = {
    "passwordauthentication": "ssh_password_login",
    "permitrootlogin": "ssh_root_login",
    "permitemptypasswords": "permit_empty_passwords",
    "x11forwarding": "x11_forwarding",
    "maxauthtries": "max_auth_tries",
    "loglevel": "log_level",
    "port": "ssh_port",
}

SSH_MULTI = {
    "hostkey",
    "listenaddress",
    "acceptenv",
    "subsystem",
    "allowusers",
    "allowgroups",
    "denyusers",
    "denygroups",
    "include",
}

SSH_KNOWN = set(SSH_ALIASES) | SSH_MULTI | {
    "protocol",
    "syslogfacility",
    "logingracetime",
    "strictmodes",
    "pubkeyauthentication",
    "authorizedkeysfile",
    "usepam",
    "challengeresponseauthentication",
    "kbdinteractiveauthentication",
    "printmotd",
    "printlastlog",
    "clientaliveinterval",
    "clientalivecountmax",
    "usedns",
    "allowtcpforwarding",
    "gatewayports",
    "permittunnel",
    "maxsessions",
    "maxstartups",
    "banner",
    "ciphers",
    "macs",
    "kexalgorithms",
    "ignorerhosts",
    "hostbasedauthentication",
    "permituserenvironment",
    "compression",
    "tcpkeepalive",
    "authenticationmethods",
    "permittty",
    "chrootdirectory",
    "forcecommand",
    "allowagentforwarding",
}


def _snake(name: str) -> str:
    s = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", name)
    return re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", s).lower()


def _coerce(v: str):
    low = v.lower()

    if low in BOOL:
        return BOOL[low]

    if re.fullmatch(r"-?\d+", v):
        return int(v)

    return v


def parse_ssh(text: str) -> dict:
    """Parse an sshd_config file into normalized settings."""

    out = {}
    ports = []
    known_seen = 0

    for raw in text.splitlines():
        line = raw.strip()

        if not line or line.startswith("#"):
            continue

        match = re.match(
            r"^([A-Za-z][A-Za-z0-9]*)(?:\s*=\s*|\s+)(.+)$",
            line,
        )

        if not match:
            continue

        key = match.group(1)
        val = re.sub(r"\s+#.*$", "", match.group(2))
        val = val.strip().strip('"')

        low = key.lower()

        if low == "match":
            break

        if low in SSH_KNOWN:
            known_seen += 1

        if low == "port":
            if val.isdigit():
                ports.append(int(val))
            continue

        name = SSH_ALIASES.get(low) or _snake(key)

        if low in SSH_MULTI:
            out.setdefault(name, []).append(val)

        elif name not in out:
            out[name] = val.lower() if low == "loglevel" else _coerce(val)

    if not known_seen:
        raise ConfigError(
            "This doesn't look like an SSH config (sshd_config). "
            "Upload a JSON object of settings or an sshd_config file."
        )

    if ports:
        out["ssh_port"] = sorted(set(ports))

    return out


def parse_json(text: str, filename: str) -> dict:
    try:
        data = json.loads(text)

    except json.JSONDecodeError as e:
        raise ConfigError(
            f"{filename} is not valid JSON "
            f"(line {e.lineno}, column {e.colno}: {e.msg})."
        )

    if not isinstance(data, dict) or not data:
        raise ConfigError(
            f'{filename} must contain a JSON object of settings, '
            'e.g. {"firewall_enabled": true}.'
        )

    out = {}

    for key, value in data.items():
        norm = SSH_ALIASES.get(str(key).lower())

        if norm:
            key = norm

            if isinstance(value, str):
                value = _coerce(value)

        out[str(key)] = value

    return out


def parse_config(filename: str, data: bytes) -> tuple[dict, str]:
    """Detect JSON vs SSH and return (settings, kind)."""

    if len(data) > MAX_BYTES:
        raise ConfigError(
            f"{filename} is larger than 2 MB. "
            "Upload just the configuration file."
        )

    try:
        text = data.decode("utf-8-sig")

    except UnicodeDecodeError:
        raise ConfigError(
            f"{filename} is not a text file. "
            "Upload a JSON or SSH config file."
        )

    if "\x00" in text:
        raise ConfigError(
            f"{filename} is not a text file. "
            "Upload a JSON or SSH config file."
        )

    stripped = text.lstrip()

    if not stripped:
        raise ConfigError(f"{filename} is empty.")

    if filename.lower().endswith(".json") or stripped[0] in "{[":
        return parse_json(text, filename), "json"

    return parse_ssh(text), "ssh"


# ---------------------------------------------------------------------
# BUILD COMPARISON
# ---------------------------------------------------------------------

def build_run(
    cur_name: str,
    cur_bytes: bytes,
    base_name: str | None = None,
    base_bytes: bytes | None = None,
) -> dict:
    """
    Prepare one comparison.

    Custom baseline takes priority when supplied.
    Otherwise, use the existing standard baseline.
    """

    cur, cur_kind = parse_config(cur_name, cur_bytes)

    if base_bytes is not None:
        base, base_kind = parse_config(
            base_name or "baseline",
            base_bytes,
        )

        mode = "custom"
        base_label = base_name or "baseline"
        not_covered = []
        missing = []

    else:
        shared = [
            key for key in STANDARD_BASELINE
            if key in cur
        ]

        if not shared:
            raise ConfigError(
                f"None of the settings in {cur_name} are covered "
                "by the standard baseline. "
                "Upload your own baseline file to compare against."
            )

        base = {
            key: STANDARD_BASELINE[key]
            for key in shared
        }

        not_covered = [
            key for key in cur
            if key not in base
        ]

        cur = {
            key: cur[key]
            for key in shared
        }

        missing = [
            key for key in STANDARD_BASELINE
            if key not in base
        ]

        mode = "standard"
        base_kind = "standard"
        base_label = "Standard baseline"

    digest = hashlib.sha1(
        cur_bytes
        + (
            base_bytes
            if base_bytes is not None
            else b"standard"
        )
    ).hexdigest()[:8]

    return dict(
        id=f"cfg-{digest}",
        name=cur_name,
        kind=cur_kind,
        base_kind=base_kind,
        mode=mode,
        base_label=base_label,
        baseline=base,
        current=cur,
        not_covered=not_covered,
        missing=missing,
        last_scan=datetime.now(),
    )


# ---------------------------------------------------------------------
# DRIFT DETECTION
# ---------------------------------------------------------------------

def _norm(value):
    if isinstance(value, list):
        try:
            value = sorted(value)
        except TypeError:
            value = sorted(value, key=str)

    return json.dumps(value, sort_keys=True)


def find_drifts(baseline: dict, current: dict) -> list[dict]:
    """Compare baseline vs current."""

    out = []

    for key, expected in baseline.items():

        if key not in current:
            out.append({
                "setting": key,
                "type": "removed",
                "expected": expected,
                "actual": None,
            })

        elif _norm(expected) != _norm(current[key]):
            out.append({
                "setting": key,
                "type": "modified",
                "expected": expected,
                "actual": current[key],
            })

    for key, actual in current.items():

        if key not in baseline:
            out.append({
                "setting": key,
                "type": "added",
                "expected": None,
                "actual": actual,
            })

    return out


# ---------------------------------------------------------------------
# RISK SCORING
# ---------------------------------------------------------------------

def rate_risk(f: dict) -> str:
    """Return the existing dashboard risk classification."""

    return RISK_RULES.get(f["setting"], "Medium")


def calculate_security_risk(f: dict) -> tuple[int, str, str]:
    """
    Calculate the original weighted risk score from main.py.

    Returns:
        score, risk level, explanation
    """

    rule = SECURITY_RISK_RULES.get(f["setting"])

    if rule is None:
        return (
            0,
            "REVIEW REQUIRED",
            "No specific weighted risk rule exists.",
        )

    # A missing or added setting cannot be scored using this rule.
    if f["type"] in {"removed", "added"}:
        return (
            0,
            "REVIEW REQUIRED",
            "Setting requires security review.",
        )

    if f["actual"] != rule["unsafe_value"]:
        return (
            0,
            "None",
            "The predefined unsafe condition was not detected.",
        )

    score = (
        rule["severity"] * 0.40
        + rule["impact"] * 0.30
        + rule["exposure"] * 0.20
        + rule["compliance"] * 0.10
    )

    score = round(score)

    if score >= 80:
        level = "High"
    elif score >= 50:
        level = "Medium"
    else:
        level = "Low"

    return score, level, rule["reason"]


def overall_risk(findings: list[dict]) -> str:
    if not findings:
        return "None"

    return min(
        (f["risk"] for f in findings),
        key=lambda risk: RISK_ORDER[risk],
    )


def posture_score(findings: list[dict]) -> int:
    """
    Existing dashboard posture score.

    100 - 15 per High - 7 per Medium - 2 per Low.
    """

    return max(
        0,
        100 - sum(
            PENALTY[f["risk"]]
            for f in findings
        ),
    )


def analyze(run: dict) -> dict:
    """Analyze one comparison and return dashboard-compatible findings."""

    findings = []

    for drift in find_drifts(
        run["baseline"],
        run["current"],
    ):
        drift["id"] = f"{run['id']}::{drift['setting']}"
        drift["server_id"] = run["id"]

        # Preserve existing dashboard risk classification.
        drift["risk"] = rate_risk(drift)

        # Restore original weighted scoring.
        score, weighted_level, reason = calculate_security_risk(drift)

        drift["score"] = score
        drift["weighted_risk"] = weighted_level
        drift["reason"] = reason

        findings.append(drift)

    findings.sort(
        key=lambda finding: RISK_ORDER[finding["risk"]]
    )

    return {
        **run,
        "findings": findings,
        "highest": overall_risk(findings),
        "score": posture_score(findings),
    }


# ---------------------------------------------------------------------
# DASHBOARD TOTALS
# ---------------------------------------------------------------------

def totals(analyzed: list[dict]) -> dict:

    all_findings = [
        finding
        for server in analyzed
        for finding in server["findings"]
    ]

    counts = {
        "High": 0,
        "Medium": 0,
        "Low": 0,
    }

    for finding in all_findings:
        counts[finding["risk"]] += 1

    affected = sum(
        1 for server in analyzed
        if server["findings"]
    )

    posture = (
        round(
            sum(server["score"] for server in analyzed)
            / len(analyzed)
        )
        if analyzed
        else 100
    )

    return {
        "all": all_findings,
        "c": counts,
        "affected": affected,
        "healthy": len(analyzed) - affected,
        "total": len(all_findings),
        "posture": posture,
    }


# ---------------------------------------------------------------------
# REPORTS
# ---------------------------------------------------------------------

def plain(value, present: bool = True) -> str:

    if not present:
        return "not set"

    if isinstance(value, bool):
        return "ON" if value else "OFF"

    if isinstance(value, list):
        return "[" + ", ".join(str(x) for x in value) + "]"

    if isinstance(value, dict):
        return json.dumps(value)

    return str(value)


def f_expected(f):
    return plain(
        f["expected"],
        f["type"] != "added",
    )


def f_actual(f):
    return plain(
        f["actual"],
        f["type"] != "removed",
    )


def summary(f: dict) -> str:
    return (
        f"{label(f['setting'])}: "
        f"{f_expected(f)} → {f_actual(f)}"
    )


def report_data(
    analyzed: list[dict],
    decisions: dict,
) -> dict:

    t = totals(analyzed)

    return {
        "generatedAt": datetime.now().isoformat(
            timespec="seconds"
        ),

        "summary": {
            "comparisons": len(analyzed),
            "drifts": t["total"],
            "high": t["c"]["High"],
            "medium": t["c"]["Medium"],
            "low": t["c"]["Low"],
            "postureScore": t["posture"],
        },

        "comparisons": [
            {
                "id": server["id"],
                "currentFile": server["name"],
                "fileType": server["kind"],
                "comparedAgainst": server["base_label"],
                "baselineMode": server["mode"],
                "scannedAt": server["last_scan"].isoformat(
                    timespec="seconds"
                ),
                "riskLevel": server["highest"],
                "score": server["score"],

                "findings": [
                    {
                        "setting": finding["setting"],
                        "change": finding["type"],
                        "expected": finding["expected"],
                        "actual": finding["actual"],
                        "risk": finding["risk"],
                        "weightedScore": finding["score"],
                        "weightedRisk": finding["weighted_risk"],
                        "decision": decisions.get(
                            finding["id"],
                            {"status": "Pending"},
                        ),
                    }
                    for finding in server["findings"]
                ],
            }
            for server in analyzed
        ],
    }


def report_csv(
    analyzed: list[dict],
    decisions: dict,
) -> str:

    buf = io.StringIO()

    writer = csv.writer(
        buf,
        quoting=csv.QUOTE_ALL,
    )

    writer.writerow([
        "file",
        "compared_against",
        "setting",
        "change",
        "expected",
        "actual",
        "risk",
        "weighted_score",
        "weighted_risk",
        "status",
        "decided_by",
        "decided_at",
        "note",
    ])

    for server in analyzed:

        for finding in server["findings"]:

            decision = decisions.get(
                finding["id"],
                {},
            )

            writer.writerow([
                server["name"],
                server["base_label"],
                finding["setting"],
                finding["type"],
                f_expected(finding),
                f_actual(finding),
                finding["risk"],
                finding["score"],
                finding["weighted_risk"],
                decision.get("status", "Pending"),
                decision.get("by", ""),
                decision.get("at", ""),
                decision.get("note", ""),
            ])

    return buf.getvalue()
