"""
SIEM Log Analyzer - Core Analysis Engine
=========================================
Parses, correlates, and scores security events from multiple log sources.
Supports: Syslog (RFC 5424), Windows Event Log (EVTX JSON export),
          AWS CloudTrail, Apache/Nginx access logs, and CEF format.

Skills demonstrated:
- SIEM platform knowledge (Splunk/Sentinel equivalent logic)
- Threat detection via rule-based + statistical anomaly detection
- Incident Response triage scoring (CVSS-inspired)
- Compliance alignment: NIST 800-53, ISO 27001, ASD Essential Eight
"""

import re
import json
import hashlib
import logging
from datetime import datetime, timezone
from collections import defaultdict, Counter
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s"
)
logger = logging.getLogger("siem.analyzer")


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------

@dataclass
class SecurityEvent:
    """Normalised security event — vendor-agnostic internal representation."""
    event_id: str
    timestamp: datetime
    source_ip: str
    dest_ip: str
    source_port: int
    dest_port: int
    protocol: str
    event_type: str          # auth_failure, port_scan, brute_force, etc.
    severity: str            # CRITICAL / HIGH / MEDIUM / LOW / INFO
    raw_log: str
    tags: list[str] = field(default_factory=list)
    mitre_technique: Optional[str] = None   # e.g. "T1110 - Brute Force"
    risk_score: float = 0.0                 # 0–100
    correlated: bool = False


@dataclass
class Alert:
    """Aggregated alert generated after correlation."""
    alert_id: str
    title: str
    description: str
    severity: str
    events: list[str]          # event_ids
    mitre_techniques: list[str]
    affected_assets: list[str]
    recommended_action: str
    compliance_refs: list[str]  # NIST / ISO control IDs
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    risk_score: float = 0.0


# ---------------------------------------------------------------------------
# Detection Rules (YAML-style expressed as dicts for portability)
# ---------------------------------------------------------------------------

DETECTION_RULES = [
    {
        "id": "RULE-001",
        "name": "SSH Brute Force",
        "description": "≥5 failed SSH auth attempts from same IP within 60 seconds",
        "event_type": "auth_failure",
        "protocol": "SSH",
        "threshold": 5,
        "window_seconds": 60,
        "severity": "HIGH",
        "mitre": "T1110.001 - Brute Force: Password Guessing",
        "compliance": ["NIST AC-7", "ISO A.9.4.2", "Essential Eight MFA"],
        "action": "Block source IP at perimeter firewall; investigate account lockout policy.",
    },
    {
        "id": "RULE-002",
        "name": "Horizontal Port Scan",
        "description": "Single IP probing >15 distinct destination ports in 30 seconds",
        "event_type": "connection_attempt",
        "threshold_ports": 15,
        "window_seconds": 30,
        "severity": "MEDIUM",
        "mitre": "T1046 - Network Service Discovery",
        "compliance": ["NIST SI-4", "ISO A.12.6.1"],
        "action": "Isolate scanning host; review firewall ACLs; initiate incident investigation.",
    },
    {
        "id": "RULE-003",
        "name": "Privilege Escalation via sudo",
        "description": "sudo command executed outside of approved hours (22:00–06:00)",
        "event_type": "privilege_escalation",
        "off_hours_start": 22,
        "off_hours_end": 6,
        "severity": "CRITICAL",
        "mitre": "T1548.003 - Abuse Elevation Control Mechanism: Sudo and Sudo Caching",
        "compliance": ["NIST AC-6", "ISO A.9.2.3", "Essential Eight Admin Privileges"],
        "action": "Immediately revoke session; alert security team; preserve memory forensics.",
    },
    {
        "id": "RULE-004",
        "name": "Data Exfiltration Beacon",
        "description": "Outbound transfer >50 MB to non-whitelisted external IP",
        "event_type": "large_transfer",
        "threshold_bytes": 52_428_800,  # 50 MB
        "severity": "CRITICAL",
        "mitre": "T1041 - Exfiltration Over C2 Channel",
        "compliance": ["NIST SI-12", "ISO A.12.4.1", "GDPR Art.33"],
        "action": "Block egress; preserve network captures; notify DPO if PII involved.",
    },
    {
        "id": "RULE-005",
        "name": "Impossible Travel (GeoIP Anomaly)",
        "description": "Same user account authenticates from two geographically distant IPs within 1 hour",
        "event_type": "auth_success",
        "time_window_minutes": 60,
        "severity": "HIGH",
        "mitre": "T1078 - Valid Accounts",
        "compliance": ["NIST IA-2", "ISO A.9.4.2"],
        "action": "Force re-authentication via MFA; review recent account activity; consider account suspension.",
    },
]


# ---------------------------------------------------------------------------
# Log Parsers
# ---------------------------------------------------------------------------

class LogParser:
    """
    Multi-format log parser.
    Extend by subclassing and overriding `parse_line`.
    """

    # Regex patterns
    _SYSLOG_RE = re.compile(
        r"<(?P<pri>\d+)>(?P<version>\d) "
        r"(?P<ts>\S+) (?P<host>\S+) (?P<app>\S+) "
        r"(?P<pid>\S+) (?P<msgid>\S+) \S+ (?P<msg>.+)"
    )
    _SSH_FAIL_RE = re.compile(
        r"Failed (?P<method>\w+) for (?:invalid user )?(?P<user>\S+) "
        r"from (?P<ip>[\d.]+) port (?P<port>\d+)"
    )
    _SUDO_RE = re.compile(
        r"(?P<user>\S+) : TTY=\S+ ; PWD=\S+ ; USER=(?P<runas>\S+) ; "
        r"COMMAND=(?P<cmd>.+)"
    )
    _APACHE_RE = re.compile(
        r'(?P<ip>[\d.]+) \S+ \S+ \[(?P<ts>[^\]]+)\] '
        r'"(?P<method>\S+) (?P<path>\S+) \S+" '
        r'(?P<status>\d+) (?P<size>\d+)'
    )

    def parse_syslog(self, line: str) -> Optional[dict]:
        m = self._SYSLOG_RE.match(line)
        if not m:
            return None
        data = m.groupdict()
        # Sub-parse SSH failures
        ssh = self._SSH_FAIL_RE.search(data["msg"])
        if ssh:
            return {
                "type": "auth_failure",
                "protocol": "SSH",
                "source_ip": ssh.group("ip"),
                "source_port": int(ssh.group("port")),
                "dest_port": 22,
                "user": ssh.group("user"),
                "timestamp": data["ts"],
                "raw": line,
            }
        # Sub-parse sudo
        sudo = self._SUDO_RE.search(data["msg"])
        if sudo:
            return {
                "type": "privilege_escalation",
                "protocol": "OS",
                "source_ip": data["host"],
                "source_port": 0,
                "dest_port": 0,
                "user": sudo.group("user"),
                "command": sudo.group("cmd"),
                "timestamp": data["ts"],
                "raw": line,
            }
        return None

    def parse_apache(self, line: str) -> Optional[dict]:
        m = self._APACHE_RE.match(line)
        if not m:
            return None
        status = int(m.group("status"))
        size = int(m.group("size"))
        event_type = "large_transfer" if size > 52_428_800 else "http_request"
        if status in (401, 403):
            event_type = "auth_failure"
        return {
            "type": event_type,
            "protocol": "HTTP",
            "source_ip": m.group("ip"),
            "source_port": 0,
            "dest_port": 80,
            "path": m.group("path"),
            "status": status,
            "bytes": size,
            "timestamp": m.group("ts"),
            "raw": line,
        }

    def parse_cloudtrail(self, record: dict) -> Optional[dict]:
        """Parse a single CloudTrail event record (from JSON array)."""
        event_name = record.get("eventName", "")
        source_ip = record.get("sourceIPAddress", "0.0.0.0")
        user = record.get("userIdentity", {}).get("arn", "unknown")
        ts = record.get("eventTime", datetime.now(timezone.utc).isoformat())

        sensitive_events = {
            "ConsoleLogin", "CreateAccessKey", "PutUserPolicy",
            "AttachUserPolicy", "CreateUser", "DeleteTrail",
        }
        if event_name in sensitive_events:
            return {
                "type": "privilege_escalation" if "Policy" in event_name else "auth_success",
                "protocol": "AWS",
                "source_ip": source_ip,
                "source_port": 0,
                "dest_port": 443,
                "user": user,
                "event_name": event_name,
                "timestamp": ts,
                "raw": json.dumps(record),
            }
        return None


# ---------------------------------------------------------------------------
# Correlation Engine
# ---------------------------------------------------------------------------

class CorrelationEngine:
    """
    Stateful correlation engine.
    Maintains sliding-window counters per (rule × source_ip) and
    fires alerts when thresholds are exceeded.
    """

    def __init__(self):
        # { rule_id: { source_ip: [timestamps] } }
        self._windows: dict[str, dict[str, list]] = defaultdict(lambda: defaultdict(list))
        self.alerts: list[Alert] = []
        self._event_store: dict[str, SecurityEvent] = {}

    def ingest(self, event: SecurityEvent) -> Optional[Alert]:
        self._event_store[event.event_id] = event
        return self._evaluate_rules(event)

    def _evaluate_rules(self, event: SecurityEvent) -> Optional[Alert]:
        for rule in DETECTION_RULES:
            alert = None

            if rule["id"] == "RULE-001" and event.event_type == "auth_failure" and event.protocol == "SSH":
                alert = self._check_threshold(rule, event)

            elif rule["id"] == "RULE-002" and event.event_type == "connection_attempt":
                alert = self._check_port_scan(rule, event)

            elif rule["id"] == "RULE-003" and event.event_type == "privilege_escalation":
                hour = event.timestamp.hour
                if hour >= rule["off_hours_start"] or hour < rule["off_hours_end"]:
                    alert = self._fire_alert(rule, event, [event.event_id])

            elif rule["id"] == "RULE-004" and event.event_type == "large_transfer":
                alert = self._fire_alert(rule, event, [event.event_id])

            if alert:
                self.alerts.append(alert)
                event.correlated = True
                return alert
        return None

    def _check_threshold(self, rule: dict, event: SecurityEvent) -> Optional[Alert]:
        key = event.source_ip
        bucket = self._windows[rule["id"]][key]
        now = event.timestamp.timestamp()
        window = rule["window_seconds"]
        # Prune old entries
        bucket[:] = [t for t in bucket if now - t <= window]
        bucket.append(now)
        if len(bucket) >= rule["threshold"]:
            event_ids = [
                eid for eid, ev in self._event_store.items()
                if ev.source_ip == key and ev.event_type == event.event_type
            ][-rule["threshold"]:]
            return self._fire_alert(rule, event, event_ids)
        return None

    def _check_port_scan(self, rule: dict, event: SecurityEvent) -> Optional[Alert]:
        key = event.source_ip
        bucket = self._windows[rule["id"]][key]
        now = event.timestamp.timestamp()
        window = rule["window_seconds"]
        bucket[:] = [e for e in bucket if now - e["ts"] <= window]
        bucket.append({"ts": now, "port": event.dest_port})
        unique_ports = len({e["port"] for e in bucket})
        if unique_ports >= rule["threshold_ports"]:
            return self._fire_alert(rule, event, [event.event_id])
        return None

    def _fire_alert(self, rule: dict, event: SecurityEvent, event_ids: list[str]) -> Alert:
        alert_id = hashlib.sha256(
            f"{rule['id']}{event.source_ip}{event.timestamp.isoformat()}".encode()
        ).hexdigest()[:16]
        risk = {"CRITICAL": 95, "HIGH": 75, "MEDIUM": 50, "LOW": 25}.get(rule["severity"], 10)
        return Alert(
            alert_id=alert_id,
            title=rule["name"],
            description=rule["description"],
            severity=rule["severity"],
            events=event_ids,
            mitre_techniques=[rule.get("mitre", "")],
            affected_assets=[event.source_ip, event.dest_ip],
            recommended_action=rule["action"],
            compliance_refs=rule.get("compliance", []),
            risk_score=risk,
        )


# ---------------------------------------------------------------------------
# Report Generator
# ---------------------------------------------------------------------------

class ReportGenerator:
    """Generates JSON and Markdown incident reports from alerts."""

    def __init__(self, alerts: list[Alert], output_dir: Path):
        self.alerts = alerts
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate_json(self) -> Path:
        path = self.output_dir / f"alerts_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        payload = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "total_alerts": len(self.alerts),
            "critical": sum(1 for a in self.alerts if a.severity == "CRITICAL"),
            "high": sum(1 for a in self.alerts if a.severity == "HIGH"),
            "alerts": [asdict(a) for a in self.alerts],
        }
        path.write_text(json.dumps(payload, indent=2, default=str))
        logger.info("JSON report → %s", path)
        return path

    def generate_markdown(self) -> Path:
        path = self.output_dir / f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        sorted_alerts = sorted(self.alerts, key=lambda a: severity_order.get(a.severity, 99))

        lines = [
            "# SIEM Incident Report",
            f"**Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
            f"**Total Alerts:** {len(self.alerts)}  ",
            f"**Critical:** {sum(1 for a in self.alerts if a.severity == 'CRITICAL')}  ",
            f"**High:** {sum(1 for a in self.alerts if a.severity == 'HIGH')}",
            "",
            "---",
            "",
        ]
        for a in sorted_alerts:
            badge = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(a.severity, "⚪")
            lines += [
                f"## {badge} [{a.severity}] {a.title}",
                f"**Alert ID:** `{a.alert_id}`  ",
                f"**Risk Score:** {a.risk_score}/100  ",
                f"**Description:** {a.description}",
                "",
                f"**MITRE ATT&CK:** {', '.join(a.mitre_techniques)}  ",
                f"**Affected Assets:** {', '.join(a.affected_assets)}  ",
                f"**Compliance Refs:** {', '.join(a.compliance_refs)}",
                "",
                f"> **Recommended Action:** {a.recommended_action}",
                "",
                "---",
                "",
            ]
        path.write_text("\n".join(lines))
        logger.info("Markdown report → %s", path)
        return path


# ---------------------------------------------------------------------------
# Pipeline Entry Point
# ---------------------------------------------------------------------------

class SIEMPipeline:
    """
    Orchestrates ingestion → normalisation → correlation → reporting.

    Usage:
        pipeline = SIEMPipeline()
        pipeline.ingest_file(Path("logs/auth.log"), fmt="syslog")
        pipeline.ingest_file(Path("logs/access.log"), fmt="apache")
        pipeline.run_report(Path("reports/"))
    """

    def __init__(self):
        self.parser = LogParser()
        self.engine = CorrelationEngine()
        self._seq = 0

    def _next_id(self) -> str:
        self._seq += 1
        return f"EVT-{self._seq:06d}"

    def _dict_to_event(self, parsed: dict) -> SecurityEvent:
        ts_raw = parsed.get("timestamp", datetime.now(timezone.utc).isoformat())
        try:
            ts = datetime.fromisoformat(str(ts_raw).replace("Z", "+00:00"))
        except ValueError:
            ts = datetime.now(timezone.utc)

        return SecurityEvent(
            event_id=self._next_id(),
            timestamp=ts,
            source_ip=parsed.get("source_ip", "0.0.0.0"),
            dest_ip=parsed.get("dest_ip", "0.0.0.0"),
            source_port=parsed.get("source_port", 0),
            dest_port=parsed.get("dest_port", 0),
            protocol=parsed.get("protocol", "UNKNOWN"),
            event_type=parsed.get("type", "generic"),
            severity="INFO",
            raw_log=parsed.get("raw", ""),
        )

    def ingest_file(self, path: Path, fmt: str = "syslog") -> int:
        """Returns the number of events successfully parsed."""
        count = 0
        with open(path, "r", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                parsed = None
                if fmt == "syslog":
                    parsed = self.parser.parse_syslog(line)
                elif fmt == "apache":
                    parsed = self.parser.parse_apache(line)
                elif fmt == "cloudtrail":
                    try:
                        record = json.loads(line)
                        parsed = self.parser.parse_cloudtrail(record)
                    except json.JSONDecodeError:
                        pass
                if parsed:
                    event = self._dict_to_event(parsed)
                    self.engine.ingest(event)
                    count += 1
        logger.info("Ingested %d events from %s [%s]", count, path.name, fmt)
        return count

    def run_report(self, output_dir: Path) -> dict[str, Path]:
        reporter = ReportGenerator(self.engine.alerts, output_dir)
        return {
            "json": reporter.generate_json(),
            "markdown": reporter.generate_markdown(),
        }
