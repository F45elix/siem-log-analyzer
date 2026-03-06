"""
Unit and integration tests for SIEM Log Analyzer.
Run with: pytest tests/ -v
"""

import pytest
from datetime import datetime, timezone, timedelta
from src.analyzer import (
    LogParser, CorrelationEngine, SecurityEvent,
    SIEMPipeline, ReportGenerator
)
from pathlib import Path
import tempfile


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def parser():
    return LogParser()


@pytest.fixture
def engine():
    return CorrelationEngine()


def make_event(event_type="auth_failure", protocol="SSH",
               source_ip="10.0.0.1", dest_port=22,
               ts_offset_seconds=0) -> SecurityEvent:
    return SecurityEvent(
        event_id=f"EVT-{ts_offset_seconds:04d}",
        timestamp=datetime.now(timezone.utc) + timedelta(seconds=ts_offset_seconds),
        source_ip=source_ip,
        dest_ip="192.168.1.1",
        source_port=54321,
        dest_port=dest_port,
        protocol=protocol,
        event_type=event_type,
        severity="INFO",
        raw_log="test log line",
    )


# ---------------------------------------------------------------------------
# Parser Tests
# ---------------------------------------------------------------------------

class TestLogParser:

    def test_parse_ssh_failure(self, parser):
        line = (
            "<38>1 2024-01-15T10:30:00.000Z host01 sshd 1234 - - "
            "Failed password for admin from 203.0.113.5 port 54321 ssh2"
        )
        result = parser.parse_syslog(line)
        assert result is not None
        assert result["type"] == "auth_failure"
        assert result["source_ip"] == "203.0.113.5"
        assert result["protocol"] == "SSH"

    def test_parse_sudo_escalation(self, parser):
        line = (
            "<38>1 2024-01-15T22:05:00.000Z host01 sudo 5678 - - "
            "devops : TTY=pts/0 ; PWD=/home/devops ; USER=root ; COMMAND=/bin/bash"
        )
        result = parser.parse_syslog(line)
        assert result is not None
        assert result["type"] == "privilege_escalation"
        assert result["user"] == "devops"

    def test_parse_apache_large_transfer(self, parser):
        line = '203.0.113.10 - - [15/Jan/2024:10:00:00 +0000] "GET /export.zip HTTP/1.1" 200 60000000'
        result = parser.parse_apache(line)
        assert result is not None
        assert result["type"] == "large_transfer"
        assert result["bytes"] == 60_000_000

    def test_parse_apache_auth_failure(self, parser):
        line = '203.0.113.10 - - [15/Jan/2024:10:00:00 +0000] "GET /admin HTTP/1.1" 401 512'
        result = parser.parse_apache(line)
        assert result is not None
        assert result["type"] == "auth_failure"

    def test_parse_invalid_syslog(self, parser):
        result = parser.parse_syslog("this is not a valid syslog line")
        assert result is None


# ---------------------------------------------------------------------------
# Correlation Engine Tests
# ---------------------------------------------------------------------------

class TestCorrelationEngine:

    def test_brute_force_triggers_alert(self, engine):
        """5 SSH failures from the same IP within 60s should generate a HIGH alert."""
        alerts_generated = []
        for i in range(5):
            event = make_event(ts_offset_seconds=i * 5)
            alert = engine.ingest(event)
            if alert:
                alerts_generated.append(alert)

        assert len(alerts_generated) >= 1
        alert = alerts_generated[0]
        assert alert.severity == "HIGH"
        assert "Brute Force" in alert.title

    def test_brute_force_does_not_trigger_below_threshold(self, engine):
        """4 SSH failures should not yet trigger an alert."""
        alerts = []
        for i in range(4):
            event = make_event(ts_offset_seconds=i * 5)
            alert = engine.ingest(event)
            if alert:
                alerts.append(alert)
        assert len(alerts) == 0

    def test_privilege_escalation_off_hours(self, engine):
        """Sudo at 23:00 should fire a CRITICAL alert."""
        ts = datetime.now(timezone.utc).replace(hour=23, minute=0, second=0)
        event = SecurityEvent(
            event_id="EVT-SUDO",
            timestamp=ts,
            source_ip="10.0.0.5",
            dest_ip="10.0.0.5",
            source_port=0,
            dest_port=0,
            protocol="OS",
            event_type="privilege_escalation",
            severity="INFO",
            raw_log="sudo root command",
        )
        alert = engine.ingest(event)
        assert alert is not None
        assert alert.severity == "CRITICAL"

    def test_large_transfer_alert(self, engine):
        """Transfer >50MB should fire CRITICAL data exfiltration alert."""
        event = make_event(event_type="large_transfer", protocol="HTTP", dest_port=80)
        alert = engine.ingest(event)
        assert alert is not None
        assert alert.severity == "CRITICAL"
        assert "Exfiltration" in alert.title

    def test_port_scan_detection(self, engine):
        """15+ unique ports from same IP in 30s should generate a MEDIUM alert."""
        alerts = []
        for port in range(1, 20):
            event = make_event(
                event_type="connection_attempt",
                protocol="TCP",
                dest_port=port,
                ts_offset_seconds=port,
            )
            alert = engine.ingest(event)
            if alert:
                alerts.append(alert)
        assert len(alerts) >= 1
        assert alerts[0].severity == "MEDIUM"

    def test_alert_contains_compliance_refs(self, engine):
        """Alerts must always include compliance references."""
        for i in range(5):
            event = make_event(ts_offset_seconds=i * 5)
            alert = engine.ingest(event)
            if alert:
                assert len(alert.compliance_refs) > 0
                break


# ---------------------------------------------------------------------------
# Report Generator Tests
# ---------------------------------------------------------------------------

class TestReportGenerator:

    def test_json_report_created(self, engine):
        for i in range(5):
            engine.ingest(make_event(ts_offset_seconds=i * 5))

        with tempfile.TemporaryDirectory() as tmpdir:
            reporter = ReportGenerator(engine.alerts, Path(tmpdir))
            path = reporter.generate_json()
            assert path.exists()
            import json
            data = json.loads(path.read_text())
            assert "alerts" in data
            assert data["total_alerts"] == len(engine.alerts)

    def test_markdown_report_created(self, engine):
        for i in range(5):
            engine.ingest(make_event(ts_offset_seconds=i * 5))

        with tempfile.TemporaryDirectory() as tmpdir:
            reporter = ReportGenerator(engine.alerts, Path(tmpdir))
            path = reporter.generate_markdown()
            assert path.exists()
            content = path.read_text()
            assert "SIEM Incident Report" in content
