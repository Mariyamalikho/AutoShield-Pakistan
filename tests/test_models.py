from app.extensions import db
from app.models.user import User
from app.models.asset import Asset
from app.models.scan import Scan, ScanResult
from app.models.finding import Finding
from app.models.remediation import Remediation
from app.models.audit_log import AuditLog
from app.models.yara_rule import YaraRule


def test_user_password_hashing(app):
    """Verify password hashing security and verification."""
    user = User(username="testuser", email="test@autoshield.pk")
    user.set_password("CorrectHorseBatteryStaple!")

    assert user.password_hash != "CorrectHorseBatteryStaple!"
    assert user.check_password("CorrectHorseBatteryStaple!") is True
    assert user.check_password("WrongPassword") is False


def test_asset_and_scan_relationship(app):
    """Verify asset creation and scan relationship integrity."""
    asset = Asset(
        name="Lab-Server-01",
        asset_type="host",
        ip_address="192.168.1.50",
        environment="Lab",
    )
    db.session.add(asset)
    db.session.commit()

    scan = Scan(
        scan_type="network",
        target="192.168.1.50",
        asset_id=asset.id,
        status="completed",
        execution_time_sec=2.45,
    )
    db.session.add(scan)
    db.session.commit()

    assert scan.asset.name == "Lab-Server-01"
    assert asset.scans.count() == 1


def test_finding_and_remediation_cascade(app):
    """Verify finding creation, score, and remediation relationship."""
    scan = Scan(scan_type="system", target="localhost", status="completed")
    db.session.add(scan)
    db.session.commit()

    finding = Finding(
        scan_id=scan.id,
        category="system",
        title="Unrestricted Inbound SMB Listening",
        severity="HIGH",
        risk_score=7.5,
        description="Port 445 is actively listening without firewall restrictions.",
        affected_component="TCP/445",
    )
    db.session.add(finding)
    db.session.commit()

    remediation = Remediation(
        finding_id=finding.id,
        what_detected="SMB service detected listening on 0.0.0.0:445",
        why_matters="Exposes host to unauthorized network file sharing and protocol exploits.",
        potential_impact="Lateral movement or unauthenticated credential harvesting.",
        fix_instructions="Restrict SMB traffic using host firewall to trusted subnets only.",
        verification_command="Get-NetFirewallRule -DisplayGroup 'File and Printer Sharing'",
        platform="windows",
    )
    db.session.add(remediation)
    db.session.commit()

    assert finding.remediations.count() == 1
    rem = finding.remediations.first()
    assert rem.platform == "windows"
    assert rem.is_completed is False


def test_audit_log_and_yara_rule(app):
    """Verify administrative audit log and YARA rule catalog models."""
    log = AuditLog(
        action="network_audit_started",
        target_resource="192.168.1.1",
        ip_address="127.0.0.1",
        details="Authorized scan started",
    )
    db.session.add(log)

    rule = YaraRule(
        rule_name="suspicious_powershell_base64",
        rule_file="suspicious_scripts.yar",
        description="Detects encoded execution payloads in scripts",
        severity="HIGH",
    )
    db.session.add(rule)
    db.session.commit()

    assert log.id is not None
    assert rule.id is not None
    assert rule.is_active is True
