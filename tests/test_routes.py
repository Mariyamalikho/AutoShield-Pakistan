from app.models.user import User
from app.models.scan import Scan
from app.models.finding import Finding
from app.extensions import db


def test_unauthenticated_redirect(client):
    """Accessing the dashboard without authentication redirects to login."""
    res = client.get("/dashboard")
    assert res.status_code == 302
    assert "/auth/login" in res.location


def test_login_flow(client, app):
    """Verify auditor authentication and session establishment."""
    with app.app_context():
        user = User(username="admin_user", email="admin@autoshield.pk")
        user.set_password("AdminPass2026!")
        db.session.add(user)
        db.session.commit()

    # Valid credentials
    res = client.post(
        "/auth/login",
        data={"username": "admin_user", "password": "AdminPass2026!"},
        follow_redirects=True,
    )
    assert res.status_code == 200
    assert b"Welcome back, admin_user!" in res.data
    assert b"Security Posture Overview" in res.data


def test_dashboard_empty_state(auth_client):
    """When no audits exist, dashboard renders clear zero-data empty state without fabrication."""
    res = auth_client.get("/dashboard")
    assert res.status_code == 200
    assert b"No Security Audits Executed Yet" in res.data
    assert b"N/A" in res.data  # Posture score empty state


def test_dashboard_with_audit_data(auth_client, app):
    """When audits and findings exist, dashboard calculates real statistics."""
    with app.app_context():
        scan = Scan(scan_type="network", target="192.168.1.1", status="completed", execution_time_sec=1.2)
        db.session.add(scan)
        db.session.commit()

        f1 = Finding(
            scan_id=scan.id,
            category="network",
            title="Unencrypted Telnet Port Open",
            severity="CRITICAL",
            risk_score=9.0,
            description="TCP/23 is open.",
            affected_component="TCP/23",
        )
        f2 = Finding(
            scan_id=scan.id,
            category="system",
            title="Firewall Inactive",
            severity="HIGH",
            risk_score=7.0,
            description="Host firewall is disabled.",
            affected_component="Firewall",
        )
        db.session.add_all([f1, f2])
        db.session.commit()

    res = auth_client.get("/dashboard")
    assert res.status_code == 200
    # Penalty: 100 - (1*25 + 1*10) = 65
    assert b"65" in res.data
    assert b"Unencrypted Telnet Port Open" not in res.data  # Not in high-level table
    assert b"1 issues" not in res.data  # scan has 2 issues
    assert b"2 issues" in res.data
