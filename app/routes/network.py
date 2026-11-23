"""
Network Security Auditor — Flask blueprint.

Exposes:
  GET  /network        — Scan form
  POST /network/scan   — Execute a port scan or subnet sweep

All scanning requires the user to explicitly confirm authorisation via a
checkbox before any packets are sent.  Scan records and findings are
persisted to SQLite after each successful run.
"""
from __future__ import annotations

import datetime
import json
import socket
import re

from flask import (
    Blueprint,
    flash,
    redirect,
    render_template,
    request,
    url_for,
)
from flask_login import current_user, login_required

from app.extensions import db
from app.models.scan import Scan, ScanResult
from app.models.finding import Finding
from app.modules.network.scanner import PortScanner, COMMON_PORTS
from app.modules.network.banner import grab_banner
from app.modules.network.risk_mapper import classify_port_risk
from app.modules.network.subnet_scanner import scan_subnet
from app.utils.validators import is_safe_target, is_valid_ip, is_valid_subnet

network_bp = Blueprint("network", __name__, url_prefix="/network")

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
_SCANNER = PortScanner(default_timeout=1.0, max_workers=20)

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

_HOSTNAME_RE = re.compile(
    r"^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*"
    r"([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$"
)


def _is_valid_hostname(value: str) -> bool:
    return bool(_HOSTNAME_RE.match(value.strip()))


def _resolve_host(target: str) -> str | None:
    """Return IPv4 string for *target*, or None on resolution failure."""
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        return None


def _persist_host_scan(
    target: str,
    open_ports: list[dict],
) -> Scan:
    """Write Scan, ScanResult, and Finding rows to SQLite."""
    now = datetime.datetime.utcnow()
    scan = Scan(
        scan_type="network_host",
        target=target,
        status="completed",
        started_at=now,
        completed_at=now,
        user_id=current_user.id if current_user.is_authenticated else None,
    )
    db.session.add(scan)
    db.session.flush()  # get scan.id

    for entry in open_ports:
        result = ScanResult(
            scan_id=scan.id,
            component_name="port_scan",
            raw_data_json=json.dumps(entry),
            status="ok",
        )
        db.session.add(result)

        sev = entry.get("severity", "INFO")
        if sev not in (None, "INFO"):
            # risk_score in model is 0-10 scale; our mapper uses 0-100
            normalized_score = round(entry.get("risk_score", 50) / 10, 1)
            finding = Finding(
                scan_id=scan.id,
                category="network",
                title=f"Open port {entry.get('port')} ({entry.get('service', 'unknown')})",
                description=entry.get("explanation", ""),
                severity=sev,
                risk_score=normalized_score,
                affected_component=f"{target}:{entry.get('port')}",
                evidence=json.dumps({
                    "port": entry.get("port"),
                    "service": entry.get("service"),
                    "banner": entry.get("banner"),
                    "response_time_ms": entry.get("response_time_ms"),
                }),
            )
            db.session.add(finding)

    db.session.commit()
    return scan


def _persist_subnet_scan(
    cidr: str,
    open_ports: list[dict],
) -> Scan:
    """Write a subnet sweep Scan record to SQLite."""
    now = datetime.datetime.utcnow()
    scan = Scan(
        scan_type="network_subnet",
        target=cidr,
        status="completed",
        started_at=now,
        completed_at=now,
        user_id=current_user.id if current_user.is_authenticated else None,
    )
    db.session.add(scan)
    db.session.flush()

    for entry in open_ports:
        result = ScanResult(
            scan_id=scan.id,
            component_name="subnet_port_scan",
            raw_data_json=json.dumps(entry),
            status="ok",
        )
        db.session.add(result)

        sev = entry.get("severity", "INFO")
        if sev not in (None, "INFO"):
            normalized_score = round(entry.get("risk_score", 50) / 10, 1)
            finding = Finding(
                scan_id=scan.id,
                category="network",
                title=f"Open port {entry.get('port')} on {entry.get('host')}",
                description=entry.get("explanation", ""),
                severity=sev,
                risk_score=normalized_score,
                affected_component=f"{entry.get('host')}:{entry.get('port')}",
                evidence=json.dumps({
                    "host": entry.get("host"),
                    "port": entry.get("port"),
                    "service": entry.get("service"),
                }),
            )
            db.session.add(finding)

    db.session.commit()
    return scan


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@network_bp.route("/", methods=["GET"])
@login_required
def index():
    recent_scans = (
        Scan.query.filter_by(scan_type="network_host")
        .order_by(Scan.started_at.desc())
        .limit(10)
        .all()
    )
    subnet_scans = (
        Scan.query.filter_by(scan_type="network_subnet")
        .order_by(Scan.started_at.desc())
        .limit(5)
        .all()
    )
    return render_template(
        "network/index.html",
        common_ports=COMMON_PORTS,
        recent_scans=recent_scans,
        subnet_scans=subnet_scans,
    )


@network_bp.route("/scan", methods=["POST"])
@login_required
def scan():
    # --- Authorization gate -------------------------------------------
    if not request.form.get("authorised"):
        flash(
            "You must confirm that you are authorised to scan the target before proceeding.",
            "danger",
        )
        return redirect(url_for("network.index"))

    scan_mode = request.form.get("scan_mode", "host")
    target_raw = request.form.get("target", "").strip()
    timeout_raw = request.form.get("timeout", "1.0")

    try:
        timeout = float(timeout_raw)
        timeout = max(0.3, min(timeout, 5.0))
    except (ValueError, TypeError):
        timeout = 1.0

    # -----------------------------------------------------------------
    # Host scan
    # -----------------------------------------------------------------
    if scan_mode == "host":
        if not target_raw:
            flash("Please enter a target IP address or hostname.", "warning")
            return redirect(url_for("network.index"))

        if not (is_valid_ip(target_raw) or _is_valid_hostname(target_raw)):
            flash(f"'{target_raw}' is not a valid IP address or hostname.", "danger")
            return redirect(url_for("network.index"))

        resolved = _resolve_host(target_raw)
        if resolved is None:
            flash(f"Could not resolve '{target_raw}' to an IP address.", "danger")
            return redirect(url_for("network.index"))

        ok, reason = is_safe_target(resolved)
        if not ok:
            flash(f"Scan blocked: {reason}", "danger")
            return redirect(url_for("network.index"))

        open_ports = _SCANNER.scan_host(resolved, timeout=timeout, open_only=True)

        for entry in open_ports:
            banner = grab_banner(resolved, entry["port"], timeout=min(timeout * 2, 3.0))
            entry["banner"] = banner
            cls = classify_port_risk(entry["port"], entry["state"], banner)
            entry.update(cls)

        scan_record = _persist_host_scan(resolved, open_ports)

        open_ports.sort(
            key=lambda r: SEVERITY_ORDER.get(r.get("severity", "INFO"), 99)
        )

        return render_template(
            "network/results.html",
            target=target_raw,
            resolved=resolved,
            results=open_ports,
            scan_id=scan_record.id,
            scan_mode="host",
        )

    # -----------------------------------------------------------------
    # Subnet sweep
    # -----------------------------------------------------------------
    elif scan_mode == "subnet":
        if not target_raw:
            flash("Please enter a CIDR subnet (e.g. 192.168.1.0/24).", "warning")
            return redirect(url_for("network.index"))

        if not is_valid_subnet(target_raw):
            flash(
                f"'{target_raw}' is not a valid private (RFC 1918) CIDR block.",
                "danger",
            )
            return redirect(url_for("network.index"))

        try:
            raw_results = scan_subnet(target_raw, timeout=timeout)
        except ValueError as exc:
            flash(str(exc), "danger")
            return redirect(url_for("network.index"))

        for entry in raw_results:
            if entry.get("state") == "open" and entry.get("port"):
                cls = classify_port_risk(entry["port"], entry["state"])
                entry.update(cls)

        open_only = [e for e in raw_results if e.get("state") == "open"]
        scan_record = _persist_subnet_scan(target_raw, open_only)

        return render_template(
            "network/results.html",
            target=target_raw,
            resolved=None,
            results=raw_results,
            scan_id=scan_record.id,
            scan_mode="subnet",
        )

    flash("Invalid scan mode selected.", "warning")
    return redirect(url_for("network.index"))
