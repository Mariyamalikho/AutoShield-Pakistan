from flask import Blueprint, render_template
from flask_login import login_required
from sqlalchemy import func
from app.extensions import db
from app.models.scan import Scan
from app.models.asset import Asset
from app.models.finding import Finding
from app.models.remediation import Remediation

dashboard_bp = Blueprint("dashboard", __name__)


def calculate_posture_score(critical: int, high: int, medium: int, low: int, total_scans: int) -> int | None:
    """
    Calculate an explainable cyber hygiene score (0-100).
    Returns None if no scans have been performed yet (empty state).
    Deductions:
      Critical: -25 points each
      High: -10 points each
      Medium: -4 points each
      Low: -1 point each
    Score is bounded between 0 and 100.
    """
    if total_scans == 0:
        return None

    penalty = (critical * 25) + (high * 10) + (medium * 4) + (low * 1)
    score = max(0, 100 - penalty)
    return score


@dashboard_bp.route("/")
@dashboard_bp.route("/dashboard")
@login_required
def index():
    # 1. Real metrics directly aggregated from SQLite
    total_audits = Scan.query.count()
    total_assets = Asset.query.count()

    # Finding counts by severity
    critical_count = Finding.query.filter_by(severity="CRITICAL").count()
    high_count = Finding.query.filter_by(severity="HIGH").count()
    medium_count = Finding.query.filter_by(severity="MEDIUM").count()
    low_count = Finding.query.filter_by(severity="LOW").count()
    info_count = Finding.query.filter_by(severity="INFORMATIONAL").count()
    total_findings = critical_count + high_count + medium_count + low_count + info_count

    # Remediation progress
    total_remediations = Remediation.query.count()
    completed_remediations = Remediation.query.filter_by(is_completed=True).count()
    remediation_percentage = (
        round((completed_remediations / total_remediations) * 100, 1)
        if total_remediations > 0
        else 0.0
    )

    # Posture score
    posture_score = calculate_posture_score(
        critical_count, high_count, medium_count, low_count, total_audits
    )

    # Latest audit
    latest_audit = Scan.query.order_by(Scan.started_at.desc()).first()

    # Recent scans (limit 8)
    recent_scans = Scan.query.order_by(Scan.started_at.desc()).limit(8).all()

    # Most common vulnerability categories
    top_categories = (
        db.session.query(Finding.category, func.count(Finding.id).label("count"))
        .group_by(Finding.category)
        .order_by(func.count(Finding.id).desc())
        .limit(5)
        .all()
    )

    return render_template(
        "dashboard/index.html",
        total_audits=total_audits,
        total_assets=total_assets,
        critical_count=critical_count,
        high_count=high_count,
        medium_count=medium_count,
        low_count=low_count,
        info_count=info_count,
        total_findings=total_findings,
        total_remediations=total_remediations,
        completed_remediations=completed_remediations,
        remediation_percentage=remediation_percentage,
        posture_score=posture_score,
        latest_audit=latest_audit,
        recent_scans=recent_scans,
        top_categories=top_categories,
    )
