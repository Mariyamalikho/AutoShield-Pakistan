import uuid
from datetime import datetime, timezone
from app.extensions import db


class Finding(db.Model):
    __tablename__ = "findings"

    id = db.Column(db.Integer, primary_key=True)
    finding_uid = db.Column(
        db.String(36),
        unique=True,
        nullable=False,
        default=lambda: str(uuid.uuid4()),
        index=True,
    )
    scan_id = db.Column(db.Integer, db.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    category = db.Column(
        db.String(32),
        nullable=False,
        index=True,
    )  # network, system, password, browser, software, malware
    title = db.Column(db.String(255), nullable=False)
    severity = db.Column(
        db.String(16),
        nullable=False,
        index=True,
    )  # CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL
    risk_score = db.Column(db.Float, default=0.0, nullable=False)  # 0.0 - 10.0 scale
    description = db.Column(db.Text, nullable=False)
    evidence = db.Column(db.Text, nullable=True)
    affected_component = db.Column(db.String(255), nullable=False)
    status = db.Column(
        db.String(20),
        default="open",
        nullable=False,
        index=True,
    )  # open, acknowledged, remediated, false_positive
    detected_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    # Relationships
    scan = db.relationship("Scan", back_populates="findings")
    remediations = db.relationship(
        "Remediation", back_populates="finding", cascade="all, delete-orphan", lazy="dynamic"
    )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "finding_uid": self.finding_uid,
            "scan_id": self.scan_id,
            "category": self.category,
            "title": self.title,
            "severity": self.severity,
            "risk_score": self.risk_score,
            "description": self.description,
            "evidence": self.evidence,
            "affected_component": self.affected_component,
            "status": self.status,
            "detected_at": self.detected_at.isoformat() if self.detected_at else None,
        }

    def __repr__(self) -> str:
        return f"<Finding [{self.severity}] {self.title[:30]}>"
