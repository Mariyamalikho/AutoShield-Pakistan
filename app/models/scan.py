import uuid
from datetime import datetime, timezone
from app.extensions import db


class Scan(db.Model):
    __tablename__ = "scans"

    id = db.Column(db.Integer, primary_key=True)
    scan_uid = db.Column(
        db.String(36),
        unique=True,
        nullable=False,
        default=lambda: str(uuid.uuid4()),
        index=True,
    )
    scan_type = db.Column(
        db.String(32),
        nullable=False,
    )  # network, system, password, browser, software, malware, comprehensive
    target = db.Column(db.String(255), nullable=False)
    status = db.Column(
        db.String(20),
        default="pending",
        nullable=False,
    )  # pending, running, completed, failed, cancelled
    asset_id = db.Column(db.Integer, db.ForeignKey("assets.id", ondelete="SET NULL"), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    
    started_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    completed_at = db.Column(db.DateTime, nullable=True)
    execution_time_sec = db.Column(db.Float, default=0.0, nullable=False)
    configuration_json = db.Column(db.Text, nullable=True)
    error_message = db.Column(db.Text, nullable=True)

    # Relationships
    asset = db.relationship("Asset", back_populates="scans")
    user = db.relationship("User", back_populates="scans")
    findings = db.relationship("Finding", back_populates="scan", cascade="all, delete-orphan", lazy="dynamic")
    results = db.relationship("ScanResult", back_populates="scan", cascade="all, delete-orphan", lazy="dynamic")

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "scan_uid": self.scan_uid,
            "scan_type": self.scan_type,
            "target": self.target,
            "status": self.status,
            "asset_id": self.asset_id,
            "user_id": self.user_id,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "execution_time_sec": round(self.execution_time_sec, 2),
            "findings_count": self.findings.count(),
        }

    def __repr__(self) -> str:
        return f"<Scan {self.scan_uid[:8]} ({self.scan_type} -> {self.target})>"


class ScanResult(db.Model):
    __tablename__ = "scan_results"

    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    component_name = db.Column(db.String(64), nullable=False)  # port_scan, process_list, yara_match, etc.
    raw_data_json = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), default="ok", nullable=False)
    recorded_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    # Relationships
    scan = db.relationship("Scan", back_populates="results")

    def __repr__(self) -> str:
        return f"<ScanResult scan_id={self.scan_id} component={self.component_name}>"
