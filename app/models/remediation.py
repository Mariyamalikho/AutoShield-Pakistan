from datetime import datetime, timezone
from app.extensions import db


class Remediation(db.Model):
    __tablename__ = "remediations"

    id = db.Column(db.Integer, primary_key=True)
    finding_id = db.Column(db.Integer, db.ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, index=True)
    
    # 5 Structured Remediation Questions
    what_detected = db.Column(db.Text, nullable=False)
    why_matters = db.Column(db.Text, nullable=False)
    potential_impact = db.Column(db.Text, nullable=False)
    fix_instructions = db.Column(db.Text, nullable=False)
    verification_command = db.Column(db.Text, nullable=True)
    
    platform = db.Column(db.String(32), default="cross-platform", nullable=False)  # windows, linux, cross-platform
    is_completed = db.Column(db.Boolean, default=False, nullable=False)
    verified_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    # Relationships
    finding = db.relationship("Finding", back_populates="remediations")

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "finding_id": self.finding_id,
            "what_detected": self.what_detected,
            "why_matters": self.why_matters,
            "potential_impact": self.potential_impact,
            "fix_instructions": self.fix_instructions,
            "verification_command": self.verification_command,
            "platform": self.platform,
            "is_completed": self.is_completed,
            "verified_at": self.verified_at.isoformat() if self.verified_at else None,
        }

    def __repr__(self) -> str:
        return f"<Remediation for Finding {self.finding_id} (completed={self.is_completed})>"
