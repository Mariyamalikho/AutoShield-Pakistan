from datetime import datetime, timezone
from app.extensions import db


class YaraRule(db.Model):
    __tablename__ = "yara_rules"

    id = db.Column(db.Integer, primary_key=True)
    rule_name = db.Column(db.String(128), unique=True, nullable=False, index=True)
    rule_file = db.Column(db.String(128), nullable=False)  # suspicious_files.yar, etc.
    description = db.Column(db.Text, nullable=True)
    severity = db.Column(db.String(16), default="MEDIUM", nullable=False)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    updated_at = db.Column(
        db.DateTime,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "rule_name": self.rule_name,
            "rule_file": self.rule_file,
            "description": self.description,
            "severity": self.severity,
            "is_active": self.is_active,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }

    def __repr__(self) -> str:
        return f"<YaraRule {self.rule_name} (active={self.is_active})>"
