from datetime import datetime, timezone
from app.extensions import db


class Asset(db.Model):
    __tablename__ = "assets"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), nullable=False)
    asset_type = db.Column(db.String(32), default="host", nullable=False)  # host, subnet, web_app, local_system
    ip_address = db.Column(db.String(45), nullable=True)  # Supports IPv4 and IPv6
    mac_address = db.Column(db.String(17), nullable=True)
    hostname = db.Column(db.String(255), nullable=True)
    os_info = db.Column(db.String(255), nullable=True)
    environment = db.Column(db.String(64), default="Internal", nullable=False)  # Lab, SME, Classroom, Production
    description = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = db.Column(
        db.DateTime,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # Relationships
    scans = db.relationship("Scan", back_populates="asset", cascade="all, delete-orphan", lazy="dynamic")

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "asset_type": self.asset_type,
            "ip_address": self.ip_address,
            "mac_address": self.mac_address,
            "hostname": self.hostname,
            "os_info": self.os_info,
            "environment": self.environment,
            "description": self.description,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }

    def __repr__(self) -> str:
        return f"<Asset {self.name} ({self.ip_address or self.hostname})>"
