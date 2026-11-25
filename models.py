import datetime as dt, enum
from sqlalchemy import String, Integer, ForeignKey, DateTime, Text, Boolean
from sqlalchemy.orm import Mapped, mapped_column, relationship
from .db import Base

def now():
    return dt.datetime.now(dt.timezone.utc)

class Role(str, enum.Enum):
    owner = "owner"; admin = "admin"; geologist = "geologist"; viewer = "viewer"

class DataClass(str, enum.Enum):
    """Scientific-integrity labels required by the spec on every dataset/result."""
    MEASURED = "MEASURED"; IMPORTED = "IMPORTED"; DERIVED = "DERIVED"
    PREDICTED = "PREDICTED"; SIMULATED = "SIMULATED"

class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(16))
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    failed_logins: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=now)

class Project(Base):
    __tablename__ = "projects"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(200))
    description: Mapped[str] = mapped_column(Text, default="")
    crs: Mapped[str] = mapped_column(String(64), default="")  # e.g. EPSG:32636; empty = not yet set
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=now)
    datasets = relationship("Dataset", back_populates="project", cascade="all, delete-orphan")

class Dataset(Base):
    __tablename__ = "datasets"
    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"))
    name: Mapped[str] = mapped_column(String(200))
    method: Mapped[str] = mapped_column(String(64))       # e.g. ERT, GPR, magnetics, gravity, seismic, borehole
    data_class: Mapped[str] = mapped_column(String(16))
    source: Mapped[str] = mapped_column(Text)              # provenance: instrument, operator, survey date, or derivation
    filename: Mapped[str] = mapped_column(String(255), default="")
    sha256: Mapped[str] = mapped_column(String(64), default="")
    size_bytes: Mapped[int] = mapped_column(Integer, default=0)
    created_by: Mapped[int] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=now)
    project = relationship("Project", back_populates="datasets")

class AuditLog(Base):
    __tablename__ = "audit_log"
    id: Mapped[int] = mapped_column(primary_key=True)
    ts: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=now)
    user_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    action: Mapped[str] = mapped_column(String(64))
    detail: Mapped[str] = mapped_column(Text, default="")

class License(Base):
    """Scaffold only. No payment processing, no activation server (spec: do not activate until authorized)."""
    __tablename__ = "licenses"
    id: Mapped[int] = mapped_column(primary_key=True)
    tier: Mapped[str] = mapped_column(String(32))   # individual/professional/enterprise/subscription
    holder: Mapped[str] = mapped_column(String(200))
    device_id: Mapped[str] = mapped_column(String(128), default="")
    expires_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    active: Mapped[bool] = mapped_column(Boolean, default=False)
