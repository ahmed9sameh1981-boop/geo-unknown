import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, DeclarativeBase

DB_URL = os.environ.get("GEO_DB_URL") or os.environ.get("DATABASE_URL") or "sqlite:///./geo_unknown.db"
# Hosts hand out postgres:// or postgresql://; SQLAlchemy needs the driver named.
if DB_URL.startswith("postgres://"):
    DB_URL = "postgresql+psycopg2://" + DB_URL[len("postgres://"):]
elif DB_URL.startswith("postgresql://"):
    DB_URL = "postgresql+psycopg2://" + DB_URL[len("postgresql://"):]
engine = create_engine(DB_URL, pool_pre_ping=True, **({"connect_args": {"check_same_thread": False}} if DB_URL.startswith("sqlite") else {}))
SessionLocal = sessionmaker(bind=engine, autoflush=False)

class Base(DeclarativeBase):
    pass

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
