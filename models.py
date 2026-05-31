# models.py
import uuid
import datetime
from sqlalchemy import create_engine, Column, String, Integer, Float, DateTime, Text, inspect, text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

SQLALCHEMY_DATABASE_URL = "sqlite:///./scans.db"

engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine, expire_on_commit=False)
Base = declarative_base()


class Scan(Base):
    __tablename__ = "scans"
    id = Column(String, primary_key=True, index=True, default=lambda: str(uuid.uuid4()))
    target = Column(String)
    user_id = Column(String, index=True)
    session_id = Column(String, index=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    html_code = Column(Text, nullable=True)


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"
    id = Column(String, primary_key=True, index=True, default=lambda: str(uuid.uuid4()))
    scan_id = Column(String, index=True)
    cve_id = Column(String)
    name = Column(String)
    description = Column(Text)
    severity = Column(String)
    cvss_score = Column(Float)
    recommendation = Column(Text)
    advisory_url = Column(String)
    code_snippet = Column(Text, nullable=True)


class VulnerabilityCache(Base):
    __tablename__ = "vuln_cache"
    id = Column(Integer, primary_key=True, autoincrement=True)
    source = Column(String, index=True)
    key = Column(String, index=True)
    payload = Column(Text)
    fetched_at = Column(DateTime, default=datetime.datetime.utcnow)


class User(Base):
    __tablename__ = "users"
    id = Column(String, primary_key=True, index=True, default=lambda: str(uuid.uuid4()))
    username = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)


# Создаём таблицы
Base.metadata.create_all(bind=engine)


def _ensure_column(table_name: str, column_name: str, column_type_sql: str) -> None:
    inspector = inspect(engine)
    existing_columns = {column["name"] for column in inspector.get_columns(table_name)}
    if column_name in existing_columns:
        return

    with engine.begin() as connection:
        connection.execute(text(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_type_sql}"))


_ensure_column("scans", "session_id", "VARCHAR")
_ensure_column("scans", "user_id", "VARCHAR")
_ensure_column("scans", "html_code", "TEXT")
_ensure_column("vulnerabilities", "code_snippet", "TEXT")
_ensure_column("vuln_cache", "source", "VARCHAR")
