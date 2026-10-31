"""
Camada de persistência do Sentinela.
SQLite por padrão (zero setup); troque DATABASE_URL por uma Postgres em produção.
"""
import os
from datetime import datetime, timezone
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Float, Text
from sqlalchemy.orm import declarative_base, sessionmaker

DATABASE_URL = os.environ.get("SENTINELA_DB_URL", "sqlite:///sentinela.db")

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {},
)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()


def utcnow():
    return datetime.now(timezone.utc)


class Event(Base):
    """Evento normalizado: vem de logs (SIEM) ou de pacotes de rede (sniffer)."""
    __tablename__ = "events"

    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=utcnow, index=True)
    source = Column(String(50), index=True)     # ex: "auth_log", "network", "nginx_log"
    src_ip = Column(String(45), index=True)
    dst_ip = Column(String(45), nullable=True)
    dst_port = Column(Integer, nullable=True)
    user = Column(String(100), nullable=True)
    action = Column(String(100))                 # ex: "ssh_login_failed", "tcp_syn", "http_request"
    outcome = Column(String(20), nullable=True)   # "success" | "failure" | None
    raw = Column(Text, nullable=True)             # linha original / detalhe bruto


class Alert(Base):
    """Alerta gerado pelo motor de detecção a partir de um ou mais Events."""
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=utcnow, index=True)
    rule = Column(String(100), index=True)        # nome da regra que disparou
    mitre_id = Column(String(20), nullable=True)  # ex: "T1110" (brute force)
    severity = Column(String(20))                 # low | medium | high | critical
    src_ip = Column(String(45), index=True)
    description = Column(Text)
    status = Column(String(20), default="open")   # open | mitigated | ignored


class Vulnerability(Base):
    """Resultado do scanner: porta/serviço/versão e possível CVE associado."""
    __tablename__ = "vulnerabilities"

    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=utcnow, index=True)
    host = Column(String(100), index=True)
    port = Column(Integer)
    service = Column(String(100), nullable=True)
    banner = Column(Text, nullable=True)
    cve_id = Column(String(30), nullable=True)
    severity = Column(String(20), nullable=True)
    cvss = Column(Float, nullable=True)
    description = Column(Text, nullable=True)


class ResponseAction(Base):
    """Log de toda ação de resposta ativa tomada (dentro do próprio perímetro)."""
    __tablename__ = "response_actions"

    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=utcnow, index=True)
    alert_id = Column(Integer, nullable=True)
    action = Column(String(100))   # ex: "ban_ip", "isolate_host"
    target = Column(String(100))
    result = Column(String(20))    # "applied" | "dry_run" | "failed"
    detail = Column(Text, nullable=True)


def init_db():
    Base.metadata.create_all(engine)
