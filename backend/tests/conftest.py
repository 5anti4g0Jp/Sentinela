"""
Fixtures compartilhadas. Cada teste roda com um SQLite em memória, isolado
— nada toca o banco de verdade (sentinela.db), mesmo rodando os testes na
sua própria máquina com o servidor ligado em outra aba.
"""
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import db as db_module
from db import Base

# Cada módulo fez `from db import SessionLocal` — isso cria uma referência
# LOCAL em cada um (detection.engine.SessionLocal, etc.), independente da
# de db.py. Trocar só db.SessionLocal não afeta os outros, então precisa
# trocar em cada módulo que usa banco.
_MODULES_WITH_SESSIONLOCAL = [
    "db",
    "detection.engine",
    "siem.collector",
    "scanner.vuln_scanner",
    "response.active_response",
]


@pytest.fixture
def session(monkeypatch):
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    TestSession = sessionmaker(bind=engine)

    import importlib
    for mod_name in _MODULES_WITH_SESSIONLOCAL:
        mod = importlib.import_module(mod_name)
        monkeypatch.setattr(mod, "SessionLocal", TestSession)

    s = TestSession()
    yield s
    s.close()
