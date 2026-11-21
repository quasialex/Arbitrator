import os
from pathlib import Path
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker
from app.models import Base


def database_url() -> str:
    raw = os.getenv("ASSESSMENT_DB_URL")
    if raw:
        return raw
    path = Path(__file__).resolve().parents[1] / "assessment_v015.sqlite3"
    return "sqlite:///" + str(path)


engine = create_engine(database_url(), connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


@event.listens_for(engine, "connect")
def enforce_sqlite_foreign_keys(dbapi_connection, _):
    if engine.url.get_backend_name() == "sqlite":
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()


def init_db() -> None:
    Base.metadata.create_all(bind=engine)
    # Additive compatibility migration for existing v0.13 SQLite copies.
    # Take a database backup before upgrade; never drop existing columns.
    if engine.url.get_backend_name() == "sqlite":
        from sqlalchemy import inspect
        columns = {c["name"] for c in inspect(engine).get_columns("servicenow_group_mappings")}
        with engine.begin() as conn:
            for column, max_length in (("group_name", 200), ("group_email", 255)):
                if column not in columns:
                    conn.exec_driver_sql(f"ALTER TABLE servicenow_group_mappings ADD COLUMN {column} VARCHAR({max_length}) NOT NULL DEFAULT ''")


def get_session():
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()
