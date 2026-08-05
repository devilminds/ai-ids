"""Database engine, session, and declarative base."""
import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

# Defaults to a local SQLite file so the project runs with zero setup.
# Set DATABASE_URL=postgresql://user:pass@host:5432/dbname to use Postgres instead.
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./ai_ids.db")

# Render/Heroku-style Postgres URLs use the "postgres://" scheme, but SQLAlchemy
# 1.4+ requires "postgresql://" — rewrite it automatically so hosted DATABASE_URL
# values work without the person needing to know about this gotcha.
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}

engine = create_engine(DATABASE_URL, connect_args=connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    """FastAPI dependency that yields a DB session and always closes it."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

