"""Custom SQLAlchemy types for cross-database compatibility."""
from sqlalchemy import JSON, TypeDecorator


class JSONBCompat(TypeDecorator):
    """JSONB on PostgreSQL, JSON on SQLite/other databases."""
    impl = JSON
    cache_ok = True

    def load_dialect_impl(self, dialect):
        if dialect.name == "postgresql":
            from sqlalchemy.dialects.postgresql import JSONB
            return dialect.type_descriptor(JSONB())
        return dialect.type_descriptor(JSON())
