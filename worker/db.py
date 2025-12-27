import os
from contextlib import contextmanager

import psycopg


def _require_env(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise RuntimeError(f"Missing required env var: {name}")
    return value


def get_database_url() -> str:
    return _require_env("DATABASE_URL")


@contextmanager
def get_conn():
    conn = psycopg.connect(get_database_url(), autocommit=False)
    try:
        yield conn
    finally:
        conn.close()
