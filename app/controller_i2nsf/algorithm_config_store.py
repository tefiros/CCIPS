import ipaddress
import json
import os
import sqlite3
import threading
import time
import uuid
from contextlib import closing
from pathlib import Path
from typing import Dict


DEFAULT_TTL_SECONDS = 60 * 60
DEFAULT_DB_PATH = Path(__file__).resolve().parents[1] / "data" / "algorithm_configs.sqlite3"


class PendingAlgorithmConfigExists(Exception):
    """Raised when an unexpired configuration already exists for an endpoint pair."""


class PendingAlgorithmConfigStore:
    def __init__(self, db_path: str | os.PathLike, ttl_seconds: int = DEFAULT_TTL_SECONDS):
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be greater than zero")

        self.db_path = Path(db_path)
        self.ttl_seconds = ttl_seconds
        self.lock = threading.RLock()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    @classmethod
    def from_environment(cls):
        db_path = os.environ.get("CCIPS_ALGORITHM_DB_PATH", str(DEFAULT_DB_PATH))
        ttl_seconds = int(
            os.environ.get("CCIPS_ALGORITHM_CONFIG_TTL_SECONDS", DEFAULT_TTL_SECONDS)
        )
        return cls(db_path, ttl_seconds)

    def _initialize(self) -> None:
        with closing(sqlite3.connect(self.db_path)) as connection:
            with connection:
                connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS pending_algorithm_configs (
                        id TEXT PRIMARY KEY,
                        endpoint_a TEXT NOT NULL,
                        endpoint_b TEXT NOT NULL,
                        payload TEXT NOT NULL,
                        status TEXT NOT NULL CHECK (
                            status IN ('pending', 'processing', 'applied')
                        ),
                        created_at REAL NOT NULL,
                        expires_at REAL NOT NULL
                    )
                    """
                )
                connection.execute(
                    """
                    CREATE UNIQUE INDEX IF NOT EXISTS
                        idx_pending_algorithm_config_active_endpoints
                    ON pending_algorithm_configs (endpoint_a, endpoint_b)
                    WHERE status IN ('pending', 'processing')
                    """
                )

    @staticmethod
    def _normalize_endpoint(endpoint: str) -> str:
        value = endpoint.strip()
        try:
            return str(ipaddress.ip_address(value))
        except ValueError:
            return value.rstrip(".").casefold()

    def save(self, payload: Dict[str, str]) -> str:
        endpoints = sorted(
            (
                self._normalize_endpoint(payload["endpoint1"]),
                self._normalize_endpoint(payload["endpoint2"]),
            )
        )
        now = time.time()
        config_id = str(uuid.uuid4())

        with self.lock, closing(sqlite3.connect(self.db_path, timeout=5)) as connection:
            try:
                with connection:
                    connection.execute("BEGIN IMMEDIATE")
                    connection.execute(
                        """
                        DELETE FROM pending_algorithm_configs
                        WHERE status = 'pending' AND expires_at <= ?
                        """,
                        (now,),
                    )
                    connection.execute(
                        """
                        INSERT INTO pending_algorithm_configs (
                            id, endpoint_a, endpoint_b, payload, status, created_at, expires_at
                        ) VALUES (?, ?, ?, ?, 'pending', ?, ?)
                        """,
                        (
                            config_id,
                            endpoints[0],
                            endpoints[1],
                            json.dumps(payload),
                            now,
                            now + self.ttl_seconds,
                        ),
                    )
            except sqlite3.IntegrityError as error:
                raise PendingAlgorithmConfigExists(
                    "A pending algorithm configuration already exists for these endpoints"
                ) from error

        return config_id
