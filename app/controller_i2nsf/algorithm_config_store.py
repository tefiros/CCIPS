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


class AlgorithmConfigInUse(Exception):
    """Raised when a matching configuration is already being used."""


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
                    CREATE TABLE IF NOT EXISTS tunnels (
                        id TEXT PRIMARY KEY,
                        request TEXT NOT NULL,
                        response TEXT NOT NULL,
                        algorithm_config TEXT
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

    def reset(self) -> None:
        with self.lock, closing(sqlite3.connect(self.db_path, timeout=5)) as connection:
            with connection:
                connection.execute("BEGIN IMMEDIATE")
                connection.execute("DELETE FROM tunnels")
                connection.execute("DELETE FROM pending_algorithm_configs")

    @staticmethod
    def _normalize_endpoint(endpoint: str) -> str:
        value = endpoint.strip()
        try:
            return str(ipaddress.ip_address(value))
        except ValueError:
            return value.rstrip(".").casefold()

    @classmethod
    def _endpoint_pair(cls, endpoint1: str, endpoint2: str):
        return tuple(sorted((cls._normalize_endpoint(endpoint1), cls._normalize_endpoint(endpoint2))))

    def save(self, payload: Dict[str, str]) -> str:
        endpoints = self._endpoint_pair(payload["endpoint1"], payload["endpoint2"])
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

    def reserve(self, endpoint1: str, endpoint2: str):
        endpoints = self._endpoint_pair(endpoint1, endpoint2)
        with self.lock, closing(sqlite3.connect(self.db_path, timeout=5)) as connection:
            with connection:
                connection.execute("BEGIN IMMEDIATE")
                connection.execute(
                    "DELETE FROM pending_algorithm_configs WHERE status = 'pending' AND expires_at <= ?",
                    (time.time(),),
                )
                row = connection.execute(
                    """
                    SELECT id, status FROM pending_algorithm_configs
                    WHERE endpoint_a = ? AND endpoint_b = ?
                      AND status IN ('pending', 'processing')
                    """,
                    endpoints,
                ).fetchone()
                if row is None:
                    return None
                if row[1] == "processing":
                    raise AlgorithmConfigInUse("Algorithm configuration is already being used")
                connection.execute(
                    "UPDATE pending_algorithm_configs SET status = 'processing' WHERE id = ?",
                    (row[0],),
                )
                return row[0]

    def release(self, config_id: str) -> None:
        with self.lock, closing(sqlite3.connect(self.db_path, timeout=5)) as connection:
            with connection:
                connection.execute("BEGIN IMMEDIATE")
                connection.execute(
                    "DELETE FROM pending_algorithm_configs WHERE id = ? AND status = 'processing' AND expires_at <= ?",
                    (config_id, time.time()),
                )
                connection.execute(
                    "UPDATE pending_algorithm_configs SET status = 'pending' WHERE id = ? AND status = 'processing'",
                    (config_id,),
                )

    def save_tunnel(self, tunnel_id: uuid.UUID, request: dict, response: dict, config_id: str = None) -> None:
        with self.lock, closing(sqlite3.connect(self.db_path, timeout=5)) as connection:
            with connection:
                connection.execute("BEGIN IMMEDIATE")
                algorithm_config = None
                if config_id is not None:
                    row = connection.execute(
                        "SELECT payload FROM pending_algorithm_configs WHERE id = ? AND status = 'processing'",
                        (config_id,),
                    ).fetchone()
                    if row is None:
                        raise RuntimeError("Reserved algorithm configuration not found")
                    algorithm_config = row[0]
                connection.execute(
                    "INSERT INTO tunnels (id, request, response, algorithm_config) VALUES (?, ?, ?, ?)",
                    (str(tunnel_id), json.dumps(request), json.dumps(response), algorithm_config),
                )
                if config_id is not None:
                    connection.execute("DELETE FROM pending_algorithm_configs WHERE id = ?", (config_id,))

    def get_tunnel(self, tunnel_id: uuid.UUID):
        with closing(sqlite3.connect(self.db_path, timeout=5)) as connection:
            row = connection.execute(
                "SELECT response FROM tunnels WHERE id = ?", (str(tunnel_id),)
            ).fetchone()
        return json.loads(row[0]) if row else None

    def get_tunnel_ids(self):
        with closing(sqlite3.connect(self.db_path, timeout=5)) as connection:
            rows = connection.execute("SELECT id FROM tunnels ORDER BY rowid").fetchall()
        return [uuid.UUID(row[0]) for row in rows]

    def delete_tunnel(self, tunnel_id: uuid.UUID) -> None:
        with self.lock, closing(sqlite3.connect(self.db_path, timeout=5)) as connection:
            with connection:
                cursor = connection.execute("DELETE FROM tunnels WHERE id = ?", (str(tunnel_id),))
                if cursor.rowcount != 1:
                    raise ValueError(f"Handler {tunnel_id} not found")
