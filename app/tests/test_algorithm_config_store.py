import json
import sqlite3
import tempfile
import time
import unittest
import uuid
from pathlib import Path

from controller_i2nsf.algorithm_config_store import (
    AlgorithmConfigInUse,
    PendingAlgorithmConfigExists,
    PendingAlgorithmConfigStore,
)


class PendingAlgorithmConfigStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "algorithm_configs.sqlite3"
        self.store = PendingAlgorithmConfigStore(self.db_path)
        self.payload = {
            "use-qkd": "yes",
            "pqc-algorithm": "kyber-512",
            "hybridization-method": "xor",
            "endpoint1": "192.0.2.10",
            "endpoint2": "192.0.2.20",
        }

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_saves_pending_configuration_to_sqlite(self):
        config_id = self.store.save(self.payload)

        with sqlite3.connect(self.db_path) as connection:
            row = connection.execute(
                """
                SELECT id, endpoint_a, endpoint_b, payload, status
                FROM pending_algorithm_configs
                """
            ).fetchone()

        self.assertEqual(row[0], config_id)
        self.assertEqual(row[1:3], ("192.0.2.10", "192.0.2.20"))
        self.assertEqual(json.loads(row[3]), self.payload)
        self.assertEqual(row[4], "pending")

    def test_duplicate_pair_is_rejected_regardless_of_order(self):
        self.store.save(self.payload)
        reversed_payload = {
            **self.payload,
            "endpoint1": self.payload["endpoint2"],
            "endpoint2": self.payload["endpoint1"],
        }

        with self.assertRaises(PendingAlgorithmConfigExists):
            self.store.save(reversed_payload)

    def test_reserve_consume_and_reset(self):
        config_id = self.store.save(self.payload)
        self.assertEqual(self.store.reserve("192.0.2.20", " 192.0.2.10 "), config_id)
        with self.assertRaises(AlgorithmConfigInUse):
            self.store.reserve("192.0.2.10", "192.0.2.20")

        tunnel_id = uuid.uuid4()
        self.store.save_tunnel(tunnel_id, {"method": "http"}, {"handler ID": str(tunnel_id)}, config_id)
        self.assertEqual(self.store.get_tunnel(tunnel_id), {"handler ID": str(tunnel_id)})
        self.assertEqual(self.store.get_tunnel_ids(), [tunnel_id])
        with sqlite3.connect(self.db_path) as connection:
            row = connection.execute("SELECT algorithm_config FROM tunnels").fetchone()
            self.assertEqual(json.loads(row[0]), self.payload)
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM pending_algorithm_configs").fetchone()[0], 0)
            connection.execute("CREATE TABLE unrelated (value TEXT)")
            connection.execute("INSERT INTO unrelated VALUES ('preserved')")

        self.store.reset()
        self.assertEqual(self.store.get_tunnel_ids(), [])
        with sqlite3.connect(self.db_path) as connection:
            self.assertEqual(connection.execute("SELECT value FROM unrelated").fetchone()[0], "preserved")

    def test_release_and_expiration(self):
        config_id = self.store.save(self.payload)
        self.assertEqual(self.store.reserve("192.0.2.10", "192.0.2.20"), config_id)
        self.store.release(config_id)
        self.assertEqual(self.store.reserve("192.0.2.20", "192.0.2.10"), config_id)
        with sqlite3.connect(self.db_path) as connection:
            connection.execute(
                "UPDATE pending_algorithm_configs SET expires_at = ? WHERE id = ?",
                (time.time() - 1, config_id),
            )
        self.store.release(config_id)
        self.assertIsNone(self.store.reserve("192.0.2.10", "192.0.2.20"))
        self.store.save(self.payload)

    def test_expired_pending_configuration_is_not_reserved(self):
        config_id = self.store.save(self.payload)
        with sqlite3.connect(self.db_path) as connection:
            connection.execute(
                "UPDATE pending_algorithm_configs SET expires_at = ? WHERE id = ?",
                (time.time() - 1, config_id),
            )
        self.assertIsNone(self.store.reserve("192.0.2.20", "192.0.2.10"))
        self.store.save(self.payload)

    def test_failed_tunnel_insert_does_not_consume_reservation(self):
        config_id = self.store.save(self.payload)
        self.store.reserve("192.0.2.10", "192.0.2.20")
        tunnel_id = uuid.uuid4()
        self.store.save_tunnel(tunnel_id, {}, {}, None)
        with self.assertRaises(sqlite3.IntegrityError):
            self.store.save_tunnel(tunnel_id, {}, {}, config_id)
        self.store.release(config_id)
        self.assertEqual(self.store.reserve("192.0.2.10", "192.0.2.20"), config_id)


if __name__ == "__main__":
    unittest.main()
