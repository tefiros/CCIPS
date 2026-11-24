import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from controller_i2nsf.algorithm_config_store import (
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


if __name__ == "__main__":
    unittest.main()
