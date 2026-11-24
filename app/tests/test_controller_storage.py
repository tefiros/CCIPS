import json
import os
import sqlite3
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from flask import Flask
from lxml import etree
from ncclient.operations import RPCError

from controller_i2nsf.handler import Handler, StorageHandler
from controller_i2nsf.templates import load_templates
from nbi_swagger.routers import new_router
from sbi import ssh_netconf


class FakeConfig:
    def parse_config_to_nbi_swagger(self, handler_id):
        return {"handler ID": handler_id, "status": "Deployed"}


class FakeHandler:
    def __init__(self, request, handler_id):
        self.cfg = [FakeConfig(), FakeConfig()]
        self.is_stopped = False
        self.cleanup_failed = False

    def set_initial_config_values(self):
        return True

    def stop(self):
        self.is_stopped = True
        return None


class ControllerStorageTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "controller.sqlite3"
        self.env = patch.dict(os.environ, {"CCIPS_ALGORITHM_DB_PATH": str(self.db_path)})
        self.env.start()
        self.addCleanup(self.env.stop)
        self.addCleanup(self.temp_dir.cleanup)
        self.storage = StorageHandler()
        self.app = Flask(__name__)
        self.app.register_blueprint(new_router(self.storage))
        self.client = self.app.test_client()
        self.algorithm = {
            "use-qkd": "yes",
            "pqc-algorithm": "kyber-512",
            "hybridization-method": "xor",
            "endpoint1": "192.0.2.10",
            "endpoint2": "192.0.2.20",
        }
        self.tunnel = {
            "nodes": [
                {"ipControl": "192.0.2.20", "ipData": "198.51.100.20"},
                {"ipControl": "192.0.2.10", "ipData": "198.51.100.10"},
            ],
            "encAlg": ["aes-cbc"],
            "intAlg": ["sha2-256"],
        }

    @patch("controller_i2nsf.handler.Handler", FakeHandler)
    def test_http_create_status_list_delete_and_restart(self):
        self.assertEqual(self.client.post("/configure_algorithm", json=self.algorithm).status_code, 200)
        response = self.client.post("/ccips", json=self.tunnel)
        self.assertEqual(response.status_code, 200, response.get_json())
        tunnel_id = response.get_json()["handler ID"]
        self.assertEqual(self.client.get(f"/ccips/{tunnel_id}").get_json(), response.get_json())
        self.assertEqual(self.client.get("/ccips-all").get_json(), [tunnel_id])
        with sqlite3.connect(self.db_path) as connection:
            row = connection.execute("SELECT request, algorithm_config FROM tunnels").fetchone()
            self.assertEqual(json.loads(row[0])["nodes"][0]["ipControl"], "192.0.2.20")
            self.assertEqual(json.loads(row[1]), self.algorithm)
        self.assertEqual(self.client.delete(f"/ccips/{tunnel_id}").status_code, 200)
        self.assertEqual(self.client.get(f"/ccips/{tunnel_id}").status_code, 400)
        self.assertEqual(self.client.get("/ccips-all").get_json(), [])

        self.assertEqual(self.client.post("/configure_algorithm", json=self.algorithm).status_code, 200)
        self.assertEqual(self.client.post("/ccips", json=self.tunnel).status_code, 200)
        self.assertEqual(self.client.post("/configure_algorithm", json=self.algorithm).status_code, 200)
        restarted = StorageHandler()
        self.assertEqual(restarted.get_all_ids(), ([], None))
        with sqlite3.connect(self.db_path) as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM pending_algorithm_configs").fetchone()[0], 0)

    @patch("controller_i2nsf.handler.Handler", FakeHandler)
    def test_tunnel_without_algorithm_configuration(self):
        response = self.client.post("/ccips", json=self.tunnel)
        self.assertEqual(response.status_code, 200, response.get_json())
        with sqlite3.connect(self.db_path) as connection:
            self.assertIsNone(connection.execute("SELECT algorithm_config FROM tunnels").fetchone()[0])

    def test_failure_releases_reservation_and_reports_cleanup_error(self):
        class FailingHandler(FakeHandler):
            def set_initial_config_values(self):
                return False

            def stop(self):
                return RuntimeError("cleanup failed")

        self.assertEqual(self.client.post("/configure_algorithm", json=self.algorithm).status_code, 200)
        with patch("controller_i2nsf.handler.Handler", FailingHandler):
            response = self.client.post("/ccips", json=self.tunnel)
        self.assertEqual(response.status_code, 400)
        self.assertIn("cleanup failed", response.get_json()["error"])
        self.assertEqual(self.client.get("/ccips-all").get_json(), [])
        with patch("controller_i2nsf.handler.Handler", FakeHandler):
            self.assertEqual(self.client.post("/ccips", json=self.tunnel).status_code, 200)

    def test_concurrent_tunnel_creation_does_not_reuse_reservation(self):
        started = threading.Event()
        proceed = threading.Event()
        result = []

        class BlockingHandler(FakeHandler):
            def set_initial_config_values(self):
                started.set()
                if not proceed.wait(5):
                    raise RuntimeError("Timed out waiting for test")
                return True

        self.client.post("/configure_algorithm", json=self.algorithm)

        def create_tunnel():
            with self.app.test_client() as client:
                result.append(client.post("/ccips", json=self.tunnel).status_code)

        with patch("controller_i2nsf.handler.Handler", BlockingHandler):
            thread = threading.Thread(target=create_tunnel)
            thread.start()
            try:
                self.assertTrue(started.wait(5))
                self.assertEqual(self.client.post("/ccips", json=self.tunnel).status_code, 409)
            finally:
                proceed.set()
                thread.join(5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(result, [200])

    def test_database_failure_compensates_and_releases_config(self):
        self.assertEqual(self.client.post("/configure_algorithm", json=self.algorithm).status_code, 200)
        with patch("controller_i2nsf.handler.Handler", FakeHandler), patch.object(
            self.storage.pending_algorithm_configs, "save_tunnel", side_effect=sqlite3.OperationalError("disk error")
        ):
            response = self.client.post("/ccips", json=self.tunnel)
        self.assertEqual(response.status_code, 400)
        self.assertIn("disk error", response.get_json()["error"])
        self.assertEqual(self.storage.handlers, {})
        with patch("controller_i2nsf.handler.Handler", FakeHandler):
            self.assertEqual(self.client.post("/ccips", json=self.tunnel).status_code, 200)

    @patch("controller_i2nsf.handler.time.sleep")
    @patch("controller_i2nsf.handler.ssh_netconf.create_notification_stream", return_value=None)
    @patch("controller_i2nsf.handler.ssh_netconf.establish_session")
    @patch("controller_i2nsf.handler.ssh_netconf.edit_config", return_value=True)
    def test_real_handler_persists_and_deletes_tunnel(
        self, edit_config, establish_session, create_notification_stream, sleep
    ):
        establish_session.side_effect = lambda *args: MagicMock()
        load_templates(str(Path(__file__).resolve().parents[1] / "templates"))
        self.assertEqual(self.client.post("/configure_algorithm", json=self.algorithm).status_code, 200)
        response = self.client.post("/ccips", json=self.tunnel)
        self.assertEqual(response.status_code, 200, response.get_json())
        tunnel_id = response.get_json()["handler ID"]
        self.assertEqual(self.client.get(f"/ccips/{tunnel_id}").get_json(), response.get_json())
        self.assertEqual(edit_config.call_count, 4)
        self.assertEqual(self.client.delete(f"/ccips/{tunnel_id}").status_code, 200)
        self.assertEqual(edit_config.call_count, 12)
        self.assertEqual(self.client.get("/ccips-all").get_json(), [])

    @patch("controller_i2nsf.handler.Handler", FakeHandler)
    def test_failed_delete_keeps_the_tunnel(self):
        response = self.client.post("/ccips", json=self.tunnel)
        tunnel_id = response.get_json()["handler ID"]
        active = next(iter(self.storage.handlers.values()))
        with patch.object(active, "stop", return_value=RuntimeError("remote delete failed")):
            response = self.client.delete(f"/ccips/{tunnel_id}")
        self.assertEqual(response.status_code, 400)
        self.assertIn("remote delete failed", response.get_json()["error"])
        self.assertEqual(self.client.get("/ccips-all").get_json(), [tunnel_id])

    @patch("controller_i2nsf.handler.Handler", FakeHandler)
    def test_database_delete_failure_keeps_stopped_handler_for_retry(self):
        created = self.client.post("/ccips", json=self.tunnel)
        tunnel_id = created.get_json()["handler ID"]
        with patch.object(
            self.storage.pending_algorithm_configs, "delete_tunnel", side_effect=sqlite3.OperationalError("disk error")
        ):
            response = self.client.delete(f"/ccips/{tunnel_id}")
        self.assertEqual(response.status_code, 400)
        self.assertEqual(self.client.get(f"/ccips/{tunnel_id}").status_code, 400)
        self.assertEqual(self.client.get("/ccips-all").get_json(), [tunnel_id])
        self.assertEqual(self.client.delete(f"/ccips/{tunnel_id}").status_code, 200)

    @patch("controller_i2nsf.handler.ssh_netconf.establish_session")
    def test_failed_session_setup_closes_open_sessions_and_releases_config(self, establish_session):
        opened_session = MagicMock()
        establish_session.side_effect = [opened_session, RuntimeError("connection failed")]
        self.client.post("/configure_algorithm", json=self.algorithm)
        response = self.client.post("/ccips", json=self.tunnel)
        self.assertEqual(response.status_code, 400)
        self.assertIn("connection failed", response.get_json()["error"])
        opened_session.close_session.assert_called_once()
        with patch("controller_i2nsf.handler.Handler", FakeHandler):
            self.assertEqual(self.client.post("/ccips", json=self.tunnel).status_code, 200)

    @patch("controller_i2nsf.handler.time.sleep")
    @patch("controller_i2nsf.handler.ssh_netconf.create_notification_stream", return_value=None)
    @patch("controller_i2nsf.handler.ssh_netconf.establish_session")
    @patch("controller_i2nsf.handler.ssh_netconf.edit_config", return_value=True)
    def test_partial_remote_delete_is_not_reported_as_deployed(
        self, edit_config, establish_session, create_notification_stream, sleep
    ):
        establish_session.side_effect = lambda *args: MagicMock()
        load_templates(str(Path(__file__).resolve().parents[1] / "templates"))
        created = self.client.post("/ccips", json=self.tunnel)
        self.assertEqual(created.status_code, 200, created.get_json())
        tunnel_id = created.get_json()["handler ID"]
        edit_config.return_value = False
        self.assertEqual(self.client.delete(f"/ccips/{tunnel_id}").status_code, 400)
        self.assertEqual(self.client.get(f"/ccips/{tunnel_id}").status_code, 400)
        edit_config.return_value = True
        self.assertEqual(self.client.delete(f"/ccips/{tunnel_id}").status_code, 200)

    def test_netconf_rpc_error_is_not_treated_as_success(self):
        session = MagicMock()
        session.edit_config.side_effect = RPCError(
            etree.fromstring(
                b"<rpc-error><error-type>application</error-type>"
                b"<error-tag>operation-failed</error-tag><error-severity>error</error-severity>"
                b"</rpc-error>"
            )
        )
        self.assertFalse(ssh_netconf.edit_config(session, "<config/>"))

    def test_unsupported_remote_delete_reports_error(self):
        handler = Handler.__new__(Handler)
        handler.locker = threading.RLock()
        handler.is_stopped = False
        handler.method = "http"
        self.assertIn("not implemented", str(handler.stop()))

    def test_controller_startup_resets_existing_database(self):
        from main import main

        self.storage.save_pending_algorithm_config(self.algorithm)
        with patch("main.load_templates"), patch("flask.Flask.run") as run:
            main()
        run.assert_called_once()
        with sqlite3.connect(self.db_path) as connection:
            self.assertEqual(
                connection.execute("SELECT COUNT(*) FROM pending_algorithm_configs").fetchone()[0],
                0,
            )


if __name__ == "__main__":
    unittest.main()
