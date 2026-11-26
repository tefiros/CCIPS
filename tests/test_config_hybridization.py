import sys
import unittest
from pathlib import Path

from flask import Flask

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "app"))

from nbi_swagger.routers import new_router


class ConfigHybridizationTest(unittest.TestCase):
    def setUp(self):
        app = Flask(__name__)
        app.register_blueprint(new_router(object()))
        self.client = app.test_client()
        self.config = {
            "use-qkd": "yes",
            "pqc-algorithm": "kyber-512",
            "hybridization-method": "xor",
            "endpoint1": "192.168.159.35",
            "endpoint2": "192.168.159.21",
        }

    def post(self, config):
        return self.client.post("/ccips/config-hybridization", json=config)

    def test_default_and_explicit_method(self):
        response = self.post(self.config)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json(), {**self.config, "method": "http"})

        response = self.post({**self.config, "method": "https"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["method"], "https")

    def test_required_fields(self):
        for field in self.config:
            with self.subTest(field=field):
                config = self.config.copy()
                del config[field]
                self.assertEqual(self.post(config).status_code, 400)

    def test_invalid_fields(self):
        for field, value in (
            ("use-qkd", "maybe"),
            ("pqc-algorithm", ""),
            ("hybridization-method", "invalid"),
            ("endpoint1", "192.168.1.999"),
            ("endpoint2", 123),
            ("method", None),
            ("method", ""),
        ):
            with self.subTest(field=field, value=value):
                response = self.post({**self.config, field: value})
                self.assertEqual(response.status_code, 400)
                self.assertIn("error", response.get_json())

    def test_invalid_json_and_non_objects(self):
        for data in ("{", "null", "[]", '"text"'):
            with self.subTest(data=data):
                response = self.client.post(
                    "/ccips/config-hybridization",
                    data=data,
                    content_type="application/json",
                )
                self.assertEqual(response.status_code, 400)
                self.assertIn("error", response.get_json())
        self.assertEqual(self.client.post("/ccips/config-hybridization").status_code, 400)


if __name__ == "__main__":
    unittest.main()
