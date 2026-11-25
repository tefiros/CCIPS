"""© 2026 Telefónica Innovación Digital 
(mattinantartiko.elorzaforcada@telefonica.com)
(victor.hernandofernandez@telefonica.com)
(laura.dominguez.cespedes@telefonica.com)

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License."""

import ssl
import threading
import time
import requests
import json
import uuid

from logger.log import Logger

log = Logger()


class HttpSession:
    def __init__(self, base_url: str, timeout: int = 20, cert=None):
        context = ssl.create_default_context()
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        CIPHERS = "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY130"
        context.set_ciphers(CIPHERS)
        
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.session = requests.Session()
        self.cert = cert
        self.subscription_running = False

    def close_session(self):
        self.subscription_running = False
        self.session.close()

    def close(self):
        self.close_session()


def establish_session(address: str, port: str):
    print(f"OpenSSL version: {ssl.OPENSSL_VERSION}")
    try:
        if address == "192.168.165.151":
            client_cert = (
                "/home/ubuntu/CCIPS-Python/app/certs_PQC/agent1.crt",
                "/home/ubuntu/CCIPS-Python/app/certs_PQC/agent1.key"
            )
        elif address == "192.168.165.85":
            client_cert = (
                "/home/ubuntu/CCIPS-Python/app/certs_PQC/agent2.crt",
                "/home/ubuntu/CCIPS-Python/app/certs_PQC/agent2.key"
            )
        else:
            # Certificado por defecto
            client_cert = (
                "/home/ubuntu/CCIPS-Python/app/certs/client.crt",
                "/home/ubuntu/CCIPS-Python/app/certs/client.key"
            )

        http_session = HttpSession(
            base_url=f"https://{address}:{port}",
            timeout=20,
            cert=client_cert
        )

        # response = http_session.session.get(
        #     f"{http_session.base_url}/health",
        #     timeout=http_session.timeout,
        #     cert=http_session.cert,
        #     verify="/home/ubuntu/CCIPS-Python/app/certs_PQC/CA.crt"
        # )

        #response.raise_for_status()
        log.info(f"HTTPS session established with {address}:{port}")
        return http_session

    except Exception as e:
        log.error(f"Error establishing HTTPS session with {address}:{port}: {e}")
        return None


def edit_config(session: HttpSession, data: str, handler_id: uuid.UUID) -> bool:
    try:
        if session is None:
            log.error("edit_config recibió una sesión None")
            return False

        decoder = json.JSONDecoder()
        pos = 0

        while pos < len(data):
            while pos < len(data) and data[pos].isspace():
                pos += 1
            if pos >= len(data):
                break

            config_json, consumed = decoder.raw_decode(data, pos)
            response = session.session.post(
                f"{session.base_url}/ipsec-entries",
                json=config_json,
                headers={
                    "X-Handler-ID": str(handler_id)
                },
                timeout=session.timeout,
                cert=session.cert,
                verify="/home/ubuntu/CCIPS-Python/app/certs_PQC/CA.crt"
            )

            response.raise_for_status()
            payload = response.json()
            if payload.get("STATUS") != "OK":
                log.error(f"RPC error: {payload}")
                return False
            pos = consumed
            print("Status:", response.status_code)
            for k, v in response.request.headers.items():
                print(f"{k}: {v}")
            print("Body:", response.text)
        return True

    except Exception as e:
        log.error(f"Error in edit_config: {str(e)}")
        return False


def delete_config(session: HttpSession, data: str, handler_id: uuid.UUID) -> bool:
    try:
        if session is None:
            log.error("delete_config recibió una sesión None")
            return False

        if not data or not data.strip():
            log.warning("delete_config recibió data vacía")
            return True

        decoder = json.JSONDecoder()
        pos = 0
        count = 0

        while pos < len(data):

            while pos < len(data) and data[pos].isspace():
                pos += 1

            if pos >= len(data):
                break

            config_json, pos = decoder.raw_decode(data, pos)
            if "spd-entry" in config_json:
                config_json["spd-entry"].pop("nc:operation", None)
                config_json["spd-entry"].pop("direction", None)
            if "sad-entry" in config_json:
                config_json["sad-entry"].pop("nc:operation", None)
            count += 1

            log.debug(
                "DELETE #%d:\n%s",
                count,
                json.dumps(config_json, indent=2)
            )

            response = session.session.delete(
                f"{session.base_url}/ipsec-entries",
                json=config_json,
                headers={
                    "X-Handler-ID": str(handler_id)
                },
                timeout=session.timeout,
                cert=session.cert,
                verify="/home/ubuntu/CCIPS-Python/app/certs_PQC/CA.crt"
            )

            response.raise_for_status()

        log.debug("Se eliminaron %d entradas", count)

        return True

    except Exception as e:
        log.error(f"DELETE DATA: {repr(data)}")
        log.error(f"Error in delete_config: {str(e)}")
        return False

