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

    def close(self):
        self.subscription_running = False
        self.session.close()


def establish_session(address: str, port: str):
    print(f"OpenSSL version: {ssl.OPENSSL_VERSION}")
    try:
        http_session = HttpSession(
            base_url="https://{address}:{port}".format(address=address, port=port),
            timeout=20,
            #cert= ('/home/ubuntu/CCIPS-Python/app/certs_PQC/client.crt', '/home/ubuntu/CCIPS-Python/app/certs_PQC/client.key')
            cert= ('/home/ubuntu/CCIPS-Python/app/certs/client.crt', '/home/ubuntu/CCIPS-Python/app/certs/client.key')
        )

        response = http_session.session.get(
            f"{http_session.base_url}/health",
            timeout=http_session.timeout,
            cert=http_session.cert,
            #verify="/home/ubuntu/CCIPS-Python/app/certs_PQC/CA.crt"
            verify="/home/ubuntu/CCIPS-Python/app/certs/CA.crt"
        )
        response.raise_for_status()

        log.info(f"HTTPS session established with {address}:{port}")
        return http_session

    except Exception as e:
        log.error(f"Error establishing HTTPS session with {address}:{port}: {e}")
        return None


def edit_config(session: HttpSession, data: str) -> bool:
    try:
        if session is None:
            log.error("edit_config recibió una sesión None")
            return False

        response = session.session.post(
            f"{session.base_url}/edit-config",
            json={
                "target": "running",
                "default_operation": "merge",
                "config": data
            },
            timeout=session.timeout,
            cert=session.cert,
            verify=True
        )
        response.raise_for_status()

        payload = response.json()
        if not payload.get("ok", False):
            log.error(f"RPC error: {payload}")
            return False

        return True

    except Exception as e:
        log.error(f"Error in edit_config: {str(e)}")
        return False


def create_subscription(session, timeout, stream, filter, handler):
    try:
        if session is None:
            raise ValueError("La sesión es None")

        session.subscription_running = True

        def listener():
            last_event_id = None

            while session.subscription_running:
                try:
                    response = session.session.get(
                        f"{session.base_url}/notifications",
                        params={
                            "stream": stream,
                            "filter": filter,
                            "last_event_id": last_event_id
                        },
                        timeout=timeout or 5,
                        cert=session.cert,
                        verify=True
                    )
                    response.raise_for_status()

                    payload = response.json()
                    events = payload.get("events", [])

                    for event in events:
                        last_event_id = event.get("id")
                        handler(event)

                except Exception as e:
                    log.error(f"Subscription polling error: {e}")

                time.sleep(1)

        threading.Thread(target=listener, daemon=True).start()
        return None

    except Exception as e:
        return e
