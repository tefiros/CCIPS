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


import threading
import time
import requests
import uuid
from json import dumps
import json
from logger.log import Logger

log = Logger()


class HttpNotificationAdapter:
    def __init__(self, event):
        self._event = event

    @property
    def RawReply(self):
        return dumps(self._event, indent=2)

    @property
    def Data(self):
        return self.RawReply


class HttpEventAdapter:
    def __init__(self, event):
        self._event = event

    def Notification(self):
        return HttpNotificationAdapter(self._event)


class HttpSession:
    def __init__(self, base_url: str, timeout: int = 20):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.session = requests.Session()
        self.subscription_running = False

    def close_session(self):
        self.subscription_running = False
        self.session.close()

    def close(self):
        self.close_session()


def establish_session(address: str, port: str):
    try:
        base_url = f"http://{address}:{port}"
        http_session = HttpSession(base_url=base_url, timeout=20)

        # response = http_session.session.get(
        #     f"{http_session.base_url}/health",
        #     timeout=http_session.timeout
        # )
        # response.raise_for_status()

        log.info(f"HTTP session established with {address}:{port}")
        return http_session

    except Exception as e:
        log.error(f"Error establishing HTTP session with {address}:{port}: {e}")
        return None


def delete_config(session: HttpSession, data: str, handler_id: uuid.UUID) -> bool:
    print(f"delete_config called with handler_id: {handler_id}")
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
                json={
                    "handler_id": str(handler_id),
                    "target": "running",
                    "config": config_json
                },
                timeout=session.timeout
            )

            response.raise_for_status()

        log.debug("Se eliminaron %d entradas", count)

        return True

    except Exception as e:
        log.error(f"DELETE DATA: {repr(data)}")
        log.error(f"Error in delete_config: {str(e)}")
        return False

def edit_config(session: HttpSession, data: str, handler_id: uuid.UUID) -> bool:
    try:
        if session is None:
            log.error("edit_config recibió una sesión None")
            return False

        response = session.session.post(
            f"{session.base_url}/ipsec-entries",
            json={
                "handler_id": str(handler_id),
                "target": "running",
                "config": data
            },
            timeout=session.timeout
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