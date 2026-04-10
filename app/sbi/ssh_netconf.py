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
from ncclient import manager
from logger.log import Logger
from ncclient.operations import RPCError
from lxml import etree

log = Logger() 

class NetconfNotificationAdapter:
    def __init__(self, notif):
        self._notif = notif

    @property
    def RawReply(self):
        raw = getattr(self._notif, "notification_xml", b"")
        if isinstance(raw, bytes):
            return raw.decode("utf-8", errors="ignore")
        return str(raw)

    @property
    def Data(self):
        ele = getattr(self._notif, "notification_ele", None)
        if ele is None:
            return self.RawReply

        try:
            parts = []
            for child in ele:
                parts.append(etree.tostring(child, encoding="unicode"))
            return "".join(parts)
        except Exception:
            return self.RawReply


class NetconfEventAdapter:
    def __init__(self, notif):
        self._notif = notif

    def Notification(self):
        return NetconfNotificationAdapter(self._notif)
    
def establish_session(address: str, port: int):
    try:
        session = manager.connect(
            host=address,
            port=port,
            username="netconf",
            password="netconf",
            hostkey_verify=False,
            look_for_keys=False,
            allow_agent=False,
            timeout=20,
            device_params={"name": "default"}
        )

        if session is None:
            raise RuntimeError("ncclient.connect returned None")

        if hasattr(session, 'connected') and not session.connected:
            raise RuntimeError("SSH NETCONF session is not connected")

        log.info(f"SSH NETCONF session established with {address}:{port}")
        return session

    except Exception as e:
        log.error(f"Error establishing SSH NETCONF session with {address}:{port}: {e}")
        raise

def edit_config(session, data):
    try:
        reply = session.edit_config(
            target="running",
            config=data,
            default_operation="merge"
        )
        if reply.errors:
            log.error(f"RPC error: {reply.errors}")
            return False
        return True

    except RPCError as e:
        print("=== RPCError ===")
        print("message :", getattr(e, "message", None))
        print("tag     :", getattr(e, "tag", None))
        print("type    :", getattr(e, "type", None))
        print("severity:", getattr(e, "severity", None))
        print("path    :", getattr(e, "path", None))
        print("info    :", getattr(e, "info", None))
        print("XML sent:")
        print(data)
        return e

    except Exception as e:
        print("=== Generic exception ===")
        print(str(e))
        print("XML sent:")
        print(data)
        return e


def create_notification_stream(session, timeout, stream_name, notif_filter, handler):
    try:
        session.create_subscription(
            stream_name=stream_name or None,
            filter=notif_filter or None
        )
    except Exception as e:
        return e

    def listener():
        while True:
            try:
                notif = session.take_notification(block=True, timeout=timeout)
                if notif is not None:
                    event = NetconfEventAdapter(notif)
                    handler(event)
            except Exception as e:
                print(f"Notification listener error: {e}")
                break

    threading.Thread(target=listener, daemon=True).start()
    return None