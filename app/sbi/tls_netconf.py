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


import time


from netconf_client.ncclient import Manager
from netconf_client.connect import connect_tls
from logger.log import Logger

log = Logger() 

def establish_session(address: str, port: str):
    try:
        session = connect_tls(
            host=address,
            port=port,
            keyfile="/home/ubuntu/CCIPS-Python/app/certs/client.key",
            certfile="/home/ubuntu/CCIPS-Python/app/certs/client.crt",
            ca_certs="/home/ubuntu/CCIPS-Python/app/certs/CA.crt",
            initial_timeout=10,
            general_timeout=30
        )
        mgr = Manager(session, timeout=120)
        return mgr

    except Exception as e:
        log.error(f"Error establishing session with {address}: {e}")
        return None
    

def edit_config(session: Manager, data: str) -> bool:
    try:
        session.edit_config(
            target='running',
            config=data,
            default_operation='merge'
        )
        log.info("edit_config OK")
        return True

    except Exception as e:
        log.error(f"edit_config failed: {e}")
        return False