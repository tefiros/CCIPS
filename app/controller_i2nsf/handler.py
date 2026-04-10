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
from unittest import case
import uuid
import threading
from typing import Dict, Optional, Tuple, Any
from logger.log import Logger
import nbi_swagger.models as models
from controller_i2nsf.algs import ENCALGS, AUTHALGS
from controller_i2nsf.config import IpsecConfig, CryptoConfig
from controller_i2nsf.templates import generateI2NSFConfig
from controller_i2nsf.notifications import SADBExpireNotification
from sbi import ssh_netconf, tls_netconf, http_request, https_request
import xml.etree.ElementTree as ET

# Constants
THRESHOLD = 5
log = Logger() 

class OutIn:
    def __init__(self, cfg, s0, s1):
        self.cfg = cfg
        self.s0 = s0
        self.s1 = s1
        self.session1 = s0
        self.session2 = s1


class StorageHandler:
    """Manages multiple handlers indexed by UUID."""
    
    def __init__(self):
        self.storage: Dict[uuid.UUID, 'Handler'] = {}
        self.lock = threading.RLock()
    
    def create_handler(self, request: models.I2NSFRequest) -> Tuple[Any, Optional[Exception]]:
        try:
            handler_id = uuid.uuid4()
            h = Handler(request, handler_id)
            if not h.set_initial_config_values():
                return None, Exception("Failed to set initial config values")
            log.debug("Initial values have been established")
            log.debug("Handler assigned to id %s", handler_id)
            with self.lock:
                self.storage[handler_id] = h
            log.debug("Handler %s stored", handler_id)

            return h.cfg[0].parse_config_to_nbi_swagger(handler_id), None

        except Exception as err:
            return None, err
    
    def delete_handler(self, handler_id: uuid.UUID) -> Optional[Exception]:
        try:
            if handler_id not in self.storage:
                return Exception(f"Handler with id {handler_id}, does not exist")
            h = self.storage[handler_id]
            err = h.stop()
            if err is not None:
                return err
            del self.storage[handler_id]
            return None
        except Exception as err:
            return err
    
    def get_config(self, handler_id: uuid.UUID)  -> Optional[Exception]:
        if handler_id not in self.storage:
            return None, Exception(f"Handler {handler_id} not found")

        h = self.storage[handler_id]
        return h.cfg[0].parse_config_to_nbi_swagger(handler_id), None
    
    def get_all_ids(self) -> Optional[Exception]:
        try:
            all_ids = []
            with self.lock:
                for handler_id in self.storage:
                    all_ids.append(handler_id)
            return all_ids, None
        except Exception as err:
            return None, Exception(f"Exception error {err}")


class Handler:
    def __init__(self, request: models.I2NSFRequest, id: uuid.UUID):
        self.session: list = [None] * 4  # 2 for configuration sessions, 2 for notifications
        self.cfg: list = [None] * 2
        self.ids: Dict[str, OutIn] = {}
        self.locker = threading.RLock()
        self.is_stopped = False
        self.id = id
        self.method = request.method
        self._initialize_from_request(request)
    
    def process_rekey(self, notification: SADBExpireNotification):
        with self.locker:
            if self.is_stopped:
                return None

            s = notification.IPsecName.split("_")
            if len(s) < 2:
                raise Exception("the id of the SAD notification is incorrect")

            id_ = s[0]

            manager = self.ids.get(id_)
            if manager is None:
                return None

            cfg = manager.cfg
            s0 = manager.s0
            s1 = manager.s1

            log.debug("Received notification to proceed with rekey of %s", id_)

            try:
                spi = int(s[1])
            except ValueError:
                log.error("We should never receive anything different than a number")
                raise

            if cfg.spi != spi or cfg.rekeys_done.get(spi, False):
                log.warning("Rekey of %s has been already completed", s[1])
                return None

            cfg.rekeys_done[cfg.spi] = True
            old_spi = cfg.spi

            log.debug("Timer for %s has expired. Proceed to setup new SADs", cfg.name)
            log.debug("Creating delete config SPI %d from config %s", cfg.spi, cfg.name)

            if self.method == "netconf-ssh":
                del_sad_xml = cfg.create_del_sad()
            if self.method == "http" or self.method == "https":
                del_sad_xml = cfg.create_del_sad_json()

            cfg.crypto_config.set_new_crypto_values()
            cfg.set_new_spi()

            try:
                out_sad, in_sad = cfg.create_sad_config()
                s0_data = generateI2NSFConfig([out_sad], [])
                s1_data = generateI2NSFConfig([in_sad], [])
            except Exception as e:
                log.error("Couldn't generate sad entries during the rekey process of %s: %s", cfg.name, str(e))
                raise

            log.info("Adding new entries out %s in %s SPI %d", cfg.origin, cfg.end, cfg.spi)

            match self.method:
                case "netconf-ssh":
                    ok = ssh_netconf.edit_config(self.session[0], s0_data)
                    log.debug("%s: edit_config returned: %r", self.cfg[0].origin, ok)
                    if not ok:
                        log.error("%s: Failed to edit config line 166", self.cfg[0].origin)
                        return False

                    ok = ssh_netconf.edit_config(self.session[1], s1_data)
                    log.debug("%s: edit_config returned: %r", self.cfg[1].origin, ok)
                    if not ok:
                        log.error("%s: Failed to edit config line 170", self.cfg[1].origin)
                        return False

                    log.info("Deleting old entries out %s in %s SPI %d", cfg.origin, cfg.end, old_spi)

                    ok = ssh_netconf.edit_config(self.session[0], del_sad_xml)
                    if not ok:
                        log.error("%s: Failed to edit config line 180", self.cfg[0].origin)
                        return False

                    ok = ssh_netconf.edit_config(self.session[1], del_sad_xml)
                    if not ok:
                        log.error("%s: Failed to edit config line 185", self.cfg[1].origin)
                        return False

                    log.info("Rekey process of %d already completed", cfg.req_id)
                # FALTARÍA PARA LOS OTROS MÉTODOS SBI
            return None
    

    def _initialize_from_request(self, request: models.I2NSFRequest):
        method = request.method
        log.debug("Received new request with method %s", method)
        node0 = request.nodes[0]
        node1 = request.nodes[1]
        # Check mode
        if not node0.networkInternal:
            mode = "H2H"
            log.debug("New Handler for H2H mode")
        else:
            mode = "G2G"
            log.debug("New Handler for G2G mode")

        if request.encAlg[0] not in ENCALGS:
            raise ValueError(f"ENC algorithm not found: {request.encAlg[0]}")
        else:
            enc_alg = ENCALGS[request.encAlg[0]]
        
        if request.encAlg[0] == "aes-gcmv-8" or request.encAlg[0] == "aes-gcmv-12" or request.encAlg[0] == "aes-gcmv-16":
            auth_alg = 0
        if request.intAlg[0] not in AUTHALGS:
            raise ValueError(f"AUTH algorithm not found: {request.intAlg[0]}")
        else:
            auth_alg = AUTHALGS.get(request.intAlg[0])

        crypto_config = CryptoConfig(enc_alg, auth_alg)
        cfg0 = IpsecConfig.new_config_from_nbi_swagger(
            node0,
            node1,
            request.softLifetime,
            request.hardLifetime,
            mode,
            crypto_config,
            id
        )
        
        cfg1 = IpsecConfig.new_config_from_nbi_swagger(
            node1,
            node0,
            request.softLifetime,
            request.hardLifetime,
            mode,
            crypto_config,
            id
        )
        cfg0.set_new_spi()
        cfg1.set_new_spi()
        self.set_new_handler(node0, node1, cfg0, cfg1, method)

    
    def set_new_handler(self, node0: str, node1: str, cfg0 , cfg1, method):
        match method:
            case "netconf-ssh":
                try:
                    s0_nots =  ssh_netconf.establish_session(node0.ipControl, 830)
                except Exception as e:
                    log.error(f"There was an error trying to setup the session with node {node0}: {str(e)}")
                    raise
                try:
                    s1_nots = ssh_netconf.establish_session(node1.ipControl, 830)
                except Exception as e:
                    log.error(f"There was an error trying to setup the session with node {node1}: {str(e)}")
                    raise
                try:
                    s0 = ssh_netconf.establish_session(node0.ipControl, 830)
                except Exception as e:
                    log.error(f"There was an error trying to setup the session with node {node0}: {str(e)}")
                    raise
                try:
                    s1 = ssh_netconf.establish_session(node1.ipControl, 830)
                except Exception as e:
                    log.error(f"There was an error trying to setup the session with node {node1}: {str(e)}")
                    raise
            case "netconf-tls":
                print("Setting up TLS sessions")
                try:
                    s0_nots =  tls_netconf.establish_session(node0.ipControl, 6513)
                except Exception as e:
                    log.error(f"There was an error trying to setup the session with node {node0}: {str(e)}")
                    raise
                try:
                    s1_nots = tls_netconf.establish_session(node1.ipControl, 6514)
                except Exception as e:
                    log.error(f"There was an error trying to setup the session with node {node1}: {str(e)}")
                    raise
                try:
                    s0 = tls_netconf.establish_session(node0.ipControl, 6513)
                except Exception as e:
                    log.error(f"There was an error trying to setup the session with node {node0}: {str(e)}")
                    raise
                try:
                    s1 = tls_netconf.establish_session(node1.ipControl, 6514)
                except Exception as e:
                    log.error(f"There was an error trying to setup the session with node {node1}: {str(e)}")
                    raise
            case "http":
                print("Setting up TLS sessions")
                try:
                    s0_nots =  http_request.establish_session(node0.ipControl, 8080)
                except Exception as e:
                    log.error(f"There was an error trying to setup the session with node {node0}: {str(e)}")
                    raise
                try:
                    s1_nots = http_request.establish_session(node1.ipControl, 8081)
                except Exception as e:
                    log.error(f"There was an error trying to setup the session with node {node1}: {str(e)}")
                    raise
                try:
                    s0 = http_request.establish_session(node0.ipControl, 8080)
                except Exception as e:
                    log.error(f"There was an error trying to setup the session with node {node0}: {str(e)}")
                    raise
                try:
                    s1 = http_request.establish_session(node1.ipControl, 8081)
                except Exception as e:
                    log.error(f"There was an error trying to setup the session with node {node1}: {str(e)}")
                    raise
            case "https":
                print("Setting up TLS sessions")
                try:
                    s0_nots =  https_request.establish_session(node0.ipControl, 4043)
                except Exception as e:
                    log.error(f"There was an error trying to setup the session with node {node0}: {str(e)}")
                    raise
                try:
                    s1_nots = https_request.establish_session(node1.ipControl, 4044)
                except Exception as e:
                    log.error(f"There was an error trying to setup the session with node {node1}: {str(e)}")
                    raise
                try:
                    s0 = https_request.establish_session(node0.ipControl, 4043)
                except Exception as e:
                    log.error(f"There was an error trying to setup the session with node {node0}: {str(e)}")
                    raise
                try:
                    s1 = https_request.establish_session(node1.ipControl, 4044)
                except Exception as e:
                    log.error(f"There was an error trying to setup the session with node {node1}: {str(e)}")
                    raise
        # Store sessions
        self.session[0] = s0
        self.session[1] = s1
        self.session[2] = s0_nots
        self.session[3] = s1_nots
        
        # Save config
        self.cfg[0] = cfg0
        self.cfg[1] = cfg1
        
        # Generate OutIn configs
        self.ids[cfg0.name] = OutIn(cfg0, s0, s1)
        self.ids[cfg1.name] = OutIn(cfg1, s1, s0)

        #Establish subscriptions
        match method:
            case "netconf-ssh":
                log.debug("Establishing subscriptions with XML for NETCONF over SSH")
                err = ssh_netconf.create_notification_stream(s0_nots, 5, "", "", self.handler_notification)
                if err is not None:
                    log.error(err)

                err = ssh_netconf.create_notification_stream(s1_nots, 5, "", "", self.handler_notification)
                if err is not None:
                    log.error(err)
            case "http":
                err = http_request.create_subscription(s0_nots, 5, "", "", self.handle_notification)
                if err != None:
                    return None, err
                err = http_request.create_subscription(s1_nots, 5, "", "", self.handle_notification)
                if err != None:
                    return None, err

    def set_initial_config_values(self) -> bool:
        try:
            method = self.method
            spd0 = [None, None]
            spd1 = [None, None]
            sad0 = [None, None]
            sad1 = [None, None]
            
            if self.method == "netconf-ssh":
                log.debug("Setting initial config values as XML for NETCONF over SSH")
                spd0[0], spd1[0] = self.cfg[0].create_spd_config()
                spd1[1], spd0[1] = self.cfg[1].create_spd_config()
                sad0[0], sad1[0] = self.cfg[0].create_sad_config()
                sad1[1], sad0[1] = self.cfg[1].create_sad_config()
            if self.method == "http" or self.method == "https":
                log.debug("Setting initial config values as JSON for HTTP/HTTPS")
                spd0[0], spd1[0] = self.cfg[0].create_spd_config_json()
                spd1[1], spd0[1] = self.cfg[1].create_spd_config_json()
                sad0[0], sad1[0] = self.cfg[0].create_sad_config_json()
                sad1[1], sad0[1] = self.cfg[1].create_sad_config_json()
            log.debug("Generated configuration values")
            # Format the data
            s0_data_in = generateI2NSFConfig([sad0[1]], spd0)
            s1_data_in = generateI2NSFConfig([sad1[0]], spd1)
            s0_data_out = generateI2NSFConfig([sad0[0]], [])
            s1_data_out = generateI2NSFConfig([sad1[1]], [])
            match method:
                case "netconf-ssh":
                    # Setup inbound configs
                    if not ssh_netconf.edit_config(self.session[0], s0_data_in):
                        log.error(f"{self.cfg[0].origin}: Failed to edit config")
                        return False
                    
                    if not ssh_netconf.edit_config(self.session[1], s1_data_out):
                        log.error(f"{self.cfg[1].origin}: Failed to edit config")
                        return False
            
                    # Setup outbound configs
                    if not ssh_netconf.edit_config(self.session[0], s0_data_out):
                        log.error(f"{self.cfg[0].origin}: Failed to edit config")
                        return False
                    
                    if not ssh_netconf.edit_config(self.session[1], s1_data_in):
                        log.error(f"{self.cfg[1].origin}: Failed to edit config")
                        return False
                    return True
                case "netconf-tls":
                    # # Setup inbound configs
                    if not tls_netconf.edit_config(self.session[0], s0_data_in):
                        log.error(f"{self.cfg[0].origin}: Failed to edit config")
                        return False
                    
                    if not tls_netconf.edit_config(self.session[1], s1_data_out):
                        log.error(f"{self.cfg[1].origin}: Failed to edit config")
                        return False
                    
                    # Setup outbound configs
                    if not tls_netconf.edit_config(self.session[0], s0_data_out):
                        log.error(f"{self.cfg[0].origin}: Failed to edit config")
                        return False
                    
                    if not tls_netconf.edit_config(self.session[1], s1_data_in):
                        log.error(f"{self.cfg[1].origin}: Failed to edit config")
                        return False
                    return True
                case "http":
                    # # Setup inbound configs
                    if not http_request.edit_config(self.session[0], s0_data_in):
                        log.error(f"{self.cfg[0].origin}: Failed to edit config")
                        return False
                    
                    if not http_request.edit_config(self.session[1], s1_data_out):
                        log.error(f"{self.cfg[1].origin}: Failed to edit config")
                        return False
                    
                    # Setup outbound configs
                    if not http_request.edit_config(self.session[0], s0_data_out):
                        log.error(f"{self.cfg[0].origin}: Failed to edit config")
                        return False
                    
                    if not http_request.edit_config(self.session[1], s1_data_in):
                        log.error(f"{self.cfg[1].origin}: Failed to edit config")
                        return False
                    return True
                case "https":
                    # # Setup inbound configs
                    if not https_request.edit_config(self.session[0], s0_data_in):
                        log.error(f"{self.cfg[0].origin}: Failed to edit config")
                        return False
                    
                    if not https_request.edit_config(self.session[1], s1_data_out):
                        log.error(f"{self.cfg[1].origin}: Failed to edit config")
                        return False
                    
                    # Setup outbound configs
                    if not https_request.edit_config(self.session[0], s0_data_out):
                        log.error(f"{self.cfg[0].origin}: Failed to edit config")
                        return False
                    
                    if not https_request.edit_config(self.session[1], s1_data_in):
                        log.error(f"{self.cfg[1].origin}: Failed to edit config")
                        return False
                    return True
        except Exception as e:
            log.error(f"Error setting initial config values: {str(e)}")
            return False
        
    def handler_notification(self, event):
        noti = event.Notification()

        if "sadb-expire" in noti.Data:
            try:
                sadb_not = self.unmarshal_sadb_expire(noti.RawReply)
            except Exception as e:
                log.error(f"Incorrect sadb-expire notification: {e}")
                return

            try:
                self.process_rekey(sadb_not)
            except Exception as e:
                log.error(str(e))

    def unmarshal_sadb_expire(self, raw_xml: str) -> SADBExpireNotification:
        root = ET.fromstring(raw_xml)

        notification = SADBExpireNotification()

        for elem in root.iter():
            tag = elem.tag.split("}")[-1]
            text = elem.text.strip() if elem.text else ""

            if tag == "eventTime":
                notification.EventTime = text
            elif tag == "sadb-expire":
                notification.EventType = "sadb-expire"
            elif tag == "ipsec-sa-name":
                notification.IPsecName = text
            elif tag == "soft-lifetime-expire":
                notification.SoftLifeTime = text.lower() == "true"

        return notification

    def stop(self) -> Optional[Exception]:
        with self.locker:
            for outin in self.ids.values():
                cfg = outin.cfg
                s1 = outin.s0
                s2 = outin.s1
                # Generate del SADs and SPDs
                if self.method == "http" or self.method == "https":
                    del_sad = cfg.create_del_sad_json()
                    del_spd = cfg.create_del_spd_json()
                if self.method == "netconf-ssh" or self.method == "netconf-tls":
                    del_sad = cfg.create_del_sad()
                    del_spd = cfg.create_del_spd()
                match self.method:
                    case "netconf-ssh":
                        ok = ssh_netconf.edit_config(s1, del_sad)
                        if not ok:
                            log.error("%s: Failed to delete SAD", cfg.origin)
                        ok = ssh_netconf.edit_config(s2, del_sad)
                        if not ok:
                            log.error("%s: Failed to delete SAD", cfg.end)
                        time.sleep(10)
                        ok = ssh_netconf.edit_config(s1, del_spd)
                        if not ok:
                            log.error("%s: Failed to delete SPD", cfg.origin)
                        ok = ssh_netconf.edit_config(s2, del_spd)
                        if not ok:
                            log.error("%s: Failed to delete SPD", cfg.end)
                        log.info("Removed SAD/SPD entries for session %s (reqId=%d)", cfg.name, cfg.req_id)
            self.is_stopped = True
            time.sleep(10)
            for s in self.session:
                if s is not None:
                    try:
                        s.close_session()
                    except Exception as e:
                        log.error(f"Error closing session: {e}")

            return None

