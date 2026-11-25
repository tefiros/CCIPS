''' © 2026 Telefónica Innovación Digital 
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
limitations under the License. ''' 

from __future__ import annotations
from statistics import mode
from logger.log import Logger
import os
import secrets
import threading
import time
import uuid
from dataclasses import dataclass
from enum import IntEnum
from typing import Any, Dict, Optional, Tuple
from controller_i2nsf.algs import EncAlgType, AuthAlgType, enc_alg_decoder, int_alg_decoder, ENCKEYLENGTH, AUTHKEYLENGTH
from controller_i2nsf.templates import (
    formatG2GDelSAD,
    formatG2GDelSADJson,
    formatG2GDelSPD,
    formatG2GDelSPDJson,
    formatG2GSADValues,
    formatG2GSADValuesJSON,
    formatH2HDelSAD,
    formatH2HDelSADJson,
    formatH2HDelSPD,
    formatH2HDelSPDJson,
    formatH2HSADValues,
    formatH2HSADValuesJson,
    formatG2GSPDValues,
    formatG2GSPDValuesJSON,
    formatH2HSPDValues,
    formatH2HSPDValuesJson
)
log = Logger() 

def to_int(value, default=0):
    if value in (None, ""):
        return default
    return int(value)

@dataclass
class LifetimeConfig:
    n_bytes: int
    n_packets: int
    time: int
    time_idle: int

class CryptoConfig:
    def __init__(
        self,
        enc_alg: EncAlgType,
        auth_alg: AuthAlgType,
        enc_key_length: Optional[int] = None,
        auth_key_length: Optional[int] = None,
    ) -> None:
        self.enc_alg = enc_alg
        self.int_alg = auth_alg
        # Select key's length
        if enc_key_length is None:
            if enc_alg not in ENCKEYLENGTH:
                raise ValueError(
                    f"ENCKEYLENGTH no length defined {enc_alg}."
                )
            enc_key_length = ENCKEYLENGTH[enc_alg]
        if auth_key_length is None:
            if auth_alg not in AUTHKEYLENGTH:
                raise ValueError(
                    f"AUTHKEYLENGTH no length defined {auth_alg}."
                )
            auth_key_length = AUTHKEYLENGTH[auth_alg]

        self.enc_key_length = int(enc_key_length)
        self.auth_key_length = int(auth_key_length)

        # Cryptographic material (bytes)
        self.enc_key: bytes = b""
        self.int_key: bytes = b""
        self.iv: bytes = b""

        # Read/Write lock for crypto material
        self._lock = threading.RLock()

    def set_new_crypto_values(self) -> None:
        if self.enc_alg == EncAlgType.AES_GCM_8 or self.enc_alg == EncAlgType.AES_GCM_12 or self.enc_alg == EncAlgType.AES_GCM_12 or self.enc_alg == EncAlgType.AES_GCM_16:
            self.enc_key = secrets.token_bytes(self.enc_key_length)
            self.int_key = None
            self.iv = None
        
        with self._lock:
            self.enc_key = secrets.token_bytes(self.enc_key_length)
            self.int_key = secrets.token_bytes(self.auth_key_length)
            self.iv = secrets.token_bytes(self.enc_key_length)


class IPsecConfigType(IntEnum):
    H2H = 0  # Host to Host
    G2G = 1  # Gateway to Gateway

class SPIManager:
    """Manages SPI (Security Parameter Index) numbers."""
    def __init__(self):
        self.cspi  = 0
        self.lock = threading.Lock()
    
    def get_new_spi(self) -> int:
        with self.lock:
            self.cspi += 1
            return self.cspi

spi_manager = SPIManager()


class IpsecConfig:
    def __init__(self) -> None:
        self._lock = threading.RLock()

        # Default values
        self.conf_type: str = ""
        self.name: str = ""
        self.spi: int = 0
        self.req_id: int = 0

        self.origin: str = ""
        self.end: str = ""

        self.prefix_origin: str = ""
        self.prefix_end: str = ""

        self.data_origin: str = ""
        self.data_end: str = ""

        self.dmz_origin: str = ""
        self.dmz_end: str = ""

        self.crypto_config: Optional[CryptoConfig] = None
        self.soft_lifetime: Optional[LifetimeConfig] = None
        self.hard_lifetime: Optional[LifetimeConfig] = None

        self.timestamp: int = int(time.time())
        self.id: uuid.UUID = uuid.uuid4()
        self.rekeys_done: Dict[int, bool] = {}

    def create_del_sad(self):
        if self.conf_type == IPsecConfigType.G2G:
            del_cfg = formatG2GDelSAD(config=self)
        if self.conf_type == IPsecConfigType.H2H:
            del_cfg = formatH2HDelSAD(config=self)
        return del_cfg
    
    def create_del_spd(self):
        if self.conf_type == IPsecConfigType.G2G:
            del_cfg = formatG2GDelSPD(config=self)
        if self.conf_type == IPsecConfigType.H2H:
            del_cfg = formatH2HDelSPD(config=self)
        return del_cfg

    def create_del_sad_json(self):
        if self.conf_type == IPsecConfigType.G2G:
            del_cfg = formatG2GDelSADJson(config=self)
        if self.conf_type == IPsecConfigType.H2H:
            del_cfg = formatH2HDelSADJson(config=self)
        return del_cfg
    
    def create_del_spd_json(self):
        if self.conf_type == IPsecConfigType.G2G:
            del_cfg = formatG2GDelSPDJson(config=self)
        if self.conf_type == IPsecConfigType.H2H:
            del_cfg = formatH2HDelSPDJson(config=self)
        return del_cfg
    
    def set_new_spi(self) -> None:
        self.spi = spi_manager.get_new_spi()

    def create_sad_config(self) -> Tuple[str, str]:
        if self.conf_type == IPsecConfigType.G2G:
            out_cfg = formatG2GSADValues(
                self, self.prefix_origin, self.prefix_end, self.dmz_origin, self.data_end
            )
            in_cfg = formatG2GSADValues(
                self, self.prefix_origin, self.prefix_end, self.data_origin, self.dmz_end
            )
        if self.conf_type == IPsecConfigType.H2H:
            out_cfg = formatH2HSADValues(self, self.data_origin, self.data_end)
            in_cfg = formatH2HSADValues(self, self.data_origin, self.data_end)
        return out_cfg, in_cfg

    def create_sad_config_json(self) -> Tuple[str, str]:
        if self.conf_type == IPsecConfigType.G2G:
            out_cfg = formatG2GSADValuesJSON(
                self, self.prefix_origin, self.prefix_end, self.dmz_origin, self.data_end
            )
            in_cfg = formatG2GSADValuesJSON(
                self, self.prefix_origin, self.prefix_end, self.data_origin, self.dmz_end
            )
        if self.conf_type == IPsecConfigType.H2H:
            out_cfg = formatH2HSADValuesJson(self, self.data_origin, self.data_end)
            in_cfg = formatH2HSADValuesJson(self, self.data_origin, self.data_end)
        return out_cfg, in_cfg

    def create_spd_config(self) -> Tuple[str, str]:
        if self.conf_type == IPsecConfigType.G2G:
            out_cfg = formatG2GSPDValues(
                self, self.prefix_origin, self.prefix_end, self.dmz_origin, self.data_end, "outbound"
            )
            in_cfg = formatG2GSPDValues(
                self, self.prefix_origin, self.prefix_end, self.dmz_origin, self.data_end, "inbound"
            )
        elif self.conf_type == IPsecConfigType.H2H:
            out_cfg = formatH2HSPDValues(self, self.data_origin, self.data_end, "outbound")
            in_cfg = formatH2HSPDValues(self, self.data_origin, self.data_end, "inbound")
        return out_cfg, in_cfg

    def create_spd_config_json(self) -> Tuple[str, str]:
        if self.conf_type == IPsecConfigType.G2G:
            out_cfg = formatG2GSPDValuesJSON(
                self, self.prefix_origin, self.prefix_end, self.dmz_origin, self.data_end, "outbound"
            )
            in_cfg = formatG2GSPDValuesJSON(
                self, self.prefix_origin, self.prefix_end, self.dmz_origin, self.data_end, "inbound"
            )
        elif self.conf_type == IPsecConfigType.H2H:
            out_cfg = formatH2HSPDValuesJson(self, self.data_origin, self.data_end, "outbound")
            in_cfg = formatH2HSPDValuesJson(self, self.data_origin, self.data_end, "inbound")

        return out_cfg, in_cfg

    def parse_config_to_nbi_swagger(self, handler_id=None) -> Dict[str, Any]:
        if not self.crypto_config or not self.soft_lifetime or not self.hard_lifetime:
            raise ValueError("Parameters are missing")

        return {
            "handler ID": handler_id,
            "nodes": [
                {
                    "ipControl": self.origin,
                    "networkInternal": self.prefix_origin,
                    "ipData": self.data_origin,
                    "ipDMZ": self.dmz_origin,
                },
                {
                    "ipControl": self.end,
                    "networkInternal": self.prefix_end,
                    "ipData": self.data_end,
                    "ipDMZ": self.dmz_end,
                },
            ],
            "status": "Deployed",
            "softLifetime": float(self.soft_lifetime.time),
            "hardLifetime": float(self.hard_lifetime.time),
            "encAlg": enc_alg_decoder(self.crypto_config.enc_alg),
            "intAlg": int_alg_decoder(self.crypto_config.int_alg)
        }

    def new_config_from_nbi_swagger(
        node1: Any,
        node2: Any,
        soft_lifetime: Any,
        hard_lifetime: Any,
        mode: Any,
        crypto_cfg: CryptoConfig,
        id_: uuid.UUID,
    ) -> "IpsecConfig":

        cfg = IpsecConfig()
        cfg.rekeys_done = {}
        if isinstance(mode, str):
            cfg.conf_type = IPsecConfigType.G2G if mode == "G2G" else IPsecConfigType.H2H
        else:
            cfg.conf_type = mode

        cfg.name = f"out/{_get(node1, 'ipData')}/in/{_get(node2, 'ipData')}"

        # Control IPs
        cfg.origin = _get(node1, "ipControl")
        cfg.end = _get(node2, "ipControl")
        
        if cfg.conf_type == IPsecConfigType.G2G:
            cfg.prefix_origin = _get(node1, "networkInternal")
            cfg.prefix_end = _get(node2, "networkInternal")
            cfg.dmz_origin = _get(node1, "ipDMZ")
            cfg.dmz_end = _get(node2, "ipDMZ")
        else:
            cfg.prefix_origin = ""
            cfg.prefix_end = ""
            cfg.dmz_origin = ""
            cfg.dmz_end = ""
        # Data IPs
        cfg.data_origin = _get(node1, "ipData")
        cfg.data_end = _get(node2, "ipData")

        cfg.timestamp = int(time.time())

        cfg.req_id = secrets.randbelow(10_000)
        log.debug("Generated reqId is %d", cfg.req_id)

        cfg.crypto_config = crypto_cfg
        crypto_cfg.set_new_crypto_values()

        cfg.soft_lifetime = LifetimeConfig(
            n_bytes=to_int(_get(soft_lifetime, "nBytes")),
            n_packets=to_int(_get(soft_lifetime, "nPackets")),
            time=to_int(_get(soft_lifetime, "nTime")),
            time_idle=to_int(_get(soft_lifetime, "nTimeIdle")),
        )

        cfg.hard_lifetime = LifetimeConfig(
            n_bytes=to_int(_get(hard_lifetime, "nBytes")),
            n_packets=to_int(_get(hard_lifetime, "nPackets")),
            time=to_int(_get(hard_lifetime, "nTime")),
            time_idle=to_int(_get(hard_lifetime, "nTimeIdle")),
        )

        return cfg

def _get(obj: Any, name: str, default: Any = "") -> Any:
    if isinstance(obj, dict):
        return obj.get(name, default)
    return getattr(obj, name, default)
