'''  © 2026 Telefónica Innovación Digital 
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

import os
import re
from enum import Enum
from typing import Dict, Any, List

from flask import config

from controller_i2nsf.algs import EncAlgType

class TemplateType(str, Enum):
    AddSAD = "addSAD"
    AddSPD = "addSPD"
    DelSAD = "delSAD"
    DelSPD = "delSPD"
    AddSADJson = "addSadJson"
    AddSPDJson = "addSpdJson"
    DelSADJson = "delSadJson"
    DelSPDJson = "delSpdJson"

#G2GTemplates map loaded when the controller is started, in order to set the g2g xml templates
G2GTemplates: Dict[TemplateType, str] = {}
#H2hTemplates map loaded when the controller is started, in order to set the g2g xml templates
H2hTemplates: Dict[TemplateType, str] = {}


EditconfigTemplate = """
<config xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0">
  <ipsec-ikeless xmlns="urn:ietf:params:xml:ns:yang:ietf-i2nsf-ikeless">
    REPLACE_DATA
  </ipsec-ikeless>
</config>
"""
EditconfigTemplateJson = """REPLACE_DATA"""

def load_templates(dirPath: str) -> None:
    global G2GTemplates, H2hTemplates
    G2GTemplates = {}
    H2hTemplates = {}

    G2GTemplates[TemplateType.AddSAD] = read_template(dirPath, os.path.join("g2g", "add_sad_g2g.xml"))
    G2GTemplates[TemplateType.AddSPD] = read_template(dirPath, os.path.join("g2g", "add_spd_g2g.xml"))
    G2GTemplates[TemplateType.DelSAD] = read_template(dirPath, os.path.join("g2g", "del_sad_g2g.xml"))
    G2GTemplates[TemplateType.DelSPD] = read_template(dirPath, os.path.join("g2g", "del_spd_g2g.xml"))
    G2GTemplates[TemplateType.AddSADJson] = read_template(dirPath, os.path.join("g2g", "add_sad_g2g.json"))
    G2GTemplates[TemplateType.AddSPDJson] = read_template(dirPath, os.path.join("g2g", "add_spd_g2g.json"))
    G2GTemplates[TemplateType.DelSADJson] = read_template(dirPath, os.path.join("g2g", "del_sad_g2g.json"))
    G2GTemplates[TemplateType.DelSPDJson] = read_template(dirPath, os.path.join("g2g", "del_spd_g2g.json"))

    H2hTemplates[TemplateType.AddSAD] = read_template(dirPath, os.path.join("h2h", "add_sad_h2h.xml"))
    H2hTemplates[TemplateType.AddSPD] = read_template(dirPath, os.path.join("h2h", "add_spd_h2h.xml"))
    H2hTemplates[TemplateType.DelSAD] = read_template(dirPath, os.path.join("h2h", "del_sad_h2h.xml"))
    H2hTemplates[TemplateType.DelSPD] = read_template(dirPath, os.path.join("h2h", "del_spd_h2h.xml"))
    H2hTemplates[TemplateType.AddSADJson] = read_template(dirPath, os.path.join("h2h", "add_sad_h2h.json"))
    H2hTemplates[TemplateType.AddSPDJson] = read_template(dirPath, os.path.join("h2h", "add_spd_h2h.json"))
    H2hTemplates[TemplateType.DelSADJson] = read_template(dirPath, os.path.join("h2h", "del_sad_h2h.json"))
    H2hTemplates[TemplateType.DelSPDJson] = read_template(dirPath, os.path.join("h2h", "del_spd_h2h.json"))


def read_template(dirPath: str, file_rel: str) -> str:
    full_path = os.path.join(dirPath, file_rel)
    with open(full_path, "r", encoding="utf-8") as f:
        return f.read()

def replace(template: str, replace_name: str, val: Any) -> str:
    if isinstance(val, bool):
        return template.replace(replace_name, "true" if val else "false")
    if isinstance(val, str):
        return template.replace(replace_name, val)
    if isinstance(val, int):
        return template.replace(replace_name, str(val))
    if isinstance(val, (bytes, bytearray)):
        hex_string = val.hex()
        chunks = [hex_string[i:i + 2] for i in range(0, len(hex_string), 2)]
        output = ":".join(chunks)
        return template.replace(replace_name, output)

    return template.replace(replace_name, str(val))

def formatG2GDelSAD(config) -> str:
	t = G2GTemplates[TemplateType.DelSAD]
	t = replace(t, "ID_NAME", f"{config.name}_{config.spi}")
	t = replace(t, "REQ_ID", config.req_id)
	return replace(EditconfigTemplate, "REPLACE_DATA", f"<sad>{t}</sad>")

def formatH2HDelSAD(config) -> str:
	t = H2hTemplates[TemplateType.DelSAD]
	t = replace(t, "ID_NAME", f"{config.name}_{config.spi}")
	t = replace(t, "REQ_ID", config.req_id)
	return replace(EditconfigTemplate, "REPLACE_DATA", f"<sad>{t}</sad>")

def formatG2GDelSPD(config) -> str:
	t = G2GTemplates[TemplateType.DelSPD]
	out = replace(t, "ID_NAME", f"{config.name}")
	out = replace(out, "DIRECTION", "outbound")
	out = replace(out, "REQ_ID", config.req_id)
	inbound = replace(t, "ID_NAME", f"{config.name}_{config.spi}")
	inbound = replace(inbound, "DIRECTION", "inbound")
	inbound = replace(inbound, "REQ_ID", config.req_id)
	return replace(EditconfigTemplate, "REPLACE_DATA", f"<spd>{out}\n{inbound}</spd>")

def formatH2HDelSPD(config) -> str:
	t = H2hTemplates[TemplateType.DelSPD]
	out = replace(t, "ID_NAME", config.name)
	out = replace(out, "DIRECTION", "outbound")
	out = replace(out, "REQ_ID", config.req_id)
	inbound = replace(t, "ID_NAME", config.name)
	inbound = replace(inbound, "DIRECTION", "inbound")
	inbound = replace(inbound, "REQ_ID", config.req_id)
	return replace(EditconfigTemplate, "REPLACE_DATA", f"<spd>{out}\n{inbound}</spd>")

def formatG2GDelSADJson(config) -> str:
	t = G2GTemplates[TemplateType.DelSADJson]
	t = replace(t, "ID_NAME", f"{config.name}_{config.spi}")
	t = replace(t, "REQ_ID", config.req_id)
	t = replace("<sad>DATA</sad>", "DATA", t)
	return replace(EditconfigTemplateJson, "REPLACE_DATA", t)

def formatH2HDelSADJson(config) -> str:
	t = H2hTemplates[TemplateType.DelSADJson]
	t = replace(t, "ID_NAME", f"{config.name}_{config.spi}")
	t = replace(t, "REQ_ID", config.req_id)
	t = replace("<sad>DATA</sad>", "DATA", t)
	return replace(EditconfigTemplateJson, "REPLACE_DATA", t)

def formatG2GDelSPDJson(config) -> str:
    t = G2GTemplates[TemplateType.DelSPDJson]
    out = replace(t, "ID_NAME", config.name)
    out = replace(out, "DIRECTION", "outbound")
    out = replace(out, "REQ_ID", config.req_id)
    inbound = replace(t, "ID_NAME", f"{config.name}")
    inbound = replace(inbound, "DIRECTION", "inbound")
    inbound = replace(inbound, "REQ_ID", config.req_id)
    t = f"{out}\n{inbound}"
    return replace(EditconfigTemplateJson, "REPLACE_DATA", t)

def formatH2HDelSPDJson(config) -> str:
    t = H2hTemplates[TemplateType.DelSPDJson]
    out = replace(t, "ID_NAME", config.name)
    out = replace(out, "DIRECTION", "outbound")
    out = replace(out, "REQ_ID", config.req_id)
    inbound = replace(t, "ID_NAME", config.name)
    inbound = replace(inbound, "DIRECTION", "inbound")
    inbound = replace(inbound, "REQ_ID", config.req_id)
    t = f"{out}\n{inbound}"
    return replace(EditconfigTemplateJson, "REPLACE_DATA", t)

def formatG2GSADValues(config, localPrefix, remotePrefix, local, remote):
    t = G2GTemplates[TemplateType.AddSAD]

    t = replace(t, "ID_NAME", f"{config.name}_{config.spi}")
    t = replace(t, "REQ_ID", config.req_id)
    t = replace(t, "SPI", config.spi)
    t = replace(t, "LOCAL_PREFIX", localPrefix)
    t = replace(t, "REMOTE_PREFIX", remotePrefix)
    t = replace(t, "ENC_ALG", str(config.crypto_config.enc_alg.value))
    t = replace(t, "ENC_KEY", config.crypto_config.enc_key)
    if config.crypto_config.enc_alg == EncAlgType.AES_GCM_8 or config.crypto_config.enc_alg == EncAlgType.AES_GCM_12 or config.crypto_config.enc_alg == EncAlgType.AES_GCM_16:
        t = replace(t, "INT_ALG", 0)
        t = replace(t, "INT_KEY", "")
        t = replace(t, "ENC_IV", "")
    else:
        t = replace(t, "INT_ALG", str(config.crypto_config.int_alg.value))
        t = replace(t, "INT_KEY", config.crypto_config.int_key)
        t = replace(t, "ENC_IV", config.crypto_config.iv)
    t = replace(t, "HARD_BYTES", config.hard_lifetime.n_bytes)
    t = replace(t, "HARD_PACKETS", config.hard_lifetime.n_packets)
    t = replace(t, "HARD_TIME", config.hard_lifetime.time)
    t = replace(t, "HARD_IDLE", config.hard_lifetime.time_idle)
    t = replace(t, "SOFT_BYTES", config.soft_lifetime.n_bytes)
    t = replace(t, "SOFT_PACKETS", config.soft_lifetime.n_packets)
    t = replace(t, "SOFT_TIME", config.soft_lifetime.time)
    t = replace(t, "SOFT_IDLE", config.soft_lifetime.time_idle)
    t = replace(t, "LOCAL_TUNNEL", local)
    t = replace(t, "REMOTE_TUNNEL", remote)


    return t

def formatG2GSADValuesJSON(config, localPrefix, remotePrefix, local, remote):
    t = G2GTemplates[TemplateType.AddSADJson]

    t = replace(t, "ID_NAME", f"{config.name}_{config.spi}")
    t = replace(t, "REQ_ID", config.req_id)
    t = replace(t, "SPI", config.spi)
    t = replace(t, "LOCAL_PREFIX", localPrefix)
    t = replace(t, "REMOTE_PREFIX", remotePrefix)
    t = replace(t, "ENC_ALG", str(config.crypto_config.enc_alg.value))
    t = replace(t, "ENC_KEY", config.crypto_config.enc_key)
    if config.crypto_config.enc_alg == EncAlgType.AES_GCM_8 or config.crypto_config.enc_alg == EncAlgType.AES_GCM_12 or config.crypto_config.enc_alg == EncAlgType.AES_GCM_16:
        t = replace(t, "INT_ALG", 0)
        t = replace(t, "INT_KEY", "")
        t = replace(t, "ENC_IV", "")
    else:
        t = replace(t, "INT_ALG", str(config.crypto_config.int_alg.value))
        t = replace(t, "INT_KEY", config.crypto_config.int_key)
        t = replace(t, "ENC_IV", config.crypto_config.iv)
    t = replace(t, "HARD_BYTES", config.hard_lifetime.n_bytes)
    t = replace(t, "HARD_PACKETS", config.hard_lifetime.n_packets)
    t = replace(t, "HARD_TIME", config.hard_lifetime.time)
    t = replace(t, "HARD_IDLE", config.hard_lifetime.time_idle)
    t = replace(t, "SOFT_BYTES", config.soft_lifetime.n_bytes)
    t = replace(t, "SOFT_PACKETS", config.soft_lifetime.n_packets)
    t = replace(t, "SOFT_TIME", config.soft_lifetime.time)
    t = replace(t, "SOFT_IDLE", config.soft_lifetime.time_idle)
    t = replace(t, "LOCAL_TUNNEL", local)
    t = replace(t, "REMOTE_TUNNEL", remote)

    return t

def formatG2GSPDValuesJSON(config, localPrefix, remotePrefix, local, remote, direction):
    t = G2GTemplates[TemplateType.AddSPDJson]

    t = replace(t, "ID_NAME", config.name)
    t = replace(t, "REQ_ID", config.req_id)
    t = replace(t, "SPI", config.spi)
    t = replace(t, "LOCAL_PREFIX", localPrefix)
    t = replace(t, "REMOTE_PREFIX", remotePrefix)
    t = replace(t, "ENC_ALG", str(config.crypto_config.enc_alg.value))
    t = replace(t, "ENC_KEY_LENGTH", config.crypto_config.enc_key_length)
    if config.crypto_config.enc_alg == EncAlgType.AES_GCM_8 or config.crypto_config.enc_alg == EncAlgType.AES_GCM_12 or config.crypto_config.enc_alg == EncAlgType.AES_GCM_16:
        t = replace(t, "INT_ALG", 0)
        t = replace(t, "INT_KEY", "")
        t = replace(t, "ENC_IV", "")
    else:
        t = replace(t, "INT_ALG", str(config.crypto_config.int_alg.value))
        t = replace(t, "INT_KEY", config.crypto_config.int_key)
        t = replace(t, "ENC_IV", config.crypto_config.iv)
    t = replace(t, "HARD_BYTES", config.hard_lifetime.n_bytes)
    t = replace(t, "HARD_PACKETS", config.hard_lifetime.n_packets)
    t = replace(t, "HARD_TIME", config.hard_lifetime.time)
    t = replace(t, "HARD_IDLE", config.hard_lifetime.time_idle)
    t = replace(t, "SOFT_BYTES", config.soft_lifetime.n_bytes)
    t = replace(t, "SOFT_PACKETS", config.soft_lifetime.n_packets)
    t = replace(t, "SOFT_TIME", config.soft_lifetime.time)
    t = replace(t, "SOFT_IDLE", config.soft_lifetime.time_idle)
    t = replace(t, "LOCAL_TUNNEL", local)
    t = replace(t, "REMOTE_TUNNEL", remote)
    t = replace(t, "DIRECTION", direction)
    return t

def formatG2GSPDValues(config, localPrefix, remotePrefix, local, remote, direction):
    t = G2GTemplates[TemplateType.AddSPD]
   
    t = replace(t, "ID_NAME", config.name)
    t = replace(t, "REQ_ID", config.req_id)
    t = replace(t, "SPI", config.spi)
    t = replace(t, "LOCAL_PREFIX", localPrefix)
    t = replace(t, "REMOTE_PREFIX", remotePrefix)
    t = replace(t, "ENC_ALG", str(config.crypto_config.enc_alg.value))
    t = replace(t, "ENC_KEY_LENGTH", config.crypto_config.enc_key_length)
    if config.crypto_config.enc_alg == EncAlgType.AES_GCM_8 or config.crypto_config.enc_alg == EncAlgType.AES_GCM_12 or config.crypto_config.enc_alg == EncAlgType.AES_GCM_16:
        t = replace(t, "INT_ALG", 0)
        t = replace(t, "INT_KEY", "")
        t = replace(t, "ENC_IV", "")
    else:
        t = replace(t, "INT_ALG", str(config.crypto_config.int_alg.value))
        t = replace(t, "INT_KEY", config.crypto_config.int_key)
        t = replace(t, "ENC_IV", config.crypto_config.iv)
    t = replace(t, "HARD_BYTES", config.hard_lifetime.n_bytes)
    t = replace(t, "HARD_PACKETS", config.hard_lifetime.n_packets)
    t = replace(t, "HARD_TIME", config.hard_lifetime.time)
    t = replace(t, "HARD_IDLE", config.hard_lifetime.time_idle)
    t = replace(t, "SOFT_BYTES", config.soft_lifetime.n_bytes)
    t = replace(t, "SOFT_PACKETS", config.soft_lifetime.n_packets)
    t = replace(t, "SOFT_TIME", config.soft_lifetime.time)
    t = replace(t, "SOFT_IDLE", config.soft_lifetime.time_idle)
    t = replace(t, "LOCAL_TUNNEL", local)
    t = replace(t, "REMOTE_TUNNEL", remote)
    t = replace(t, "DIRECTION", direction)
    return t

def formatH2HSADValues(config, localPrefix, remotePrefix):
    t = H2hTemplates[TemplateType.AddSAD]

    t = replace(t, "ID_NAME", f"{config.name}_{config.spi}")   
    t = replace(t, "REQ_ID", config.req_id)
    t = replace(t, "SPI", config.spi)
    t = replace(t, "LOCAL_PREFIX", localPrefix)
    t = replace(t, "REMOTE_PREFIX", remotePrefix)
    t = replace(t, "ENC_ALG", str(config.crypto_config.enc_alg.value))
    t = replace(t, "ENC_KEY", config.crypto_config.enc_key)
    if config.crypto_config.enc_alg == EncAlgType.AES_GCM_8 or config.crypto_config.enc_alg == EncAlgType.AES_GCM_12 or config.crypto_config.enc_alg == EncAlgType.AES_GCM_16:
        t = replace(t, "INT_ALG", 0)
        t = replace(t, "INT_KEY", "")
        t = replace(t, "ENC_IV", "")
    else:
        t = replace(t, "INT_ALG", str(config.crypto_config.int_alg.value))
        t = replace(t, "INT_KEY", config.crypto_config.int_key)
        t = replace(t, "ENC_IV", config.crypto_config.iv)
    t = replace(t, "HARD_BYTES", config.hard_lifetime.n_bytes)
    t = replace(t, "HARD_PACKETS", config.hard_lifetime.n_packets)
    t = replace(t, "HARD_TIME", config.hard_lifetime.time)
    t = replace(t, "HARD_IDLE", config.hard_lifetime.time_idle)
    t = replace(t, "SOFT_BYTES", config.soft_lifetime.n_bytes)
    t = replace(t, "SOFT_PACKETS", config.soft_lifetime.n_packets)
    t = replace(t, "SOFT_TIME", config.soft_lifetime.time)
    t = replace(t, "SOFT_IDLE", config.soft_lifetime.time_idle)

    return t

def formatH2HSADValuesJson(config, localPrefix, remotePrefix):
    t = H2hTemplates[TemplateType.AddSADJson]
    
    t = replace(t, "ID_NAME", f"{config.name}_{config.spi}")
    t = replace(t, "REQ_ID", config.req_id)
    t = replace(t, "SPI", config.spi)
    t = replace(t, "LOCAL_PREFIX", localPrefix)
    t = replace(t, "REMOTE_PREFIX", remotePrefix)
    t = replace(t, "ENC_ALG", str(config.crypto_config.enc_alg.value))
    t = replace(t, "ENC_KEY", config.crypto_config.enc_key)
    t = replace(t, "HARD_BYTES", config.hard_lifetime.n_bytes)
    t = replace(t, "HARD_PACKETS", config.hard_lifetime.n_packets)
    t = replace(t, "HARD_TIME", config.hard_lifetime.time)
    t = replace(t, "HARD_IDLE", config.hard_lifetime.time_idle)
    t = replace(t, "SOFT_BYTES", config.soft_lifetime.n_bytes)
    t = replace(t, "SOFT_PACKETS", config.soft_lifetime.n_packets)
    t = replace(t, "SOFT_TIME", config.soft_lifetime.time)
    t = replace(t, "SOFT_IDLE", config.soft_lifetime.time_idle)
    if config.crypto_config.enc_alg == EncAlgType.AES_GCM_8 or config.crypto_config.enc_alg == EncAlgType.AES_GCM_12 or config.crypto_config.enc_alg == EncAlgType.AES_GCM_16:
        t = replace(t, "INT_ALG", 0)
        t = replace(t, "INT_KEY", "")
        t = replace(t, "ENC_IV", "")
    else:
        t = replace(t, "INT_ALG", str(config.crypto_config.int_alg.value))
        t = replace(t, "INT_KEY", config.crypto_config.int_key)
        t = replace(t, "ENC_IV", config.crypto_config.iv)

    return t

def formatH2HSPDValues(config, localPrefix, remotePrefix, direction):
    t = H2hTemplates[TemplateType.AddSPD]

    t = replace(t, "ID_NAME", config.name)
    t = replace(t, "REQ_ID", config.req_id)
    t = replace(t, "SPI", config.spi)
    t = replace(t, "LOCAL_PREFIX", localPrefix)
    t = replace(t, "REMOTE_PREFIX", remotePrefix)
    t = replace(t, "ENC_ALG", str(config.crypto_config.enc_alg.value))
    if config.crypto_config.enc_alg == EncAlgType.AES_GCM_8 or config.crypto_config.enc_alg == EncAlgType.AES_GCM_12 or config.crypto_config.enc_alg == EncAlgType.AES_GCM_16:
        t = replace(t, "INT_ALG", 0)
        t = replace(t, "INT_KEY", "")
        t = replace(t, "ENC_IV", "")
    else:
        t = replace(t, "INT_ALG", str(config.crypto_config.int_alg.value))
        t = replace(t, "INT_KEY", config.crypto_config.int_key)
        t = replace(t, "ENC_IV", config.crypto_config.iv)
    t = replace(t, "HARD_BYTES", config.hard_lifetime.n_bytes)
    t = replace(t, "HARD_PACKETS", config.hard_lifetime.n_packets)
    t = replace(t, "HARD_TIME", config.hard_lifetime.time)
    t = replace(t, "HARD_IDLE", config.hard_lifetime.time_idle)
    t = replace(t, "SOFT_BYTES", config.soft_lifetime.n_bytes)
    t = replace(t, "SOFT_PACKETS", config.soft_lifetime.n_packets)
    t = replace(t, "SOFT_TIME", config.soft_lifetime.time)
    t = replace(t, "SOFT_IDLE", config.soft_lifetime.time_idle)
    t = replace(t, "DIRECTION", direction)
    t = replace(t, "ENC_KEY_LENGTH", config.crypto_config.enc_key_length)

    return t

def formatH2HSPDValuesJson(config, localPrefix, remotePrefix, direction):
    t = H2hTemplates[TemplateType.AddSPDJson]

    t = replace(t, "ID_NAME", config.name)
    t = replace(t, "SPI", config.spi)
    t = replace(t, "REQ_ID", config.req_id)
    t = replace(t, "LOCAL_PREFIX", localPrefix)
    t = replace(t, "REMOTE_PREFIX", remotePrefix)
    t = replace(t, "ENC_ALG", str(config.crypto_config.enc_alg.value))
    if config.crypto_config.enc_alg == EncAlgType.AES_GCM_8 or config.crypto_config.enc_alg == EncAlgType.AES_GCM_12 or config.crypto_config.enc_alg == EncAlgType.AES_GCM_16:
        t = replace(t, "INT_ALG", 0)
        t = replace(t, "INT_KEY", "")
        t = replace(t, "ENC_IV", "")
    else:
        t = replace(t, "INT_ALG", str(config.crypto_config.int_alg.value))
        t = replace(t, "INT_KEY", config.crypto_config.int_key)
        t = replace(t, "ENC_IV", config.crypto_config.iv)
    t = replace(t, "HARD_BYTES", config.hard_lifetime.n_bytes)
    t = replace(t, "HARD_PACKETS", config.hard_lifetime.n_packets)
    t = replace(t, "HARD_TIME", config.hard_lifetime.time)
    t = replace(t, "HARD_IDLE", config.hard_lifetime.time_idle)
    t = replace(t, "SOFT_BYTES", config.soft_lifetime.n_bytes)
    t = replace(t, "SOFT_PACKETS", config.soft_lifetime.n_packets)
    t = replace(t, "SOFT_TIME", config.soft_lifetime.time)
    t = replace(t, "SOFT_IDLE", config.soft_lifetime.time_idle)
    t = replace(t, "DIRECTION", direction)
    t = replace(t, "ENC_KEY_LENGTH", config.crypto_config.enc_key_length)

    return t

def generateI2NSFConfig(SADEntries: List[str], SPDEntries: List[str]) -> str:
    data = ""
    if len(SPDEntries) > 0:
        data = "<spd>" + "\n".join(SPDEntries) + "</spd>"
    if len(SADEntries) > 0:
        entries = "<sad>" + "\n".join(SADEntries) + "</sad>"
        if len(data) > 0:
            data = f"{data}{entries}"
        else:
            data = entries

    return replace(EditconfigTemplate, "REPLACE_DATA", data)

def generateI2NSFConfigJson(SADEntries: List[str], SPDEntries: List[str]) -> str:
    data = ""
    if len(SPDEntries) > 0:
        data = "\n".join(SPDEntries)
    if len(SADEntries) > 0:
        entries = "\n" + "\n".join(SADEntries) + "\n"
        if len(data) > 0:
            data = f"{data}{entries}"
        else:
            data = entries

    return replace(EditconfigTemplateJson, "REPLACE_DATA", data)