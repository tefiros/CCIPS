import logging
from enum import Enum
from ncclient.transport.session import etree
from logger import Logger

ALG = "aes-gcm-16-icv"
files = ["./xml/g2g/0_g2g_tunnel_esp_enc_auth_gwX.xml",
         "./xml/g2g/1_g2g_tunnel_add_sad_in_gX.xml",
         "./xml/g2g/2_g2g_tunnel_add_sad_out_gX.xml",
         "./xml/g2g/3_g2g_tunnel_del_sad_in_out_hX.xml",
         "./xml/g2g/4_g2g_tunnel_del_sad.xml",
         "./xml/g2g/4_g2g_tunnel_del_spd.xml"]
log = Logger().get_logger()


# Initial configuration (SPD and SAD) sent in the registration process to create SAs between two nodes.
def create_initial_config(rule_in, rule_out, rule_fwd, local_address, remote_address, local_internal, remote_internal,
                          spi_in, spi_out, enc_key, vector, int_key, enc_alg, int_alg, soft_time, hard_time):
    log.debug(f'GENERATING INITIAL PHASE')
    snippet = etree.tostring(etree.parse(files[0]), pretty_print=True).decode("utf-8")
    # snippet_str = snippet.decode("utf-8")
    snippet = snippet.replace("RULE_IN", str(rule_in))
    snippet = snippet.replace("RULE_OUT", str(rule_out))
    snippet = snippet.replace("RULE_FWD", str(rule_fwd))
    snippet = snippet.replace("LOCAL_ADDRESS", local_address)
    snippet = snippet.replace("REMOTE_ADDRESS", remote_address)
    snippet = snippet.replace("SPI_IN", str(spi_in))
    snippet = snippet.replace("SPI_OUT", str(spi_out))

    snippet = snippet.replace("LOCAL_INTERNAL", local_internal)
    snippet = snippet.replace("REMOTE_INTERNAL", remote_internal)
    snippet = snippet.replace("ENC_ALG", enc_alg)
    snippet = snippet.replace("ENC_KEY", enc_key)
    snippet = snippet.replace("VECTOR", vector)
    snippet = snippet.replace("INT_ALG", int_alg)
    snippet = snippet.replace("INT_KEY", int_key)

    # To configure the lifetime of rekey
    snippet = snippet.replace("SOFT_TIME_USED", str(int(soft_time)))
    snippet = snippet.replace("SOFT_TIME_ADDED", str(int(soft_time) + 20))
    snippet = snippet.replace("HARD_TIME_USED", str(int(hard_time)))
    snippet = snippet.replace("HARD_TIME_ADDED", str(int(hard_time) + 20))

    f = open(f'/tmp/initial_config{local_address}_{remote_address}.txt', "w")
    f.write(snippet)

    return snippet


# Configuration inbound - Rekey - Phase 1
def create_inbound_config(spi_in, local_address, remote_address, local_internal, remote_internal, enc_key, vector,
                          int_key, enc_alg, int_alg, soft_time, hard_time):
    log.debug(f'GENERATING INBOUND REKEY CONFIG PHASE 1')
    snippet = etree.tostring(etree.parse(files[1]), pretty_print=True).decode("utf-8")
    snippet = snippet.replace("LOCAL_ADDRESS", local_address)
    snippet = snippet.replace("REMOTE_ADDRESS", remote_address)
    snippet = snippet.replace("SPI_IN", str(spi_in))

    snippet = snippet.replace("LOCAL_INTERNAL", local_internal)
    snippet = snippet.replace("REMOTE_INTERNAL", remote_internal)

    snippet = snippet.replace("ENC_KEY", enc_key)
    snippet = snippet.replace("VECTOR", vector)
    snippet = snippet.replace("ENC_ALG", enc_alg)
    snippet = snippet.replace("INT_ALG", int_alg)
    snippet = snippet.replace("INT_KEY", int_key)

    snippet = snippet.replace("SOFT_TIME_USED", str(int(soft_time)))
    snippet = snippet.replace("SOFT_TIME_ADDED", str(int(soft_time) + 20))
    snippet = snippet.replace("HARD_TIME_USED", str(int(hard_time)))
    snippet = snippet.replace("HARD_TIME_ADDED", str(int(hard_time) + 20))
    f = open(f'/tmp/inbound_config{local_address}_{remote_address}.txt', "w")
    f.write(snippet)
    return snippet


# Configuration outbound - Rekey - Phase 2
def create_outbound_config(spi_out, local_address, remote_address, local_internal, remote_internal, enc_key, vector,
                           int_key, enc_alg, int_alg, soft_time, hard_time):
    log.debug(f'GENERATING OUTBOUND REKEY CONFIG PHASE 2')
    snippet = etree.tostring(etree.parse(files[2]), pretty_print=True).decode("utf-8")
    snippet = snippet.replace("LOCAL_ADDRESS", local_address)
    snippet = snippet.replace("REMOTE_ADDRESS", remote_address)
    snippet = snippet.replace("SPI_OUT", str(spi_out))

    snippet = snippet.replace("LOCAL_INTERNAL", local_internal)
    snippet = snippet.replace("REMOTE_INTERNAL", remote_internal)
    snippet = snippet.replace("ENC_ALG", enc_alg)
    snippet = snippet.replace("ENC_KEY", enc_key)
    snippet = snippet.replace("VECTOR", vector)
    snippet = snippet.replace("INT_ALG", int_alg)
    snippet = snippet.replace("INT_KEY", int_key)

    snippet = snippet.replace("SOFT_TIME_USED", str(int(soft_time)))
    snippet = snippet.replace("SOFT_TIME_ADDED", str(int(soft_time) + 20))
    snippet = snippet.replace("HARD_TIME_USED", str(int(hard_time)))
    snippet = snippet.replace("HARD_TIME_ADDED", str(int(hard_time) + 20))
    f = open(f'/tmp/outbound_config{local_address}_{remote_address}.txt', "w")
    f.write(snippet)
    return snippet


# Configuration delete - Rekey - Phase 3
def delete_config(local_address, remote_address, local_internal, remote_internal, spi_in, spi_out, old_enc_key,
                  old_vector, old_int_key, enc_alg, int_alg, soft_time, hard_time):
    log.debug(f'GENERATING DELETE REKEY CONFIG PHASE 3')
    snippet = etree.tostring(etree.parse(files[3]), pretty_print=True).decode("utf-8")
    snippet = snippet.replace("LOCAL_ADDRESS", local_address)
    snippet = snippet.replace("REMOTE_ADDRESS", remote_address)
    snippet = snippet.replace("SPI_IN", str(spi_in))
    snippet = snippet.replace("SPI_OUT", str(spi_out))
    snippet = snippet.replace("ENC_ALG", enc_alg)
    snippet = snippet.replace("LOCAL_INTERNAL", local_internal)
    snippet = snippet.replace("REMOTE_INTERNAL", remote_internal)
    snippet = snippet.replace("ENC_ALG", enc_alg)

    snippet = snippet.replace("ENC_KEY", old_enc_key)
    snippet = snippet.replace("VECTOR", old_vector)
    snippet = snippet.replace("INT_ALG", int_alg)
    snippet = snippet.replace("INT_KEY", old_int_key)

    snippet = snippet.replace("SOFT_TIME_USED", str(int(soft_time)))
    snippet = snippet.replace("SOFT_TIME_ADDED", str(int(soft_time) + 20))
    snippet = snippet.replace("HARD_TIME_USED", str(int(hard_time)))
    snippet = snippet.replace("HARD_TIME_ADDED", str(int(hard_time) + 20))
    f = open(f'/tmp/delete_config{local_address}_{remote_address}.txt', "w")
    f.write(snippet)
    return snippet


# Configuration delete sad
def remove_ipsec_sad(spi_in):
    # print("[DELETE CONFIG]")
    log.debug(f'GENERATING DELETE CONFIG FOR SPI {spi_in}')
    snippet = etree.tostring(etree.parse(files[4]), pretty_print=True).decode("utf-8")
    snippet = snippet.replace("SPI_IN", str(spi_in))
    # snippet = snippet.replace("RULE_IN", str(rule_in))
    # snippet = snippet.replace("SPI_OUT", str(spi_out))
    return snippet


# Configuration delete spd
def remove_ipsec_spd(rule_number):
    log.debug(f'GENERATING DELETE CONFIG FOR RULE {rule_number}')
    snippet = etree.tostring(etree.parse(files[5]), pretty_print=True).decode("utf-8")
    snippet = snippet.replace("RULE_NUMBER", str(rule_number))
    # snippet = snippet.replace("RULE_IN", str(rule_in))
    # snippet = snippet.replace("SPI_OUT", str(spi_out))
    return snippet


class Host:
    def __init__(self, ip_control, ip_data, ip_internal, ip_dmz, manager):
        self.ip_control = ip_control
        self.ip_dmz = ip_dmz
        self.ip_data = ip_data
        self.ip_internal = ip_internal
        self.manager = manager

    def get_list_ip(self):
        log.info(
            "Host-----------------Address when asking for get_list_ip " + self.ip_dmz if self.ip_dmz is not None else self.ip_data)
        return self.ip_dmz if self.ip_dmz is not None else self.ip_data


# ip_local_internal
class Ipsa:
    def __init__(self, ip_local_control, ip_local_data, ip_local_internal, ip_remote_control, ip_remote_data,
                 ip_remote_internal, spi_in, spi_out, rules, ip_dmz_local,ip_dmz_remote):
        self.ip_local_control = ip_local_control
        self.ip_local_data = ip_local_data
        self.ip_remote_control = ip_remote_control
        self.ip_remote_data = ip_remote_data
        self.ip_local_internal = ip_local_internal
        self.ip_remote_internal = ip_remote_internal
        self.spi_in = spi_in
        self.spi_out = spi_out
        self.rules = rules
        self.ip_dmz_local = ip_dmz_local
        self.ip_dmz_remote = ip_dmz_remote

    def get_local_ip(self):
        return self.ip_dmz_local if self.ip_dmz_local is not None else self.ip_local_data

    def get_remote_ip(self):
        return self.ip_dmz_remote if self.ip_dmz_remote is not None else self.ip_remote_data





class InformationRekey:
    def __init__(self, spi_in_new, spi_out_new, msg_id1, msg_id2, receive_id1, receive_id2, state):
        self.spi_in_new = spi_in_new
        self.spi_out_new = spi_out_new
        self.msg_id1 = msg_id1
        self.msg_id2 = msg_id2
        self.receive_id1 = receive_id1
        self.receive_id2 = receive_id2
        self.state = state


# Enum
class StateRekey(Enum):
    INBOUD = 1
    OUTBOUND = 2
    DELETE = 3
