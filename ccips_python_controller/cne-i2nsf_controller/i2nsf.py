import logging
import string
import random
import time
import traceback
from threading import Thread, Lock
from snippets import *
from multiprocessing import Queue
from ncclient import manager
from ncclient.transport.session import *
from werkzeug.serving import run_simple
from flask import Flask, request, Response
from logger import Logger

# Some constants
SADB_STATE_DYING = 'Dying'
time_out = 60

log = Logger().get_logger()


class I2NSF:

    def __init__(self, data) -> None:
        self.hosts = {}  # Hosts inside the network
        self.registration_process = {}  # Currently active registration processes.
        self.ipsec_associations = {}  # IPSec associations established
        self.active_rekeys = []  # SPIs of SAs that are in an active rekey process
        self.rpc_ids = {}  # Dictionary msg_id <---> spi for troubleshooting
        self.active_rekey_information = {}  # Information generated for the renovation of a SA. -
        # Dictionary spi_in_old --> information_rekey
        self.workers = []  # Threads to execute tasks

        self.spinumber = 257
        # Maybe move this to a global value
        self.rulenumber = 1

        self.mutex_register = Lock()  # Lock to control registration process
        self.mutex = Lock()  # Lock to control that if two notifications arrive sadb_expire (soft type) of the same SA in the same
        # instant of time, only the rekey process is executed once.

        self.mutex_update_spinumber = Lock()
        self.mutex_update_rulenumber = Lock()
        self.mutex_rpc = Lock()
        self.mutex_hosts = Lock()
        self.mutex_ipsec_associations = Lock()
        self.mutex_active_rekeys = Lock()
        self.mutex_rpc_ids = Lock()
        self.mutex_active_rekeys_information = Lock()
        self.mutex_registration_process = Lock()

        self.old_enc_key = self.old_vector = self.old_int_key = None

        # Set algorithm settings
        self.enc_alg = data['encAlg'][0]
        self.int_alg = data['intAlg'][0]
        self.create_random_keys()

        # Lifetime settings
        self.soft_lifetime = data['softLifetime']
        self.hard_lifetime = data['hardLifetime']

        self.pool = ThreadPool(20, self.workers)

        # Setup the listener
        self.listener = Listener(self.pool, self.analyze_notification, self.analyze_rpc_reply)

    def create_random_keys(self, stringLength=8):
        log.debug('CREATE RANDOM KEYS')
        # lettersAndDigits= string.digits + "ABCDEF"
        for i in range(3):
            lettersAndDigits = string.digits + "abcdef"
            random_string = ''.join(random.choice(lettersAndDigits) for i in range(stringLength))
            # Convert to data type: yang:hex-string
            if i == 0:
                t = iter(random_string)
                self.enc_key = ''.join(a + b for a, b in zip(t, t))
                # enc_key = ':'.join(a+b for a,b in zip(t, t))
                # print("enc_key " + enc_key)
            if i == 1:
                t = iter(random_string)
                self.vector = ''.join(a + b for a, b in zip(t, t))
                # vector = ':'.join(a+b for a,b in zip(t, t))
                # print("vector " + vector)
            if i == 2:
                t = iter(random_string)
                # int_key = ':'.join(a+b for a,b in zip(t, t))
                self.int_key = ''.join(a + b for a, b in zip(t, t))
                # print("int_key " + int_key)
        # return cadena
        log.info("ENC_KEY: {}".format(self.enc_key))
        log.info("VECTOR: {}".format(self.vector))
        log.info("INT_KEY: {}".format(self.int_key))

    def sign_up(self, ip_control, networkInternal, ip_data, ip_dmz=None):
        log.debug('SIGN UP')

        log_writeln(
            "Registro recibido ----> IP Control: " + ip_control + " IP internal " + networkInternal + " IP Data: " + ip_data)

        # Setup first node
        # try:
        #     m = manager.connect(host=ip_control, port=830, username="osm", password="osm4u",
        #                         hostkey_verify=False)
        #     m._session.add_listener(self.listener)
        #     try:
        #         m.create_subscription()
        #     except Exception as e:
        #         logging.error("ERROR subscription: {}".format(e))
        #         raise e
        #     m.async_mode = True
        # except Exception as e:
        #     logging.error(str(e))
        #     logging.error(traceback.format_exc())
        #     raise e
        # This is only for dmz case...
        m = 0
        result = self.create_associations(ip_control, networkInternal, ip_data, ip_dmz, m)
        # if result:
        #     log_writeln(
        #         "Registro completado: nodo ip_control " + ip_control + " ip_internal " + networkInternal + " ip_data " + ip_data)
        #     return True
        # else:
        #     logging.error(
        #         "Registro no completado: nodo ip_control " + ip_control + " ip_internal " + networkInternal + " ip_data " + ip_data)
        #     m.close_session()
        #     return False
        return True

    def create_associations(self, ip_control, ip_internal, ip_data, ip_dmz, manager):
        log.debug('CREATE ASSOCIATIONS')
        config1 = config2 = True
        if self.hosts:
            self.mutex_register.acquire()
            self.add_host(ip_control, ip_data, ip_internal, ip_dmz, manager)
            self.mutex_register.release()
            for ip_control_remote in self.hosts:
                message_id1 = message_id2 = None
                log.info("Creando asociaciones de seguridad IPsec para " + ip_data + " -> " +
                         self.hosts[ip_control_remote].ip_data)

                self.mutex_update_spinumber.acquire()
                spi_in = self.get_spi_number()  # Security Parameter Index
                spi_out = self.increment_spi_number()  # Security Parameter Index + 1
                self.increment_spi_number()  # Update global SPI Generator
                self.mutex_update_spinumber.release()
                #
                # # TODO guardar las rules em
                self.mutex_update_rulenumber.acquire()
                rule_in = self.get_rule_number()  # Rule number
                rule_out = self.increment_rule_number()  # Rule number + 1
                rule_fwd = self.increment_rule_number()  # Rule number + 1
                self.mutex_update_rulenumber.release()

                try:
                    config_local_node = create_initial_config(rule_in, rule_out, rule_fwd,
                                                              self.hosts[ip_control].get_list_ip(),
                                                              self.hosts[ip_control_remote].ip_data,
                                                              ip_internal, self.hosts[ip_control_remote].ip_internal,
                                                              spi_in, spi_out,
                                                              self.enc_key, self.vector, self.int_key, self.enc_alg,
                                                              self.int_alg, self.soft_lifetime, self.hard_lifetime)
                    log_writeln("-----------------LOCAL_NODE_CONFIG--------------")
                    log_writeln(config_local_node)
                    # rpc = manager.edit_config(target='running', config=config_local_node, test_option='test-then-set')
                    # message_id1 = rpc.id
                    # self.add_registration_process(message_id1, False)

                except Exception as e:
                    logging.error("{}".format(e))
                    config1 = False
                    logging.error(str(e))
                    logging.error(traceback.format_exc())

                try:
                    config_remote_node = create_initial_config(rule_in, rule_out, rule_fwd,
                                                               self.hosts[ip_control_remote].get_list_ip(), ip_data,
                                                               self.hosts[ip_control_remote].ip_internal, ip_internal,
                                                               spi_out, spi_in,
                                                               self.enc_key, self.vector, self.int_key, self.enc_alg,
                                                               self.int_alg, self.soft_lifetime, self.hard_lifetime)
                    log_writeln("-----------------REMOTE_NODE_CONFIG--------------")
                    log_writeln(config_remote_node)
                    # m = self.hosts[ip_control_remote].manager
                    # rpc = m.edit_config(target='running', config=config_remote_node, test_option='test-then-set')
                    # message_id2 = rpc.id
                    # self.add_registration_process(message_id2, False)

                except Exception as e:
                    logging.error("{}".format(e))
                    config2 = False
                    logging.error(str(e))
                    logging.error(traceback.format_exc())

                return True
                reg = self.check_registration_process(message_id1, message_id2)

                if config1 and config2 and reg:  # and reg
                    log.debug("Associations Done")
                    # Create a ipsec association for local node (Local ---> Remote)
                    log.error(f'Setting local as {self.hosts[ip_control].ip_dmz}')
                    self.add_ipsec_association(
                        Ipsa(ip_control, self.hosts[ip_control].ip_data,
                             ip_internal, ip_control_remote, self.hosts[ip_control_remote].ip_data,
                             self.hosts[ip_control].ip_internal, spi_in, spi_out,
                             [rule_in, rule_out, rule_fwd], self.hosts[ip_control].ip_dmz,
                             self.hosts[ip_control_remote].ip_dmz))
                    # Create a ipsec association for local node (Remote ---> Local)
                    # log.error(f'Setting local as {self.hosts[ip_control_remote].ip_dmz} and remote {}')
                    self.add_ipsec_association(
                        Ipsa(ip_control_remote, self.hosts[ip_control_remote].ip_data,
                             self.hosts[ip_control_remote].ip_internal, ip_control,
                             ip_data, ip_internal, spi_out, spi_in,
                             [rule_in, rule_out, rule_fwd], self.hosts[ip_control_remote].ip_dmz,
                             self.hosts[ip_control].ip_dmz))
                else:
                    return False
                break
            return True
        else:
            self.mutex_register.acquire()
            self.add_host(ip_control, ip_data, ip_internal, ip_dmz, manager)
            self.mutex_register.release()
            return True

    # Procedure that analyze a sadb_expire notification, if this is a soft type then the rekey process for the SA identified
    # with the SPI containing the notification is started.
    def analyze_notification(self, notification):
        log.error('ANALYZE NOTIFICATION')
        sadb_notification = notification.find("{http://example.net/ietf-ipsec}sadb_expire")
        if sadb_notification is not None:
            state = notification.find("{http://example.net/ietf-ipsec}sadb_expire").find(
                "{http://example.net/ietf-ipsec}state").text
            if state is not None and state == SADB_STATE_DYING:
                spi_received = notification.find("{http://example.net/ietf-ipsec}sadb_expire").find(
                    "{http://example.net/ietf-ipsec}spi").text  # GET the SPI from the notification

                if spi_received is not None:
                    spi_received = int(spi_received)
                    log_writeln("spi_received = " + str(spi_received))

                    self.mutex.acquire()
                    if spi_received not in self.active_rekeys:

                        if spi_received in self.ipsec_associations.keys():  # Check if the ipsa is active or not
                            ipsec_association = self.ipsec_associations.get(spi_received)
                            spi_in = spi_received
                            spi_out = ipsec_association.spi_out
                            self.add_active_rekeys(spi_in, spi_out)
                            log_writeln("Rekey : spi_in = " + str(spi_in) + " spi_out = " + str(spi_out))
                            log_writeln("Set inboud task spi_in_old = " + str(spi_in))
                            self.pool.add_task(self.inbound_rekey, ipsec_association)
                        else:
                            log_writeln("Rekey done for spi -> " + str(spi_received))
                    else:
                        log_writeln("Active rekey for spi -> " + str(spi_received))

                    self.mutex.release()

    # Procedure to analyze RPC-Replys for the control of confirmations of Netconf operations
    def analyze_rpc_reply(self, rpc_reply):
        log.debug('ANALZE RPC REPLY')
        rpc_reply = etree.fromstring(rpc_reply)
        msg_id = rpc_reply.attrib['message-id']

        if msg_id is not None:
            if msg_id in self.registration_process.keys():
                self.add_registration_process(msg_id, True)

            elif msg_id in self.rpc_ids.keys():
                spi_in_old = self.rpc_ids.get(msg_id)
                active_rekey = self.active_rekey_information.get(spi_in_old)

                if msg_id == active_rekey.msg_id1:
                    active_rekey.receive_id1 = True
                    self.add_active_rekeys_information(spi_in_old, active_rekey)  # Update variable
                    self.delete_rpc_id(msg_id)
                else:
                    active_rekey.receive_id2 = True
                    self.add_active_rekeys_information(spi_in_old, active_rekey)  # Update variable
                    self.delete_rpc_id(msg_id)

                active_rekey = self.active_rekey_information.get(spi_in_old)

                if active_rekey.receive_id1 and active_rekey.receive_id2:
                    active_rekey.msg_id1 = None
                    active_rekey.msg_id2 = None
                    active_rekey.receive_id1 = False
                    active_rekey.receive_id2 = False
                    self.add_active_rekeys_information(spi_in_old, active_rekey)  # Update variable
                    ipsa = self.ipsec_associations.get(spi_in_old)

                    if active_rekey.state == StateRekey.INBOUD:
                        log_writeln("Set outbound task spi_old = " + str(spi_in_old))
                        self.pool.add_task(self.outbound_rekey, ipsa)
                    elif active_rekey.state == StateRekey.OUTBOUND:
                        log_writeln("Set delete task spi_old = " + str(spi_in_old))
                        self.pool.add_task(self.delete_rekey, ipsa)
                    elif active_rekey.state == StateRekey.DELETE:
                        log_writeln("Set update task spi_old = " + str(spi_in_old))
                        self.pool.add_task(self.update_structures, ipsa)

    # It is checked if the confirmations of the configurations applied in the nodes are received, in case of not receiving
    # these in the established time the process of registry will fail.
    def check_registration_process(self, message_id1, message_id2):
        log.debug('CHECK REGISTRATION PROCESS')
        initial = time.time()
        limit = initial + time_out

        while initial <= limit:
            if (message_id1 in self.registration_process.keys()) and (message_id2 in self.registration_process.keys()):
                received1 = self.registration_process.get(message_id1)
                received2 = self.registration_process.get(message_id2)
                if received1 and received2:
                    self.delete_registration_process(message_id1)
                    self.delete_registration_process(message_id2)
                    return True

                time.sleep(0.2)
                initial = time.time()

        return False

    def inbound_rekey(self, ipsa):
        log.debug('INBOUND REKEY')
        self.mutex_update_spinumber.acquire()
        new_spi_in = self.get_spi_number()
        new_spi_out = self.increment_spi_number()
        self.increment_spi_number()
        self.mutex_update_spinumber.release()

        log_writeln(
            "Rekey : spi_in_old = " + str(ipsa.spi_in) + " spi_out_old = " + str(ipsa.spi_out) + "spi_in_new = " +
            str(new_spi_in) + " spi_out_new = " + str(new_spi_out))

        # create_qkd_keys()

        self.old_enc_key = self.enc_key
        self.old_vector = self.vector
        self.old_int_key = self.int_key
        self.create_random_keys()

        config_local_node = create_inbound_config(new_spi_in, ipsa.get_local_ip(), ipsa.ip_remote_data,
                                                  ipsa.ip_local_internal, ipsa.ip_remote_internal, self.enc_key,
                                                  self.vector, self.int_key, self.enc_alg, self.int_alg,
                                                  self.soft_lifetime, self.hard_lifetime)
        m = self.hosts[ipsa.ip_local_control].manager
        rpc = m.edit_config(target='running', config=config_local_node, test_option='test-then-set')
        message_id1 = rpc.id

        config_remote_node = create_inbound_config(new_spi_out, ipsa.get_remote_ip(), ipsa.ip_local_data,
                                                   ipsa.ip_remote_internal, ipsa.ip_local_internal, self.enc_key,
                                                   self.vector, self.int_key, self.enc_alg, self.int_alg,
                                                   self.soft_lifetime, self.hard_lifetime)
        m = self.hosts[ipsa.ip_remote_control].manager
        rpc = m.edit_config(target='running', config=config_remote_node, test_option='test-then-set')
        message_id2 = rpc.id

        log_writeln("IDs Inbound: spi_in_old = " + str(ipsa.spi_in) + " spi_out_old = " + str(ipsa.spi_out) +
                    "Inbound ID 1 = " + message_id1 + " Inbound ID 2 = " + message_id2)

        self.add_rpc_ids(ipsa.spi_in, message_id1, message_id2)

        self.add_active_rekeys_information(ipsa.spi_in,
                                           InformationRekey(new_spi_in, new_spi_out, message_id1, message_id2,
                                                            False, False, StateRekey.INBOUD))
        log_writeln(
            "Rekey : spi_in_old = " + str(ipsa.spi_in) + " spi_out_old = " + str(ipsa.spi_out) + "spi_in_new = " +
            str(new_spi_in) + " spi_out_new = " + str(new_spi_out) + " ------> Inbound is sent")

    # Procedure outbound - Rekey - Phase 2
    def outbound_rekey(self, ipsa):
        log.debug("OUTBOUND REKEY")
        info_rekey = self.active_rekey_information.get(ipsa.spi_in)

        config_local_node = create_outbound_config(info_rekey.spi_out_new, ipsa.get_local_ip(), ipsa.ip_remote_data,
                                                   ipsa.ip_local_internal, ipsa.ip_remote_internal, self.enc_key,
                                                   self.vector, self.int_key, self.enc_alg, self.int_alg,
                                                   self.soft_lifetime, self.hard_lifetime)
        m = self.hosts[ipsa.ip_local_control].manager
        rpc = m.edit_config(target='running', config=config_local_node, test_option='test-then-set')
        message_id1 = rpc.id

        config_remote_node = create_outbound_config(info_rekey.spi_in_new, ipsa.get_remote_ip(), ipsa.ip_local_data,
                                                    ipsa.ip_remote_internal, ipsa.ip_local_internal, self.enc_key,
                                                    self.vector, self.int_key, self.enc_alg, self.int_alg,
                                                    self.soft_lifetime, self.hard_lifetime)
        m = self.hosts[ipsa.ip_remote_control].manager
        rpc = m.edit_config(target='running', config=config_remote_node, test_option='test-then-set')
        message_id2 = rpc.id

        log_writeln("IDs Outbound: spi_in_old = " + str(ipsa.spi_in) + " spi_out_old = " + str(ipsa.spi_out) +
                    "Outbound ID 1 = " + message_id1 + " Outbound ID 2 = " + message_id2)

        self.add_rpc_ids(ipsa.spi_in, message_id1, message_id2)
        info_rekey.msg_id1 = message_id1
        info_rekey.msg_id2 = message_id2
        info_rekey.receive_id1 = False
        info_rekey.receive_id2 = False
        info_rekey.state = StateRekey.OUTBOUND

        self.add_active_rekeys_information(ipsa.spi_in, info_rekey)

        log_writeln("Rekey : spi_in_old = " + str(ipsa.spi_in) + " spi_out_old = " + str(ipsa.spi_out) +
                    "spi_in_new = " + str(info_rekey.spi_in_new) + " spi_out_new = " + str(info_rekey.spi_out_new)
                    + " -----> Outbound is sent")

    # Procedure delete - Rekey - Phase 3
    def delete_rekey(self, ipsa: Ipsa):
        log.debug('DELETE REKEYS')
        info_rekey = self.active_rekey_information.get(ipsa.spi_in)

        config_local_node = delete_config(ipsa.get_local_ip(), ipsa.ip_remote_data, ipsa.ip_local_internal,
                                          ipsa.ip_remote_internal, ipsa.spi_in, ipsa.spi_out, self.old_enc_key,
                                          self.old_vector,
                                          self.old_int_key, self.enc_alg, self.int_alg, self.soft_lifetime,
                                          self.hard_lifetime)
        m = self.hosts[ipsa.ip_local_control].manager
        rpc = m.edit_config(target='running', config=config_local_node, test_option='test-then-set')
        message_id1 = rpc.id

        # TODO change ip_local_data, two a method that will decide if use dmz or exposed ip
        config_remote_node = delete_config(ipsa.get_remote_ip(), ipsa.ip_local_data, ipsa.ip_remote_internal,
                                           ipsa.ip_local_internal, ipsa.spi_out, ipsa.spi_in, self.old_enc_key,
                                           self.old_vector,
                                           self.old_int_key, self.enc_alg, self.int_alg, self.soft_lifetime,
                                           self.hard_lifetime)
        m = self.hosts[ipsa.ip_remote_control].manager
        rpc = m.edit_config(target='running', config=config_remote_node, test_option='test-then-set')
        message_id2 = rpc.id
        log_writeln("IDS Delete: spi_in_old = " + str(ipsa.spi_in) + " spi_out_old = ""Inbound ID 1 = " + message_id1 +
                    " Inbound ID 2 = " + message_id2)

        self.add_rpc_ids(ipsa.spi_in, message_id1, message_id2)
        info_rekey.msg_id1 = message_id1
        info_rekey.msg_id2 = message_id2
        info_rekey.receive_id1 = False
        info_rekey.receive_id2 = False
        info_rekey.state = StateRekey.DELETE

        self.add_active_rekeys_information(ipsa.spi_in, info_rekey)
        log_writeln("Rekey : spi_in_old = " + str(ipsa.spi_in) + " spi_out_old = " + str(ipsa.spi_out) +
                    "spi_in_new = " + str(info_rekey.spi_in_new) + " spi_out_new = " + str(info_rekey.spi_out_new)
                    + " -----> Delete is sent")

    def remove_ipsec_policies(self):

        log.debug("Removing IPSEC ASSOCIATIONS")
        self.listener.stopListening()
        # self.delete_rekey(self,ipsa)
        for k, v in self.ipsec_associations.items():
            try:
                config_local_node = remove_ipsec_sad(v.spi_in)
                m = self.hosts[v.ip_local_control].manager
                rpc = m.edit_config(target='running', config=config_local_node)
                message_id1 = rpc.id

                config_remote_node = remove_ipsec_sad(v.spi_in)
                m = self.hosts[v.ip_remote_control].manager
                rpc = m.edit_config(target='running', config=config_remote_node)
                message_id2 = rpc.id
                log_writeln(
                    "IDS Delete: spi_in_old = " + str(v.spi_in) + " spi_out_old = ""Inbound ID 1 = " + message_id1 +
                    " Inbound ID 2 = " + message_id2)
            except:
                pass
            # Remove rules
            for r in v.rules:
                config_local_node = remove_ipsec_spd(r)
                m = self.hosts[v.ip_local_control].manager
                m.async_mode = False
                rpc = m.edit_config(target='running', config=config_local_node)

        for k, v in self.hosts.items():
            # Close ncclient sessions
            v.manager.close_session()

    # Procedure for deleting and updating SAs Information  - Rekey - Phase 4
    def update_structures(self, ipsa: Ipsa):
        log.debug("UPDATE STRUCTURES")
        info_rekey = self.active_rekey_information.get(ipsa.spi_in)
        # new_ipsas = []
        # log.error(f'Longitud de associations {self.ipsec_associations.items()}')
        # self.mutex_ipsec_associations.acquire()
        # for k, ipsa in self.ipsec_associations.items():
        #     log.error(f'Setting local as {ipsa.get_list_ip()}')
        #     if ipsa.spi_in == ipsaOld.spi_in:
        #         new_ipsas.append(
        #             Ipsa(ipsa.ip_local_control, ipsa.ip_local_data, ipsa.ip_local_internal, ipsa.ip_remote_control,
        #                  ipsa.ip_remote_data, ipsa.ip_remote_internal,
        #                  info_rekey.spi_in_new, info_rekey.spi_out_new, ipsa.rules, ipsa.ip_dmz))
        #     else:
        #         log.error(f'Setting local as {ipsa.get_list_ip()}')
        #         new_ipsas.append(
        #             Ipsa(ipsa.ip_local_control, ipsa.ip_local_data, ipsa.ip_local_internal, ipsa.ip_remote_control,
        #                  ipsa.ip_remote_data, ipsa.ip_remote_internal,
        #                  info_rekey.spi_out_new, info_rekey.spi_in_new, ipsa.rules, ipsa.ip_dmz))
        # self.mutex_ipsec_associations.release()

        log.error(f'Setting local as {ipsa.get_local_ip()}')
        ipsa_new_1 = Ipsa(ipsa.ip_local_control, ipsa.ip_local_data, ipsa.ip_local_internal, ipsa.ip_remote_control,
                          ipsa.ip_remote_data, ipsa.ip_remote_internal,
                          info_rekey.spi_in_new, info_rekey.spi_out_new, ipsa.rules, ipsa.ip_dmz_local,
                          ipsa.ip_dmz_remote)

        log.error(f'Setting local as {ipsa.get_remote_ip()}')
        ipsa_new_2 = Ipsa(ipsa.ip_remote_control, ipsa.ip_remote_data, ipsa.ip_remote_internal, ipsa.ip_local_control,
                          ipsa.ip_local_data, ipsa.ip_local_internal,
                          info_rekey.spi_out_new, info_rekey.spi_in_new, ipsa.rules, ipsa.ip_dmz_remote,
                          ipsa.ip_dmz_local)

        self.add_ipsec_association(ipsa_new_1)
        self.add_ipsec_association(ipsa_new_2)

        self.delete_ipsec_association(ipsa.spi_in)
        self.delete_ipsec_association(ipsa.spi_out)

        self.delete_active_rekeys(ipsa.spi_in, ipsa.spi_out)

        self.delete_active_rekeys_information(ipsa.spi_in)
        log_writeln("Rekey : spi_in_old = " + str(ipsa.spi_in) + " spi_out_old = " + str(ipsa.spi_out) +
                    "spi_in_new = " + str(info_rekey.spi_in_new) + " spi_out_new = " + str(info_rekey.spi_out_new)
                    + " -----> Structures Updated")

    def add_registration_process(self, message_id, received):
        # log.debug(f'ADD REGISTRATION PROCESS')
        self.mutex_registration_process.acquire()
        self.registration_process.update({message_id: received})
        self.mutex_registration_process.release()

    def delete_registration_process(self, message_id):
        # log.debug("[DELETE REGISTRATION PROCESS]")
        self.mutex_registration_process.acquire()
        self.registration_process.pop(message_id)
        self.mutex_registration_process.release()

    def add_host(self, ip_control, ip_data, ip_internal, ip_dmz, manager):
        log.debug(f'ADD HOST {ip_control}, {ip_data}, {ip_internal}')
        self.mutex_hosts.acquire()
        host = Host(ip_control, ip_data, ip_internal, ip_dmz, manager)
        self.hosts.update({ip_control: host})
        self.mutex_hosts.release()

    def add_ipsec_association(self, ipsa):
        log.debug("ADD IPSEC ASSOCIATION")
        self.mutex_ipsec_associations.acquire()
        self.ipsec_associations.update({ipsa.spi_in: ipsa})
        self.mutex_ipsec_associations.release()

    def delete_ipsec_association(self, spi_in):
        log.debug(f'DELETE IPSEC ASSOCIATION {spi_in}')
        self.mutex_ipsec_associations.acquire()
        self.ipsec_associations.pop(spi_in)
        self.mutex_ipsec_associations.release()

    def add_active_rekeys(self, spi, spi2):
        log.debug('ADD ACTIVE REKEYS: {spi1}, {spi2}')
        self.mutex_active_rekeys.acquire()
        self.active_rekeys.append(spi)
        self.active_rekeys.append(spi2)
        self.mutex_active_rekeys.release()

    def delete_active_rekeys(self, spi1, spi2):
        log.debug(f'DELETE ACTIVE REKEYS: {spi1}, {spi2}')
        self.mutex_active_rekeys.acquire()
        self.active_rekeys.remove(spi1)
        self.active_rekeys.remove(spi2)
        self.mutex_active_rekeys.release()

    def add_rpc_ids(self, spi_in_old, message_id1, message_id2):
        # log.info("[ADD RPC IDS]")
        self.mutex_rpc_ids.acquire()
        self.rpc_ids.update({message_id1: spi_in_old})
        self.rpc_ids.update({message_id2: spi_in_old})
        self.mutex_rpc_ids.release()

    def delete_rpc_id(self, msg_id):
        # log.info("[DELETE REPC IDS]")
        self.mutex_rpc_ids.acquire()
        self.rpc_ids.pop(msg_id)
        self.mutex_rpc_ids.release()

    def add_active_rekeys_information(self, spi_in_old, information_rekey):
        log.debug(f'ADD ACTIVE REKEYS INFORMATION: {spi_in_old}')
        self.mutex_active_rekeys_information.acquire()
        self.active_rekey_information.update({spi_in_old: information_rekey})
        self.mutex_active_rekeys_information.release()

    def delete_active_rekeys_information(self, spi_in_old):
        log.debug(f'DELETE ACTIVE REKEYS INFORMATION: {spi_in_old}')
        self.mutex_active_rekeys_information.acquire()
        self.active_rekey_information.pop(spi_in_old)
        self.mutex_active_rekeys_information.release()

    def get_spi_number(self):
        # log.info("[GET SPI NUMBER]")
        return self.spinumber

    def increment_spi_number(self):
        # log.info("[INCREMENT SPI NUMBER]")
        self.spinumber += 1
        return self.spinumber

    def get_rule_number(self):
        # log.info("GET RULE NUMBER]")
        return self.rulenumber

    def increment_rule_number(self):
        # log.info("INCREMENT RULE NUMBER")
        self.rulenumber += 1
        return self.rulenumber


class Listener(SessionListener):

    def __init__(self, pool, analyze_notification, analyze_rpc_reply):
        super().__init__()
        self.pool = pool
        self.analyze_notification = analyze_notification
        self.analyze_rpc_reply = analyze_rpc_reply
        self.stop = False

    def errback(self, ex):
        # print(ex)
        pass

    def stopListening(self):
        self.stop = True

    def callback(self, root, raw):
        tag, _ = root
        if self.stop:
            # print("Listener Stoped:", root)
            # print("Listener Stoped:", raw)
            return
        if tag == qualify('notification', NETCONF_NOTIFICATION_NS):  # check if it is a Netconf notification
            # log_writeln("Notification -> " + raw + "\n")
            root = etree.fromstring(raw)
            self.pool.add_task(self.analyze_notification, root)
        else:  # RCP Notification
            rpc_reply = raw
            self.pool.add_task(self.analyze_rpc_reply, rpc_reply)


class Worker(Thread):
    # Thread executing tasks from a given tasks queue

    def __init__(self, tasks):
        Thread.__init__(self)
        self.tasks = tasks
        self.daemon = True
        self.start()

    def run(self):
        while True:
            func, args = self.tasks.get()
            try:
                func(args[0])
            except Exception as e:
                # An exception happened in this thread
                log.error(str(e))
                log.error(traceback.format_exc())
            finally:
                # Mark this task as done, whether an exception happened or not
                self.tasks.task_done()


class ThreadPool:
    # Pool of threads consuming tasks from a queue

    def __init__(self, num_threads, workers):
        self.tasks = Queue()
        for _ in range(num_threads):
            workers.append(Worker(self.tasks))

    def add_task(self, func, *args):
        # Add a task to the queue
        self.tasks.put((func, args))


def log_writeln(cadena):
    log.info(cadena)
