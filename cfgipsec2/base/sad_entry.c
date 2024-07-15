/*
 * Copyright (c) 2018 Gabriel López <gabilm@um.es>, Rafael Marín <rafa@um.es>, Fernando Pereñiguez <fernando.pereniguez@cud.upct.es> 
 *
 * This file is part of cfgipsec2.
 *
 * cfgipsec2 is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * cfgipsec2 is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "sad_entry.h"

char src[20], dst[20], src_tunnel[20], dst_tunnel[20], protocol[4], encrypt_key[30],auth_key[20];
int protocol_next_layer, srcport, dstport, satype, encrypt_alg, auth_alg,iv, mode, spi;
int replay = 0;
int seq_number = 0;
int rule_number = 0;
bool combined_enc_intr;
int lft_byte_hard = 0;
int lft_byte_soft = 0;
int lft_byte_current = 0;
int lft_packet_hard = 0;
int lft_packet_soft = 0;
int lft_packet_current = 0;
int lft_hard_add_expires_seconds = 0;
int lft_hard_use_expires_seconds = 0;
int lft_soft_add_expires_seconds = 0;
int lft_soft_use_expires_seconds = 0;
int lft_current_add_expires_seconds = 0;
int lft_current_use_expires_seconds = 0;


char address[30];
sad_entry_node *init_sad_node = NULL;

sad_entry_node* createSADnode(){

    sad_entry_node *sad_node = (sad_entry_node*) malloc(sizeof(sad_entry_node));

    sad_node->spi =0;
    sad_node->seq_number = 0;
    sad_node->state = 0;
    sad_node->replay = 0;
    sad_node->rule_number = 0;
    sad_node->mode =0;
    sad_node->satype=0;
    sad_node->protocol_next_layer=0; 
    sad_node->protocol = (char *) malloc(30); 
    sad_node->srcport=0; 
    sad_node->dstport=0; 
    sad_node->src = (char *) malloc(sizeof(char) * strlen(address)); 
    sad_node->dst = (char *) malloc(sizeof(char) * strlen(address));
    sad_node->src_tunnel = (char *) malloc(sizeof(char) * strlen(address));
    sad_node->dst_tunnel = (char *) malloc(sizeof(char) * strlen(address)); 
    sad_node->auth_alg = 0;
    sad_node->iv = 0;
    sad_node->encrypt_alg = 0;
    sad_node->encrypt_key = (char *) malloc(30); 
    sad_node->auth_key = (char *) malloc(30); 
    sad_node->combined_enc_intr = 0;
    sad_node->lft_byte_hard = 0;
    sad_node->lft_byte_soft = 0;
    sad_node->lft_byte_current = 0;
    sad_node->lft_packet_hard = 0;
    sad_node->lft_packet_soft = 0;
    sad_node->lft_packet_current = 0;
    sad_node->lft_hard_add_expires_seconds = 0;
    sad_node->lft_hard_use_expires_seconds = 0;
    sad_node->lft_soft_add_expires_seconds = 0;
    sad_node->lft_soft_use_expires_seconds = 0;
    sad_node->lft_current_add_expires_seconds = 0;
    sad_node->lft_current_use_expires_seconds = 0;
    sad_node->next=NULL;
    
    return sad_node;

}

void addSAD_node(sad_entry_node* node_entry){

    if (init_sad_node == NULL){
        init_sad_node=node_entry;
        node_entry->next=NULL;
    } else{
        sad_entry_node *node = init_sad_node;
        while(node->next != NULL)
            node=node->next;
        node->next=node_entry;
    }
}

// for case 1
void show_sad_list(){

    sad_entry_node *node = init_sad_node;
    
    INFO("SPI -- SRC --- DST --- MODE --- ");
    while (node != NULL){
        INFO("%d --- %s --- %s --- %d --- ", node->spi, node->src, node->dst, node->mode);
        node=node->next;
    }
}

sad_entry_node *get_sad_node(int spi){

    int i = 0;
    sad_entry_node *node = init_sad_node;

    if (node->spi == spi) 
        return node;
    else {
        while (node->spi != spi) {
            node=node->next;
            i++;
        }
    }
    if (i != 0)
        return node;
    else return NULL;
}

void free_sad_node(sad_entry_node * n) {

    if (n != NULL) {  
        free (n);
    } 
}


int del_sad_node(int spi) {

    sad_entry_node *node = init_sad_node;

    if (node != NULL) {
        sad_entry_node *prev_node = NULL;
        prev_node = createSADnode();

        while (spi != node->spi) {
            prev_node = node;
            node = node->next;
        }
        if (node == init_sad_node){
            init_sad_node = init_sad_node->next;
            free_sad_node(prev_node);
        }
        else if (spi == node->spi) {
            prev_node->next = node->next;
            free_sad_node(node);
        }
    } else return SR_ERR_OPERATION_FAILED;

    return SR_ERR_OK;
}

int removeSAD_entry(sr_session_ctx_t *sess, sr_change_iter_t *it,char *xpath,char *spi_number) {

    int rc = SR_ERR_OK;

    spi = atoi(spi_number);
    DBG("SAD entry REMOVE: %i",spi);

    rc = readSAD_entry(sess,it,xpath,spi_number);
    if (rc != SR_ERR_OK) {
            ERR("ADD SAD in getSAD_entrty: %s", sr_strerror(rc));
            return SR_ERR_VALIDATION_FAILED;
    }

    DBG("SAD verifyed "); 
    sad_entry_node *node = get_sad_node(spi);
    if (node != NULL) {
        rc = pf_delsad(node);
        if (SR_ERR_OK != rc){
            ERR("Remove SAD in pfkeyv2_delsad: %s",sr_strerror(rc));
            rc = SR_ERR_OPERATION_FAILED;
        } else {
            rc = del_sad_node(spi);
            if (rc != SR_ERR_OK) {
                ERR("Remove SAD entry in del_sad_node: %s",sr_strerror(rc));
                rc = SR_ERR_OPERATION_FAILED;
            } else rc = SR_ERR_OK;
        }
    } else{
        rc = SR_ERR_OPERATION_FAILED;
        ERR("Remove SAD, spi not found: %s",sr_strerror(rc));
    }

    show_sad_list();
    return rc;


}



int getSelectorListSAD_it(sr_session_ctx_t *sess, sr_change_iter_t *it,char *xpath, sr_change_oper_t oper, sr_val_t *old_val, sr_val_t *new_val) {

    int rc = SR_ERR_OK;
    sr_val_t *value = NULL;
    char  *name = NULL;
    char new_xpath[MAX_PATH] = "";
   
    do {
        if (oper == SR_OP_CREATED) value = new_val;
        else value = old_val;

        strcpy(new_xpath,xpath);

        if ((0 == strncmp(value->xpath, xpath,strlen(xpath))) && (strlen(value->xpath)!=strlen(xpath))) {
	        name = strrchr(value->xpath, '/');
            if (0 == strcmp("/next-layer-protocol", name)) {
                if (!strcasecmp(value->data.string_val, "TCP"))
                        protocol_next_layer =  IPSEC_NLP_TCP;
                else if (!strcasecmp(value->data.string_val, "UDP"))
                        protocol_next_layer = IPSEC_NLP_UDP;
                else if (!strcasecmp(value->data.string_val, "SCTP"))
                        protocol_next_layer = IPSEC_NLP_SCTP;
                else {
                        ERR("spd-entry Bad next-layer-protocol: %s",sr_strerror(SR_ERR_VALIDATION_FAILED));
                        return SR_ERR_VALIDATION_FAILED;
                }
                DBG("next-layer-protocol: %i",protocol_next_layer);
            }

            else if (0 == strncmp("/start", name,strlen("/start"))) {
                if (NULL != strstr(value->xpath,"/local-addresses")) {
                    strcpy(src, value->data.string_val);
                    DBG("local-address start: %s",src);
                }
                else if (NULL != strstr(value->xpath,"/remote-addresses")) {
                    strcpy(dst, value->data.string_val);
                    DBG("remote-address start: %s",dst);
                }
                else if (NULL != strstr(value->xpath,"/local-ports")) {
                    srcport = value->data.int64_val;
                    DBG("local-port start: %i",srcport);
                }
                else if (NULL != strstr(value->xpath,"/remote-ports")) {
                    dstport = value->data.int64_val;
                    DBG("remote-port start: %i",dstport);
                }
            }

            else if (0 == strcmp("/security-protocol", name)) {
                if (!strcasecmp(value->data.string_val, "ESP")){
                    satype = SADB_SATYPE_ESP;
                }
                else if (!strcasecmp(value->data.string_val, "AH")) {
                    satype = SADB_SATYPE_AH;
                }
                else {
                    ERR("spd-entry Bad satype %s", sr_strerror(SR_ERR_VALIDATION_FAILED));
                    return SR_ERR_VALIDATION_FAILED;
                }
                DBG("satype: %i",satype);
            }

            else if (0 == strcmp("/mode", name)) {
                if (!strcasecmp(value->data.string_val, "TRANSPORT")){
                    mode = IPSEC_MODE_TRANSPORT;
                }
                else if (!strcasecmp(value->data.string_val, "TUNNEL")) {
                    mode = IPSEC_MODE_TUNNEL;
                }
                else {
                    ERR("spd-entry Bad mode %s",sr_strerror(SR_ERR_VALIDATION_FAILED));
                    return SR_ERR_VALIDATION_FAILED;
                }
                DBG("mode: %i",mode);
            }

            else if (0 == strcmp("/anti-replay-window", name)) {
                replay = value->data.uint16_val;
                DBG("anti-replay-window found: %i", replay);
            }

            else if (0 == strcmp("/seq-number", name)) {
                seq_number = value->data.uint64_val;
                DBG("seq-number found: %d", seq_number);
            }

             else if (0 == strcmp("/rule-number", name)) {
                rule_number = value->data.uint32_val;
                DBG("rule-number found: %d", rule_number);
            }

            else if (0 == strcmp("/local", name)) {
                strcpy(src_tunnel, value->data.string_val);
                DBG("mode tunnel src_tunnel: %s",src_tunnel);
            }

            else if (0 == strcmp("/remote", name)) {
                strcpy(dst_tunnel, value->data.string_val);
                DBG("mode tunnel dst_tunnel: %s",dst_tunnel);
            }

            else if (0 == strcmp("/integrity-algorithm", name)) {
                auth_alg = getAuthAlg(value->data.string_val);
                DBG ("auth alg %i",auth_alg);
            }

            else if (0 == strcmp("/key", name)) {
	            if (NULL != strstr(value->xpath,"/ah-sa")) {
                   	strcpy(auth_key,value->data.string_val);
                    DBG ("auth key %s",auth_key);
	            }
	            if (NULL != strstr(value->xpath,"/esp-sa/encryption")) {
		           strcpy(encrypt_key,value->data.string_val);
                    DBG ("esp enc key %s",encrypt_key);
            	}
	            if (NULL != strstr(value->xpath,"/esp-sa/integrity")) {
                    strcpy(auth_key,value->data.string_val);
                    DBG ("esp auth key %s",auth_key);
                }
            }
            else if (0 == strcmp("/encryption-algorithm", name)) {
                if (NULL != strstr(value->xpath,"/esp-sa")) {
        	        encrypt_alg = getEncryptAlg(value->data.string_val);
                    DBG ("encrypt alg %i",encrypt_alg);
                }
            }
            else if (0 == strcmp("/iv", name)) {
                if (NULL != strstr(value->xpath,"/esp-sa")) {
        	        iv = value->data.int64_val;
                    DBG ("iv %i",iv);
            	}
            }
            else if (0 == strcmp ("/combined-enc-intr",name)) { 
                if (NULL != strstr(value->xpath,"/esp-sa")) { 
                    combined_enc_intr = value->data.bool_val;
                    DBG("combined_enc_intr %i", combined_enc_intr);
                }   
            }

            else if (0 == strcmp("/bytes", name)) {
                if (NULL != strstr(value->xpath,"/sad-lifetime-soft")) { 
                    lft_byte_soft = value->data.int32_val;
                    DBG("lifetime byte-soft: %i",lft_byte_soft);
                } else if (NULL != strstr(value->xpath,"/sad-lifetime-hard")) { 
                    lft_byte_hard = value->data.int32_val;
                    DBG("lifetime byte-hard: %i",lft_byte_hard);
                }
            }  

            else if (0 == strcmp("/packets", name)) {
                if (NULL != strstr(value->xpath,"/sad-lifetime-soft")) { 
                    lft_packet_soft = value->data.int32_val;
                    DBG("lifetime packet-soft: %i",lft_packet_soft);
                } else if (NULL != strstr(value->xpath,"/sad-lifetime-hard")) {  
                    lft_packet_hard = value->data.int32_val;
                    DBG("lifetime packet-hard: %i",lft_packet_hard);
                }  
            }  
            else if (0 == strcmp("/added", name)) {
                if (NULL != strstr(value->xpath,"/sad-lifetime-soft")) { 
                    lft_soft_add_expires_seconds = value->data.int64_val;
                    DBG("lifetime time-soft: %i",lft_soft_add_expires_seconds);
                } else if (NULL != strstr(value->xpath,"/sad-lifetime-hard")) { 
                    lft_hard_add_expires_seconds= value->data.int64_val;
                    DBG("lifetime time-hard: %i",lft_hard_add_expires_seconds);
                }
            }  
            else if (0 == strcmp("/used", name)) {
                if (NULL != strstr(value->xpath,"/sad-lifetime-soft")) { 
                    lft_soft_use_expires_seconds = value->data.int64_val;
                    DBG("lifetime time-use-soft: %i",lft_soft_use_expires_seconds);
                } else if (NULL != strstr(value->xpath,"/sad-lifetime-hard")) {  
                    lft_hard_use_expires_seconds= value->data.int64_val;
                    DBG("lifetime time-use-hard: %i",lft_hard_use_expires_seconds);
                }  
            }  

            // container encap TBD

        } else break;
            
	    sr_free_val(old_val);
        sr_free_val(new_val);

    } while (SR_ERR_OK == sr_get_change_next(sess, it,&oper, &old_val, &new_val));


    return SR_ERR_OK;

}


int verifySAD_entry(sr_session_ctx_t *sess, sr_change_iter_t *it, sr_change_oper_t oper, char *xpath,char *spi_number) {


    int rc = SR_ERR_OK;
    sr_val_t *old_value = NULL;
    sr_val_t *new_value = NULL;
    sr_val_t *value = NULL;
    //sr_change_oper_t oper;
    char  *name = NULL;

    DBG("**VERIFY SAD entry: %s",spi_number);

    if (oper == SR_OP_CREATED) {
        DBG ("Verify SAD entry SPI is not already used");
    } else {
        DBG ("Verify SAD entry SPI is used");
    }
    
    return SR_ERR_OK;
}

int readSAD_entry(sr_session_ctx_t *sess, sr_change_iter_t *it,char *xpath,char *spi_number) {


    int rc = SR_ERR_OK;
    sr_val_t *old_value = NULL;
    sr_val_t *new_value = NULL;
    sr_val_t *value = NULL;
    sr_change_oper_t oper;
    char  *name = NULL;

    DBG("**Read SAD entry: %s",spi_number);
    rc = sr_get_change_next(sess, it, &oper, &old_value, &new_value);
    if (SR_ERR_OK != rc)
            return rc;

    do {
	    if (oper == SR_OP_CREATED) value = new_value;
        else value = old_value;

        //if (value == NULL) break;

        if (0 == strncmp(value->xpath, xpath,strlen(xpath))) {
            name = strrchr(value->xpath, '/');
		    rc = getSelectorListSAD_it(sess,it,xpath,oper,old_value,new_value);
		    if (SR_ERR_OK != rc)
                return rc;
            else break;
        } else break;
            
	    sr_free_val(old_value);
        sr_free_val(new_value);

    } while (SR_ERR_OK == sr_get_change_next(sess, it,&oper, &old_value, &new_value));

    return SR_ERR_OK;
}

int addSAD_entry(sr_session_ctx_t *sess, sr_change_iter_t *it,char *xpath,char *spi_number) {

    int rc = SR_ERR_OK;

    spi = atoi(spi_number);
    DBG("**ADD SAD entry: %i",spi);
    rc = readSAD_entry(sess,it,xpath,spi_number);
    if (rc != SR_ERR_OK) {
        ERR("ADD SAD in getSAD_entry: %s",sr_strerror(rc));
        return rc;
    }

    sad_entry_node *sad_node = createSADnode();
    sad_node->spi = spi;
    if (seq_number != NULL) sad_node->seq_number = seq_number;
    if (replay != NULL) sad_node->replay = replay;
    if (rule_number != NULL) sad_node->rule_number = rule_number;
    if (mode != NULL) sad_node->mode = mode;
    if (satype != NULL) sad_node->satype = satype;
    if (protocol_next_layer != NULL) sad_node->protocol_next_layer = protocol_next_layer;
    if (protocol != NULL) sad_node->protocol = protocol;
    if (srcport != NULL) sad_node->srcport = srcport;
    if (dstport != NULL) sad_node->dstport = dstport;
    if (src != NULL) strcpy(sad_node->src,src);
    if (dst != NULL) strcpy(sad_node->dst,dst);
    if (src_tunnel != NULL) strcpy(sad_node->src_tunnel,src_tunnel);
    if (dst_tunnel != NULL) strcpy(sad_node->dst_tunnel,dst_tunnel);
    if (auth_alg != NULL) sad_node->auth_alg = auth_alg;
    if (iv != NULL) sad_node->iv = iv;
    if (encrypt_alg != NULL) sad_node->encrypt_alg = encrypt_alg;
    if (encrypt_key != NULL) sad_node->encrypt_key = encrypt_key; 
    if (auth_key != NULL) sad_node->auth_key = auth_key; 
    if (combined_enc_intr != NULL) sad_node->combined_enc_intr = combined_enc_intr;
    if (lft_byte_hard != NULL) sad_node->lft_byte_hard = lft_byte_hard;
    if (lft_byte_soft != NULL) sad_node->lft_byte_soft = lft_byte_soft;
    if (lft_packet_hard != NULL) sad_node->lft_packet_hard = lft_packet_hard;
    if (lft_packet_soft != NULL) sad_node->lft_packet_soft = lft_packet_soft;
    if (lft_hard_add_expires_seconds != NULL) sad_node->lft_hard_add_expires_seconds = lft_hard_add_expires_seconds;
    if (lft_hard_use_expires_seconds != NULL) sad_node->lft_hard_use_expires_seconds = lft_hard_use_expires_seconds;
    if (lft_soft_add_expires_seconds != NULL) sad_node->lft_soft_add_expires_seconds = lft_soft_add_expires_seconds;
    if (lft_soft_use_expires_seconds != NULL) sad_node->lft_soft_use_expires_seconds = lft_soft_use_expires_seconds;
   
    addSAD_node(sad_node);

    rc = pf_addsad(sad_node);
    if (SR_ERR_OK != rc) {
        ERR("ADD SAD in getSAD_entry: %s", sr_strerror(rc));
        return rc;     
    }
 
    //INFO("SAD entry added! ");
    show_sad_list();

    return SR_ERR_OK;

}


int get_sad_lifetime_current(const char *xpath, sr_val_t **values, size_t *values_cnt, void *private_ctx){
    
    sr_val_t *vals;
    int rc;
    int goteof;
    int packets;
    int bytes;
    uint64_t added;
    uint64_t used;
    char tmp_xpath[MAX_PATH] = "";
    int spi = 0;

    //get the spi from xpath
    strcpy(tmp_xpath,xpath);
    char * st = strtok(tmp_xpath,"'");
    char * st2 = strtok(NULL,"'");
    spi = atoi(st2);
    DBG("get_sad_lifetime_current spi: %i",spi);

    sad_entry_node *node = get_sad_node(spi);
    if (node == NULL) {
        ERR("SAD, spi not found");
        rc = SR_ERR_OPERATION_FAILED;
        return rc;
    }

    if (rc = pf_get_sad_lifetime_current_by_spi(node)) {
        ERR("sad_lifetime_current_cb in pf_get_sad_lifetime_current_by_rule: %i", rc);
        return rc;
    }

    rc = sr_new_values(4, &vals);
    if (SR_ERR_OK != rc) {
        ERR("sad_lifetime_current_cb: %i", rc);
        return rc;
    }

    char new_xpath[MAX_PATH] = "";
    strcpy(new_xpath,xpath);
    strcat(new_xpath,"/bytes");
    sr_val_set_xpath(&vals[0], new_xpath);
    vals[0].type = SR_UINT32_T;
    vals[0].data.uint32_val = node->lft_byte_current;

    strcpy(new_xpath,xpath);
    strcat(new_xpath,"/packets");
    sr_val_set_xpath(&vals[1], new_xpath);
    vals[1].type = SR_UINT32_T;
    vals[1].data.uint32_val = node->lft_packet_current;

    strcpy(new_xpath,xpath);
    strcat(new_xpath,"/added");
    sr_val_set_xpath(&vals[2], new_xpath);
    vals[2].type = SR_UINT64_T;
    vals[2].data.uint64_val = node->lft_current_add_expires_seconds;

    strcpy(new_xpath,xpath);
    strcat(new_xpath,"/used");
    sr_val_set_xpath(&vals[3], new_xpath);
    vals[3].type = SR_UINT64_T;
    vals[3].data.uint64_val = node->lft_current_use_expires_seconds;;
    
    *values = vals;
    *values_cnt = 4;
    
    return SR_ERR_OK;

}



int get_sad_stats(const char *xpath, sr_val_t **values, size_t *values_cnt, void *private_ctx){
    
    DBG("get_sad_stats TBD");

    return SR_ERR_OK;

}

int send_delete_SAD_request(int spi_number) {

    char xpath[MAX_PATH] = "";
    sr_conn_ctx_t *conn = NULL;
    sr_session_ctx_t *session = NULL;
    int rc = SR_ERR_OK;

    /* connect to sysrepo */
    rc = sr_connect("sdn_ipsec_application", SR_CONN_DEFAULT, &conn);
    if (SR_ERR_OK != rc) {
        goto cleanup;
    }

    /* start session */
    rc = sr_session_start(conn, SR_DS_RUNNING, SR_SESS_DEFAULT, &session);
    if (SR_ERR_OK != rc) {
        goto cleanup;
    }

    sprintf(xpath, "/ietf-ipsec:ietf-ipsec/ipsec/sad/sad-entry[spi='%i']", spi_number);
    DBG("removeSADbySPI xpath: %s", xpath);
    rc = sr_delete_item(session, xpath, SR_EDIT_DEFAULT);
    if (SR_ERR_OK != rc) {
        ERR("sr_delete_item: %s", sr_strerror(rc));
        goto cleanup;
    }
    /* commit the changes */
    rc = sr_commit(session);
    if (SR_ERR_OK != rc) {
        ERR("sr_commit: %s", sr_strerror(rc));
        goto cleanup;
    }

    cleanup:
    if (NULL != session) {
        sr_session_stop(session);
    }
    if (NULL != conn) {
        sr_disconnect(conn);
    }

    return rc;

}





int send_acquire_notification(sr_session_ctx_t *session, struct sadb_msg *msgp, int msglen){

    int rc = SR_ERR_OK;
    sr_val_t *input = NULL;
    int input_cnt = 0;

    DBG ("send_acquire_notification...");
    rc = create_base_grouping(msgp, msglen, "/ietf-ipsec:sadb_acquire", &input, &input_cnt);
    if (SR_ERR_OK != rc) {
        ERR("create_base_grouping");
        return rc;
    }

    DBG("Acquire notification inputs values:");
    for (size_t i = 0; i < input_cnt; ++i) {
        sr_print_val(&input[i]);
    }

    rc = sr_event_notif_send(session, "/ietf-ipsec:sadb_acquire", input, input_cnt, SR_EV_NOTIF_DEFAULT);
    if (SR_ERR_NOT_FOUND == rc) {
        ERR("No application subscribed for sadb_acquire_notifications, skipping.");
        sr_free_values(input, input_cnt);
        rc = SR_ERR_OK;
    } else if (SR_ERR_OK != rc) 
        ERR("send_acquired_notification %i",rc);
    
    sr_free_values(input, input_cnt);
    DBG("end send_acquire_notification ..... ");

    return rc;
}

int send_sa_expire_notification(sr_session_ctx_t *session, struct sadb_msg *msgp, int msglen){


    int rc = SR_ERR_OK;
    sr_val_t *input = NULL;
    int input_cnt = 0;
    char full_xpath[MAX_PATH];
    char tmp_xpath[MAX_PATH];

    DBG ("send_expire_notification...");
    rc = create_base_grouping(msgp, msglen, "/ietf-ipsec:sadb_expire", &input, &input_cnt);
    if (SR_ERR_OK != rc) {
        ERR("create_base_grouping");
        return rc;
    }

    sad_entry_node *sad_node = createSADnode();
    pf_fill_sa_node(sad_node, msgp, msglen);

    strcpy(full_xpath,"/ietf-ipsec:sadb_expire");
    int input_cnt_old = input_cnt;
    input_cnt = input_cnt + 5; // poner a 5!! ****************
    rc = sr_realloc_values(input_cnt_old,input_cnt,&input); 
    if (SR_ERR_OK != rc) {
        return rc;
    }

    strcpy(tmp_xpath,full_xpath);
    strcat(tmp_xpath,"/spi");
    rc = sr_val_set_xpath(&input[input_cnt_old], tmp_xpath);
    if (SR_ERR_OK != rc) {
        return rc;
    }
    input[input_cnt_old].type = SR_UINT32_T;
    input[input_cnt_old].data.uint32_val = sad_node->spi;

    strcpy(tmp_xpath,full_xpath);
    strcat(tmp_xpath,"/anti-replay-window");
    rc = sr_val_set_xpath(&input[input_cnt_old+1], tmp_xpath);
    if (SR_ERR_OK != rc) {
        return rc;
    }
    input[input_cnt_old+1].type = SR_UINT16_T;
    input[input_cnt_old+1].data.uint16_val = sad_node->replay;

    strcpy(tmp_xpath,full_xpath);
    strcat(tmp_xpath,"/state");
    rc = sr_val_set_xpath(&input[input_cnt_old+2], tmp_xpath);
    if (SR_ERR_OK != rc) {
        return rc;
    }
    input[input_cnt_old+2].type = SR_ENUM_T;
    input[input_cnt_old+2].data.enum_val = get_sa_state(sad_node->state);

    strcpy(tmp_xpath,full_xpath);
    strcat(tmp_xpath,"/encryption-algorithm");
    rc = sr_val_set_xpath(&input[input_cnt_old+3], tmp_xpath);
    if (SR_ERR_OK != rc) {
        return rc;
    }
    input[input_cnt_old+3].type = SR_ENUM_T;
    if (sad_node->encrypt_alg != 0) {
        input[input_cnt_old+3].data.enum_val = get_encrypt_str(sad_node->encrypt_alg);
    }
    else  { 
        input[input_cnt_old+3].data.enum_val = "null"; 
    }

    strcpy(tmp_xpath,full_xpath);
    strcat(tmp_xpath,"/authentication-algorithm");
    rc = sr_val_set_xpath(&input[input_cnt_old+4], tmp_xpath);
    if (SR_ERR_OK != rc) {
        return rc;
    }
    input[input_cnt_old+4].type = SR_ENUM_T;
    if (sad_node->auth_alg != 0) {
        input[input_cnt_old+4].data.enum_val = get_auth_str(sad_node->auth_alg);
    }
    else {
        input[input_cnt_old+4].data.enum_val = "none";
    }

    DBG("Expire notification inputs values:");
    for (size_t i = 0; i < input_cnt; ++i) {
        sr_print_val(&input[i]);
    }
    
    rc = sr_event_notif_send(session, "/ietf-ipsec:sadb_expire", input, input_cnt, SR_EV_NOTIF_DEFAULT);
    if (SR_ERR_NOT_FOUND == rc) {
        ERR("No application subscribed for sadb_expire_notifications', skipping.");
        sr_free_values(input, input_cnt);
        rc = SR_ERR_OK;
    } else if (SR_ERR_OK != rc) 
        ERR("send_expire_notification %i",rc);
    
    sr_free_values(input, input_cnt);
    DBG("end send_expire_notification ... ");

    return rc;
}











