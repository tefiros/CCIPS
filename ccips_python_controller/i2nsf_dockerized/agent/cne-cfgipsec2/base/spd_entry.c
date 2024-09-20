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

#include "spd_entry.h"


char src[30], dst[30], src_remove[30], dst_remove[30],src_tunnel[30], dst_tunnel[30];
int satype, action_policy_type, policy_dir, policy_id, protocol_next_layer, srcport, dstport, mode, proto;
int spd_lft_byte_hard = 0;
int spd_lft_byte_soft = 0;
int spd_lft_byte_current = 0;
int spd_lft_packet_hard = 0;
int spd_lft_packet_soft = 0;
int spd_lft_packet_current = 0;
int spd_lft_hard_add_expires_seconds = 0;
int spd_lft_hard_use_expires_seconds = 0;
int spd_lft_soft_add_expires_seconds = 0;
int spd_lft_soft_use_expires_seconds = 0;
int spd_lft_current_add_expires_seconds = 0;
int spd_lft_current_use_expires_seconds = 0;


char address[30];
spd_entry_node* init_spd_node = NULL;

spd_entry_node* getSPDEntry( char* local_addrs, char* remote_addrs){

	spd_entry_node *node = init_spd_node;

	while (node != NULL){ 
		if (node->mode == IPSEC_MODE_TRANSPORT){ 

			if (!strcmp(remote_addrs, get_ip(node->dst))) {
				if (!strcmp(local_addrs, get_ip(node->src))){
					return node;
				}
			}
		}
		else if (node->mode == IPSEC_MODE_TUNNEL){
			if (!strcmp(remote_addrs, node->dst_tunnel)){
				if (!strcmp(local_addrs, node->src_tunnel)){
					return node;
				}
			}
		}
		node=node->next;
	}
	return NULL;
 }
// for case 1
void addSPD_node(spd_entry_node* node_entry){
	if (init_spd_node == NULL){
		init_spd_node=node_entry;
		node_entry->next=NULL;
	}else{
		spd_entry_node *node = init_spd_node;
		while(node->next != NULL)
			node=node->next;
		node->next=node_entry;
	}
}

// for case 1
void show_spd_list(){
	spd_entry_node *node = init_spd_node;
	int index = 0;
	INFO("ID --- INDEX -- SRC --- DST --- DIRECTION --- PROTOCOL --- MODE --- ACTION ---");
	while (node != NULL){
		INFO("%d --- %d -- %s --- %s --- %d --- %d --- %d --- %d --- ", node->policy_id, node->index, node->src, node->dst, node->policy_dir, node->protocol_next_layer,
			node->mode, node->action_policy_type);
		node=node->next;
		index++;
	}
}

spd_entry_node *get_spd_node(int rule_number){

    int i = 0;
    spd_entry_node *node = init_spd_node;
    if (node->policy_id == rule_number) 
        return node;
    else {
        while (node->policy_id != rule_number) {
            node=node->next;
            i++;
        }
    }
    if (i != 0)
        return node;
    else return NULL;
}

spd_entry_node* get_spd_node_by_index(int policy_index){

    int i = 0;
    spd_entry_node *node = init_spd_node;
    if (node->index == policy_index) 
        return node;
    else {
        while (node->index != policy_index) {
            node=node->next;
            i++;
        }
    }
    if (i != 0)
        return node;
    else return NULL;
}

spd_entry_node* createSPDnode(){
	spd_entry_node *spd_node = (spd_entry_node*) malloc(sizeof(spd_entry_node));
	spd_node->policy_id=0;
    spd_node->index=0;
	spd_node->src = (char *) malloc(sizeof(char) * strlen(address)); 
	spd_node->dst = (char *) malloc(sizeof(char) * strlen(address));
	spd_node->src_tunnel = (char *) malloc(sizeof(char) * strlen(address));
	spd_node->dst_tunnel = (char *) malloc(sizeof(char) * strlen(address)); 
	spd_node->satype=0; 
    spd_node->request_protocol = 0;
	spd_node->action_policy_type=0; 
	spd_node->policy_dir=0; 
	spd_node->protocol_next_layer=0; 
	spd_node->srcport=0; 
	spd_node->dstport=0; 
	spd_node->mode=0;

    spd_node->lft_byte_hard = 0;
    spd_node->lft_byte_soft = 0;
    spd_node->lft_byte_current = 0;
    spd_node->lft_packet_hard = 0;
    spd_node->lft_packet_soft = 0;
    spd_node->lft_packet_current = 0;
    spd_node->lft_hard_add_expires_seconds = 0;
    spd_node->lft_hard_use_expires_seconds = 0;
    spd_node->lft_soft_add_expires_seconds = 0;
    spd_node->lft_soft_use_expires_seconds = 0;
    spd_node->lft_current_add_expires_seconds = 0;
    spd_node->lft_current_use_expires_seconds = 0;
	
	spd_node->next=NULL;
	
	return spd_node;

}

void free_spd_node(spd_entry_node * n) {

    if (n != NULL) {  
        /*free (n->src);
        free (n->dst);
        free (n->dst_tunnel);
        free (n->src_tunnel);*/
        free (n);
    } 
}

int del_spd_node(int rule_number) {

    spd_entry_node *node = init_spd_node;

    if (node != NULL) {
        spd_entry_node *prev_node = NULL;
        prev_node = createSPDnode();

        while (rule_number != node->policy_id) {
            prev_node = node;
            node = node->next;
        }
        if (node == init_spd_node){
            init_spd_node = init_spd_node->next;
            free_spd_node(prev_node);
        }
        else if (rule_number == node->policy_id) {
            prev_node->next = node->next;
            free_spd_node(node);
        }
    } else return SR_ERR_OPERATION_FAILED;

    return SR_ERR_OK;
}


int removeSPD_entry(sr_session_ctx_t *sess, sr_change_iter_t *it,char *xpath,char *rule_number, int case_value) {

    
    int rc = SR_ERR_OK;  

    policy_id = atoi(rule_number);

    DBG("****Remove SPD entry %i",policy_id);

    rc = readSPD_entry(sess,it,xpath,rule_number,case_value);
    if (rc != SR_ERR_OK) {
        ERR("Remove SPD in getSDP_entry: %s", sr_strerror(rc));
        return rc;
    }

	if (case_value == 1) {
		ERR("Remove SPD entry for case 1 not supported yet !!");
	} else { 	
	
		DBG("Remove SPD entry for case 2 ");

        spd_entry_node *node = get_spd_node(policy_id);
        if (node != NULL) {
            rc = pf_delpolicy(node);
            if (SR_ERR_OK != rc){
                ERR("Remove SPD in pfkeyv2_delpolicy: %s", sr_strerror(rc));
            } else {
                rc = del_spd_node(policy_id);
                if (rc != SR_ERR_OK) {
                    ERR("Remove SPD entry in del_spd_node: %s", sr_strerror(rc));
                } else rc = SR_ERR_OK;
            }
        } else{
            rc = SR_ERR_OPERATION_FAILED;
            ERR("Remove SPD, policy not found: %s",sr_strerror(rc));
        }
	}
    show_spd_list();
	return rc;

}


int verifySPD_entry(sr_session_ctx_t *sess, sr_change_iter_t *it,sr_change_oper_t oper, char *xpath,char *rule_number, int case_value) {

	int rc = SR_ERR_OK;
    sr_val_t *old_value = NULL;
    sr_val_t *new_value = NULL;
	sr_val_t *value = NULL;
	//sr_change_oper_t oper;
	char  *name = NULL;

	DBG("**SPD VERIFY .... ");

    
    // if oper= CREATED
    if (oper == SR_OP_CREATED) {
        DBG("Verify rule-number is not already used");
        DBG("Verify ts-number is not already used");
    } else {
        // if oper= DELETE
        DBG("Verify rule-number exists");
    }    
    
	return rc;
}


int readSPD_entry(sr_session_ctx_t *sess, sr_change_iter_t *it,char *xpath,char *rule_number, int case_value) {

    int rc = SR_ERR_OK;
    sr_val_t *old_value = NULL;
    sr_val_t *new_value = NULL;
    sr_val_t *value = NULL;
    sr_change_oper_t oper;
    char  *name = NULL;

    DBG("**SPD READ.... ");

        rc = sr_get_change_next(sess, it, &oper, &old_value, &new_value);
        if (SR_ERR_OK != rc)
            return SR_ERR_VALIDATION_FAILED;

        do {
        

            if (oper == SR_OP_CREATED) value = new_value;
            else value = old_value;

            /*if (value == NULL) {
                DBG("SPD read, value == NULL");
                break;
            } */   
            if (0 == strncmp(value->xpath, xpath,strlen(xpath))) {

                name = strrchr(value->xpath, '/');
                if (NULL != strstr(value->xpath,"/condition")) {
                    if (getSelectorList_it(sess,it,xpath,oper,old_value,new_value)){
                        rc = SR_ERR_VALIDATION_FAILED;
                       break;
                    }
                }
                else if (NULL != strstr(value->xpath,"/processing-info")) {
                    if (getProcessing_it(sess,it,xpath,oper,old_value,new_value)) {
                        rc = SR_ERR_VALIDATION_FAILED;
                       break;
                    }
                }

                else if (0 == strcmp("/bytes", name)) {
                    if (NULL != strstr(value->xpath,"/spd-lifetime-soft")) { 
                        spd_lft_byte_soft = value->data.int32_val;
                        DBG("lifetime byte-soft: %i",spd_lft_byte_soft);
                    } else if (NULL != strstr(value->xpath,"/spd-lifetime-hard")) { 
                        spd_lft_byte_hard = value->data.int32_val;
                        DBG("lifetime byte-hard: %i",spd_lft_byte_hard);
                    }
                }  

                else if (0 == strcmp("/packets", name)) {
                    if (NULL != strstr(value->xpath,"/spd-lifetime-soft")) { 
                        spd_lft_packet_soft = value->data.int32_val;
                        DBG("lifetime packet-soft: %i",spd_lft_packet_soft);
                    } else if (NULL != strstr(value->xpath,"/spd-lifetime-hard")) {  
                        spd_lft_packet_hard = value->data.int32_val;
                        DBG("lifetime packet-hard: %i",spd_lft_packet_hard);
                    }  
                }  
                else if (0 == strcmp("/added", name)) {
                    if (NULL != strstr(value->xpath,"/spd-lifetime-soft")) { 
                        spd_lft_soft_add_expires_seconds = value->data.int64_val;
                        DBG("lifetime time-soft: %i",spd_lft_soft_add_expires_seconds);
                    } else if (NULL != strstr(value->xpath,"/spd-lifetime-hard")) { 
                        spd_lft_hard_add_expires_seconds= value->data.int64_val;
                        DBG("lifetime time-hard: %i",spd_lft_hard_add_expires_seconds);
                    }
                }  
                else if (0 == strcmp("/used", name)) {
                    if (NULL != strstr(value->xpath,"/spd-lifetime-soft")) { 
                        spd_lft_soft_use_expires_seconds = value->data.int64_val;
                        DBG("lifetime time-use-soft: %i",spd_lft_soft_use_expires_seconds);
                    } else if (NULL != strstr(value->xpath,"/spd-lifetime-hard")) {  
                        spd_lft_hard_use_expires_seconds= value->data.int64_val;
                        DBG("lifetime time-use-hard: %i",spd_lft_hard_use_expires_seconds);
                    }  
                }      



            } else break;
             
            sr_free_val(old_value);
            sr_free_val(new_value);

        } while (SR_ERR_OK == sr_get_change_next(sess, it,&oper, &old_value, &new_value));

    return rc;
}

int addSPD_entry(sr_session_ctx_t *sess, sr_change_iter_t *it,char *xpath,char *rule_number, int case_value) {




	int rc = SR_ERR_OK;

    policy_id = atoi(rule_number);

	DBG("**ADD/MOD SPD %s with rule number: %i",xpath, policy_id);

	rc = readSPD_entry(sess,it,xpath,rule_number,case_value);
	if (rc != SR_ERR_OK) {
		ERR("ADD SPD in getSDP_entry: %s", sr_strerror(rc));
		return rc;
	}
	
    
    
	///if (case_value == 1) {
	//	DBG("SPD entry for case 1 added ");

	spd_entry_node *spd_node = createSPDnode();
	spd_node->policy_id = policy_id;
    spd_node->index = 0;
	if (policy_dir != NULL) spd_node->policy_dir = policy_dir;
	if (src != NULL) strcpy(spd_node->src,src);
	if (dst != NULL) strcpy(spd_node->dst,dst);
	if (src_tunnel != NULL) strcpy(spd_node->src_tunnel,src_tunnel);
	if (dst_tunnel != NULL) strcpy(spd_node->dst_tunnel,dst_tunnel);
	if (satype != NULL) spd_node->satype = satype;
    if (proto != NULL) spd_node->request_protocol = proto;
	if (action_policy_type != NULL) spd_node->action_policy_type=action_policy_type;
	if (mode != NULL) spd_node->mode = mode;
	if (protocol_next_layer != NULL) spd_node->protocol_next_layer = protocol_next_layer;
	if (srcport != NULL) spd_node->srcport = srcport;
	if (dstport != NULL) spd_node->dstport = dstport;

    if (spd_lft_byte_hard != NULL) spd_node->lft_byte_hard = spd_lft_byte_hard;
    if (spd_lft_byte_soft != NULL) spd_node->lft_byte_soft = spd_lft_byte_soft;
    if (spd_lft_packet_hard != NULL) spd_node->lft_packet_hard = spd_lft_packet_hard;
    if (spd_lft_packet_soft != NULL) spd_node->lft_packet_soft = spd_lft_packet_soft;
    if (spd_lft_hard_add_expires_seconds != NULL) spd_node->lft_hard_add_expires_seconds = spd_lft_hard_add_expires_seconds;
    if (spd_lft_hard_use_expires_seconds != NULL) spd_node->lft_hard_use_expires_seconds = spd_lft_hard_use_expires_seconds;
    if (spd_lft_soft_add_expires_seconds != NULL) spd_node->lft_soft_add_expires_seconds = spd_lft_soft_add_expires_seconds;
    if (spd_lft_soft_use_expires_seconds != NULL) spd_node->lft_soft_use_expires_seconds = spd_lft_soft_use_expires_seconds;



	addSPD_node(spd_node);
        

    //    return SR_ERR_OK;
	//} else {
    if (case_value == 2) {
        rc = pf_addpolicy(spd_node);    
        if (SR_ERR_OK != rc) {
            ERR("ADD SPD in getSDP_entry: %s", sr_strerror(rc));
            return rc;     
        }

	}
    
    //INFO("SPD entry added ");
    show_spd_list();

    return SR_ERR_OK;
}


int getSelectorList_it(sr_session_ctx_t *sess, sr_change_iter_t *it,char *xpath, sr_change_oper_t oper, sr_val_t *old_val, sr_val_t *new_val) {

    int rc = SR_ERR_OK;
    char new_xpath[MAX_PATH] = "";
    sr_val_t *value = NULL;	
    char  *name = NULL;

    do {
		if (oper == SR_OP_CREATED) value = new_val;
		else value = old_val;
                
		//DBG ("add condition: %s",value->xpath);
		strcpy(new_xpath,xpath);
		strcat(new_xpath,"/condition");
        if ((0 == strncmp(value->xpath, new_xpath,strlen(new_xpath))) && (strlen(value->xpath)!=strlen(new_xpath))) {
			
            name = strrchr(value->xpath, '/');
            // ONLY ONE TRAFFIC SELECTOR
            if (0 == strcmp("/direction", name)) {
                    if (!strcasecmp(value->data.string_val, "OUTBOUND"))
                        policy_dir =  IPSEC_DIR_OUTBOUND;
                    else if (!strcasecmp(value->data.string_val, "INBOUND"))
                        policy_dir = IPSEC_DIR_INBOUND;
                    else if (!strcasecmp(value->data.string_val, "FORWARD"))
                        policy_dir = IPSEC_DIR_FORWARD;
                    else {
                        rc = SR_ERR_VALIDATION_FAILED;    
                        ERR("spd-entry Bad direction: %s", sr_strerror(rc));
                        return rc;
                    }
                    DBG("direction: %i",policy_dir);
            }
            else if (0 == strcmp("/next-layer-protocol", name)) {
                    DBG("next-layer-protocol found");
                    if (!strcasecmp(value->data.string_val, "TCP"))
                        protocol_next_layer =  IPSEC_NLP_TCP;
                    else if (!strcasecmp(value->data.string_val, "UDP"))
                        protocol_next_layer = IPSEC_NLP_UDP;
                    else if (!strcasecmp(value->data.string_val, "SCTP"))
                        protocol_next_layer = IPSEC_NLP_SCTP;
                    else {
                        rc = SR_ERR_VALIDATION_FAILED;
                        ERR("spd-entry Bad next-layer-protocol: %s", sr_strerror(rc));
                        return rc;
                    }
                    DBG("next-layer-protocol: %i",protocol_next_layer);
            }

			else if (0 == strncmp("/start", name,strlen("/start"))) {
                    //sr_print_val(value);
					if (NULL != strstr(value->xpath,"/local-addresses")) {
                        strcpy(src, value->data.string_val);    
                        DBG("local-address start: %s",src);
					}
					if (NULL != strstr(value->xpath,"/remote-addresses")) {
						strcpy(dst, value->data.string_val);
						DBG("remote-address start: %s",dst);
					}
                    if (NULL != strstr(value->xpath,"/local-ports")) {
                        srcport = value->data.int64_val;
						DBG("local-port start: %i",srcport);
					}
					if (NULL != strstr(value->xpath,"/remote-ports")) {
                        dstport = value->data.int64_val;
                        DBG("remote-port start: %i",dstport);
                    }
			}

		} else break;
		
		sr_free_val(old_val);
        sr_free_val(new_val);

    } while (SR_ERR_OK == (rc = sr_get_change_next(sess, it,&oper, &old_val, &new_val))); 


    return SR_ERR_OK;	

}


int getProcessing_it(sr_session_ctx_t *sess, sr_change_iter_t *it,char *xpath, sr_change_oper_t oper, sr_val_t *old_val, sr_val_t *new_val) {


    int rc = SR_ERR_OK;
    sr_val_t *value = NULL;
    char  *name = NULL;
    char new_xpath[MAX_PATH] = "";

	do {
        if (oper == SR_OP_CREATED) value = new_val;
        else value = old_val;
        //DBG ("add processing_it: %s",value->xpath);


        strcpy(new_xpath,xpath);
        strcat(new_xpath,"/processing-info");

		if ((0 == strncmp(value->xpath, new_xpath,strlen(new_xpath))) && (strlen(value->xpath)!=strlen(new_xpath))) {

            name = strrchr(value->xpath, '/');
            // SE SUPONE QUE SOLO HAY UN TRAFFIC SELECTOR
            if (0 == strcmp("/action", name)) {
                if (!strcasecmp(value->data.string_val, "PROTECT"))
                    action_policy_type=IPSEC_POLICY_PROTECT;
                else if (!strcasecmp(value->data.string_val, "BYPASS"))
                    action_policy_type=IPSEC_POLICY_BYPASS;
                else if (!strcasecmp(value->data.string_val, "DISCARD"))
                    action_policy_type=IPSEC_POLICY_DISCARD;
                else {
                    rc = SR_ERR_VALIDATION_FAILED;
                    ERR("spd-entry Bad action: %s", sr_strerror(rc));
                    return rc;
                }
                DBG("action: %i",action_policy_type);
            }
		    else if (0 == strcmp("/security-protocol", name)) {
                if (!strcasecmp(value->data.string_val, "ESP")){
                    satype = SADB_SATYPE_ESP;
                    proto = IPPROTO_ESP;
                }
                else if (!strcasecmp(value->data.string_val, "AH")) {
                    satype = SADB_SATYPE_AH;
                    proto = IPPROTO_AH;
                }
                else {
                    rc = SR_ERR_VALIDATION_FAILED;
                    ERR("spd-entry Bad satype: %s", sr_strerror(rc));
                    return rc;
                }
                DBG("satype: %i",satype);
            }

            else if (0 == strcmp("/mode", name)) {
                DBG("mode found");
                if (!strcasecmp(value->data.string_val, "TRANSPORT")){
                    mode = IPSEC_MODE_TRANSPORT;
                }
                else if (!strcasecmp(value->data.string_val, "TUNNEL")) {
                    mode = IPSEC_MODE_TUNNEL; 

                }
                else {
                    rc = SR_ERR_VALIDATION_FAILED;
                    ERR("spd-entry Bad mode: %s", sr_strerror(rc));
                    return rc;
                }
                DBG("mode: %i",mode);
            }

 			else if (0 == strcmp("/local", name)) {
                strcpy(src_tunnel, value->data.string_val);
                DBG("mode tunnel src_tunnel: %s",src_tunnel);
				 //error = 1;
            }

			else if (0 == strcmp("/remote", name)) {
                strcpy(dst_tunnel, value->data.string_val);
                DBG("mode tunnel dst_tunnel: %s",dst_tunnel);
            }
	
        } else break;

		sr_free_val(old_val);
        sr_free_val(new_val);
                 
    }  while (SR_ERR_OK == (rc = sr_get_change_next(sess, it,&oper, &old_val, &new_val)));

    return SR_ERR_OK;
}


char* getSPDmode(spd_entry_node* node){
	if (node->mode == IPSEC_MODE_TRANSPORT)
		return "transport";
	else if (node->mode == IPSEC_MODE_TUNNEL)
		return "tunnel";

	return "NONE";
}

char* getSPDsrc(spd_entry_node* node){

    // check null
    return node->src;
}

char* getSPDdst(spd_entry_node* node){

    // check null
    return node->dst;
}



char* getSPDsatype(spd_entry_node * node){
	if (node->satype == SADB_SATYPE_AH){
		return "ah_proposals";}
	else if (node->satype == SADB_SATYPE_ESP)
		return "esp_proposals";
	return "esp_proposals";
}


int get_spd_lifetime_current(const char *xpath, sr_val_t **values, size_t *values_cnt, void *private_ctx){
    
    sr_val_t *vals;
    int rc;
    int packets;
    int bytes;
    uint64_t added;
    uint64_t used;
    char tmp_xpath[MAX_PATH] = "";
    int policy_id = 0;

    //get the spi from xpath
    strcpy(tmp_xpath,xpath);
    char * st = strtok(tmp_xpath,"'");
    char * st2 = strtok(NULL,"'");
    policy_id = atoi(st2);
    DBG("get_spd_lifetime_current rule_number: %i",policy_id);


    spd_entry_node *node = get_spd_node(policy_id);
    if (node == NULL) {
        rc = SR_ERR_OPERATION_FAILED;
        ERR("SPD, policy not found: %s", sr_strerror(rc));
        return rc;
    }

    if (rc = pf_get_spd_lifetime_current_by_rule(node)) {
    //if (rc = pf_get_spd_lifetime_current_by_rule(node,&packets, &bytes, &added, &used)) {
        ERR("spd_lifetime_current_cb in pf_get_spd_lifetime_current_by_rule: %s", sr_strerror(rc));
        return rc;
    }
    
    rc = sr_new_values(4, &vals);
    if (SR_ERR_OK != rc) {
        ERR("spd_lifetime_current_cb: %s", sr_strerror(rc));
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
    vals[3].data.uint64_val = node->lft_current_use_expires_seconds;
    
    *values = vals;
    *values_cnt = 4;
    
    return SR_ERR_OK;

}




