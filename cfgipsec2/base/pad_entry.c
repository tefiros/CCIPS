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

#include "pad_entry.h"

pad_entry_node* init_pad_node = NULL;
int entry_id;
int key;
char ipv4_addr[30];
char auth_protocol[50];
char auth_method[40];
char ssecret[40];


pad_entry_node* getPADEntry(char* remote_ts){

	pad_entry_node *node = init_pad_node;
	while (node != NULL){
		if (!strcmp(remote_ts, node->ipv4_address))
			return node;
		node=node->next;
	}
	return NULL;
}

void addPAD_node(pad_entry_node* node_entry){

	if (init_pad_node == NULL){
		init_pad_node=node_entry;
		node_entry->next=NULL;
	}else{
		pad_entry_node *node = init_pad_node;
		while(node->next != NULL)
			node=node->next;
		node->next=node_entry;
	}
}

void show_pad_list(){

	pad_entry_node *node = init_pad_node;
	int index = 0;

	INFO("INDEX --- PAD_ENTRY_ID --- IDENTITY --- PAD_AUTH_PROTOCOL --- AUTH_M --- SECRET ---- ");
	while (node != NULL){
		INFO("%d --- %d --- %s --- %s --- %s --- %s ", index, node->pad_entry_id, node->ipv4_address, node->pad_auth_protocol, node->auth_m, node->secret);
		node=node->next;
		index++;
	}
}

pad_entry_node* create_node(int entry_idCN, char* ipv4, char* auth_protocolCN, char* auth_methodCN, char* ssecretCN){

	pad_entry_node *new_node = (pad_entry_node*) malloc(sizeof(pad_entry_node));
	new_node->pad_entry_id= entry_idCN;
	new_node->ipv4_address= (char *) malloc(sizeof(char) * strlen(ipv4));
	strcpy(new_node->ipv4_address, ipv4);
	new_node->pad_auth_protocol = (char*) malloc(sizeof(char) * strlen(auth_protocolCN));
	strcpy(new_node->pad_auth_protocol, auth_protocolCN);
	new_node->auth_m = (char*) malloc(sizeof(char) *strlen(auth_methodCN));
	strcpy(new_node->auth_m, auth_methodCN);
	new_node->secret = (char*) malloc(sizeof(char) *strlen(ssecretCN));
	strcpy(new_node->secret, ssecretCN);
	new_node->next=NULL;

	return new_node;
}

int readPAD_entry(sr_session_ctx_t *sess, sr_change_iter_t *it,char *xpath,char *pad_id) {

	int rc = SR_ERR_OK;
    sr_val_t *old_value = NULL;
    sr_val_t *new_value = NULL;
	sr_change_oper_t oper;
    sr_val_t *value = NULL;
    char  *name = NULL;

	entry_id = atoi(pad_id);

	DBG("**Read PAD entry: %i",entry_id);
	rc = sr_get_change_next(sess, it, &oper, &old_value, &new_value);
    if (SR_ERR_OK != rc)
        return rc;

    do {
        if (oper == SR_OP_CREATED) value = new_value;
        else value = old_value;

		if ((0 == strncmp(value->xpath, xpath,strlen(xpath))) && (strlen(value->xpath)!=strlen(xpath))) {
        	name = strrchr(value->xpath, '/');

			if (0 == strcmp("/id_key", name)) {
            	key = value->data.int64_val;
            	DBG ("id_keyt %i",key);
        	}
			else if (0 == strcmp("/ipv4-address",name)) {
                strcpy(ipv4_addr, value->data.string_val);
                DBG("ipv4-address: %s",ipv4_addr);
            }
			else if (0 == strcmp("/pad-auth-protocol",name)) {
                strcpy(auth_protocol, value->data.string_val);
                DBG("auth_protocol: %s",auth_protocol);
            }
			else if (0 == strcmp("/auth-m",name)) {
				if (0 == strcmp(value->data.string_val,"pre-shared")) {		
                    strcpy(auth_method, "psk");
                    DBG("auth_method: %s",auth_method);
				} else {
					ERR("Auth_method unsuppoted: %s",sr_strerror(SR_ERR_VALIDATION_FAILED));
					return SR_ERR_VALIDATION_FAILED;
				}
            }
			else if (0 == strcmp("/secret",name)) {
                strcpy(ssecret, value->data.string_val);
            }

        } else break;

		sr_free_val(old_value);
        sr_free_val(new_value);

    } while (SR_ERR_OK == sr_get_change_next(sess, it,&oper, &old_value, &new_value));

	return SR_ERR_OK;
}

int addPAD_entry(sr_session_ctx_t *sess, sr_change_iter_t *it,char *xpath,char *pad_id) {

	int rc = SR_ERR_OK;
	entry_id = atoi(pad_id);

    DBG("**ADD PAD entry: %i",entry_id);

	rc = readPAD_entry(sess,it,xpath,pad_id);
	if (rc != SR_ERR_OK) {
        ERR("ADD PAD in verifyPAD_entry: %s",sr_strerror(rc));
        return rc;
    }

	pad_entry_node *node =  create_node(entry_id, ipv4_addr, auth_protocol, auth_method, ssecret);
    addPAD_node(node);
    show_pad_list();

    return SR_ERR_OK;
}


int verifyPAD_entry(sr_session_ctx_t *sess, sr_change_iter_t *it, sr_change_oper_t oper, char *xpath,char *pad_id) {

	int rc = SR_ERR_OK;
    sr_val_t *old_value = NULL;
    sr_val_t *new_value = NULL;
	//sr_change_oper_t oper;
    sr_val_t *value = NULL;
    char  *name = NULL;

	entry_id = atoi(pad_id);

	DBG("**VERIFY PAD entry: %i",entry_id);

	if (oper == SR_OP_CREATED) {
		DBG("Verify PAD entry pad_id is not already used");
	} else {
		DBG("Verify PAD entry pad_id is already used");
	}

	return SR_ERR_OK;
}

int removePAD_entry(sr_session_ctx_t *sess, sr_change_iter_t *it,char *xpath,char *pad_id) {

	DBG("**REMOVE PAD conn entry TBD ....");

	return SR_ERR_OPERATION_FAILED;
}

