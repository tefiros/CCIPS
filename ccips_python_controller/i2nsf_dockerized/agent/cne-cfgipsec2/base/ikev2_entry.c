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

#include "ikev2_entry.h"


char conn_name1[50]="";
char autostartup[20]="";
char version[5]="2";
int ike_sa_lifetime;
int ipsec_sa_lifetime;
int ike_reauth_lifetime;
char phase1_authby[50]="";
int dh_group;
char local_ts[30]="";
char local_identifier[50]="";
char remote_ts[30]="";
char remote_identifier[50]="";
char local_addrs[30]="";
char remote_addrs[30]="";
int pfs_group;


int removeIKE_conn_entry(sr_session_ctx_t *sess, sr_change_iter_t *it,char *xpath,char *ike_id) {

	int rc = SR_ERR_OK;

    ERR("DELETE IKEv2 conn entry TBD ......");

	return SR_ERR_OPERATION_FAILED;
}


int checkIKE_connection() {

	vici_conn_t *conn;
    int rc = SR_ERR_OK;

    vici_init();
    conn = vici_connect(NULL);
    if (conn){
            INFO(" Connected to vici ");
	} else {
            ERR("Connecting failed: %s", strerror(errno));
            return SR_ERR_OPERATION_FAILED;
    }
    
    vici_deinit();
    return SR_ERR_OK;
}

int newIke_connection(char* conn_name, char* version, char* local_addrs, char* remote_addrs, char* phase1_authby, 
		char* local_ts, char* local_id, char* remote_ts, char* remote_id, char * proposals,
		char* satype, char* mode, char* type, char* secr, int ike_reauth_lifetime, int ike_sa_lifetime, int ipsec_sa_lifetime){

	vici_conn_t *conn;
	int rc = SR_ERR_OK;

	vici_init();
	conn = vici_connect(NULL);
	if (conn){
    	DBG("Connected to vici ");

    	vici_req_t *req_cmd;
    	vici_res_t *res_cmd;
    	req_cmd = vici_begin("load-conn");

    	vici_begin_section(req_cmd,conn_name);
    	vici_begin_list(req_cmd,"local_addrs");
        vici_add_list_itemf(req_cmd,"%s",local_addrs);
    	vici_end_list(req_cmd);

    	vici_begin_list(req_cmd,"remote_addrs");
        vici_add_list_itemf(req_cmd,"%s",remote_addrs); 
    	vici_end_list(req_cmd);

    	vici_add_key_valuef(req_cmd,"version","%s",version);
    
        vici_begin_list(req_cmd,"proposals");    
        vici_add_list_itemf(req_cmd,"%s",proposals);
    	vici_end_list(req_cmd);

    	vici_begin_section(req_cmd,"local");
        vici_add_key_valuef(req_cmd,"auth","%s",phase1_authby);
        vici_add_key_valuef(req_cmd,"id","%s",local_id);
    	vici_end_section(req_cmd);  // LOCAL

    	vici_begin_section(req_cmd,"remote");
        vici_add_key_valuef(req_cmd,"auth","%s",phase1_authby);
        vici_add_key_valuef(req_cmd,"id","%s",remote_id);
    	vici_end_section(req_cmd);  // REMOTE
		
        DBG ("rekey_time %i",ike_sa_lifetime);   
        vici_add_key_valuef(req_cmd,"rekey_time", "%i",ike_sa_lifetime);
		DBG ("reauth_time %i",ike_reauth_lifetime);  
		vici_add_key_valuef(req_cmd,"reauth_time", "%i",ike_reauth_lifetime);
		

    	DBG ("CHILD SA found! %s",conn_name);
    	vici_begin_section(req_cmd,"children");
                    
        vici_begin_section(req_cmd,conn_name);
                
        if (local_ts[0] != '\0') {
                vici_begin_list(req_cmd,"local_ts");
                vici_add_list_itemf(req_cmd,"%s",local_ts); 
                vici_end_list(req_cmd);
        }
        if (remote_ts[0] != '\0') {
                vici_begin_list(req_cmd,"remote_ts");
                vici_add_list_itemf(req_cmd,"%s",remote_ts); 
                vici_end_list(req_cmd);        
        }

	    vici_add_key_valuef(req_cmd,"start_action","%s","trap");	// No SPD, start listen traffic
             
        if (!strcmp(satype, "ah_proposals")){
        	vici_begin_list(req_cmd,"ah_proposals");    
            vici_add_list_itemf(req_cmd,"%s","default");//ah_proposals);                                  
			vici_end_list(req_cmd);                                              
        }
            // else -> ESP (default)
            
        vici_add_key_valuef(req_cmd,"mode","%s",mode); // Mode -> TUNNEL (default)   
        DBG ("ipsec rekey_time %i",ipsec_sa_lifetime);     
        vici_add_key_valuef(req_cmd,"rekey_time","%i",ipsec_sa_lifetime);
                   

        vici_end_section(req_cmd);  // CHILD_NAME
    	vici_end_section(req_cmd); // CHILDREN             
    	vici_end_section(req_cmd); // INIT

    /**********************************/
    /**************SECRET**************/
    /**********************************/

    	res_cmd = vici_submit(req_cmd, conn);
    	if (res_cmd){ 
                INFO("Conn %s loaded successfully", conn_name);
        		vici_free_res(res_cmd);
    	}else{
        	ERR("Request load_conn %s failed: %s", conn_name, strerror(errno));
		    return SR_ERR_OPERATION_FAILED;
    	}
    
    	/*Secret over vici swanctl/load_creds.c*/
    	vici_req_t *req;
    	vici_res_t *res;

    	req = vici_begin("load-shared");

    	vici_add_key_valuef(req, "type", "%s", type); // ike, xauth, eap
    	vici_add_key_value(req, "data", secr, strlen(secr)); // share secret 

    	vici_begin_list(req, "owners");
    	vici_add_list_itemf(req, "%s", remote_id);
    	vici_end_list(req);

    	res = vici_submit(req, conn);

    	if (res){ 
        	INFO("Secret %s loaded successfully", local_id);
        	vici_free_res(res);
    	}else{
        	ERR("Request load_secret %s failed: %s", local_id, strerror(errno));
		    return SR_ERR_OPERATION_FAILED;
    	}

    	vici_disconnect(conn);
    	DBG("Disconnected from vici ");

	} else {
    	ERR("Connecting failed: %s", strerror(errno));
	    return SR_ERR_OPERATION_FAILED;
	}

	vici_deinit();
	return SR_ERR_OK;
}

int addIKE_conn_entry(sr_session_ctx_t *sess, sr_change_iter_t *it,char *xpath,char *ike_id) {

	int rc = SR_ERR_OK;

	DBG("**ADD IKE entry: %s",ike_id);

	rc = readIKE_conn_entry(sess,it,xpath,ike_id);
	if (rc != SR_ERR_OK) {
        ERR("Add IKE in verifyIKE_entrty: %s", sr_strerror(rc));
        return SR_ERR_VALIDATION_FAILED;
    }

    /********SPD********/
    spd_entry_node* spd_node = getSPDEntry(local_addrs, remote_addrs);
    if (spd_node == NULL){
        ERR("MUST INSERT A VALID SPD: %s", sr_strerror(SR_ERR_VALIDATION_FAILED));
        return SR_ERR_VALIDATION_FAILED;
    }

     // get remote_addr from SPD
    strcpy(remote_ts,getSPDdst(spd_node));
    strcpy(local_ts,getSPDsrc(spd_node));

	char proposals[50] = "default";
    char peer[30];

    if (spd_node->mode == IPSEC_MODE_TUNNEL) {
        strcpy(peer,spd_node->dst_tunnel);
    } else {
        strcpy(peer,remote_addrs);
    }

    pad_entry_node* pad_node = getPADEntry(remote_addrs);
    if (pad_node == NULL){
        ERR("MUST INSERT A VALID PAD: %s", sr_strerror(SR_ERR_VALIDATION_FAILED));
        return SR_ERR_VALIDATION_FAILED;
    }

    char* type = (char *) malloc(sizeof(char) * strlen(pad_node->pad_auth_protocol));
    if (!strcmp(pad_node->pad_auth_protocol, "IKEv2"))
        strcpy(type, "ike");

    // get phase1-authby from PAD     
    strcpy(phase1_authby, pad_node->auth_m);
    

    /*CREATING A NEW IKE CONNECTION*/
    rc = newIke_connection(conn_name1, version, local_addrs, remote_addrs, phase1_authby, 
          local_ts, local_identifier, remote_ts, remote_identifier, proposals, getSPDsatype(spd_node), getSPDmode(spd_node), 
          type, pad_node->secret, ike_reauth_lifetime, ike_sa_lifetime, ipsec_sa_lifetime);

	if (rc != SR_ERR_OK) {
		ERR("newIKE_connection: %s", sr_strerror(rc));
		return rc;
	}
    free(type);

    return SR_ERR_OK;
}



int verifyIKE_conn_entry(sr_session_ctx_t *sess, sr_change_iter_t *it, sr_change_oper_t oper, char *xpath,char *ike_id) {

	int rc = SR_ERR_OK;
    //sr_change_oper_t oper;
	sr_val_t *value = NULL;
   	sr_val_t *old_value = NULL;
    sr_val_t *new_value = NULL;
    char  *name = NULL;
    char proposals[50] = "default";
    char peer[30];

    strcpy(conn_name1,ike_id);

	DBG("**VERIFY IKE entry: %s",conn_name1);


    if (oper == SR_OP_CREATED) {
        DBG("Verify IKE entry ike_id is not already used");
    } else {
        DBG("Verify IKE entry ike_id is already used");
    }

	return rc;
}


int readIKE_conn_entry(sr_session_ctx_t *sess, sr_change_iter_t *it,char *xpath,char *ike_id) {

    int rc = SR_ERR_OK;
    sr_change_oper_t oper;
    sr_val_t *value = NULL;
    sr_val_t *old_value = NULL;
    sr_val_t *new_value = NULL;
    char  *name = NULL;
    char proposals[50] = "default";
    char peer[30];

    strcpy(conn_name1,ike_id);

    DBG("**Read IKE entry: %s",conn_name1);

    rc = sr_get_change_next(sess, it, &oper, &old_value, &new_value);
    if (SR_ERR_OK != rc)
        return rc;

    do {

        if (oper == SR_OP_CREATED) value = new_value;
        else value = old_value;

        if ((0 == strncmp(value->xpath, xpath,strlen(xpath))) && (strlen(value->xpath)!=strlen(xpath))) {
            name = strrchr(value->xpath, '/');      


            // conn-name: TBD
            if (0 == strcmp("/autostartup", name)) {
                if (0 == strcmp(value->data.enum_val,"ALWAYSON")) 
                    strcpy(autostartup,"true");
                else strcpy(autostartup,"false");
                    DBG ("autostartup %s",autostartup);
            }       

            // nat-traversal: TBD

            // encap: TBD

            else if (0 == strcmp("/version", name)) {
                if (0 == strcmp(value->data.string_val,"ikev2")) {
                    strcpy(version, "2");
                    DBG("version %s", version);
                }
            }   

            // grouping isakmp-proposal
            else if (0 == strcmp("/ike-reauth-lifetime", name)) {
                ike_reauth_lifetime = value->data.int64_val;
                DBG ("ike_reauth_lifetime: %i",ike_reauth_lifetime);
            } 
            else if (0 == strcmp("/ike-sa-lifetime", name)) {
                ike_sa_lifetime = value->data.int64_val;
                DBG ("ike_sa_lifetime: %i",ike_sa_lifetime);
            } 
            else if (0 == strcmp("/ipsec-sa-lifetime", name)) {
                ipsec_sa_lifetime = value->data.int64_val;
                DBG ("ipsec_sa_lifetime: %i",ipsec_sa_lifetime);
            } 
			
			// tmp lifetimes
			

            else if (0 == strcmp("/phase1-authalg", name)) {
                DBG ("phase1-authalg not implemented");
            }
            else if (0 == strcmp("/phase1-encalg", name)) {
                DBG ("phase1-encalg not implemented");
            }

            // combined-enc-intr: TBD

            else if (0 == strcmp("/dh_group", name)) {
                dh_group = value->data.int32_val;
                DBG ("dh_group %i",dh_group);
            }

            // end grouping isakmp-proposal

            // local and remote groupings
            else if (0 == strcmp("/ipv4",name)) {
                if (NULL != strstr(value->xpath,"local")) {
                   strcpy(local_addrs,value->data.string_val);
                   DBG("local ipv4 %s", local_addrs);
                }
                if (NULL != strstr(value->xpath,"remote")) {
                    strcpy(remote_addrs,value->data.string_val);
                    DBG("remote ipv4 %s", remote_addrs);
                }
            }
            else if (0 == strcmp("/my-identifier",name)) {
                if (NULL != strstr(value->xpath,"local")) {
                    strcpy(local_identifier,value->data.string_val);
                    DBG("local identifier %s", local_identifier);
                }
                if (NULL != strstr(value->xpath,"remote")) {
                    strcpy(remote_identifier,value->data.string_val);
                    DBG("remote identifier %s", remote_identifier);
                }
            }

            // end local and remote groupings    

            /*else if (0 == strcmp("/local-addrs", name)) {
                strcpy(local_addrs,value->data.string_val);
                DBG ("local_addrs %s",local_addrs);
            }
            else if (0 == strcmp("/remote-addr", name)) {
                strcpy(remote_addr,value->data.string_val);
                DBG("remote_addr %s", remote_addr); 
            }*/
            else if (0 == strcmp("pfs_group", name)) {
                pfs_group = value->data.int32_val;
                DBG("pfs_group %i", pfs_group);
            }   
            /*else if (0 == strcmp("phase2-lifetime", name)) {
                phase2_lifetime = value->data.int64_val;
                DBG("phase2_lifetime %i", phase2_lifetime);
            }*/
        } else  break;
               
        sr_free_val(old_value);
        sr_free_val(new_value);
        
    } while (SR_ERR_OK == sr_get_change_next(sess, it,&oper, &old_value, &new_value));


    DBG ("Looking for a valid SPD for local peer: %s  and remote peer: %s",local_addrs, remote_addrs);
    spd_entry_node* spd_node = getSPDEntry(local_addrs, remote_addrs);
    if (spd_node == NULL){
        ERR("MUST INSERT A VALID SPD: %s", sr_strerror(SR_ERR_VALIDATION_FAILED));
        return SR_ERR_VALIDATION_FAILED;
    }
    DBG ("SPD found ");

     // get remote_addr from SPD
    strcpy(remote_ts,getSPDdst(spd_node));
    DBG("SPD found remote_ts: %s",remote_ts);
    strcpy(local_ts,getSPDsrc(spd_node));
    DBG("SPD found local_ts: %s",local_ts);

    if (spd_node->mode == IPSEC_MODE_TUNNEL) {
        strcpy(peer,spd_node->dst_tunnel);
    } else {
        strcpy(peer,remote_addrs);
    }

    DBG ("Looking for a valid PAD for %s ", peer);
    pad_entry_node* pad_node = getPADEntry(remote_addrs);
    if (pad_node == NULL){
        ERR("MUST INSERT A VALID PAD: %s", sr_strerror(SR_ERR_VALIDATION_FAILED));
        return SR_ERR_OPERATION_FAILED;
    }
    
    char* type = (char *) malloc(sizeof(char) * strlen(pad_node->pad_auth_protocol)); 
    if (!strcmp(pad_node->pad_auth_protocol, "IKEv2"))
        strcpy(type, "ike");
    free(type);

    return rc;
}





