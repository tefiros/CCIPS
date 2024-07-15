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

#include "utils.h"
#include "sysrepo_utils.h"

int feature_case_value = 0;

char *
ev_to_str(sr_notif_event_t ev) {

    switch (ev) {
    case SR_EV_VERIFY:
        return "verify";
    case SR_EV_APPLY:
        return "apply";
    case SR_EV_ABORT:
    default:
        return "abort";
    }
}


static void
print_current_config(sr_session_ctx_t *session, const char *module_name) {

    sr_val_t *values = NULL;
    size_t count = 0;
    int rc = SR_ERR_OK;
    char select_xpath[XPATH_MAX_LEN];
    snprintf(select_xpath, XPATH_MAX_LEN, "/%s:*//*", module_name);

    rc = sr_get_items(session, select_xpath, &values, &count);
    if (SR_ERR_OK != rc) {
        ERR("sr_get_items: %s", sr_strerror(rc));
        return;
    }
    for (size_t i = 0; i < count; i++){
        sr_print_val(&values[i]);
    }
    sr_free_values(values, count);
}


// callbackk for ike-conn-entry element
int ike_entry_change_cb(sr_session_ctx_t *session, const char *ike_entry_xpath, sr_notif_event_t event, void *private_ctx)
{

    sr_change_iter_t *it = NULL;
    int rc = SR_ERR_OK;
    sr_change_oper_t oper;
    sr_val_t *old_value = NULL;
    sr_val_t *new_value = NULL;
    char * name = NULL;
    char * token_ike = "/conn-name";
    int l = strlen(token_ike);
    char xpath[MAX_PATH] = "";

    DBG(" ========== IKE Notification  %s ============================================", ev_to_str(event));
    if (SR_EV_VERIFY == event) {

        DBG("========= VERIFY: IKE-ENTRY HAS CHANGED, CURRENT RUNNING CONFIG: ==========");

        rc = sr_get_changes_iter(session, ike_entry_xpath , &it);
        if (SR_ERR_OK != rc) {
            ERR("Get changes iter failed for xpath %s: %s", ike_entry_xpath, sr_strerror(rc));
            goto cleanup;
        }
        while (SR_ERR_OK == sr_get_change_next(session, it, &oper, &old_value, &new_value)) {
            switch(oper) {
                case SR_OP_CREATED:
                        name = strrchr(new_value->xpath, '/');
                        if (0 == strncmp(token_ike,name,l)) {

                            INFO("Verify ike-conn-entry %s",sr_val_to_str(new_value));
                            strncpy(xpath,new_value->xpath,strlen(new_value->xpath)-l);

                            if (!verifyIKE_conn_entry(session,it,oper,xpath,sr_val_to_str(new_value))) {
                                INFO("ike-conn-entry verified");
                            }
                            else {
                                rc = SR_ERR_VALIDATION_FAILED;
                                ERR("Verify ike-conn-entry: %s", sr_strerror(rc));
                                goto cleanup;
                            }
                        }
                    break;
                case SR_OP_DELETED:
                        name = strrchr(old_value->xpath, '/');
                        if (0 == strncmp(token_ike,name,l)) {

                            INFO("Verify ike-conn-entry %s",sr_val_to_str(old_value));
                            strncpy(xpath,old_value->xpath,strlen(old_value->xpath)-l);

                            if (!verifyIKE_conn_entry(session,it,oper,xpath,sr_val_to_str(old_value))) {
                                INFO("ike-conn-entry verified");
                            }
                            else {
                                rc = SR_ERR_VALIDATION_FAILED; 
                                ERR("Verify ike-conn-entry %s", sr_strerror(rc));
                                goto cleanup;
                            }
                        }
                    break;
				case SR_OP_MODIFIED:     
	                DBG("OPERATION MODIFIED not supported: %i",oper);
				case SR_OP_MOVED:     
		            DBG("OPERATION MOVED not supported: %i",oper);
            } //swith
            sr_free_val(old_value);
            sr_free_val(new_value);
        }

        DBG(" ========== FIN READING running CONFIG: ==========");
    }
    else if (SR_EV_APPLY == event) {

        DBG(" ========== APPLY: IKE CHANGES: =============================================");
        rc = sr_get_changes_iter(session, ike_entry_xpath , &it);
        if (SR_ERR_OK != rc) {
            ERR( "Get changes iter failed for xpath %s: %s", ike_entry_xpath,sr_strerror(rc));
            goto cleanup;
        }

        while (SR_ERR_OK == sr_get_change_next(session, it, &oper, &old_value, &new_value)) {

            switch(oper) {
                case SR_OP_CREATED:
                        name = strrchr(new_value->xpath, '/');
                        
                        if (0 == strncmp(token_ike,name,l)) {
                            
                            INFO("Add ike-conn-entry %s",sr_val_to_str(new_value));
                            strncpy(xpath,new_value->xpath,strlen(new_value->xpath)-l);

                            if (!addIKE_conn_entry(session,it,xpath,sr_val_to_str(new_value))) {
                                INFO("ike-conn-entry added");
                            }
                            else {
                                rc = SR_ERR_OPERATION_FAILED;
                                ERR("Add ike-conn-entry: %s", sr_strerror(rc));
                                goto cleanup;
                            }
                        }
                    break;
                case SR_OP_DELETED:
                        name = strrchr(old_value->xpath, '/');
                        if (0 == strncmp(token_ike,name,l)) {

                            INFO("Delete ike-conn-entry %s",sr_val_to_str(old_value));
                            strncpy(xpath,old_value->xpath,strlen(old_value->xpath)-l);

                            if (!removeIKE_conn_entry(session,it,xpath,sr_val_to_str(old_value))) {
                                INFO("ike-conn-entry deleted");
                            }
                            else {
                                rc = SR_ERR_OPERATION_FAILED;   
                                ERR("Delete ike-conn-entry: %s",sr_strerror(rc));
                                goto cleanup;
                            }
                        }
                    break;
				case SR_OP_MODIFIED:     
	                DBG("OPERATION MODIFIED not supported: %i",oper);
				case SR_OP_MOVED:     
		            DBG("OPERATION MOVED not supported: %i",oper);
            } //swith

            sr_free_val(old_value);
            sr_free_val(new_value);
        }
        DBG(" ========== END OF CHANGES =======================================");
    }
cleanup:

    sr_free_change_iter(it);
    return rc;
}

// callbackk for pad-entry element
int
pad_entry_change_cb(sr_session_ctx_t *session, const char *pad_entry_xpath, sr_notif_event_t event, void *private_ctx)
{

    sr_change_iter_t *it = NULL;
    int rc = SR_ERR_OK;
    sr_change_oper_t oper;
    sr_val_t *old_value = NULL;
    sr_val_t *new_value = NULL;
    char * name = NULL;
    char * token_pad = "/pad-entry-id"; 
    int l = strlen(token_pad);
    char xpath[MAX_PATH] = "";  

    DBG(" ========== PAD Notification  %s =============================================", ev_to_str(event));
    if (SR_EV_VERIFY == event) {

        DBG(" ========== VERIFY: PAD-ENTRY HAS CHANGED, CURRENT RUNNING CONFIG: ==========");

        rc = sr_get_changes_iter(session, pad_entry_xpath , &it);
        if (SR_ERR_OK != rc) {
            ERR("Get changes iter failed for xpath %s: %s", pad_entry_xpath, sr_strerror(rc));
            goto cleanup;
        }
        while (SR_ERR_OK == sr_get_change_next(session, it, &oper, &old_value, &new_value)) {
            
            switch(oper) {
                case SR_OP_CREATED:
                        name = strrchr(new_value->xpath, '/');     
                        if (0 == strncmp(token_pad,name,l)) {

                            INFO("Verify pad-entry %s",sr_val_to_str(new_value));
                            strncpy(xpath,new_value->xpath,strlen(new_value->xpath)-l);

                            if (!verifyPAD_entry(session,it,oper,xpath,sr_val_to_str(new_value))) {
                                INFO("pad-entry verified");
                            }
                            else {
                                rc = SR_ERR_VALIDATION_FAILED;
                                ERR("Verify pad-entry: %s",sr_strerror(rc));
                                goto cleanup;
                            }
                        }
                    break;
                case SR_OP_DELETED:
                        name = strrchr(old_value->xpath, '/');
                        if (0 == strncmp(token_pad,name,l)) {

                            INFO("Verify pad-entry %s",sr_val_to_str(old_value));
                            strncpy(xpath,old_value->xpath,strlen(old_value->xpath)-l);

                            if (!verifyPAD_entry(session,it,oper,xpath,sr_val_to_str(old_value))){
                                INFO("pad-entry verified");
                            }
                            else {
                                rc = SR_ERR_VALIDATION_FAILED;
                                ERR("Verify pad-entry: %s",sr_strerror(rc));
                                goto cleanup;
                            }
                        }
                    break;
				case SR_OP_MODIFIED:     
		            DBG("OPERATION MODIFIED not supported: %i",oper);
			    case SR_OP_MOVED:     
			        DBG("OPERATION MOVED not supported: %i",oper);
            } //swith

        sr_free_val(old_value);
        sr_free_val(new_value);
        }
        DBG(" ========== FIN READING running CONFIG: ========== ");
    }
    else if (SR_EV_APPLY == event) {

        DBG(" ========== APPLY: PAD CHANGES: =============================================");
        rc = sr_get_changes_iter(session, pad_entry_xpath , &it);
        if (SR_ERR_OK != rc) {
            ERR("Get changes iter failed for xpath %s: %s", pad_entry_xpath, sr_strerror(rc));
            goto cleanup;
        }
        while (SR_ERR_OK == sr_get_change_next(session, it, &oper, &old_value, &new_value)) {

            switch(oper) {
                case SR_OP_CREATED:
                        name = strrchr(new_value->xpath, '/');
                        if (0 == strncmp(token_pad,name,l)) {

                            INFO("Add pad-entry %s",sr_val_to_str(new_value));
                            strncpy(xpath,new_value->xpath,strlen(new_value->xpath)-l);

                            if (!addPAD_entry(session,it,xpath,sr_val_to_str(new_value))) {
                                INFO("pad-entry added");
                            }
                            else {
                                rc = SR_ERR_OPERATION_FAILED;
                                ERR("Add pad-entry: %s",sr_strerror(rc));
                                goto cleanup;
                            }
                        }
                    break;
                case SR_OP_DELETED:
                        name = strrchr(old_value->xpath, '/');
                        if (0 == strncmp(token_pad,name,l)) {

                            INFO("Delete pad-entry %s",sr_val_to_str(old_value));
                            strncpy(xpath,old_value->xpath,strlen(old_value->xpath)-l);

                            if (!removePAD_entry(session,it,xpath,sr_val_to_str(old_value))){
                                INFO("pad-entry added");
                            }
                            else {
                                rc = SR_ERR_OPERATION_FAILED;
                                ERR("Delete pad-entry: %s",sr_strerror(rc));
                                goto cleanup;                                                        
                            }   
                        }
                    break;
				case SR_OP_MODIFIED:     
		            DBG("OPERATION MODIFIED not supported: %i",oper);
				case SR_OP_MOVED:     
			        DBG("OPERATION MOVED not supported: %i",oper);
            } //swith

            sr_free_val(old_value);
            sr_free_val(new_value);
        }
        DBG("========== END OF CHANGES =======================================");
    }
cleanup:

    sr_free_change_iter(it);
    return rc;
}

// callbackk for sad-entry element
int
sad_entry_change_cb(sr_session_ctx_t *session, const char *sad_entry_xpath, sr_notif_event_t event, void *private_ctx)
{

    sr_change_iter_t *it = NULL;
    int rc = SR_ERR_OK;
    sr_change_oper_t oper;
    sr_val_t *old_value = NULL;
    sr_val_t *new_value = NULL;
    char * name = NULL;
    char * token_spi = "/spi";
    int l = strlen(token_spi);
    char xpath[MAX_PATH] = "";  

    if (SR_EV_VERIFY == event) {

        DBG(" ========== VERIFY: SAD-ENTRY HAS CHANGED, CURRENT RUNNING CONFIG: ==========");

        rc = sr_get_changes_iter(session, sad_entry_xpath , &it);
        if (SR_ERR_OK != rc) {
            ERR("Get changes iter failed for xpath %s: %s", sad_entry_xpath, sr_strerror(rc));
            goto cleanup;
        }
        while (SR_ERR_OK == sr_get_change_next(session, it,&oper, &old_value, &new_value)) {
            switch(oper) {
                case SR_OP_CREATED:
                       name = strrchr(new_value->xpath, '/');
                        if (0 == strncmp(token_spi,name,l)) {

                            INFO("Verify sad-entry %s",sr_val_to_str(new_value));
                            strncpy(xpath,new_value->xpath,strlen(new_value->xpath)-l);

                            if (SR_ERR_OK == verifySAD_entry(session,it,oper,xpath,sr_val_to_str(new_value))) {
                                INFO("sad-entry verified");
                            }
                            else {
                                rc = SR_ERR_VALIDATION_FAILED;
                                ERR("Verify sad-entry: %s",sr_strerror(rc));
                                goto cleanup;
                            }
                        }
                    break;
                case SR_OP_DELETED:
                        name = strrchr(old_value->xpath, '/');
                        if (0 == strncmp(token_spi,name,l)) {

                            INFO("Verify sad-entry %s",sr_val_to_str(old_value));
                            strncpy(xpath,old_value->xpath,strlen(old_value->xpath)-l);

                            if (SR_ERR_OK == verifySAD_entry(session,it,oper,xpath,sr_val_to_str(old_value))) {
                                INFO("sad-entry verified");
                            }
                            else {
                                rc = SR_ERR_VALIDATION_FAILED;
                                ERR("Verify sad-entry: %s",sr_strerror(rc));
                                goto cleanup;
                            }
                        }
                    break; 
				case SR_OP_MODIFIED:     
                	DBG("OPERATION MODIFIED not supported: %i",oper);
				case SR_OP_MOVED:     
	                DBG("OPERATION MOVED not supported: %i",oper);
		
            } //swith
            sr_free_val(old_value);
            sr_free_val(new_value);
        }

        DBG("========== FIN READING running CONFIG: ==========");
    }
    else if (SR_EV_APPLY == event) {

        DBG(" ========== APPLY: SAD CHANGES: =============================================");
        rc = sr_get_changes_iter(session, sad_entry_xpath , &it);
        if (SR_ERR_OK != rc) {
            ERR("Get changes iter failed for xpath %s: %s", sad_entry_xpath, sr_strerror(rc));
            goto cleanup;
        }
        while (SR_ERR_OK == sr_get_change_next(session, it, &oper, &old_value, &new_value)) {

            switch(oper) {
                case SR_OP_CREATED:
                        name = strrchr(new_value->xpath, '/');
                        if (0 == strncmp(token_spi,name,l)) {

                            INFO("Add sad-entry %s",sr_val_to_str(new_value));
                            strncpy(xpath,new_value->xpath,strlen(new_value->xpath)-l);
                            
                            if (SR_ERR_OK == addSAD_entry(session,it,xpath,sr_val_to_str(new_value))) {
                                INFO("sad-entry added");
                            }
                            else {
                                rc = SR_ERR_OPERATION_FAILED;
                                ERR("Add sad-entry: %s",sr_strerror(rc));
                                goto cleanup;
                            }
                        }
                    break;
                case SR_OP_DELETED:
                        name = strrchr(old_value->xpath, '/');
                        if (0 == strncmp(token_spi,name,l)) {
                            
                            INFO("Delete sad-entry %s",sr_val_to_str(old_value));
                            strncpy(xpath,old_value->xpath,strlen(old_value->xpath)-l);

                            if (SR_ERR_OK == removeSAD_entry(session,it,xpath,sr_val_to_str(old_value))){
                                INFO("sad-entry deleted");
                            }
                            else {
                                rc = SR_ERR_OPERATION_FAILED;
                                ERR("Delete sad-entry: %s",sr_strerror(rc));
                                goto cleanup;
                            }
                        }
                    break;
				case SR_OP_MODIFIED:     
	                DBG("OPERATION MODIFIED not supported: %i",oper);
				case SR_OP_MOVED:     
		            DBG("OPERATION MOVED not supported: %i",oper);
            } //swith

            sr_free_val(old_value);
            sr_free_val(new_value);
        }

        DBG(" ========== END OF CHANGES =======================================");
        }
cleanup:

    sr_free_change_iter(it);
    return rc;
}


// callback for spd-entry changes
int
spd_entry_change_cb(sr_session_ctx_t *session, const char *spd_entry_xpath, sr_notif_event_t event, void *private_ctx)
{

    sr_change_iter_t *it = NULL;
    int rc = SR_ERR_OK;
    sr_change_oper_t oper;
    sr_val_t *old_value = NULL;
    sr_val_t *new_value = NULL;
    char * name = NULL;
    char * token_rn = "/rule-number";
    int l = strlen(token_rn);   
    char xpath[MAX_PATH] = "";  


    // Verify event takes place just before changes are applied in datastores 
    if (SR_EV_VERIFY == event) {

        DBG(" ========== VERIFY: SPD-ENTRY HAS CHANGED ========== ");

        // create iterator to get every change in the datastore
        rc = sr_get_changes_iter(session, spd_entry_xpath , &it);
        if (SR_ERR_OK != rc) {
                ERR("Get changes iter failed for xpath %s: %s", spd_entry_xpath, sr_strerror(rc));
                goto cleanup;
        }
        // while there are xml elements
        while (SR_ERR_OK == sr_get_change_next(session, it, &oper, &old_value, &new_value)) {
            switch(oper) {

                // the change can be to CREATE o to DELETE the element
                case SR_OP_CREATED:
                        name = strrchr(new_value->xpath, '/');
                        if (0 == strncmp(token_rn,name,l)) {

                            INFO("Verify spd-entry %s",sr_val_to_str(new_value));
                            strncpy(xpath,new_value->xpath,strlen(new_value->xpath)-l);
                            if (SR_ERR_OK == verifySPD_entry(session,it,oper,xpath,sr_val_to_str(new_value),feature_case_value)) {
                                INFO("spd-entry verified");
                            }
                            else {  
                                rc = SR_ERR_VALIDATION_FAILED;
                                ERR("Verify spd-entry:%s",sr_strerror(rc));
                                goto cleanup;
                            }
                        }
                    break;
                case SR_OP_DELETED:
                        name = strrchr(old_value->xpath, '/');
                        if (0 == strncmp(token_rn,name,l)) {

                            INFO("Verify spd-entry %s",sr_val_to_str(old_value));
                            strncpy(xpath,old_value->xpath,strlen(old_value->xpath)-l);

                            if (SR_ERR_OK == verifySPD_entry(session,it,oper,xpath,sr_val_to_str(old_value),feature_case_value)) {
                                INFO("spd-entry verified");
                            }
                            else {
                                rc = SR_ERR_VALIDATION_FAILED;
                                ERR("Verify spd-entry:%s",sr_strerror(rc));
                                goto cleanup;
                            }
                        }
                    break;
				case SR_OP_MODIFIED:     
			        DBG("OPERATION MODIFIED not supported: %i",oper);
			    case SR_OP_MOVED:     
				    DBG("OPERATION MOVED not supported: %i",oper);
            } //swith
        sr_free_val(old_value);
        sr_free_val(new_value);

        }
        DBG(" ========== FIN READING running CONFIG: ==========");
    }
    else if (SR_EV_APPLY == event) {

        DBG(" ========== APPLY: SPD CHANGES: =============================================");

        rc = sr_get_changes_iter(session, spd_entry_xpath , &it);
        if (SR_ERR_OK != rc) {
            ERR( "Get changes iter failed for xpath %s: %s", spd_entry_xpath, sr_strerror(rc));
            goto cleanup;
        }

        while (SR_ERR_OK == sr_get_change_next(session, it, &oper, &old_value, &new_value)) {

            switch(oper) {
                // only CREATED and DELETED supported
                case SR_OP_CREATED:
                        // get the last element of xpath behind the / and compare whether it is the list "index" 
                        name = strrchr(new_value->xpath, '/');
                        if (0 == strncmp(token_rn,name,l)) {
                            

                            // if a new SPD-entry has been found (by index),
                            // then compose the xpath for that SPD-entry.
                            // that is because in case several SPD-entrys, the change list include all elements, not only the changes 
                            // of a specific SPD-entry, so we have to locate the changes for each SPD-entry and apply each SPD-entry independetly   
                            INFO("Add spd-entry %s",sr_val_to_str(new_value));                  
                            strncpy(xpath,new_value->xpath,strlen(new_value->xpath)-l);
    
                            // this function differenciates case 1 and case 2.
                            // In case 1, the SPD and PAD configuration values are stored in a struct element (the kernel is not modified), and later
                            // used by IKE
                            // In case 2, the SPD configuration values are applied into the kernel by means of pfkey_v2 or xfrm
                            if (SR_ERR_OK == addSPD_entry(session,it,xpath,sr_val_to_str(new_value),feature_case_value)) {
                                INFO("spd-entry added ");
                            }
                            else {
                                rc = SR_ERR_OPERATION_FAILED;
                                ERR("Adding spd-entry: %s",sr_strerror(rc));
                                goto cleanup;                               
                            } 
                        }
                    break;
                case SR_OP_DELETED:
                        name = strrchr(old_value->xpath, '/');
                        if (0 == strncmp(token_rn,name,l)) {

                            strncpy(xpath,old_value->xpath,strlen(old_value->xpath)-l);
                            INFO("Delete spd-entry %s",xpath);

                            if (SR_ERR_OK == removeSPD_entry(session,it,xpath,sr_val_to_str(old_value),feature_case_value)) {
                                INFO("spd-entry deleted");
                            }
                            else {
                                rc = SR_ERR_OPERATION_FAILED;
                                ERR("Deleting spd-entry: %s",sr_strerror(rc));
                                goto cleanup;
                            }
                          }
                    break;
				case SR_OP_MODIFIED:     
			        DBG("OPERATION MODIFIED not supported: %i",oper);
				case SR_OP_MOVED:     
				    DBG("OPERATION MOVED not supported: %i",oper);
            } //swith
                                
            sr_free_val(old_value);
            sr_free_val(new_value);
        } 
    
        DBG(" ========== END OF CHANGES =======================================");
    }
cleanup:

    sr_free_change_iter(it);
    return rc;
}


// callbackk for sad_register mmessages
int
rpc_sadb_register_cb(const char *xpath, const sr_val_t *input, const size_t input_cnt,
 sr_val_t **output, size_t *output_cnt, void *private_ctx) {

    int version;
    int type;
    int satype = 0;
    char *name =NULL;

    INFO("SADB REGISTER RECEIVED");

    sr_session_ctx_t *session = (sr_session_ctx_t *)private_ctx;

    int i = 0;
    
    for (i = 0; i < input_cnt; i++) {   
        name = strrchr(input[i].xpath, '/');

        if (0 == strcmp (name,"/version")) {
            DBG ("input data: %s", input[i].data.string_val);
            if(0 == strcmp(input[i].data.string_val,"PF_KEY_V2")) {
                version = PF_KEY_V2;
                DBG("version: %i",version);
            }
            else {
                ERR("Register apply, bad version");
                return EXIT_FAILURE;
            };
        }
        else if (0 == strcmp (name,"/msg_type")) {
            if(0 == strcmp(input[i].data.string_val,"sadb_register")) {
                type = SADB_REGISTER;
                DBG("type: %i",type);
            }
            else {
                ERR("Register apply, bad msg type");
                return EXIT_FAILURE;
            };      
        }
        else if (0 == strcmp (name,"/msg_satype")) {
            satype = pf_get_satype_define(input[i].data.enum_val);
            if ((satype == SADB_SATYPE_ESP) ||  (satype == SADB_SATYPE_AH)) {  
                DBG("satype : %i",satype);
            }
            else {
                ERR("Register apply, bad msg type");
                return EXIT_FAILURE;
            };
        }
    }
    
    if (session == NULL) {
        ERR("sadb_register received but session NULL: %s",sr_strerror(SR_ERR_INTERNAL));
        return SR_ERR_INTERNAL;
    }

    if (pf_exec_register(session, xpath, satype, input,input_cnt,output,output_cnt,private_ctx)) {
        ERR("sadb_register in exec_register: %s",sr_strerror(SR_ERR_INTERNAL));
        sr_free_val(input);
        return SR_ERR_INTERNAL;
    }
    
cleanup:
    sr_free_val(input);
    return SR_ERR_OK;
}

// callbackk for sad_lifetime_current element
int 
sad_lifetime_current_cb(const char *xpath, sr_val_t **values, size_t *values_cnt, void *private_ctx) {

    int rc;
    
    rc = get_sad_lifetime_current(xpath, values, values_cnt, private_ctx);
    if (SR_ERR_OK != rc) {
        ERR("sad_lifetime_current_cb: %s", sr_strerror(rc));
        return rc;
    }

    return SR_ERR_OK;

}

// callbackk for sad_stats element
int
sad_stats_cb(const char *xpath, sr_val_t **values, size_t *values_cnt, void *private_ctx) {

    int rc;

    rc = get_sad_stats(xpath, values, values_cnt, private_ctx);
    if (SR_ERR_OK != rc) {
        ERR("sad_stats_cb: %s", sr_strerror(rc));
        return rc;
    }

    return SR_ERR_OK;

}


// callbackk for spd_lifetime element
int
spd_lifetime_current_cb(const char *xpath, sr_val_t **values, size_t *values_cnt, void *private_ctx) {

    int rc;

    rc = get_spd_lifetime_current(xpath, values, values_cnt, private_ctx);
    if (SR_ERR_OK != rc) {
        ERR("spd_lifetime_current_cb: %s", sr_strerror(rc));
        return rc;
    }
    
    return SR_ERR_OK;

}


// sad register invocation
rpc_register_caller(sr_session_ctx_t *session, int satype) {

    sr_val_t *input = NULL, *output = NULL;
    size_t output_cnt = 0, input_cnt = 0;
    int rc = SR_ERR_OK;

    DBG ("Enter rpc_register_caller: ");

    /*<sadb_register xmlns="http://example.net/ietf-ipsec">
        <base-list>
            <version>PF_KEY_V2</version>
            <msg_type>sadb_register</msg_type>
            <msg_satype>sadb_satype_esp</msg_satype>
            <msg_seq>0</msg_seq>
        </base-list>
    </sadb_register>*/

    input_cnt = 4;
    rc = sr_new_values(input_cnt, &input);
    if (SR_ERR_OK != rc) {
        return rc;
    }

    rc = sr_val_set_xpath(&input[0], "/ietf-ipsec:sadb_register/base-list[version='PF_KEY_V2']/version");
    if (SR_ERR_OK != rc) {
        return rc;
    }
    input[0].type = SR_STRING_T;
    input[0].data.string_val = "PF_KEY_V2";

    rc = sr_val_set_xpath(&input[1], "/ietf-ipsec:sadb_register/base-list[version='PF_KEY_V2']/msg_type");
    if (SR_ERR_OK != rc) {
        return rc;
    }
    input[1].type = SR_ENUM_T;
    input[1].data.enum_val = "sadb_register";

    rc = sr_val_set_xpath(&input[2], "/ietf-ipsec:sadb_register/base-list[version='PF_KEY_V2']/msg_satype");
    if (SR_ERR_OK != rc) {
        return rc;
    }
    input[2].type = SR_ENUM_T;
    if (satype == SADB_SATYPE_ESP) {
        DBG("rpc_register_caller: %i", SADB_SATYPE_ESP);
        input[2].data.enum_val = "sadb_satype_esp";
    }
    else if (satype == SADB_SATYPE_AH) {
        input[2].data.enum_val = "sadb_satype_ah";
    }
    
    rc = sr_val_set_xpath(&input[3], "/ietf-ipsec:sadb_register/base-list[version='PF_KEY_V2']/msg_seq");
    if (SR_ERR_OK != rc) {
        return rc;
    }
    input[3].type = SR_UINT32_T;
    input[3].data.uint32_val = 0;

    DBG("RPC register inputs values:");
    if (get_verbose_level() >= CI_VERB_DEBUG) {
        for (size_t i = 0; i < input_cnt; ++i) {
            sr_print_val(&input[i]);
        }
    }

    DBG("RPC register send ...");
    rc = sr_rpc_send(session, "/ietf-ipsec:sadb_register", input, input_cnt, &output, &output_cnt);
    if (SR_ERR_OK != rc) {
        ERR("RPC send error: %i",rc);
        return rc;
    }

    DBG(">>> Received an RPC response:");
    if (get_verbose_level() >= CI_VERB_DEBUG) {
        for (size_t i = 0; i < output_cnt; ++i) {
            sr_print_val(output+i);
        }
    }
    
    sr_free_values(output, output_cnt);
    
    return SR_ERR_OK;
}

