#include "trust_client.h"
#include "trust_handler.h"


int ENARX_SOCKET;

int connect_ta() {
    ENARX_SOCKET = socket(AF_INET, SOCK_STREAM, 0);
    if (ENARX_SOCKET < 0) {
        ERR("socket connection to enarx failed");
        return 1;
    }

    // TODO set this so it can be changed 
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    server_addr.sin_port = htons(10000);

    // Connect to the Enarx APP
    // TODO lookup for the code to establish the channel with the TLS 
    if (connect(ENARX_SOCKET, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        ERR("Connection failed, make sure the Enarx up is running");
        return 1;
    }

    // Read the hello message of the server
    char buffer[2048] = {0};
    if (recv(ENARX_SOCKET, buffer, 2048, 0) < 0) {
        ERR("first recv failed");
        return 1;
    }
    return 0;
}

int disconnect_ta() {
    if (close(ENARX_SOCKET) != 0) {
        ERR("Error when disconnecting from the server");
        return 1;
    }
}

int add_trusted_sad_entry(sad_entry_node *new_sad, sad_entry_node *old_sad) {
    sad_entry_msg *message = (sad_entry_msg*) malloc(sizeof(sad_entry_msg)); 
    message->sad_entry =  old_sad;
    JSON_Value *new_conf_msg = encode_sad_entry_msg(message);
    char *serialized_msg = encode_default_msg(10,NEW_CONFIG_MSG,new_conf_msg);
    int result = 1;

    if (send(ENARX_SOCKET, serialized_msg, strlen(serialized_msg), 0) < 0) {
        ERR("Couldnt send any information to the server");
        free(message);
        free(serialized_msg);
        return result;
    }

    char buffer2[2048] = {0};
    if (recv(ENARX_SOCKET, buffer2, 2048, 0) < 0) {
        ERR("Couldnt receive any information from the server");
        free(message);
        free(serialized_msg);
        return result;
    }

    
    default_msg *msg = malloc(sizeof(default_msg));
    JSON_Object *schema = json_object(json_parse_string(buffer2));
    if (schema == NULL) {
        result = 1;
        goto cleanup;
    }

    if (schema == NULL || decode_default_msg(schema, msg) != 0) {
        // TODO handle error of decode_default
        goto cleanup;
    }

    sad_entry_msg *entry_msg = (sad_entry_msg*) malloc(sizeof(sad_entry_msg)); 
    switch (msg->code) {
        case INSERT_ENTRY_MSG: {
            sad_entry_msg *entry_msg = (sad_entry_msg*) malloc(sizeof(sad_entry_msg)); 
            if ((result = decode_sad_entry_msg(msg->data,entry_msg)), result != 0) {
                goto cleanup;
            }
            copy_sad_node(new_sad, entry_msg->sad_entry);
            free_sad_node(entry_msg->sad_entry);
            free(entry_msg);
            break;
        }
        case OP_RESULT_MSG: {
            op_result_msg *op_result = (op_result_msg*) malloc(sizeof(op_result_msg)); 
            if (decode_op_result_msg(msg->data, op_result) != 0) {
                goto cleanup;
            }
            if (op_result->success != 0) {
                ERR("Error when adding: %s\n",op_result->message);
                free(op_result);
                goto cleanup;
            }
            break;
        }
        default: {
            ERR("Message type not found");
            goto cleanup;
        }
    }
    result = 0;
    cleanup:
        free(message);
        free(msg);
        free(serialized_msg);
        json_object_clear(schema);
        free(schema);
        json_value_free(new_conf_msg);
        return result;
}

int verify_trusted_sad_entry(char *alert, sad_entry_node *sad_node) {
    sad_entry_msg *message = (sad_entry_msg*) malloc(sizeof(sad_entry_msg)); 
    message->sad_entry =  sad_node;
    JSON_Value *verify_entry = encode_sad_entry_msg(message);
    char *serialized_msg = encode_default_msg(10,REQUEST_VERIFY_MSG,verify_entry);
    int result = 1;

    if (send(ENARX_SOCKET, serialized_msg, strlen(serialized_msg), 0) < 0) {
        ERR("Couldnt send any information to the server");
        goto cleanup;
    }

    char buffer2[2048] = {0};
    if (recv(ENARX_SOCKET, buffer2, 2048, 0) < 0) {
        ERR("Couldnt receive any information from the server");
        goto cleanup;
    }

    default_msg *msg = malloc(sizeof(default_msg));
    JSON_Object *schema = json_object(json_parse_string(buffer2));
    if (schema == NULL) {
        result = 1;
        goto cleanup;
    }

    if (schema == NULL || decode_default_msg(schema, msg) != 0) {
        // TODO handle error of decode_default
        goto cleanup;
    }
    switch (msg->code) {
        case ALERT_STATE_MSG: {
            alert_state_msg *alert_msg = (alert_state_msg*) malloc(sizeof(alert_state_msg)); 
            alert_msg->entry_id = (char *) malloc(sizeof(char) * MAX_PATH);
            if ((result = decode_alert_state_msg(msg->data, alert_msg)), result == 0) {
                strcpy(alert, alert_msg->message);
                result = 2;
            }
            free(alert_msg);
            goto cleanup;
        }
        case OP_RESULT_MSG: {
            op_result_msg *op_result = (op_result_msg*) malloc(sizeof(op_result_msg)); 
            if (decode_op_result_msg(msg->data, op_result) != 0) {
                goto cleanup;
            }
            if (op_result->success != 0) {
                // ERR("Error when verifying: %s\n",op_result->message);
                strcpy(alert,"TA could not verify");
                free(op_result);
                result = 3;
                goto cleanup;
            }
            break;
            DBG("Verification successful");
        }
        default: {
            ERR("Message type not found");
            strcpy(alert,"Message type found");
            result = 3;
            goto cleanup;
        }
    }
    result = 0;
    cleanup:
        free(message);
        free(msg);
        free(serialized_msg);
        json_object_clear(schema);
        free(schema);
        json_value_free(verify_entry);
        return result;
}

int del_trusted_sad_entry(char *sad_name) {
    delete_config_msg *message = (delete_config_msg*) malloc(sizeof(delete_config_msg));
    message->entry_id = (char *) malloc(sizeof(char) * MAX_PATH);
    strcpy(message->entry_id,sad_name);
    int result = 1;
    JSON_Value *delete_msg =  encode_delete_config_msg(message);
    char *serialized_msg = encode_default_msg(10,DELETE_CONFIG_MSG,delete_msg);

    if (send(ENARX_SOCKET, serialized_msg, strlen(serialized_msg), 0) < 0) {
        ERR("Couldnt send any information to the server");
        free(message);
        free(serialized_msg);
        json_value_free(delete_msg);
        return result;
    }

    char bufferAnswer[1024] = {0};
    if (recv(ENARX_SOCKET, bufferAnswer, 1024, 0) < 0) {
        ERR("Couldnt receive any information from the server");
        free(message);
        free(serialized_msg);
        json_value_free(delete_msg);
        return result;
    }



    default_msg *msg = malloc(sizeof(default_msg));
    JSON_Object *schema = json_object(json_parse_string(bufferAnswer));
    op_result_msg *op_result = (op_result_msg*) malloc(sizeof(op_result_msg));
    if (schema == NULL) {
        result = 1;
        goto cleanup;
    }

    if (schema == NULL || decode_default_msg(schema, msg) != 0) {
        // TODO handle error of decode_default
        goto cleanup;
    }

    // Check if the message is type of operation
    if (msg->code != OP_RESULT_MSG) { 
        ERR("Message type not found");
        goto cleanup;
    }

    // Check that we can decode the message
    if ((result = decode_op_result_msg(msg->data, op_result)), result != 0) {
        goto cleanup;
    }

    if (op_result->success != 0) {
        ERR("Error when deleting the sad entry %s : %s\n",message->entry_id, op_result->message);
        // free(op_result);
        goto cleanup;
    }

    result = 0;
    cleanup:
        free(message);
        free(msg);
        free(op_result);
        free(serialized_msg);
        json_object_clear(schema);
        free(schema);
        // free(delete_msg);
        return result;
}

int add_trusted_spd_entry(spd_entry_node *new_spd, spd_entry_node *old_spd) {
    spd_entry_msg *message = (spd_entry_msg*) malloc(sizeof(spd_entry_msg)); 
    message->spd_entry =  old_spd;
    JSON_Value *new_spd_conf_msg = encode_spd_entry_msg(message);
    char *serialized_msg = encode_default_msg(10,NEW_SPD_CONFIG_MSG,new_spd_conf_msg);
    int result = 1;
    if (send(ENARX_SOCKET, serialized_msg, strlen(serialized_msg), 0) < 0) {
        ERR("Couldnt send any information to the server");
        free(message);
        json_free_serialized_string(serialized_msg);
        return result;
    }
    char buffer2[2048] = {0};
    if (recv(ENARX_SOCKET, buffer2, 2048, 0) < 0) {
        ERR("Couldnt receive any information from the server");
        free(message);
        json_free_serialized_string(serialized_msg);
        return result;
    }

    default_msg *msg = malloc(sizeof(default_msg));
    JSON_Value *parsed_resp = json_parse_string(buffer2);
    JSON_Object *schema = json_object(parsed_resp);
    if (schema == NULL) {
        result = 1;
        goto cleanup;
    }

    if (schema == NULL || decode_default_msg(schema, msg) != 0) {
        // TODO handle error of decode_default
        goto cleanup;
    }
 
    switch (msg->code) {
        case INSERT_SPD_ENTRY_MSG: {
            spd_entry_msg *entry_msg = (spd_entry_msg*) malloc(sizeof(spd_entry_msg)); 
            if ((result = decode_spd_entry_msg(msg->data,entry_msg)), result != 0) {
                free(entry_msg);
                goto cleanup;
            }
            //copy_spd_node(new_spd, entry_msg->spd_entry);
	        memcpy(new_spd,entry_msg->spd_entry,sizeof(spd_entry_node));
            free_spd_node(entry_msg->spd_entry);
            free(entry_msg);
            break;
        }
        case OP_RESULT_MSG: {
            op_result_msg *op_result = (op_result_msg*) malloc(sizeof(op_result_msg)); 
            if (decode_op_result_msg(msg->data, op_result) != 0) {
                free(op_result);
                goto cleanup;
            }
            if (op_result->success != 0) {
                ERR("Error when adding: %s\n",op_result->message);
                free(op_result);
                goto cleanup;
            }
            free(op_result);
            break;
        }
        default: {
            ERR("Message type not found");
            goto cleanup;
        }
    }
    result = 0;
    cleanup:
        free(message);
        free(msg);
        json_free_serialized_string(serialized_msg);
        json_value_free(parsed_resp);
        return result;
}

int verify_trusted_spd_entry(char *alert, spd_entry_node *spd_node) {
    spd_entry_msg *message = (spd_entry_msg*) malloc(sizeof(spd_entry_msg)); 
    message->spd_entry =  spd_node;
    JSON_Value *verify_entry = encode_spd_entry_msg(message);
    char *serialized_msg = encode_default_msg(10,REQUEST_VERIFY_MSG,verify_entry);
    int result = 1;

    if (send(ENARX_SOCKET, serialized_msg, strlen(serialized_msg), 0) < 0) {
        ERR("Couldnt send any information to the server");
        goto cleanup; // some variables may not be declared
    }

    char buffer2[2048] = {0};
    if (recv(ENARX_SOCKET, buffer2, 2048, 0) < 0) {
        ERR("Couldnt receive any information from the server");
        goto cleanup; // some variables may not be declared
    }

    default_msg *msg = malloc(sizeof(default_msg));
    JSON_Value *parsed_resp = json_parse_string(buffer2);
    JSON_Object *schema = json_object(parsed_resp);
    if (schema == NULL) {
        result = 1;
        goto cleanup;
    }

    if (schema == NULL || decode_default_msg(schema, msg) != 0) {
        // TODO handle error of decode_default
        goto cleanup;
    }
    switch (msg->code) {
        case ALERT_STATE_MSG: {
            alert_state_msg *alert_msg = (alert_state_msg*) malloc(sizeof(alert_state_msg)); 
            alert_msg->entry_id = (char *) malloc(sizeof(char) * MAX_PATH);
            if ((result = decode_alert_state_msg(msg->data, alert_msg)), result == 0) {
                strcpy(alert, alert_msg->message);
                result = 2;
            }
            free(alert_msg->entry_id);
            free(alert_msg);
            goto cleanup;
        }
        case OP_RESULT_MSG: {
            op_result_msg *op_result = (op_result_msg*) malloc(sizeof(op_result_msg)); 
            if (decode_op_result_msg(msg->data, op_result) != 0) {
                free(op_result);
                goto cleanup;
            }
            if (op_result->success != 0) {
                // ERR("Error when verifying: %s\n",op_result->message);
                strcpy(alert,"TA could not verify");
                free(op_result);
                result = 3;
                goto cleanup;
            }
            free(op_result);
            DBG("Verification successful");
            break;
        }
        default: {
            ERR("Message type not found");
            strcpy(alert,"Message type found");
            result = 3;
            goto cleanup;
        }
    }
    result = 0;
    cleanup:
        free(message);
        free(msg);
        json_free_serialized_string(serialized_msg);
        json_value_free(parsed_resp);
        return result;
}

int del_trusted_spd_entry(char *spd_name) {
    // delete_config_msg is for both sad and spd
    delete_config_msg *message = (delete_config_msg*) malloc(sizeof(delete_config_msg));
    message->entry_id = (char *) malloc(sizeof(char) * MAX_PATH);
    strcpy(message->entry_id,spd_name);
    int result = 1;
    JSON_Value *delete_msg =  encode_delete_config_msg(message); // same as sad
    char *serialized_msg = encode_default_msg(13,DELETE_SPD_CONFIG_MSG,delete_msg);

    if (send(ENARX_SOCKET, serialized_msg, strlen(serialized_msg), 0) < 0) {
        ERR("Couldnt send any information to the server");
        free(message->entry_id);
        free(message);
        json_free_serialized_string(serialized_msg);
        return result;
    }

    char bufferAnswer[1024] = {0};
    if (recv(ENARX_SOCKET, bufferAnswer, 1024, 0) < 0) {
        ERR("Couldnt receive any information from the server");
        free(message->entry_id);
        free(message);
        json_free_serialized_string(serialized_msg);
        return result;
    }



    default_msg *msg = malloc(sizeof(default_msg));
    JSON_Value *parsed_resp = json_parse_string(bufferAnswer);
    JSON_Object *schema = json_object(parsed_resp);
    op_result_msg *op_result = (op_result_msg*) malloc(sizeof(op_result_msg));
    if (schema == NULL) {
        result = 1;
        goto cleanup;
    }

    if (schema == NULL || decode_default_msg(schema, msg) != 0) {
        // TODO handle error of decode_default
        goto cleanup;
    }

    // Check if the message is type of operation
    if (msg->code != OP_SPD_RESULT_MSG) { 
        ERR("Message type not found");
        goto cleanup;
    }

    // Check that we can decode the message
    if ((result = decode_op_result_msg(msg->data, op_result)), result != 0) {
        goto cleanup;
    }

    if (op_result->success != 0) {
        ERR("Error when deleting the spd entry %s : %s\n",message->entry_id, op_result->message);
        goto cleanup;
    }

    result = 0;
    cleanup:
        free(message->entry_id);
        free(message);
        free(msg);
        free(op_result);
        json_free_serialized_string(serialized_msg);
        json_value_free(parsed_resp);
        return result;
}
