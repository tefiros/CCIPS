#include "messages.h"



int get_message(char *data, default_msg* msg) {
    JSON_Object *schema = json_object(json_parse_string(data));
    msg->work_id = json_object_get_number(schema,"work_id");
    msg->code = json_object_get_number(schema,"code");
    msg->data = json_object_get_object(schema,"data");
    json_value_free(schema);
    return 0;
}

char *create_message(int work_id, int code, JSON_Value *data) {
    JSON_Value *root_value = json_value_init_object();
    JSON_Object *root_object = json_value_get_object(root_value);
    json_object_set_number(root_object, "work_id", work_id);
    json_object_set_number(root_object, "code", code);
    json_object_set_value(root_object, "data", data);
    return json_serialize_to_string_pretty(root_value);
}


int decode_new_config_msg(JSON_Object *schema, new_config_msg *msg) {
    int entries_id = json_object_get_number(schema,"entries_id");
    msg->entries_id = entries_id;
    // Extract array
    JSON_Array *entries_array = json_object_get_array(schema,"sad_entries");
    int n_elements = json_array_get_count(entries_array);

    int i = 0;
    for (i = 0; i < n_elements; i++) {
        msg->sad_entries[i] = deserialize_sad_node(json_array_get_object(entries_array,i));
    }
    json_value_free(schema);
    return 0;
}

JSON_Value *encode_new_config_msg(new_config_msg *msg) {
    JSON_Value *root_value = json_value_init_object();
    JSON_Object *root_object = json_value_get_object(root_value);
    json_object_set_number(root_object,"entries_id",msg->entries_id);
    json_object_set_value(root_object, "sad_entries", json_value_init_array());
    JSON_Array *entries_array = json_object_get_array(root_object,"sad_entries");
    int i = 0;
    for (i = 0; i < 2; i++) {
        json_array_append_value(entries_array,serialize_sad_node(msg->sad_entries[i]));
    }
    json_object_set_value(root_object,"sad_entries",entries_array);
    return root_value;
}

int decode_delete_config_msg(JSON_Object *schema, delete_config_msg *msg) {
    int entries_id = json_object_get_number(schema,"entries_id");
    msg->entries_id = entries_id;
    json_value_free(schema);
    return 0;
}

JSON_Value *encode_delete_config_msg(delete_config_msg *msg) {
    JSON_Value *root_value = json_value_init_object();
    JSON_Object *root_object = json_value_get_object(root_value);
    json_object_set_number(root_object,"entries_id",msg->entries_id);
    return root_value;
}

int decode_alert_state_msg(JSON_Object *schema, alert_state_msg *msg) {
    int entries_id = json_object_get_number(schema,"entries_id");
    msg->entries_id = entries_id;
    strcpy(msg->message,json_object_get_string(schema,"message"));
    json_value_free(schema);
    return 0;
}

JSON_Value *encode_alert_state_msg(alert_state_msg *msg) {
    JSON_Value *root_value = json_value_init_object();
    JSON_Object *root_object = json_value_get_object(root_value);
    json_object_set_number(root_object,"entries_id",msg->entries_id);
    json_object_set_string(root_object,"message",msg->message);
    return root_value;
}


int decode_op_result_msg(JSON_Object *schema, op_result_msg *msg) {
    msg->success = json_object_get_number(schema,"success");
    strcpy(msg->message,json_object_get_string(schema,"message"));
    json_value_free(schema);
    return 0;
}

JSON_Value *encode_op_result_msg(op_result_msg *msg) {
    JSON_Value *root_value = json_value_init_object();
    JSON_Object *root_object = json_value_get_object(root_value);
    json_object_set_number(root_object,"success",msg->success);
    json_object_set_string(root_object,"message",msg->message);
    return root_value;
}

int decode_request_entries_msg(JSON_Object *schema, request_entries_msg *msg) {
    msg->entries_id = json_object_get_number(schema,"entries_id");
    json_value_free(schema);
    return 0;
}

JSON_Value *encode_request_entries_msg(request_entries_msg *msg) {
    JSON_Value *root_value = json_value_init_object();
    JSON_Object *root_object = json_value_get_object(root_value);
    json_object_set_number(root_object,"entries_id",msg->entries_id);
    return root_value;
}
