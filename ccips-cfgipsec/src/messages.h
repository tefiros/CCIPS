#ifndef __MESSAGES
#define __MESSAGES

#include "parson.h"
#include "sad_entry.h"`




#define NEW_CONFIG_MSG          1 
#define DELETE_CONFIG_MSG       2
#define ALERT_STATE_MSG         3
#define OP_RESULT_MSG           4
#define REQUEST_ENTRIES_MSG     5
#define INSERT_ENTRIES_MSG      6
#define RETURN_ENTRIES_MSG      7 

// default_msg Message format used to share information between the nodes
typedef struct default_msg {
    int work_id;
    int code;
    JSON_Object *data;
} default_msg;

// new_config_msg Message used to share the new spa_entries to the trusted part
typedef struct new_config_msg {
    int entries_id;
    sad_entry_node *sad_entries[2];
} new_config_msg;

// delet_config_msg Message used to delete a set of entries from the trusted part.
typedef struct delete_config_msg {
    int entries_id;
} delete_config_msg;

// alert_state_msg
typedef struct alert_state_msg {
    int entries_id;
    char *message;
} alert_state_msg;

// op_result_mgs;
typedef struct op_result_msg {
    int success; // 0 Success / 1 Fail
    char *message;
} op_result_msg;

// request_entries_msg
typedef struct request_entries_msg {
    int entries_id;
} request_entries_msg;

typedef struct insert_entries_msg 
{
    int entries_id;
    sad_entry_node *sad_entries[2];
} insert_entries_msg;




int get_message(char *data, default_msg* msg);
char *create_message(int work_id, int code, JSON_Value *data);


// Functions called to decode the messages

int decode_new_config_msg(JSON_Object *schema, new_config_msg *msg);
int decode_delete_config_msg(JSON_Object *schema, delete_config_msg *msg);
int decode_alert_state_msg(JSON_Object *schema, alert_state_msg *msg);
int decode_op_result_msg(JSON_Object *schema, op_result_msg *msg);
int decode_request_entries_msg(JSON_Object *schema, request_entries_msg *msg);
int decode_insert_entries_msg(JSON_Object *schema, insert_entries_msg *msg);

// Functions to decode the messages

JSON_Value *encode_new_config_msg(new_config_msg *msg);
JSON_Value *encode_delete_config_msg(delete_config_msg *msg);
JSON_Value *encode_alert_state_msg(alert_state_msg *msg);
JSON_Value *encode_op_result_msg(op_result_msg *msg);
JSON_Value *encode_request_entries_msg(request_entries_msg *msg);
JSON_Value *encode_insert_entries_msg(insert_entries_msg *msg);




#endif