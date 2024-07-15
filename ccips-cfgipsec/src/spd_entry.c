#include "spd_entry.h"
#define MAX_PATH  200
#define MAX_IP 40
#define MAX_KEY 1024
#define MAX_ID_LENGTH  MAX_PATH  +  MAX_IP * 4


spd_entry_node* create_spd_node(){
    spd_entry_node *spd_node = (spd_entry_node*) malloc(sizeof(spd_entry_node));
	spd_node->name = (char *) malloc(sizeof(char) * MAX_PATH);
	spd_node->index = 0;
	spd_node->policy_dir = 0;
	spd_node->req_id = 0;
	spd_node->anti_replay_window = 0; 
	spd_node->local_subnet = (char *) malloc(sizeof(char) * MAX_IP); 
	spd_node->remote_subnet = (char *) malloc(sizeof(char) * MAX_IP); 
	spd_node->tunnel_local = (char *) malloc(sizeof(char) * MAX_IP); 
	spd_node->tunnel_remote = (char *) malloc(sizeof(char) * MAX_IP); 
	spd_node->inner_protocol = 0;
	spd_node->pfp_flag =false; //take off?
	spd_node->srcport = 0; 
	spd_node->dstport = 0;
	spd_node->action = 0;
	spd_node->seq_overflow = false;
	spd_node->ipsec_mode = 0;
	spd_node->protocol_parameters = 0;
	spd_node->integrity_alg = 0;
	spd_node->encryption_alg = 0;
	spd_node->encryption_key = (char *) malloc(sizeof(char) * MAX_KEY); 
	spd_node->integrity_key = (char *) malloc(sizeof(char) * MAX_KEY); 
	spd_node->encryption_iv = (char *) malloc(sizeof(char) * MAX_KEY); 
	spd_node->stateful_frag_check = false;
	spd_node->bypass_dscp = false;
	spd_node->ecn = false;
	spd_node->tfc_pad = false;
	spd_node->df_bit = 0;
    spd_node->next=NULL;
    
    return spd_node;

}


#ifdef Trusted

// https://github.com/kgabis/parson
JSON_Value *serialize_spd_node(spd_entry_node *spd_node) {
    JSON_Value *root_value = json_value_init_object();
    JSON_Object *root_object = 	json_value_get_object(root_value);
    char *serialized_string = NULL;

    // Initial vals
    json_object_set_string(root_object, "name", spd_node->name);
    json_object_set_number(root_object, "index", spd_node->index);
    json_object_set_number(root_object, "policy_dir", spd_node->policy_dir);
    json_object_set_number(root_object, "req_id", spd_node->req_id);
    json_object_set_string(root_object, "local_subnet", spd_node->local_subnet);
    json_object_set_string(root_object, "remote_subnet", spd_node->remote_subnet);
    json_object_set_string(root_object, "tunnel_local", spd_node->tunnel_local);
    json_object_set_string(root_object, "tunnel_remote", spd_node->tunnel_remote);
	json_object_set_number(root_object, "inner_protocol", spd_node->inner_protocol);
	json_object_set_number(root_object, "srcport", spd_node->srcport);
	json_object_set_number(root_object, "dstport", spd_node->dstport);
    json_object_set_number(root_object, "action", spd_node->action);
	json_object_set_boolean(root_object, "ext_seq_num", spd_node->ext_seq_num);
	json_object_set_boolean(root_object, "seq_overflow", spd_node->seq_overflow);
	json_object_set_number(root_object, "ipsec_mode", spd_node->ipsec_mode);
	json_object_set_number(root_object, "protocol_parameters", spd_node->protocol_parameters);
	json_object_set_number(root_object, "integrity_alg", spd_node->integrity_alg);
	json_object_set_number(root_object, "encryption_alg", spd_node->encryption_alg);
	json_object_set_number(root_object, "anti_replay_window_size", spd_node->anti_replay_window);
    json_object_set_boolean(root_object, "pfp_flag", spd_node->pfp_flag);
    json_object_set_boolean(root_object, "stateful_frag_check", spd_node->stateful_frag_check);
    json_object_set_boolean(root_object, "bypass_dscp", spd_node->bypass_dscp);
	json_object_set_boolean(root_object, "ecn", spd_node->ecn);
	json_object_set_boolean(root_object, "tfc_pad", spd_node->tfc_pad);
	json_object_set_number(root_object, "df_bit", spd_node->df_bit);

    // json_value_free(root_value);
    return root_value;
}

struct spd_entry_node *deserialize_spd_node(JSON_Object *schema) {
    // JSON_Object *schema = json_object(json_parse_string(serialized));
    spd_entry_node *spd_node = create_spd_node();
    strcpy(spd_node->name,json_object_get_string(schema, "name"));
    spd_node->index = json_object_get_number(schema, "index");
    spd_node->policy_dir = json_object_get_number(schema, "policy_dir");
    spd_node->req_id = json_object_get_number(schema, "req_id");
    strcpy(spd_node->local_subnet,json_object_get_string(schema, "local_subnet"));
    strcpy(spd_node->remote_subnet,json_object_get_string(schema, "remote_subnet"));
	spd_node->inner_protocol = json_object_get_number(schema, "inner_protocol");
	spd_node->srcport = json_object_get_number(schema, "srcport");
	spd_node->dstport = json_object_get_number(schema, "dstport");
  	spd_node->action = json_object_get_number(schema, "action");
	spd_node->seq_overflow = json_object_get_boolean(schema, "seq_overflow");
	spd_node->ipsec_mode = json_object_get_number(schema, "ipsec_mode");
	spd_node->protocol_parameters = json_object_get_number(schema, "protocol_parameters");
	spd_node->integrity_alg = json_object_get_number(schema, "integrity_alg");
	spd_node->encryption_alg = json_object_get_number(schema, "encryption_alg");
	spd_node->anti_replay_window = json_object_get_number(schema, "anti_replay_window_size");
	spd_node->pfp_flag = json_object_get_number(schema, "pfp_flag");
	spd_node->stateful_frag_check = json_object_get_number(schema, "stateful_frag_check");
	spd_node->bypass_dscp = json_object_get_boolean(schema, "bypass_dscp");
	spd_node->ecn = json_object_get_boolean(schema, "ecn");
	spd_node->tfc_pad = json_object_get_boolean(schema, "tfc_pad");
	spd_node->df_bit = json_object_get_number(schema, "df_bit");
    return spd_node;

}   
#endif


