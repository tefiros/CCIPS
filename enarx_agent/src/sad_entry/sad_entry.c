
#include "sad_entry.h"
#define MAX_PATH  200
#define MAX_IP 40
#define MAX_KEY 1024
sad_entry_node* create_sad_node(){
    sad_entry_node *sad_node = (sad_entry_node*) malloc(sizeof(sad_entry_node));
	sad_node->name = (char *) malloc(sizeof(char) * MAX_PATH);
	sad_node->req_id = 0;
	sad_node->spi = 0;
	sad_node->ext_seq_num = false;
	sad_node->seq_overflow = false;
	sad_node->seq_number_counter = 0;
	sad_node->anti_replay_window = 0;
	sad_node->local_subnet = (char *) malloc(sizeof(char) * MAX_IP); 
	sad_node->remote_subnet = (char *) malloc(sizeof(char) * MAX_IP); 
	sad_node->tunnel_local = (char *) malloc(sizeof(char) * MAX_IP); 
	sad_node->tunnel_remote = (char *) malloc(sizeof(char) * MAX_IP); 
	sad_node->inner_protocol = 0;
	sad_node->srcport = 0; 
	sad_node->dstport = 0;
	sad_node->ipsec_mode = 0;
	sad_node->protocol_parameters = 0;
	sad_node->integrity_alg = 0;
	sad_node->encryption_alg = 0;
	sad_node->encryption_key = (char *) malloc(sizeof(char) * MAX_KEY); 
	sad_node->integrity_key = (char *) malloc(sizeof(char) * MAX_KEY); 
	sad_node->encryption_iv = (char *) malloc(sizeof(char) * MAX_KEY); 
	sad_node->bypass_dscp = false;
	sad_node->ecn = false;
	sad_node->tfc_pad = false;
	sad_node->df_bit = 0;
	sad_node->lft_bytes_hard = 0;
	sad_node->lft_bytes_soft = 0;
	sad_node->lft_bytes_current = 0;
	sad_node->lft_packets_hard = 0;
	sad_node->lft_packets_soft = 0;
	sad_node->lft_packets_current = 0;
	sad_node->lft_time_hard = 0;
	sad_node->lft_time_soft = 0;
	sad_node->lft_time_current = 0;
	sad_node->lft_idle_hard = 0;
	sad_node->lft_idle_soft = 0;
	sad_node->lft_idle_current = 0;	
		
    sad_node->next=NULL;
    
    return sad_node;

}

// https://github.com/kgabis/parson
char *serialize_sad_node(sad_entry_node *sad_node) {
    JSON_Value *root_value = json_value_init_object();
    JSON_Object *root_object = json_value_get_object(root_value);
    char *serialized_string = NULL;

    // Initial vals
    json_object_set_string(root_object, "name", sad_node->name);
    json_object_set_number(root_object, "req_id", sad_node->req_id);
    json_object_set_number(root_object, "spi", sad_node->spi);
    json_object_set_string(root_object, "local_subnet", sad_node->local_subnet);
    json_object_set_string(root_object, "remote_subnet", sad_node->remote_subnet);
    json_object_set_string(root_object, "tunnel_local", sad_node->tunnel_local);
    json_object_set_string(root_object, "tunnel_remote", sad_node->tunnel_remote);
    json_object_set_string(root_object, "encryption_key", sad_node->encryption_key);
    json_object_set_string(root_object, "integrity_key", sad_node->integrity_key);
    json_object_set_string(root_object, "encryption_iv", sad_node->encryption_iv);

    serialized_string = json_serialize_to_string_pretty(root_value);
    json_value_free(root_value);
    return serialized_string;
}

struct sad_entry_node *deserialize_sad_node(char *serialized) {
    JSON_Object *schema = json_object(json_parse_string(serialized));
    
    sad_entry_node *sad_node = create_sad_node();
    strcpy(sad_node->name,json_object_get_string(schema, "name"));
    sad_node->req_id = json_object_get_number(schema, "req_id");
    sad_node->spi = json_object_get_number(schema, "spi");
    strcpy(sad_node->local_subnet,json_object_get_string(schema, "local_subnet"));
    strcpy(sad_node->remote_subnet,json_object_get_string(schema, "remote_subnet"));
    strcpy(sad_node->tunnel_local,json_object_get_string(schema, "tunnel_local"));
    strcpy(sad_node->tunnel_remote,json_object_get_string(schema, "tunnel_remote"));
    strcpy(sad_node->encryption_key,json_object_get_string(schema, "encryption_key"));
    strcpy(sad_node->integrity_key,json_object_get_string(schema, "integrity_key"));
    strcpy(sad_node->encryption_iv,json_object_get_string(schema, "encryption_iv"));
    json_value_free(schema);
    return sad_node;
}   




