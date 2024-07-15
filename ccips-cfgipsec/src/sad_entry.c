#include "sad_entry.h"
#define MAX_PATH  200
#define MAX_IP 40
#define MAX_KEY 2048
#define MAX_ID_LENGTH  MAX_PATH  +  MAX_IP * 4


sad_entry_node* create_sad_node(){
    sad_entry_node *sad_node = (sad_entry_node*) malloc(sizeof(sad_entry_node));
	sad_node->name = (char *) malloc(sizeof(char) * MAX_PATH);
	memset(sad_node->name, 0, sizeof(char) * MAX_PATH);
	sad_node->req_id = 0;
	sad_node->spi = 0;
	sad_node->ext_seq_num = false;
	sad_node->seq_overflow = false;
	sad_node->seq_number_counter = 0;
	sad_node->anti_replay_window = 0; 
	sad_node->local_subnet = (char *) malloc(sizeof(char) * MAX_IP); 
	memset(sad_node->local_subnet, 0, sizeof(char) * MAX_IP);
	sad_node->remote_subnet = (char *) malloc(sizeof(char) * MAX_IP); 
	memset(sad_node->remote_subnet, 0, sizeof(char) * MAX_IP); 
	sad_node->tunnel_local = (char *) malloc(sizeof(char) * MAX_IP); 
	memset(sad_node->tunnel_local, 0, sizeof(char) * MAX_IP); 
	sad_node->tunnel_remote = (char *) malloc(sizeof(char) * MAX_IP); 
	memset(sad_node->tunnel_remote, 0, sizeof(char) * MAX_IP); 
	sad_node->inner_protocol = 0;
	sad_node->srcport = 0; 
	sad_node->dstport = 0;
	sad_node->ipsec_mode = 0;
	sad_node->protocol_parameters = 0;
	sad_node->integrity_alg = 0;
	sad_node->encryption_alg = 0;
	sad_node->encryption_key = (char *) malloc(sizeof(char) * MAX_KEY); 
	memset(sad_node->encryption_key, 0, sizeof(char) * MAX_KEY);
	sad_node->integrity_key = (char *) malloc(sizeof(char) * MAX_KEY); 
	memset(sad_node->integrity_key, 0, sizeof(char) * MAX_KEY);
	sad_node->encryption_iv = (char *) malloc(sizeof(char) * MAX_KEY); 
	memset(sad_node->encryption_iv, 0, sizeof(char) * MAX_KEY);
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


void copy_sad_node(sad_entry_node *dst, sad_entry_node *src) {
	strcpy(dst->name, src->name);
	dst->req_id = src->req_id;
	dst->spi = src->spi;
	dst->ext_seq_num = src->ext_seq_num;
	dst->seq_overflow = src->seq_overflow;
	dst->seq_number_counter = src->seq_number_counter;
	dst->anti_replay_window = src->anti_replay_window;
	memcpy(dst->local_subnet, src->local_subnet, MAX_IP);
	memcpy(dst->remote_subnet, src->remote_subnet, MAX_IP);
	memcpy(dst->tunnel_local, src->tunnel_local, MAX_IP);
	memcpy(dst->tunnel_remote, src->tunnel_remote, MAX_IP);
	dst->inner_protocol = src->inner_protocol;
	dst->srcport = src->srcport;
	dst->dstport = src->dstport;
	dst->ipsec_mode = src->ipsec_mode;
	dst->protocol_parameters = src->protocol_parameters;
	dst->integrity_alg = src->integrity_alg;
	dst->encryption_alg = src->encryption_alg;
	memcpy(dst->encryption_key, src->encryption_key, MAX_KEY);
	memcpy(dst->integrity_key, src->integrity_key, MAX_KEY);
	memcpy(dst->encryption_iv, src->encryption_iv, MAX_KEY);
	dst->bypass_dscp = src->bypass_dscp;
	dst->ecn = src->ecn;
	dst->tfc_pad = src->tfc_pad;
	dst->df_bit = src->df_bit;
	dst->lft_bytes_hard = src->lft_bytes_hard;
	dst->lft_bytes_soft = src->lft_bytes_soft;
	dst->lft_bytes_current = src->lft_bytes_current;
	dst->lft_packets_hard = src->lft_packets_hard;
	dst->lft_packets_soft = src->lft_packets_soft;
	dst->lft_packets_current = src->lft_packets_current;
	dst->lft_time_hard = src->lft_time_hard;
	dst->lft_time_soft = src->lft_time_soft;
	dst->lft_time_current = src->lft_time_current;
	dst->lft_idle_hard = src->lft_idle_hard;
	dst->lft_idle_soft = src->lft_idle_soft;
	dst->lft_idle_current = src->lft_idle_current;

	dst->next = src->next; // should be copied?

	return;
}



#ifdef Trusted

// https://github.com/kgabis/parson
JSON_Value *serialize_sad_node(sad_entry_node *sad_node) {
    JSON_Value *root_value = json_value_init_object();
    JSON_Object *root_object = 	json_value_get_object(root_value);
    char *serialized_string = NULL;

    // Initial vals
    json_object_set_string(root_object, "name", sad_node->name);
    json_object_set_number(root_object, "req_id", sad_node->req_id);
    json_object_set_number(root_object, "spi", sad_node->spi);
	json_object_set_boolean(root_object, "ext_seq_num", sad_node->ext_seq_num);
	json_object_set_boolean(root_object, "seq_overflow", sad_node->seq_overflow);
	json_object_set_number(root_object, "seq_number_counter", sad_node->seq_number_counter);
	json_object_set_number(root_object, "anti_replay_window", sad_node->anti_replay_window);
    json_object_set_string(root_object, "local_subnet", sad_node->local_subnet);
    json_object_set_string(root_object, "remote_subnet", sad_node->remote_subnet);
    json_object_set_string(root_object, "tunnel_local", sad_node->tunnel_local);
    json_object_set_string(root_object, "tunnel_remote", sad_node->tunnel_remote);
	json_object_set_number(root_object, "inner_protocol", sad_node->inner_protocol);
	json_object_set_number(root_object, "srcport", sad_node->srcport);
	json_object_set_number(root_object, "dstport", sad_node->dstport);
	json_object_set_number(root_object, "ipsec_mode", sad_node->ipsec_mode);
	json_object_set_number(root_object, "protocol_parameters", sad_node->protocol_parameters);
	json_object_set_number(root_object, "integrity_alg", sad_node->integrity_alg);
	json_object_set_number(root_object, "encryption_alg", sad_node->encryption_alg);
	json_object_set_number(root_object, "encryption_key_length", sad_node->encryption_key_length);
    json_object_set_string(root_object, "encryption_key", sad_node->encryption_key);
    json_object_set_string(root_object, "integrity_key", sad_node->integrity_key);
    json_object_set_string(root_object, "encryption_iv", sad_node->encryption_iv);
	json_object_set_boolean(root_object, "bypass_dscp", sad_node->bypass_dscp);
	json_object_set_boolean(root_object, "ecn", sad_node->ecn);
	json_object_set_boolean(root_object, "tfc_pad", sad_node->tfc_pad);
	json_object_set_number(root_object, "df_bit", sad_node->df_bit);
	json_object_set_number(root_object, "lft_bytes_hard", sad_node->lft_bytes_hard);
	json_object_set_number(root_object, "lft_bytes_soft", sad_node->lft_bytes_soft);
	json_object_set_number(root_object, "lft_bytes_current", sad_node->lft_bytes_current);
	json_object_set_number(root_object, "lft_packets_hard", sad_node->lft_packets_hard);
	json_object_set_number(root_object, "lft_packets_soft", sad_node->lft_packets_soft);
	json_object_set_number(root_object, "lft_packets_current", sad_node->lft_packets_current);
	json_object_set_number(root_object, "lft_time_hard", sad_node->lft_time_hard);
	json_object_set_number(root_object, "lft_time_soft", sad_node->lft_time_soft);
	json_object_set_number(root_object, "lft_time_current", sad_node->lft_time_current);
	json_object_set_number(root_object, "lft_idle_hard", sad_node->lft_idle_hard);
	json_object_set_number(root_object, "lft_idle_soft", sad_node->lft_idle_soft);
	json_object_set_number(root_object, "lft_idle_current", sad_node->lft_idle_current);
    // json_value_free(root_value);
    return root_value;
}

struct sad_entry_node *deserialize_sad_node(JSON_Object *schema) {
    // JSON_Object *schema = json_object(json_parse_string(serialized));
    sad_entry_node *sad_node = create_sad_node();
    strcpy(sad_node->name,json_object_get_string(schema, "name"));
    sad_node->req_id = json_object_get_number(schema, "req_id");
    sad_node->spi = json_object_get_number(schema, "spi");
	sad_node->ext_seq_num = json_object_get_boolean(schema, "ext_seq_num");
	sad_node->seq_overflow = json_object_get_boolean(schema, "seq_overflow");
	sad_node->seq_number_counter = json_object_get_number(schema, "seq_number_counter");
	sad_node->anti_replay_window = json_object_get_number(schema, "anti_replay_window");
    strcpy(sad_node->local_subnet,json_object_get_string(schema, "local_subnet"));
    strcpy(sad_node->remote_subnet,json_object_get_string(schema, "remote_subnet"));
    strcpy(sad_node->tunnel_local,json_object_get_string(schema, "tunnel_local"));
    strcpy(sad_node->tunnel_remote,json_object_get_string(schema, "tunnel_remote"));
	sad_node->inner_protocol = json_object_get_number(schema, "inner_protocol");
	sad_node->srcport = json_object_get_number(schema, "srcport");
	sad_node->dstport = json_object_get_number(schema, "dstport");
	sad_node->ipsec_mode = json_object_get_number(schema, "ipsec_mode");
	sad_node->protocol_parameters = json_object_get_number(schema, "protocol_parameters");
	sad_node->integrity_alg = json_object_get_number(schema, "integrity_alg");
	sad_node->encryption_alg = json_object_get_number(schema, "encryption_alg");
	sad_node->encryption_key_length = json_object_get_number(schema, "encryption_key_length");
    strcpy(sad_node->encryption_key,json_object_get_string(schema, "encryption_key"));
    strcpy(sad_node->integrity_key,json_object_get_string(schema, "integrity_key"));
    strcpy(sad_node->encryption_iv,json_object_get_string(schema, "encryption_iv"));
	sad_node->bypass_dscp = json_object_get_boolean(schema, "bypass_dscp");
	sad_node->ecn = json_object_get_boolean(schema, "ecn");
	sad_node->tfc_pad = json_object_get_boolean(schema, "tfc_pad");
	sad_node->df_bit = json_object_get_number(schema, "df_bit");
	sad_node->lft_bytes_hard = json_object_get_number(schema, "lft_bytes_hard");
	sad_node->lft_bytes_soft = json_object_get_number(schema, "lft_bytes_soft");
	sad_node->lft_bytes_current = json_object_get_number(schema, "lft_bytes_current");
	sad_node->lft_packets_hard = json_object_get_number(schema, "lft_packets_hard");
	sad_node->lft_packets_soft = json_object_get_number(schema, "lft_packets_soft");
	sad_node->lft_packets_current = json_object_get_number(schema, "lft_packets_current");
	sad_node->lft_time_hard = json_object_get_number(schema, "lft_time_hard");
	sad_node->lft_time_soft = json_object_get_number(schema, "lft_time_soft");
	sad_node->lft_time_current = json_object_get_number(schema, "lft_time_current");
	sad_node->lft_idle_hard = json_object_get_number(schema, "lft_idle_hard");
	sad_node->lft_idle_soft = json_object_get_number(schema, "lft_idle_soft");
	sad_node->lft_idle_current = json_object_get_number(schema, "lft_idle_current");
    return sad_node;
}   
#endif


