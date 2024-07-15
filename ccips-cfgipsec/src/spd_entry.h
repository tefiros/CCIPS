#ifndef __SPD_ENTRY
#define __SPD_ENTRY
#include <stdbool.h>
#include <stdio.h>
#include "spd_entry.h"
#include <stdlib.h>
#include <string.h>
#ifdef Trusted
	#include "parson.h"
#endif
#include <crypt.h>


typedef struct spd_entry_node{
	char *name;
	unsigned long long int req_id;
	unsigned short policy_dir;
	unsigned short index;
	unsigned long long int anti_replay_window;
	char *local_subnet;
	char *remote_subnet;
	char *tunnel_local;
	char *tunnel_remote;
	unsigned int inner_protocol;
	unsigned int srcport, dstport;
	unsigned short action;
	bool ext_seq_num;
	bool seq_overflow;
	unsigned short ipsec_mode;
	unsigned short protocol_parameters;
	unsigned int integrity_alg;
	unsigned int encryption_alg;
	unsigned int encryption_key_length;
	char *encryption_key;
	char *integrity_key;
	char *encryption_iv;
	bool pfp_flag; //take off?
	bool stateful_frag_check;
	bool bypass_dscp;
	bool ecn;
	bool tfc_pad;
	unsigned short df_bit;
	struct spd_entry_node *next;
} spd_entry_node;


/// @brief creates an empty spd_node with all the parameters initialized
/// @return 
spd_entry_node* create_spd_node();


#ifdef Trusted
/// @brief serialize a spd_node into a JSON_VALUE
/// @param spd_node input spd_node to serailize
/// @return Json value
JSON_Value *serialize_spd_node(spd_entry_node *spd_node);

/// @brief deserialized a JSON_OBJECT into a spd_node
/// @param schema json schema that contains a serialized _spd_node
/// @return spd_entry_node // TODO maybe change this so we pass the spd_entry_node to change
spd_entry_node *deserialize_spd_node(JSON_Object *schema);
#endif



#endif