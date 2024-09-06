
#ifndef __SAD_ENTRY
#define __SAD_ENTRY
#include <stdbool.h>
#include <stdio.h>
#include "sad_entry.h"
#include "../parson/parson.h"

typedef struct sad_entry_node{
	char *name;
	unsigned long long int req_id;
	unsigned long int spi;
	bool ext_seq_num;
	bool seq_overflow;
	unsigned long long int seq_number_counter;
	unsigned long long int anti_replay_window;
	char *local_subnet;
	char *remote_subnet;
	char *tunnel_local;
	char *tunnel_remote;
	unsigned int inner_protocol;
	unsigned int srcport, dstport;
	unsigned short ipsec_mode;
	unsigned short protocol_parameters;
	unsigned int integrity_alg;
	unsigned int encryption_alg;
	char *encryption_key;
	char *integrity_key;
	char *encryption_iv;
	bool bypass_dscp;
	bool ecn;
	bool tfc_pad;
	unsigned short df_bit;
	unsigned long int lft_bytes_hard;
	unsigned long int lft_bytes_soft;
	unsigned long int lft_bytes_current;
	unsigned long int lft_packets_hard;
	unsigned long int lft_packets_soft;
	unsigned long int lft_packets_current;
	unsigned long int lft_time_hard;
	unsigned long int lft_time_soft;
	unsigned long int lft_time_current;
	unsigned long int lft_idle_hard;
	unsigned long int lft_idle_soft;
	unsigned long int lft_idle_current;
	struct sad_entry_node *next;
} sad_entry_node;


sad_entry_node* create_sad_node();
char *serialize_sad_node(sad_entry_node *sad_node);
sad_entry_node *deserialize_sad_node(char *serialized);


#endif