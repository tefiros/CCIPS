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

#ifndef __SPD_ENTRY
#define __SPD_ENTRY


#include "utils.h"
#include "log.h"


typedef struct host_t host_t;

typedef struct spd_entry_node{
	int policy_id;	// rule-number
	int index;
	char *src; 
	char *dst;
	char *src_tunnel;
	char *dst_tunnel; 
	int satype; 
	int request_protocol; //PF_KEY AH/ESP
	int action_policy_type; 
	int policy_dir; 
	int protocol_next_layer; 
	int srcport; 
	int dstport; 
	int mode;
	int lft_byte_hard;
	int lft_byte_soft;
	int lft_byte_current;
	int lft_packet_hard;
	int lft_packet_soft;
	int lft_packet_current;
	int lft_hard_add_expires_seconds;
	int lft_hard_use_expires_seconds;
	int lft_soft_add_expires_seconds;
	int lft_soft_use_expires_seconds;
	int lft_current_add_expires_seconds;
	int lft_current_use_expires_seconds;
	

	struct spd_entry_node *next;

} spd_entry_node;


int pfkey_setsadbaddr(void *p, int exttype, int protocol, int prefixlen, int port, char ip[]);
int addSPD_entry(sr_session_ctx_t *sess, sr_change_iter_t *it, char *xpath,char *rule_number, int case_value);
int removeSPD_entry(sr_session_ctx_t *sess, sr_change_iter_t *it, char *xpath,char *rule_number, int case_value);
spd_entry_node* getSPDEntry( char* local_ts, char* remote_ts);
spd_entry_node* get_spd_node_by_index(int policy_index);
char* getSPDmode(spd_entry_node* node);
char* getSPDsatype(spd_entry_node * node);
char* getSPDsrc(spd_entry_node * node);
char* getSPDdst(spd_entry_node * node);
int verifySPD_entry(sr_session_ctx_t *sess, sr_change_iter_t *it, sr_change_oper_t oper, char *xpath,char *rule_number, int case_value);
int get_spd_lifetime_current(const char *xpath, sr_val_t **values, size_t *values_cnt, void *private_ctx);


#endif
