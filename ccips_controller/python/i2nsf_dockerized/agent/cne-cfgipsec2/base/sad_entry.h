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

#ifndef __SAD_ENTRY
#define __SAD_ENTRY


#include "utils.h"
#include "log.h"


typedef struct sad_entry_node{
	int spi;	// rule-number
	int state;
	int seq_number;
	int replay;
	int rule_number;
	int mode;
	int satype;
	int protocol_next_layer;
	char *protocol;
	int srcport;
	int dstport;
	char *src;
	char *dst;
	char *src_tunnel;
	char *dst_tunnel;
	int auth_alg;
	int iv;
	int encrypt_alg;
	char *encrypt_key;
	char *auth_key;
	bool combined_enc_intr;
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
	
	struct sad_entry_node *next;

} sad_entry_node;

int addSAD_entry_startup(sr_session_ctx_t *sess, sr_node_t *tree);
int addSAD_entry(sr_session_ctx_t *sess, sr_change_iter_t *it, char *xpath,char *spi);
int removeSAD_entry(sr_session_ctx_t *sess, sr_change_iter_t *it, char *xpath,char *spi);
int get_sad_lifetime_current(const char *xpath, sr_val_t **values, size_t *values_cnt, void *private_ctx);
int verifySAD_entry(sr_session_ctx_t *sess, sr_change_iter_t *it, sr_change_oper_t oper, char *xpath,char *spi_number);


#endif
