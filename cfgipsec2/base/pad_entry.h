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

#ifndef __PAD_ENTRY
#define __PAD_ENTRY

#include "utils.h"
#include "log.h"


typedef struct pad_entry_node{

	int pad_entry_id;
	char *ipv4_address;
	char *pad_auth_protocol;
	char *auth_m;
	char *secret;
	struct pad_entry_node *next;

} pad_entry_node;

int verifyPAD_entry(sr_session_ctx_t *sess, sr_change_iter_t *it, sr_change_oper_t oper, char *xpath,char *pad_id);
int addPAD_entry(sr_session_ctx_t *sess, sr_change_iter_t *it,char *xpath,char *pad_id);
int removePAD_entry(sr_session_ctx_t *sess, sr_change_iter_t *it,char *xpath,char *pad_id);
void show_pad_list();
pad_entry_node* getPADEntry(char* remote_ts);

#endif



