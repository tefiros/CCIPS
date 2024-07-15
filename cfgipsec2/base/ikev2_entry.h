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


#ifndef __IKEv2_ENTRY
#define __IKEv2_ENTRY
#include <libvici.h>

#include "pad_entry.h"
#include "spd_entry.h"
#include "utils.h"
#include "log.h"

int verifyIKE_conn_entry(sr_session_ctx_t *sess, sr_change_iter_t *it, sr_change_oper_t oper, char *xpath,char *ike_id);
int addIKE_conn_entry(sr_session_ctx_t *sess, sr_change_iter_t *it,char *xpath,char *ike_id);
int removeIKE_conn_entry(sr_session_ctx_t *sess, sr_change_iter_t *it,char *xpath,char *ike_id);
int checkIKE_connection();
 

#endif
