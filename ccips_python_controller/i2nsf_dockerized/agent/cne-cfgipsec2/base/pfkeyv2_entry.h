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

#ifndef __PFKEYV2_ENTRY
#define __PFKEYV2_ENTRY

#include "utils.h"
#include "log.h"
#include "spd_entry.h"
#include "sad_entry.h"
#include "sysrepo_utils.h"

#define PFKEY_EXTLEN(msg) \
    PFKEY_UNUNIT64(((const struct sadb_ext *)(const void *)(msg))->sadb_ext_len)
#define PFKEY_UNUNIT64(a)   ((a) << 3)

typedef struct{
    int parent_pid;
    int socket;
	sr_session_ctx_t *session;
} register_thread;

int pf_exec_register(sr_session_ctx_t *session, char *xpath, int satype, const sr_val_t *input, const size_t input_cnt,sr_val_t **output, size_t *output_cnt, void *private_ctx);

#endif


