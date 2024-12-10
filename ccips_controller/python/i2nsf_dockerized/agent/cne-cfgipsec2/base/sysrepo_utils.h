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

#include <string.h>
#include <sys/socket.h>
#include <linux/pfkeyv2.h>
#include <netinet/in.h>
#include <stdlib.h>
#include "sysrepo.h"
#include "sysrepo/values.h"
#include "log.h"
#include "utils.h"

extern int feature_case_value;


#define XPATH_MAX_LEN 200

char *ev_to_str(sr_notif_event_t ev);

int sad_lifetime_current_cb(const char *xpath, sr_val_t **values, size_t *values_cnt, void *private_ctx);
int sad_stats_cb(const char *xpath, sr_val_t **values, size_t *values_cnt, void *private_ctx);
int spd_lifetime_current_cb(const char *xpath, sr_val_t **values, size_t *values_cnt, void *private_ctx);
int rpc_register_caller(sr_session_ctx_t *session, int satype);

int ike_entry_change_cb(sr_session_ctx_t *session, const char *ike_entry_xpath, sr_notif_event_t event, void *private_ctx);
int rpc_sadb_register_cb(const char *xpath, const sr_val_t *input, const size_t input_cnt, sr_val_t **output, size_t *output_cnt, void *private_ctx);
int spd_entry_change_cb(sr_session_ctx_t *session, const char *spd_entry_xpath, sr_notif_event_t event, void *private_ctx);
int sad_entry_change_cb(sr_session_ctx_t *session, const char *sad_entry_xpath, sr_notif_event_t event, void *private_ctx);
int pad_entry_change_cb(sr_session_ctx_t *session, const char *pad_entry_xpath, sr_notif_event_t event, void *private_ctx);



