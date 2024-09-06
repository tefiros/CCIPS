#ifndef __SYSREPO_ENTRIES
#define __SYSREPO_ENTRIES
#include "utils.h"
#include "spd_entry.h"
#include "sad_entry.h"
#include "pfkeyv2_utils.h"
#include "pfkeyv2_entry.h"
#include <sysrepo.h>
#include <sysrepo/values.h>
#include <libyang/libyang.h>
#include "sad_entry.h"
#include "spd_entry.h"
#include "log.h"

void print_current_config(sr_session_ctx_t *session, const char *module_name);

// Removed from spd and sad
int addSPD_entry(sr_session_ctx_t *sess, sr_change_iter_t *it, char *xpath,char *spd_name, int case_value);
int removeSPD_entry(sr_session_ctx_t *sess, sr_change_iter_t *it, char *xpath,char *spd_name, int case_value);
spd_entry_node *get_spd_node(char *name);
spd_entry_node *get_spd_node_by_index(int policy_index);
readSPD_entry(sr_session_ctx_t *sess, sr_change_iter_t *it,char *xpath,spd_entry_node *spd_node, int case_value);
int addSAD_entry(sr_session_ctx_t *sess, sr_change_iter_t *it, char *xpath,char *sad_name);
int removeSAD_entry(sr_session_ctx_t *sess, sr_change_iter_t *it, char *xpath,char *sad_name);
int get_sad_state(sr_session_ctx_t *session, const char *module_name, const char *xpath, const char *request_xpath,
        uint32_t request_id, struct lyd_node **parent, void *private_data);
int send_sa_expire_notification(sr_session_ctx_t *session, unsigned long int spi, bool soft);
int send_delete_SAD_request(unsigned long int spi);

#endif