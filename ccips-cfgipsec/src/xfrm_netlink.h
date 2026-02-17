/*
 * XFRM Netlink header for SAD management
 */

#ifndef XFRM_NETLINK_H
#define XFRM_NETLINK_H

#include "sysrepo_entries.h"
#include <sysrepo.h>

/**
 * Add a Security Association using XFRM netlink
 * @param sad_node SAD entry to add
 * @return SR_ERR_OK on success, error code otherwise
 */
int xfrm_add_sa(sad_entry_node *sad_node);

/**
 * Delete a Security Association using XFRM netlink
 * @param sad_node SAD entry to delete
 * @return SR_ERR_OK on success, error code otherwise
 */
int xfrm_del_sa(sad_entry_node *sad_node);

#endif /* XFRM_NETLINK_H */

