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

#include <stdint.h>


#include <sys/socket.h>
#include <sys/types.h>

#include <linux/pfkeyv2.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <limits.h>
#include <time.h>
#include <pthread.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <inttypes.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>


#include "sysrepo.h"
#include "sysrepo/values.h"
#include "log.h"


#define MAX_PATH  200

#define CASE1_IPSECIKE 1
#define CASE2_IPSEC 2

//#define XPATH_MAX_LEN 100

#define SADB_REGISTER_MSG 1
#define SADB_ACQUIRE_MSG 2
#define SADB_EXPIRE_MSG 3

#define IPSEC_MODE_ANY        0
#define IPSEC_MODE_TRANSPORT  1
#define IPSEC_MODE_TUNNEL     2

#define IPSEC_NLP_TCP  0
#define IPSEC_NLP_UDP 1
#define IPSEC_NLP_SCTP 2
#define IPSEC_NLP_DCCP  3
#define IPSEC_NLP_ICMP 4
#define IPSEC_NLP_IPv6-ICMP 5
#define IPSEC_NLP_MH 6
#define IPSEC_NLP_GRE 7

#define EALG_DESCBC_KEY_BITS	  64
#define EALG_3DESCBC_KEY_BITS	  192

#define AALG_MD5HMAC_KEY_BITS    160
#define AALG_SHA1HMAC_KEY_BITS   160

//#define SADB_SATYPE_AH  2
//#define SADB_SATYPE_ESP 3

#define IPSEC_DIR_INBOUND  1
#define IPSEC_DIR_OUTBOUND 2
#define IPSEC_DIR_FORWARD 3

#define IPSEC_LEVEL_DEFAULT     0       /* reference to system default */
#define IPSEC_LEVEL_USE         1       /* use SA if present. */
#define IPSEC_LEVEL_REQUIRE     2       /* require SA. */
#define IPSEC_LEVEL_UNIQUE      3       /* unique SA. */

#define IPSEC_MODE_ANY        0
#define IPSEC_MODE_TRANSPORT  1
#define IPSEC_MODE_TUNNEL     2

#define IPSEC_POLICY_DISCARD 0
#define IPSEC_POLICY_PROTECT   2
#define IPSEC_POLICY_BYPASS  4

#define PFKEY_BUFFER_SIZE 4096
#define PFKEY_ALIGNMENT   8


char * get_ip(char * ip_mask);
int get_mask(char * ip_mask);

void set_verbose(int setting);
int v_printf(const char * restrict format, ...);
const char * get_sadb_msg_type(int type);
const char * get_sadb_satype(int type);
const char * get_sadb_alg_type(int alg, int authenc);
void print_sadb_msg(struct sadb_msg *msg, int msglen);
int Socket(int family, int type, int protocol);
void Write(int fd, void *ptr, size_t nbytes);
ssize_t Read(int fd, void *ptr, size_t nbytes);
char * sock_ntop(const struct sockaddr *sa, socklen_t salen);
const char * get_sa_state(int state);
const char * get_encrypt_str(int alg);
const char * get_auth_str(int alg);
const char * get_auth_alg(int alg);
const char * get_encrypt_alg(int alg);
int getAuthAlg(char* alg);
int getEncryptAlg(char* alg);
void sa_print(struct sadb_ext *ext);
void supported_print(struct sadb_ext *ext);
void lifetime_print(struct sadb_ext *ext);
void address_print(struct sadb_ext *ext);
void key_print(struct sadb_ext *ext);






