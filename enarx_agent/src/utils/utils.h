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

#include <netinet/in.h>
#include <stdlib.h>
#include <limits.h>
#include <time.h>
#include <stdio.h>
#include <unistd.h>
// #include <signal.h>
#include <inttypes.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>

// #include "pfkeyv2_utils.h"
#include "log.h"
#include "constants.h"


char * get_ip(char * ip_mask);
int get_mask(char * ip_mask);

void set_verbose(int setting);
int v_printf(const char * restrict format, ...);
const char * get_sadb_msg_type(int type);
const char * get_sadb_satype(int type);
const char * get_sadb_alg_type(int alg, int authenc);
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

unsigned char* hexstr_to_char(const char* hexstr);
int checkIKE_connection();






