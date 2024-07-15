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

#include "utils.h"


char * get_ip(char * ip_mask) {

	const char d[2] = "/";
	char * ip;

    ip = strdup(ip_mask);
    ip = strtok(ip,d);
 
 	return ip;
}

int get_mask(char * ip_mask) {

	const char d[2] = "/";
	/*char address_tmp[30];
    char *ip;
	char *mask = NULL;

	mask = strrchr(ip_mask, '/');
     
 	return atoi(mask);*/
	char * ip;
	char * mask;

    ip = strdup(ip_mask);
    ip = strtok(ip,d);
 	mask = strtok(NULL,d);
 	return atoi(mask);

}

int getAuthAlg(char* alg) {

	if (!strcmp(alg, "hmac-md5-128") || !strcmp(alg, "hmac-md5-96")){
		return SADB_AALG_MD5HMAC;
	}
	/*else if (!strcmp(alg, "des-mac"))
		return SADB_X_AALG_DES;*/
	else if (!strcmp(alg, "hmac-sha1-96") || !strcmp(alg, "hmac-sha1-96") ||
		     !strcmp(alg, "hmac-sha1-160"))
		return SADB_AALG_SHA1HMAC;
	/*else if (!strcmp(alg, "hmac-sha2-256-128"))
		return SADB_X_AALG_SHA2_256;
	else if (!strcmp(alg, "hmac-sha2-384-192"))
		return SADB_X_AALG_SHA2_384;
	else if (!strcmp(alg, "hmac-sha2-512-256"))
		return SADB_X_AALG_SHA2_512;*/
	else 
		return SADB_AALG_NONE;
}

int getEncryptAlg(char* alg) {

	if (!strcmp(alg, "des"))
		return SADB_EALG_DESCBC ;
	else if (!strcmp(alg, "3des"))
		return SADB_EALG_3DESCBC;
	/*else if (!strcmp(alg, "blowfish-128") || !strcmp(alg, "blowfish-192") ||
		     !strcmp(alg, "blowfish-256") || !strcmp(alg, "blowfish-448") )
		return SADB_X_EALG_BLF;
	else if (!strcmp(alg, "aes-128-cbc") || !strcmp(alg, "aes-192-cbc") ||
		     !strcmp(alg, "aes-256-cbc"))
		return SADB_X_EALG_AES;
	else if (!strcmp(alg, "cast"))
		return SADB_X_EALG_CAST;
	else if (!strcmp(alg, "aes-ctr"))
		return SADB_X_EALG_AESCTR;
	else if (!strcmp(alg, "camellia-128") || !strcmp(alg, "camellia-192") ||
		     !strcmp(alg, "camellia-256") )
		return SADB_EALG_NULL;*/
	else
		return SADB_EALG_NULL;
}

const char * get_encrypt_str(int alg) {

    static char buf[100];
    switch (alg) {
    case SADB_EALG_DESCBC:      return "des";
    case SADB_EALG_3DESCBC:     return "3des";
    case SADB_EALG_NULL:        return "null";
#ifdef SADB_X_EALG_CAST128CBC
    case SADB_X_EALG_CAST128CBC:    return "cast";
#endif
#ifdef SADB_X_EALG_BLOWFISHCBC
    case SADB_X_EALG_BLOWFISHCBC:   return "blowfish";
#endif
#ifdef SADB_X_EALG_AES
    case SADB_X_EALG_AES:           return "aes-cbc";
#endif
    default:                    sprintf(buf, "[Unknown encryption algorithm %d]", alg);
                                return buf;
    }
}

const char *
get_auth_str(int alg) {

    static char buf[100];
    switch (alg) {
    case SADB_AALG_MD5HMAC:     return "hmac-md5-96";
    case SADB_AALG_SHA1HMAC:    return "hmac-sha1-96";
/*#ifdef SADB_X_AALG_MD5
    case SADB_X_AALG_MD5:       return "Keyed MD5";
#endif
#ifdef SADB_X_AALG_SHA
    case SADB_X_AALG_SHA:       return "Keyed SHA-1";
#endif
#ifdef SADB_X_AALG_NULL
    case SADB_X_AALG_NULL:      return "Null";
#endif
#ifdef SADB_X_AALG_SHA2_256
    case SADB_X_AALG_SHA2_256:  return "SHA2-256";
#endif
#ifdef SADB_X_AALG_SHA2_384
    case SADB_X_AALG_SHA2_384:  return "SHA2-384";
#endif
#ifdef SADB_X_AALG_SHA2_512
    case SADB_X_AALG_SHA2_512:  return "SHA2-512";
#endif
*/
    default:                    sprintf(buf, "[Unknown authentication algorithm %d]", alg);
                                return buf;
    }
}

// FROM key/printsadbmsg.c

const char *
get_auth_alg(int alg) {

	static char buf[100];

	switch (alg) {
	case SADB_AALG_NONE:		return "None";
	case SADB_AALG_MD5HMAC:		return "HMAC-MD5";
	case SADB_AALG_SHA1HMAC:	return "HMAC-SHA-1";
#ifdef SADB_X_AALG_MD5
	case SADB_X_AALG_MD5:		return "Keyed MD5";
#endif
#ifdef SADB_X_AALG_SHA
	case SADB_X_AALG_SHA:		return "Keyed SHA-1";
#endif
#ifdef SADB_X_AALG_NULL
	case SADB_X_AALG_NULL:		return "Null";
#endif
#ifdef SADB_X_AALG_SHA2_256
	case SADB_X_AALG_SHA2_256:	return "SHA2-256";
#endif
#ifdef SADB_X_AALG_SHA2_384
	case SADB_X_AALG_SHA2_384:	return "SHA2-384";
#endif
#ifdef SADB_X_AALG_SHA2_512
	case SADB_X_AALG_SHA2_512:	return "SHA2-512";
#endif
	default:					sprintf(buf, "[Unknown authentication algorithm %d]", alg);
								return buf;
	}
}

const char *
get_encrypt_alg(int alg) {

	static char buf[100];

	switch (alg) {
	case SADB_EALG_NONE:		return "None";
	case SADB_EALG_DESCBC:		return "DES-CBC";
	case SADB_EALG_3DESCBC:		return "3DES-CBC";
	case SADB_EALG_NULL:		return "Null";
#ifdef SADB_X_EALG_CAST128CBC
	case SADB_X_EALG_CAST128CBC:	return "CAST128-CBC";
#endif
#ifdef SADB_X_EALG_BLOWFISHCBC
	case SADB_X_EALG_BLOWFISHCBC:	return "Blowfish-CBC";
#endif
#ifdef SADB_X_EALG_AES
	case SADB_X_EALG_AES:			return "AES";
#endif
	default:					sprintf(buf, "[Unknown encryption algorithm %d]", alg);
								return buf;
	}
}

const char *
get_sadb_alg_type(int alg, int authenc) {

	if (authenc == SADB_EXT_SUPPORTED_AUTH) {
		return get_auth_alg(alg);
	} else {
		return get_encrypt_alg(alg);
	}
}

const char *
get_sa_state(int state) {
	static char buf[100];
	switch (state) {
	case SADB_SASTATE_LARVAL:	return "Larval";
	case SADB_SASTATE_MATURE:	return "Mature";
	case SADB_SASTATE_DYING:	return "Dying";
	case SADB_SASTATE_DEAD:		return "Dead";
	default:					sprintf(buf, "[Unknown SA state %d]", state);
								return buf;
	}
}

const char *
get_sadb_msg_type(int type) {
	static char buf[100];
	switch (type) {
	case SADB_RESERVED:	return "Reserved";
	case SADB_GETSPI:	return "Get SPI";
	case SADB_UPDATE:	return "Update";
	case SADB_ADD:		return "Add";
	case SADB_DELETE:	return "Delete";
	case SADB_GET:		return "Get";
	case SADB_ACQUIRE:	return "Acquire";
	case SADB_REGISTER:	return "Register";
	case SADB_EXPIRE:	return "Expire";
	case SADB_FLUSH:	return "Flush";
	case SADB_DUMP:		return "Dump";
	default:			sprintf(buf, "[Unknown type %d]", type);
						return buf;
	}
}

const char *
get_sadb_satype(int type) {

	static char buf[100];
	switch (type) {
	case SADB_SATYPE_UNSPEC:	return "Unspecified";
	case SADB_SATYPE_AH:		return "IPsec AH";
	case SADB_SATYPE_ESP:		return "IPsec ESP";
	case SADB_SATYPE_RSVP:		return "RSVP";
	case SADB_SATYPE_OSPFV2:	return "OSPFv2";
	case SADB_SATYPE_RIPV2:		return "RIPv2";
	case SADB_SATYPE_MIP:		return "Mobile IP";
	default:					sprintf(buf, "[Unknown satype %d]", type);
								return buf;
	}
}


void
sa_print(struct sadb_ext *ext) {

	struct sadb_sa *sa = (struct sadb_sa *)ext;
	DBG(" SA: SPI=%d Replay Window=%d State=%s",
		sa->sadb_sa_spi, sa->sadb_sa_replay,
		get_sa_state(sa->sadb_sa_state));
	DBG("  Authentication Algorithm: %s",
		get_auth_alg(sa->sadb_sa_auth));
	DBG("  Encryption Algorithm: %s",
		get_encrypt_alg(sa->sadb_sa_encrypt));
	if (sa->sadb_sa_flags & SADB_SAFLAGS_PFS)
		DBG("  Perfect Forward Secrecy");
}


void
supported_print(struct sadb_ext *ext) {

	struct sadb_supported *sup = (struct sadb_supported *)ext;
	struct sadb_alg *alg;
	int len;

	DBG(" Supported %s algorithms:",
		sup->sadb_supported_exttype == SADB_EXT_SUPPORTED_AUTH ?
		"authentication" :
		"encryption");
	len = sup->sadb_supported_len * 8;
	len -= sizeof(*sup);
	if (len == 0) {
		DBG("  None");
		return;
	}
	for (alg = (struct sadb_alg *)(sup + 1); len>0; len -= sizeof(*alg), alg++) {
		DBG("  %s ivlen %d bits %d-%d",
			get_sadb_alg_type(alg->sadb_alg_id, sup->sadb_supported_exttype),
			alg->sadb_alg_ivlen, alg->sadb_alg_minbits, alg->sadb_alg_maxbits);
	}
}

void
lifetime_print(struct sadb_ext *ext) {

	struct sadb_lifetime *life = (struct sadb_lifetime *)ext;

	DBG(" %s lifetime:",
		life->sadb_lifetime_exttype == SADB_EXT_LIFETIME_CURRENT ?
		"Current" :
		life->sadb_lifetime_exttype == SADB_EXT_LIFETIME_HARD ?
		"Hard" :
		"Soft");
	DBG("  %d allocations, %d bytes", life->sadb_lifetime_allocations,
		life->sadb_lifetime_bytes);
	if (life->sadb_lifetime_exttype == SADB_EXT_LIFETIME_CURRENT) {
		time_t t;
		struct tmp *tm;
		char buf[100];

		/* absolute times */
		t = life->sadb_lifetime_addtime;
		tm = localtime(&t);
		strftime(buf, sizeof(buf), "%c", tm);
		DBG("  added at %s, ", buf);
		if (life->sadb_lifetime_usetime == 0) {
			DBG("never used");
		} else {
			t = life->sadb_lifetime_usetime;
			tm = localtime(&t);
			strftime(buf, sizeof(buf), "%c", tm);
			DBG("first used at %s", buf);
		}
	} else {
		DBG("%d addtime, %d usetime", life->sadb_lifetime_addtime,
			life->sadb_lifetime_usetime);
	}
}

void
address_print(struct sadb_ext *ext) {

	struct sadb_address *addr = (struct sadb_address *)ext;
	struct sockaddr *sa;

	DBG(" %s address: ",
		addr->sadb_address_exttype == SADB_EXT_ADDRESS_SRC ?
		"Source" :
		addr->sadb_address_exttype == SADB_EXT_ADDRESS_DST ?
		"Dest" :
		"Proxy");
	sa = (struct sockaddr *)(addr + 1);
//	printf("  %s", sock_ntop(sa, addr->sadb_address_len * 8 - sizeof(*addr)));
	if (addr->sadb_address_prefixlen == 0) {
		DBG(" ");
	}
	else
		DBG("/%d ", addr->sadb_address_prefixlen);
	switch (addr->sadb_address_proto) {
		case IPPROTO_UDP:	DBG("(UDP)"); break;
		case IPPROTO_TCP:	DBG("(TCP)"); break;
		case 0:				break;
		default:			DBG("(IP proto %d)", addr->sadb_address_proto);
							break;
	}
}

void
key_print(struct sadb_ext *ext) {

	struct sadb_key *key = (struct sadb_key *)ext;
	int bits;
	unsigned char *p;

	DBG(" %s key, %d bits: 0x",
		key->sadb_key_exttype == SADB_EXT_KEY_AUTH ?
		"Authentication" : "Encryption",
		key->sadb_key_bits);
	/*for (p = (unsigned char *)(key + 1), bits = key->sadb_key_bits;
			bits > 0; p++, bits -= 8)
		DBG("%02x", *p);
	DBG("");*/
}

void
print_sadb_msg(struct sadb_msg *msg, int msglen) {

	struct sadb_ext *ext;

	if (msglen != msg->sadb_msg_len * 8) {
		DBG("SADB Message length (%d) doesn't match msglen (%d)",
			msg->sadb_msg_len * 8, msglen);
		return;
	}
	if (msg->sadb_msg_version != PF_KEY_V2) {
		DBG("SADB Message version not PF_KEY_V2");
		return;
	}
	DBG("SADB Message %s, errno %d, satype %s, seq %d, pid %d",
		get_sadb_msg_type(msg->sadb_msg_type), msg->sadb_msg_errno,
		get_sadb_satype(msg->sadb_msg_satype), msg->sadb_msg_seq,
		msg->sadb_msg_pid);
	if (msg->sadb_msg_errno != 0)
		ERR(" errno %s", strerror(msg->sadb_msg_errno));
	if (msglen == sizeof(struct sadb_msg))
		return;	/* no extensions */
	msglen -= sizeof(struct sadb_msg);
	ext = (struct sadb_ext *)(msg + 1);
	while (msglen > 0) {
		switch (ext->sadb_ext_type) {
		case SADB_EXT_RESERVED:	DBG(" Reserved Extension"); break;
		case SADB_EXT_SA:	sa_print(ext); break;
		case SADB_EXT_LIFETIME_CURRENT:
		case SADB_EXT_LIFETIME_HARD:
		case SADB_EXT_LIFETIME_SOFT:
					lifetime_print(ext); break;
		case SADB_EXT_ADDRESS_SRC:
		case SADB_EXT_ADDRESS_DST:
		case SADB_EXT_ADDRESS_PROXY:
					address_print(ext); break;
		case SADB_EXT_KEY_AUTH:
		case SADB_EXT_KEY_ENCRYPT:
					key_print(ext); break;
		case SADB_EXT_IDENTITY_SRC:
		case SADB_EXT_IDENTITY_DST:
					DBG(" [identity...]"); break;
		case SADB_EXT_SENSITIVITY:
					DBG(" [sensitivity...]"); break;
		case SADB_EXT_PROPOSAL:
					DBG(" [proposal...]"); break;
		case SADB_EXT_SUPPORTED_AUTH:
		case SADB_EXT_SUPPORTED_ENCRYPT:
					supported_print(ext); break;
		case SADB_EXT_SPIRANGE:
					DBG(" [spirange...]"); break;
		default:	DBG(" [unknown extension %d]", ext->sadb_ext_type);
		}
		msglen -= ext->sadb_ext_len << 3;
		ext = (char *)ext + (ext->sadb_ext_len << 3);
	}
}


/* include Socket */
int
Socket(int family, int type, int protocol) {

    int n;

    if ( (n = socket(family, type, protocol)) < 0)
        ERR("socket error");
    return(n);
}
/* end Socket */

void
Write(int fd, void *ptr, size_t nbytes) {

    if (write(fd, ptr, nbytes) != nbytes)
        ERR("write error");
}

ssize_t
Read(int fd, void *ptr, size_t nbytes) {

        ssize_t n;

        if ( (n = read(fd, ptr, nbytes)) == -1)
                ERR("read error");
        return(n);
}

char *
sock_ntop(const struct sockaddr *sa, socklen_t salen) {

    char portstr[7];
    static char str[128];		/* Unix domain is largest */

	switch (sa->sa_family) {
	case AF_INET: {
		struct sockaddr_in	*sin = (struct sockaddr_in *) sa;
		if (inet_ntop(AF_INET, &sin->sin_addr, str, sizeof(str)) == NULL)
			return(NULL);
		if (ntohs(sin->sin_port) != 0) {
			snprintf(portstr, sizeof(portstr), ".%d", ntohs(sin->sin_port));
			strcat(str, portstr);
		}
		return(str);
	}
/* end sock_ntop */
	}
}





