#include "pfkeyv2_utils.h"
void print_sadb_msg(struct sadb_msg *msg, int msglen) {

	struct sadb_ext *ext;

	DBG("------------------------------------");

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

void  sa_print(struct sadb_ext *ext) {

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

void supported_print(struct sadb_ext *ext) {

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

void lifetime_print(struct sadb_ext *ext) {

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

void key_print(struct sadb_ext *ext) {

	struct sadb_key *key = (struct sadb_key *)ext;
	int bits;
	unsigned char *p;

	DBG(" %s key, %d bits: 0x",
		key->sadb_key_exttype == SADB_EXT_KEY_AUTH ?
		"Authentication" : "Encryption",
		key->sadb_key_bits);
}

