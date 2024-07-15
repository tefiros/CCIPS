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

#include "pfkeyv2_entry.h"
#include "sad_entry.h"


int pf_register_apply(const sr_val_t *input, const size_t input_cnt, int pid);
char * pf_get_alg_enum_name(struct sadb_alg * alg, struct sadb_supported *sup);

static pthread_mutex_t pf_sadb_esp_register_run_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t pf_sadb_ah_register_run_lock = PTHREAD_MUTEX_INITIALIZER;


int pf_fill_sa_node(sad_entry_node *node, struct sadb_msg *msgp, int msglen){

    int rc = SR_ERR_OK;
    struct sadb_ext *ext;

    DBG ("fill sa node...");
    msglen -= sizeof(struct sadb_msg);
    ext = (struct sadb_ext *)(msgp + 1);

    while (msglen > 0) {

        struct sadb_sa *sa;
        struct sadb_x_sa2 *sa2;
        struct sadb_lifetime *life;
        time_t a = NULL;

        switch (ext->sadb_ext_type) {
            case SADB_EXT_SA: 
                sa = (struct sadb_sa *)ext;
                node->spi = ntohl(sa->sadb_sa_spi);
                node->encrypt_alg = sa->sadb_sa_encrypt;
                node->auth_alg = sa->sadb_sa_auth;
                node->state = sa->sadb_sa_state;
                node->replay = sa->sadb_sa_replay;
                break;
            case SADB_X_EXT_SA2: 
                sa2 = (struct sadb_x_sa2 *)ext;
                node->rule_number = sa2->sadb_x_sa2_reqid;
                node->seq_number = sa2->sadb_x_sa2_sequence;
                break;
            case SADB_EXT_LIFETIME_CURRENT:
                life = (struct sadb_lifetime *)ext;
                node->lft_packet_current = life->sadb_lifetime_allocations;
                node->lft_byte_current = life->sadb_lifetime_bytes;
                a = life->sadb_lifetime_addtime;
                node->lft_current_add_expires_seconds = (uint64_t)a;
                if (life->sadb_lifetime_usetime == 0) {
                    //DBG("never used");
                    node->lft_current_use_expires_seconds = 0;
                } else {
                    time_t u = life->sadb_lifetime_usetime;
                    node->lft_current_use_expires_seconds = (uint64_t)u;
                }
                break;
            case SADB_EXT_LIFETIME_SOFT:
                life = (struct sadb_lifetime *)ext;
                node->lft_packet_soft = life->sadb_lifetime_allocations;
                node->lft_byte_soft= life->sadb_lifetime_bytes;
                a = life->sadb_lifetime_addtime;
                node->lft_soft_add_expires_seconds = (uint64_t)a;
                if (life->sadb_lifetime_usetime == 0) {
                    //DBG("never used");
                    node->lft_soft_use_expires_seconds = 0;
                } else {
                    time_t u = life->sadb_lifetime_usetime;
                    node->lft_soft_use_expires_seconds = (uint64_t)u;
                }
                break;
            case SADB_EXT_LIFETIME_HARD:
                life = (struct sadb_lifetime *)ext;
                node->lft_packet_hard = life->sadb_lifetime_allocations;
                node->lft_byte_hard = life->sadb_lifetime_bytes;
                a = life->sadb_lifetime_addtime;
                node->lft_hard_add_expires_seconds = (uint64_t)a;
                if (life->sadb_lifetime_usetime == 0) {
                    //DBG("never used");
                    node->lft_hard_use_expires_seconds = 0;
                } else {
                    time_t u = life->sadb_lifetime_usetime;
                    node->lft_hard_use_expires_seconds = (uint64_t)u;
                }
                break;      
        }
        msglen -= ext->sadb_ext_len << 3;
        ext = (char *)ext + (ext->sadb_ext_len << 3);
    }

    return rc;
}


static void* pf_sadb_esp_register_run(void* register_thread_info){

    char buf[4096];
	int     s, mypid;
    char *ntf = NULL;
	sr_session_ctx_t *session =NULL;
    int rc = 0;

	register_thread *info = (register_thread*) register_thread_info;
    mypid = (*info).parent_pid;
    s = (*info).socket;
	session = (*info).session;

	//pthread_mutex_lock(&sadb_register_run_lock);

	for ( ; ; ) {
        int     msglen;
        struct sadb_msg *msgp;
        msglen = Read(s, &buf, sizeof(buf));
        msgp = (struct sadb_msg *) &buf;
        
        if (msgp->sadb_msg_type == SADB_ACQUIRE) {
        	INFO("SADB_ACQUIRE received");
            print_sadb_msg(msgp,msglen);
            DBG("print_sadb_msg sadb_esp_register_run end ..."); 
  		    send_acquire_notification(session,msgp,msglen);
        }  
	    else if (msgp->sadb_msg_type == SADB_EXPIRE) {
            INFO("SADB_EXPIRE received");
            print_sadb_msg(msgp,msglen);
            DBG("print_sadb_msg sadb_esp_register_run end");    
            send_sa_expire_notification(session,msgp,msglen);   
            
            // if hard expire then delete SA entry in running config
            // get SPI and checks if it is hard or soft
            int spi = 0;
            bool hard = false;
            struct sadb_ext *ext;
            msglen -= sizeof(struct sadb_msg);
            ext = (struct sadb_ext *)(msgp + 1);

            while (msglen > 0) {
        
                struct sadb_sa *sa;
                struct sadb_lifetime *life;;

                switch (ext->sadb_ext_type) {
                    case SADB_EXT_SA: 
                        sa = (struct sadb_sa *)ext;
                        spi = ntohl(sa->sadb_sa_spi);
                        break;
                    case SADB_EXT_LIFETIME_HARD:
                        hard = true;
                        break;
                }
                msglen -= ext->sadb_ext_len << 3;
                ext = (char *)ext + (ext->sadb_ext_len << 3);
            }
            if (hard) {
                if (SR_ERR_OK == send_delete_SAD_request(spi)) {
                    INFO("SADB_ entry deleted in running: %i", spi); 
                }
            }                
            
        } else {
            DBG("Unknown SADB notification received.");
        }
        
    }
    pthread_mutex_unlock(&pf_sadb_esp_register_run_lock);
    close(s);
    return NULL;
}

static void* pf_sadb_ah_register_run(void* register_thread_info){

    char buf[4096];
    int s, mypid;
    char *ntf = NULL;
    sr_session_ctx_t *session =NULL;
    int rc = 0;

    register_thread *info = (register_thread*) register_thread_info;
    mypid = (*info).parent_pid;
    s = (*info).socket;
    session = (*info).session;

    //pthread_mutex_lock(&sadb_register_run_lock);

    for ( ; ; ) {
        int     msglen;
        struct sadb_msg *msgp;
        msglen = Read(s, &buf, sizeof(buf));
        msgp = (struct sadb_msg *) &buf;
        
        if (msgp->sadb_msg_type == SADB_ACQUIRE) {
            INFO("SADB_ACQUIRE received...");
            print_sadb_msg(msgp,msglen);
            DBG("print_sadb_msg sadb_ah_register_run end");
            send_acquire_notification(session,msgp,msglen);
        }  
        else if (msgp->sadb_msg_type == SADB_EXPIRE) {
            INFO("SADB_EXPIRE received...");
            print_sadb_msg(msgp,msglen);
            DBG("print_sadb_msg sadb_ah_register_run end");
            send_sa_expire_notification(session,msgp,msglen);           
            
            // if hard expire then delete SA entry in running config
            // get SPI and checks if it is hard or soft


            int spi = 0;
            bool hard = false;
            struct sadb_ext *ext;
            msglen -= sizeof(struct sadb_msg);
            ext = (struct sadb_ext *)(msgp + 1);

            while (msglen > 0) {
        
                struct sadb_sa *sa;
                struct sadb_lifetime *life;;

                switch (ext->sadb_ext_type) {
                    case SADB_EXT_SA: 
                        sa = (struct sadb_sa *)ext;
                        spi = ntohl(sa->sadb_sa_spi);
                        break;
                    case SADB_EXT_LIFETIME_HARD:
                        hard = true;
                        break;
                }
                msglen -= ext->sadb_ext_len << 3;
                ext = (char *)ext + (ext->sadb_ext_len << 3);
            }
            if (hard) {
                if (SR_ERR_OK == send_delete_SAD_request(spi)) {
                    INFO("SADB_ entry deleted in running: %i", spi); 
                }
            }                
            
        } else {
            DBG("Unknown SADB notification received. ");
        }
        
    }
    pthread_mutex_unlock(&pf_sadb_ah_register_run_lock);
    close(s);
    return NULL;
}


int pf_exec_register(sr_session_ctx_t *session, char *xpath, int satype, const sr_val_t *input, const size_t input_cnt,sr_val_t **output, size_t *output_cnt, void *private_ctx){

	char buf[4096];
    int r;
    pthread_t pf_sadb_esp_register_run_thread;
    pthread_t pf_sadb_ah_register_run_thread;
    char *emsg = NULL;
	int rc = SR_ERR_OK;

    DBG ("exec register for %s ", xpath);
    if (satype == SADB_SATYPE_ESP) {
        //DBG("pf_exec_register satype: %i", satype);
	   if (pthread_mutex_trylock(&pf_sadb_esp_register_run_lock) != 0) {
           rc = SR_ERR_OPERATION_FAILED;
	       ERR("sadb_register esp is still running: %s", sr_strerror(rc));
	       return rc;	
        }
    } else if (satype == SADB_SATYPE_AH) {
       if (pthread_mutex_trylock(&pf_sadb_ah_register_run_lock) != 0) {
           rc = SR_ERR_OPERATION_FAILED;
           ERR("sadb_register ah is still running: %s", sr_strerror(rc));
           return rc;  
        }
    } else {
            rc = SR_ERR_OPERATION_FAILED;
            ERR("sadb_register error satype invalid: %s", sr_strerror(rc));
            return rc; 
    }

    int pid = getpid();
	int s = pf_register_apply(input,input_cnt, pid);
    register_thread *info = malloc(sizeof(register_thread));
    info->socket=s;
    info->parent_pid=pid;	
	info->session=session;

	int msglen;
    struct sadb_msg *msgp;
    msglen = Read(s, &buf, sizeof(buf));
    msgp = (struct sadb_msg *) &buf;
    if (msgp->sadb_msg_pid == pid && msgp->sadb_msg_type == SADB_REGISTER) {
       	DBG("send_register_reply  ... ");
		rc = pf_send_register_reply(msgp, msglen,output,output_cnt,private_ctx);
		if (SR_ERR_OK != rc) {
        	ERR("sr_get_items: %s", sr_strerror(rc));
        	return rc;
    	} else {
            DBG("print_sadb_msg exec_register");
       		print_sadb_msg(msgp, msglen);
		}
    }

    if (satype == SADB_SATYPE_ESP) {
        if ((r = pthread_create(&pf_sadb_esp_register_run_thread, NULL, &pf_sadb_esp_register_run, (void *)info)) != 0) {
            ERR("Unable to start sadb_esp_register thread (%s)", strerror(r));
            return SR_ERR_OPERATION_FAILED;
        }
    } else if (satype == SADB_SATYPE_AH) {
        if ((r = pthread_create(&pf_sadb_ah_register_run_thread, NULL, &pf_sadb_ah_register_run, (void *)info)) != 0) {
            ERR("Unable to start sadb_ah_register thread (%s)", strerror(r));
            return SR_ERR_OPERATION_FAILED;
        }
    }    
	
    return EXIT_SUCCESS;
}



int pf_register_apply(const sr_val_t *input, const size_t input_cnt, int pid){

    int s;
    struct sadb_msg msg;
    int mypid;
    /*** Base Message Header Parameters ***/
    int version;
    int type;
	int satype = 0;
	int i;	
	char * name = NULL;


	for (i = 0; i < input_cnt; i++) {	
		name = strrchr(input[i].xpath, '/');
        //DBG("pf_register_apply: %s", name);
		if (0 == strcmp (name,"/version")) {
			if(0 == strcmp(input[i].data.string_val,"PF_KEY_V2")) {
                version = PF_KEY_V2;
                DBG("pf_register_apply version: %i", version);
            }
        }
		else if (0 == strcmp (name,"/msg_type")) { 
            if(0 == strcmp(input[i].data.string_val,"sadb_register")) {
                type = SADB_REGISTER;
                DBG("pf_register_apply type: %i", type);
            }
        }
        else if (0 == strcmp (name,"/msg_satype")) {
            satype = pf_get_satype_define(input[i].data.string_val);
            DBG("pf_register_apply satype: %i", satype);
        }
        
	}

    s = Socket(PF_KEY, SOCK_RAW, version);
    mypid = pid;
        /* Build and write SADB_REGISTER request */
    bzero(&msg, sizeof(msg));
    msg.sadb_msg_version =  version;
    msg.sadb_msg_type = type;
    msg.sadb_msg_satype = satype;
    msg.sadb_msg_len = sizeof(msg) / 8;
    msg.sadb_msg_pid = mypid;
    
    Write(s, &msg, sizeof(msg));
    return s;
}

int pf_setsadbaddr(void *p, int exttype, int protocol, int prefixlen, int port, char ip[]){
    
    struct sockaddr_in *addr= malloc (sizeof(struct sockaddr_in));
    addr->sin_family = AF_INET; 
    addr->sin_port = htons(port); 
    addr->sin_addr.s_addr = inet_addr(ip);
    
    struct sadb_address *addrext = (struct sadb_address *) p;
    addrext->sadb_address_len = (sizeof(*addrext) + sizeof(struct sockaddr_in))/8 ;
    addrext->sadb_address_exttype = exttype;
    addrext->sadb_address_proto = protocol;
    addrext->sadb_address_prefixlen = prefixlen;
    addrext->sadb_address_reserved = 0;
    memcpy(addrext +1, addr, sizeof(struct sockaddr_in));

    return (addrext->sadb_address_len *8);

}

int pf_addpolicy(spd_entry_node *spd_node) {

    int s, len, error;
    char buf[PFKEY_BUFFER_SIZE], *p;
    struct sadb_msg *msg;
    struct sadb_x_policy *policyext;
    struct sadb_x_ipsecrequest *req;
    char buf2[PFKEY_BUFFER_SIZE];

    s = Socket(PF_KEY, SOCK_RAW, PF_KEY_V2);
    bzero(&buf, sizeof(buf));
    p = buf;
    msg = (struct sadb_msg *) p;
    msg->sadb_msg_version =  PF_KEY_V2;
    msg->sadb_msg_type = SADB_X_SPDADD;
    msg->sadb_msg_satype = spd_node->satype;
    msg->sadb_msg_pid = getpid();
    len = sizeof(*msg);
    p += sizeof(*msg);

    policyext = (struct sadb_x_policy *) p;
    policyext->sadb_x_policy_len = sizeof(struct sadb_x_policy)/8;
    policyext->sadb_x_policy_exttype = SADB_X_EXT_POLICY;
    policyext->sadb_x_policy_type = spd_node->action_policy_type;
    policyext->sadb_x_policy_dir = spd_node->policy_dir;
    policyext->sadb_x_policy_id = spd_node->policy_id; // doesn't work, policy_id is asigned by kernel 
    policyext->sadb_x_policy_priority =0;
    len += policyext->sadb_x_policy_len *8;
    p += policyext->sadb_x_policy_len *8;

    req = (struct sadb_x_ipsecrequest *) p;
    req->sadb_x_ipsecrequest_proto = spd_node->request_protocol;
    req->sadb_x_ipsecrequest_len = sizeof(struct sadb_x_ipsecrequest);
    req->sadb_x_ipsecrequest_mode = spd_node->mode;
    req->sadb_x_ipsecrequest_reqid = spd_node->policy_id;
    req->sadb_x_ipsecrequest_level = IPSEC_LEVEL_REQUIRE;
    len += req->sadb_x_ipsecrequest_len;
    p += req->sadb_x_ipsecrequest_len;

    if(spd_node->mode == IPSEC_MODE_TUNNEL){

        struct sockaddr_in *src_t= malloc(sizeof(struct sockaddr_in));
        src_t->sin_family = AF_INET;
        src_t->sin_port = htons(0);
        src_t->sin_addr.s_addr = inet_addr(spd_node->src_tunnel);

        struct sockaddr_in *dst_t= malloc(sizeof(struct sockaddr_in));
        dst_t->sin_family = AF_INET;
        dst_t->sin_port = htons(0);
        dst_t->sin_addr.s_addr = inet_addr(spd_node->dst_tunnel);

        memcpy(req + 1, src_t, sizeof(struct sockaddr_in));
        memcpy((char*)(req + 1) + sizeof(struct sockaddr_in), dst_t, sizeof(struct sockaddr_in));

        req->sadb_x_ipsecrequest_len += (sizeof(struct sockaddr_in)*2);
        len += (sizeof(struct sockaddr_in)*2);
        p += (sizeof(struct sockaddr_in)*2);
    }


    policyext->sadb_x_policy_len += (req->sadb_x_ipsecrequest_len/8);
   
    int src_len = pf_setsadbaddr(p,SADB_EXT_ADDRESS_SRC, spd_node->protocol_next_layer, get_mask(spd_node->src), spd_node->srcport, get_ip(spd_node->src));
    p += src_len; len += src_len;

    int dst_len = pf_setsadbaddr(p,SADB_EXT_ADDRESS_DST, spd_node->protocol_next_layer, get_mask(spd_node->dst), spd_node->dstport, get_ip(spd_node->dst));
    len += dst_len; p += dst_len;


    msg->sadb_msg_len = len/8;

    DBG("print_sadb_msg pfkeyv2_addpolicy");
    print_sadb_msg(buf, len);
    Write(s, buf, len);
    close(s);
    


    // read the policy index asigned by the kernel
    char tmp_src[30];
    char tmp_dst[30];
    char *tmp_dst_tunnel = "";
    char *tmp_src_tunnel = "";
    int tmp_satype;
    int tmp_request_protocol;
    int tmp_action_policy_type;
    int tmp_policy_dir;
    int tmp_protocol_next_layer;
    int tmp_srcport;
    int tmp_dstport;
    int tmp_mode;
    int tmp_index;

    s = Socket(PF_KEY, SOCK_RAW, PF_KEY_V2);

    int type = SADB_SATYPE_UNSPEC;
    struct sadb_msg tmp_msg;
    bzero(&tmp_msg, sizeof (tmp_msg));
    tmp_msg.sadb_msg_version = PF_KEY_V2;
    tmp_msg.sadb_msg_type = SADB_X_SPDDUMP;
    tmp_msg.sadb_msg_satype = spd_node->satype;
    tmp_msg.sadb_msg_len = sizeof (tmp_msg) / 8;
    tmp_msg.sadb_msg_pid = getpid();
    //print_sadb_msg (&msg, sizeof (msg));
    Write(s, &tmp_msg, sizeof (tmp_msg));

       
    int goteof = 0;
    while (goteof == 0) {
        int     msglen;
        struct sadb_msg *msgp;

        msglen = Read(s, &buf2, sizeof (buf2));
        msgp = (struct sadb_msg *) &buf2;
        
        if (msglen != msgp->sadb_msg_len * 8) {
            ERR("SADB Message length (%d) doesn't match msglen (%d)",
            msgp->sadb_msg_len * 8, msglen);
            return SR_ERR_OPERATION_FAILED;
        }
        if (msgp->sadb_msg_version != PF_KEY_V2) {
            ERR("SADB Message version not PF_KEY_V2");
            return SR_ERR_OPERATION_FAILED;
        }
        if (msgp->sadb_msg_errno != 0)
            ERR("Unknown error %s", strerror(msgp->sadb_msg_errno));
        if (msglen == sizeof(struct sadb_msg))
            return SR_ERR_OPERATION_FAILED; 

        msglen -= sizeof(struct sadb_msg);
        struct sadb_ext *ext;
        ext = (struct sadb_ext *)(msgp + 1);

        while (msglen > 0) {
        
            struct sadb_x_policy *policy;
            struct sockaddr *sa;
            struct sadb_address *addr;

            switch (ext->sadb_ext_type) {
                case SADB_X_EXT_POLICY: 
                    //policy = (struct sadb_x_sa2 *)ext;
                    policy = (struct sadb_x_policy *)ext;
                    tmp_index = policy->sadb_x_policy_id;
                    tmp_action_policy_type = policy->sadb_x_policy_type;
                    tmp_policy_dir = policy->sadb_x_policy_dir;

                    struct sadb_x_ipsecrequest *xisr;
                    size_t off = sizeof(*policy);
                    while (off < PFKEY_EXTLEN(policy)) {    
                        int offset;
                        xisr = (void *)((caddr_t)(void *)policy + off);
                        tmp_mode = xisr->sadb_x_ipsecrequest_mode;
                        tmp_request_protocol = xisr->sadb_x_ipsecrequest_proto;
                        off += xisr->sadb_x_ipsecrequest_len;
                    }    

                    break;
                case SADB_EXT_ADDRESS_SRC:
                case SADB_EXT_ADDRESS_DST:
                    addr = (struct sadb_address *)ext;
                    sa = (struct sockaddr *)(addr + 1);
                    if (addr->sadb_address_exttype == SADB_EXT_ADDRESS_SRC)
                        strcpy(tmp_src,sock_ntop(sa, addr->sadb_address_len * 8 - sizeof(*addr)));
                    else 
                        strcpy(tmp_dst,sock_ntop(sa, addr->sadb_address_len * 8 - sizeof(*addr)));
                    
                    break;
                //default: printf("ext type: %i", ext->sadb_ext_type);

            }
            
            msglen -= ext->sadb_ext_len << 3;
            ext = (char *)ext + (ext->sadb_ext_len << 3);
        }

        if ((strcmp(get_ip(spd_node->src),tmp_src) == 0) &&
            (strcmp(get_ip(spd_node->dst),tmp_dst) == 0) &&
            //(strcmp(spd_node->src_tunnel, tmp_src_tunnel) == 0) &&
            //(strcmp(spd_node->dst_tunnel, tmp_dst_tunnel) == 0) &&
            //(satype == tmp_satype) &&
            //(spd_node->request_protocol == tmp_request_protocol) &&
            //(spd_node->action_policy_type == tmp_action_policy_type) &&
            (spd_node->policy_dir == tmp_policy_dir) 
            //(spd_node->mode == tmp_mode)
            ) {
                spd_node->index = tmp_index;
                goteof = 1;
                break;
        } 

        if (msgp->sadb_msg_seq == 0)
             goteof = 1;
    }

    
    close(s);  

    DBG("print_sadb_msg pfkeyv2_addpolicy end"); 

    return SR_ERR_OK;

}

int pf_delpolicy(spd_entry_node *spd_node) {

    char buf[PFKEY_BUFFER_SIZE], *p;
    struct sadb_msg *msg;
    struct sadb_x_policy *policyext;
    int s, len,i;

    s = Socket(PF_KEY, SOCK_RAW, PF_KEY_V2);
    bzero(&buf, sizeof(buf));

    p = buf;
    msg = (struct sadb_msg *) p;
    msg->sadb_msg_version =  PF_KEY_V2;
    msg->sadb_msg_type = SADB_X_SPDDELETE;
    msg->sadb_msg_satype = spd_node->satype;
    len = sizeof(*msg);
    p += sizeof(*msg);

    policyext = (struct sadb_x_policy *) p;
    policyext->sadb_x_policy_len = sizeof(struct sadb_x_policy)/8;
    policyext->sadb_x_policy_exttype = SADB_X_EXT_POLICY;
    policyext->sadb_x_policy_type = spd_node->action_policy_type;
    policyext->sadb_x_policy_dir = spd_node->policy_dir;
    len += policyext->sadb_x_policy_len *8;
    p += policyext->sadb_x_policy_len *8;

    int src_len = pf_setsadbaddr(p,SADB_EXT_ADDRESS_SRC, spd_node->protocol_next_layer, get_mask(spd_node->src), spd_node->srcport, get_ip(spd_node->src));
    p += src_len; len += src_len;

    int dst_len = pf_setsadbaddr(p,SADB_EXT_ADDRESS_DST, spd_node->protocol_next_layer, get_mask(spd_node->dst), spd_node->dstport, get_ip(spd_node->dst));
    len += dst_len; p += dst_len;

    msg->sadb_msg_len = len/8;

    DBG("print_sadb_msg pfkeyv2_delpolicy");
    print_sadb_msg(buf, len);

    Write(s, buf, len);
    close(s);

    return SR_ERR_OK;

}



int pf_addsad(sad_entry_node *sad_node) {

    int s;
    char buf[4096], *p;
    struct sadb_msg *msg;
    struct sadb_sa *saext;
    struct sadb_x_sa2 *sa2;
    struct sadb_key *keyext;
    struct sadb_address *addrext;
    int len;
    int mypid;
    int rc = SR_ERR_OK;

    s = Socket(PF_KEY, SOCK_RAW, PF_KEY_V2);
    mypid = getpid();
    //http://www.cs.fsu.edu/~baker/devices/lxr/source/2.6.31.13/linux/net/key/af_key.c 
    // Build and write SADB_ADD request 
    bzero(&buf, sizeof(buf));
    p = buf;
    msg = (struct sadb_msg *) p;
    msg->sadb_msg_version = PF_KEY_V2;
    msg->sadb_msg_type = SADB_ADD;
    msg->sadb_msg_satype = sad_node->satype;
    msg->sadb_msg_pid = getpid();
    len = sizeof(*msg);
    p += sizeof(*msg);

    saext = (struct sadb_sa *) p;
    saext->sadb_sa_len = sizeof(struct sadb_sa)/ 8;
    saext->sadb_sa_exttype = SADB_EXT_SA;
    saext->sadb_sa_spi = htonl(sad_node->spi);
    saext->sadb_sa_replay = sad_node->replay;
    saext->sadb_sa_state = SADB_SASTATE_MATURE;
    saext->sadb_sa_encrypt = sad_node->encrypt_alg;
    saext->sadb_sa_auth = sad_node->auth_alg;
    saext->sadb_sa_flags = 0;
    len += saext->sadb_sa_len * 8;
    p += saext->sadb_sa_len * 8;

    sa2 = (struct sadb_x_sa2*) p;
    sa2->sadb_x_sa2_exttype = SADB_X_EXT_SA2;
    sa2->sadb_x_sa2_len = sizeof(struct sadb_spirange)/8;
    sa2->sadb_x_sa2_mode = sad_node->mode;
    sa2->sadb_x_sa2_reqid = sad_node->rule_number;
    sa2->sadb_x_sa2_sequence = sad_node->seq_number;
    len += sa2->sadb_x_sa2_len * 8;
    p += sa2->sadb_x_sa2_len * 8;
    
    struct sadb_lifetime *lifetime;
    
    lifetime = (struct sadb_lifetime *)p;
    lifetime->sadb_lifetime_len = sizeof(struct sadb_lifetime)/sizeof(uint64_t);
    lifetime->sadb_lifetime_exttype = SADB_EXT_LIFETIME_HARD;
    lifetime->sadb_lifetime_allocations =  sad_node->lft_packet_hard;
    lifetime->sadb_lifetime_bytes = sad_node->lft_byte_hard;
    lifetime->sadb_lifetime_usetime = sad_node->lft_hard_use_expires_seconds;
    lifetime->sadb_lifetime_addtime = sad_node->lft_hard_add_expires_seconds;
    len += lifetime->sadb_lifetime_len * 8;
    p += lifetime->sadb_lifetime_len * 8;
    
    lifetime = (struct sadb_lifetime *) p;
    lifetime->sadb_lifetime_len = sizeof(struct sadb_lifetime)/sizeof(uint64_t);
    lifetime->sadb_lifetime_exttype = SADB_EXT_LIFETIME_SOFT;
    lifetime->sadb_lifetime_allocations =  sad_node->lft_packet_soft;
    lifetime->sadb_lifetime_bytes = sad_node->lft_byte_soft;
    lifetime->sadb_lifetime_usetime = sad_node->lft_soft_use_expires_seconds;
    lifetime->sadb_lifetime_addtime = sad_node->lft_soft_add_expires_seconds;
    len += lifetime->sadb_lifetime_len * 8;
    p += lifetime->sadb_lifetime_len * 8;


    if(sad_node->mode == IPSEC_MODE_TUNNEL){
    
        int src_len = pf_setsadbaddr(p,SADB_EXT_ADDRESS_SRC, sad_node->protocol_next_layer, 32, sad_node->srcport, sad_node->src_tunnel);
        p += src_len; len += src_len;
        int dst_len = pf_setsadbaddr(p,SADB_EXT_ADDRESS_DST, sad_node->protocol_next_layer, 32, sad_node->dstport, sad_node->dst_tunnel);
        len += dst_len; p += dst_len;
    
    } else {

        int src_len = pf_setsadbaddr(p,SADB_EXT_ADDRESS_SRC, sad_node->protocol_next_layer, get_mask(sad_node->src), sad_node->srcport, get_ip(sad_node->src));
        p += src_len; len += src_len;    
        int dst_len = pf_setsadbaddr(p,SADB_EXT_ADDRESS_DST, sad_node->protocol_next_layer, get_mask(sad_node->dst), sad_node->dstport, get_ip(sad_node->dst));
        len += dst_len; p += dst_len;
    }

    if(sad_node->encrypt_alg != SADB_EALG_NONE){
            keyext = (struct sadb_key *) p;
            keyext->sadb_key_exttype = SADB_EXT_KEY_ENCRYPT;
            keyext->sadb_key_reserved = 0;
            if(sad_node->encrypt_alg == SADB_EALG_DESCBC){
                    keyext->sadb_key_len = (sizeof(*keyext) + (EALG_DESCBC_KEY_BITS/8) + 7) / 8;
                    keyext->sadb_key_bits = EALG_DESCBC_KEY_BITS;
            }
            else{
                    keyext->sadb_key_len = (sizeof(*keyext) + (EALG_3DESCBC_KEY_BITS/8) + 7) / 8;
                    keyext->sadb_key_bits = EALG_3DESCBC_KEY_BITS;
            }
            memcpy(keyext + 1, sad_node->encrypt_key, strlen(sad_node->encrypt_key));
            len += keyext->sadb_key_len * 8;
            p += keyext->sadb_key_len * 8;
    }

    if(sad_node->auth_alg != SADB_AALG_NONE){
        keyext = (struct sadb_key *) p;
            keyext->sadb_key_exttype = SADB_EXT_KEY_AUTH;
            keyext->sadb_key_reserved = 0;
            if(sad_node->auth_alg == AALG_MD5HMAC_KEY_BITS){
                    keyext->sadb_key_len = (sizeof(*keyext) + (AALG_MD5HMAC_KEY_BITS/8) + 7) / 8;
                    keyext->sadb_key_bits = AALG_MD5HMAC_KEY_BITS;
            }
            else{
                    keyext->sadb_key_len = (sizeof(*keyext) + (AALG_SHA1HMAC_KEY_BITS/8) + 7) / 8;
                    keyext->sadb_key_bits = AALG_SHA1HMAC_KEY_BITS;
            }
            memcpy(keyext + 1, sad_node->auth_key,  strlen(sad_node->auth_key));
            len += keyext->sadb_key_len * 8;
            p += keyext->sadb_key_len * 8;
    }


    msg->sadb_msg_len = len / 8;
    DBG("print_sadb_msg pfkeyv2_addsad:");
    print_sadb_msg(buf, len);
    Write(s, buf, len);
    close(s);

    return SR_ERR_OK;

}

int pf_delsad(sad_entry_node *sad_node) {


    struct sadb_msg *msg;
    struct sadb_x_policy *policyext;
    int s, len, spi;
    int rc = SR_ERR_OK;
    char buf[4096], *p;
    struct sadb_sa *saext;
    struct sadb_x_sa2 *sa2;
    struct sadb_key *keyext;
    struct sadb_address *addrext;
    int mypid;

    s = Socket(PF_KEY, SOCK_RAW, PF_KEY_V2);
    mypid = getpid();

    // Build and write SADB_ADD request 
    bzero(&buf, sizeof(buf));
    p = buf;
    msg = (struct sadb_msg *) p;
    msg->sadb_msg_version = PF_KEY_V2;
    msg->sadb_msg_type = SADB_DELETE;
    msg->sadb_msg_satype = sad_node->satype;
    msg->sadb_msg_pid = getpid();
    len = sizeof(*msg);
    p += sizeof(*msg);

    saext = (struct sadb_sa *) p;
    saext->sadb_sa_len = sizeof(struct sadb_sa)/ 8;
    saext->sadb_sa_exttype = SADB_EXT_SA;
    saext->sadb_sa_spi = htonl(sad_node->spi);
    len += saext->sadb_sa_len * 8;
    p += saext->sadb_sa_len * 8;


    int src_len = pf_setsadbaddr(p,SADB_EXT_ADDRESS_SRC, sad_node->protocol_next_layer, get_mask(sad_node->src), sad_node->srcport, get_ip(sad_node->src));
    p += src_len; len += src_len;    
    int dst_len = pf_setsadbaddr(p,SADB_EXT_ADDRESS_DST, sad_node->protocol_next_layer, get_mask(sad_node->dst), sad_node->dstport, get_ip(sad_node->dst));
    len += dst_len; p += dst_len;

    msg->sadb_msg_len = len / 8;
    DBG("print_sadb_msg pfkeyv2_delsad:");
    print_sadb_msg(buf, len);
   
    Write(s, buf, len);
    close(s);

    return SR_ERR_OK;
}

int
pf_get_spd_lifetime_current_by_rule(spd_entry_node *node) {

    struct sadb_ext *ext;
    int i = 0;
    int s;
    char buf[4096];
    struct sadb_msg msg;
    int goteof;
    int rc = 0;
    int type = SADB_SATYPE_UNSPEC;

    s = Socket(PF_KEY, SOCK_RAW, PF_KEY_V2);
  
      /* Build and write SADB_DUMP request */
    bzero(&msg, sizeof (msg));
    msg.sadb_msg_version = PF_KEY_V2;
    msg.sadb_msg_type = SADB_X_SPDDUMP;
    msg.sadb_msg_satype = type;
    msg.sadb_msg_len = sizeof (msg) / 8;
    msg.sadb_msg_pid = getpid();
    //print_sadb_msg (&msg, sizeof (msg));
    Write(s, &msg, sizeof (msg));

     /* Read and print SADB_DUMP replies until done */
    goteof = 0;
    while (goteof == 0) {
        int     msglen;
        struct sadb_msg *msgp;

        msglen = Read(s, &buf, sizeof (buf));
        msgp = (struct sadb_msg *) &buf;
        

        if (msglen != msgp->sadb_msg_len * 8) {
            ERR("SADB Message length (%d) doesn't match msglen (%d)",
            msgp->sadb_msg_len * 8, msglen);
            return SR_ERR_OPERATION_FAILED;
        }
        if (msgp->sadb_msg_version != PF_KEY_V2) {
            ERR("SADB Message version not PF_KEY_V2");
            return SR_ERR_OPERATION_FAILED;
        }
        if (msgp->sadb_msg_errno != 0)
            ERR("Unknown errno %s", strerror(msgp->sadb_msg_errno));
        if (msglen == sizeof(struct sadb_msg))
            return SR_ERR_OPERATION_FAILED; /* no extensions */
        msglen -= sizeof(struct sadb_msg);
        ext = (struct sadb_ext *)(msgp + 1);

        while (msglen > 0) {
        
            struct sadb_x_policy *policy;
            struct sadb_lifetime *life;;

            switch (ext->sadb_ext_type) {
                case SADB_X_EXT_POLICY: 
                    policy = (struct sadb_x_policy *)ext;
                    if (policy->sadb_x_policy_id == node->index) {
                        DBG("SPD rule_number: %i, index: %i found",node->policy_id, node->index);
                        i = 1;
                    }  
                    break;
                case SADB_EXT_LIFETIME_CURRENT:
                    life = (struct sadb_lifetime *)ext;
                    node->lft_packet_current= life->sadb_lifetime_allocations;
                    node->lft_byte_current = life->sadb_lifetime_bytes;
                    time_t a = life->sadb_lifetime_addtime;
                    node->lft_current_add_expires_seconds = (uint64_t)a;
                    if (life->sadb_lifetime_usetime == 0) {
                        //DBG("never used");
                        node->lft_current_use_expires_seconds = 0;
                    } else {
                        time_t u = life->sadb_lifetime_usetime;
                        node->lft_current_use_expires_seconds = (uint64_t)u;
                    }
                    break;
                //default: DBG("ext type: %i", ext->sadb_ext_type);
            }
            msglen -= ext->sadb_ext_len << 3;
            ext = (char *)ext + (ext->sadb_ext_len << 3);
        }

        if (i == 1) return SR_ERR_OK;
        if (msgp->sadb_msg_seq == 0)
             goteof = 1;
    }
    close(s);

    return SR_ERR_NOT_FOUND;

}

int pf_get_sad_lifetime_current_by_spi(sad_entry_node *node)
{

    struct sadb_ext *ext;
    int i = 0;
    int s;
    char buf[4096];
    struct sadb_msg msg;
    int goteof;
    int rc = 0;   
    int type = SADB_SATYPE_UNSPEC;

    s = Socket(PF_KEY, SOCK_RAW, PF_KEY_V2);
    
      /* Build and write SADB_DUMP request */
    bzero(&msg, sizeof (msg));
    msg.sadb_msg_version = PF_KEY_V2;
    msg.sadb_msg_type = SADB_DUMP;
    msg.sadb_msg_satype = type;
    msg.sadb_msg_len = sizeof (msg) / 8;
    msg.sadb_msg_pid = getpid();
    //print_sadb_msg (&msg, sizeof (msg));
    Write(s, &msg, sizeof (msg));

     /* Read and print SADB_DUMP replies until done */
    goteof = 0;
    while (goteof == 0) {
        int     msglen;
        struct sadb_msg *msgp;

        msglen = Read(s, &buf, sizeof (buf));
        msgp = (struct sadb_msg *) &buf;
        

        if (msglen != msgp->sadb_msg_len * 8) {
            ERR("SADB Message length (%d) doesn't match msglen (%d)",
            msgp->sadb_msg_len * 8, msglen);
            return SR_ERR_OPERATION_FAILED;
        }
        if (msgp->sadb_msg_version != PF_KEY_V2) {
            ERR("SADB Message version not PF_KEY_V2");
            return SR_ERR_OPERATION_FAILED;
        }
        if (msgp->sadb_msg_errno != 0)
            ERR("Unknown errno %s", strerror(msgp->sadb_msg_errno));
        if (msglen == sizeof(struct sadb_msg))
            return SR_ERR_OPERATION_FAILED; /* no extensions */
        msglen -= sizeof(struct sadb_msg);
        ext = (struct sadb_ext *)(msgp + 1);

        while (msglen > 0) {
        
            struct sadb_sa *sa;
            struct sadb_lifetime *life;;

            switch (ext->sadb_ext_type) {
                case SADB_EXT_SA: 
                    sa = (struct sadb_sa *)ext;
                    if (ntohl(sa->sadb_sa_spi) == node->spi) {
                        DBG("SA %i found",node->spi);
                        i = 1;
                    }  
                    break;
                    
                case SADB_EXT_LIFETIME_CURRENT:
                    life = (struct sadb_lifetime *)ext;
                    node->lft_packet_current = life->sadb_lifetime_allocations;
                    node->lft_byte_current = life->sadb_lifetime_bytes;
                    time_t a = life->sadb_lifetime_addtime;
                    node->lft_current_add_expires_seconds = (uint64_t)a;
                    if (life->sadb_lifetime_usetime == 0) {
                        //DBG("never used");
                        node->lft_current_use_expires_seconds = 0;
                    } else {
                        time_t u = life->sadb_lifetime_usetime;
                        node->lft_current_use_expires_seconds = (uint64_t)u;
                    }
                    break;
                //default: DBG("ext type: %i", ext->sadb_ext_type);
            }
            msglen -= ext->sadb_ext_len << 3;
            ext = (char *)ext + (ext->sadb_ext_len << 3);
        }

        if (i == 1) return SR_ERR_OK;

        if (msgp->sadb_msg_seq == 0)
             goteof = 1;
    }
    close(s);

    return SR_ERR_NOT_FOUND;

}



int pf_send_register_reply(struct sadb_msg *msgp, int msglen, sr_val_t **output, size_t *output_cnt, void *private_ctx){

    int rc = SR_ERR_OK;
    int add_alg = 0;
    int add_address = 0;
    int add_proposal = 0;
    int add_lifetime = 0;
    struct sadb_ext *ext;

    DBG("pf_send_register_reply .... ");
    sr_session_ctx_t *session = (sr_session_ctx_t *)private_ctx;
    rc = create_base_grouping(msgp,msglen,"/ietf-ipsec:sadb_register",output,output_cnt,session);
    if (SR_ERR_OK != rc) {
        ERR("create_base_grouping: %s", sr_strerror(rc));
        return rc;
    }

    //
    // EXTENSIONS 
    //  
    msglen -= sizeof(struct sadb_msg);
    ext = (struct sadb_ext *)(msgp + 1);
    while (msglen > 0) {
        switch (ext->sadb_ext_type) {
            case SADB_EXT_SA:
                DBG("SADB_EXT_SA found!");
                break;
            case SADB_EXT_LIFETIME_CURRENT:
            case SADB_EXT_LIFETIME_HARD:
            case SADB_EXT_LIFETIME_SOFT:
                DBG("SADB_EXT_LIFETIME_SOFT found!");  
                break;
            case SADB_EXT_SUPPORTED_AUTH:
            case SADB_EXT_SUPPORTED_ENCRYPT:
                DBG("SADB_EXT_SUPPORTED_ENCRYPT found!");
                rc = pf_supported_xml_node(output,output_cnt,ext);
                if (rc != SR_ERR_OK) {
                    ERR("create rpc reply error: %s",sr_strerror(rc));
                    return rc;
                }   
                break;
            case SADB_EXT_ADDRESS_SRC:
            case SADB_EXT_ADDRESS_DST:
            case SADB_EXT_ADDRESS_PROXY:
                DBG("SADB_EXT_ADDRESS_PROSY found!");
                break;
            case SADB_EXT_PROPOSAL:
                DBG("SADB_EXT_PROPOSAL found!");
                break;
        }   
        msglen -= ext->sadb_ext_len << 3;
        ext = (char *)ext + (ext->sadb_ext_len << 3);
    }

    return SR_ERR_OK;

    
}

int pf_supported_xml_node(sr_val_t **output, size_t *output_cnt,struct sadb_ext *ext){
    
    int rc = SR_ERR_OK;
    char xpath[MAX_PATH];
    char full_xpath[MAX_PATH];
    struct sadb_supported *sup = (struct sadb_supported *)ext;
    struct sadb_alg * alg;
    int len;
        
    len = sup->sadb_supported_len * 8;
    len -= sizeof(*sup);

    if(len == 0) return SR_ERR_OPERATION_FAILED;

    for(alg = (struct sadb_alg*)(sup + 1); len>0; len -= sizeof(*alg), alg++){

        char * alg_enum_name = pf_get_alg_enum_name(alg,sup);

        if (alg_enum_name != NULL) {

            DBG("alg_enum_name %s", alg_enum_name);

            if(sup->sadb_supported_exttype == SADB_EXT_SUPPORTED_AUTH) 
                strcpy(xpath, "/ietf-ipsec:sadb_register/algorithm-supported/auth-algs[name='");
            else    
                strcpy(xpath, "/ietf-ipsec:sadb_register/algorithm-supported/enc-algs[name='");

            strcat(xpath,alg_enum_name);
            strcat(xpath,"']"); 
            
            *output_cnt = (*output_cnt)+1;
            rc = sr_realloc_values((*output_cnt)-1,*output_cnt,output);
            if (rc != SR_ERR_OK) {
                ERR("sr_realloc_values: %s", sr_strerror(rc));
                return rc;
            }

            strcpy(full_xpath,xpath);
            strcat(full_xpath,"/name");
            rc = sr_val_set_xpath(&(*output)[(*output_cnt)-1],full_xpath);
            if (SR_ERR_OK != rc) {
                return rc;
            }
            (*output)[(*output_cnt)-1].type = SR_ENUM_T;
            (*output)[(*output_cnt)-1].data.enum_val = alg_enum_name;

            //ivlen
            *output_cnt = (*output_cnt)+1;
            rc = sr_realloc_values((*output_cnt)-1,*output_cnt,output);
            if (rc != SR_ERR_OK) {
                ERR("sr_realloc_values: %s", sr_strerror(rc));
                return rc;
            }
            strcpy(full_xpath,xpath);
            strcat(full_xpath,"/ivlen");
            rc = sr_val_set_xpath(&(*output)[(*output_cnt)-1],full_xpath);
            if (SR_ERR_OK != rc) {
                return rc;
            }
            (*output)[(*output_cnt)-1].type = SR_UINT8_T;
            (*output)[(*output_cnt)-1].data.uint8_val = alg->sadb_alg_ivlen;


            //min-bits
            *output_cnt = (*output_cnt)+1;
            rc = sr_realloc_values((*output_cnt)-1,*output_cnt,output);
            if (rc != SR_ERR_OK) {
                ERR("sr_realloc_values: %s", sr_strerror(rc));
                return rc;
            }
            strcpy(full_xpath,xpath);
            strcat(full_xpath,"/min-bits");
            rc = sr_val_set_xpath(&(*output)[(*output_cnt)-1],full_xpath);
            if (SR_ERR_OK != rc) {
                return rc;
            }
            (*output)[(*output_cnt)-1].type = SR_UINT16_T;
            (*output)[(*output_cnt)-1].data.uint16_val = alg->sadb_alg_minbits;

            //max-bits
            *output_cnt = (*output_cnt)+1;
            rc = sr_realloc_values((*output_cnt)-1,*output_cnt,output);
            if (rc != SR_ERR_OK) {
                ERR("sr_realloc_values: %s", sr_strerror(rc));
                return rc;
            }
            strcpy(full_xpath,xpath);
            strcat(full_xpath,"/max-bits");
            rc = sr_val_set_xpath(&(*output)[(*output_cnt)-1],full_xpath);
            if (SR_ERR_OK != rc) {
                return rc;
            }
            (*output)[(*output_cnt)-1].type = SR_UINT16_T;
            (*output)[(*output_cnt)-1].data.uint16_val = alg->sadb_alg_maxbits;

        }
    }

    return SR_ERR_OK;
}

// Review and merge with code in utils.c
char * pf_get_alg_enum_name(struct sadb_alg * alg, struct sadb_supported *sup) {

    char name[100];

    if ("Null" ==  get_sadb_alg_type(alg->sadb_alg_id, sup->sadb_supported_exttype)){
        return NULL;
    } 

    strcpy(name,get_sadb_alg_type(alg->sadb_alg_id, sup->sadb_supported_exttype));

    if (0 == strcmp(name,"HMAC-MD5")) {
        return "hmac-md5-96";
    } else if (0 == strcmp(name,"HMAC-SHA-1")) {
        return "hmac-sha1-96";
    } else if (0 == strcmp(name,"DES-CBC")) {
        return "des";
    } else if (0 == strcmp(name,"3DES-CBC")) {
        return "3des";
    } else if (0 == strcmp(name,"Blowfish-CBC")) {
        return "blowfish";
    } else {
        DBG("pf_get_alg_enum_name unknown : %s]", name);
        return NULL;
    }
    
}

// Review and merge with code in utils.c
int pf_get_satype_define(char* saType){

        if (!strcmp(saType, "sadb_satype_unspec"))         return SADB_SATYPE_UNSPEC;
        else if (!strcmp(saType, "sadb_satype_ah"))        return SADB_SATYPE_AH ;
        else if (!strcmp(saType, "sadb_satype_esp"))       return SADB_SATYPE_ESP ;
        else if (!strcmp(saType, "sadb_satype_rsvp"))      return SADB_SATYPE_RSVP ;
        else if (!strcmp(saType, "sadb_satype_ospfv2"))    return SADB_SATYPE_OSPFV2 ;
        else if (!strcmp(saType, "sadb_satype_ripv2"))     return SADB_SATYPE_RIPV2 ;
        else if (!strcmp(saType, "sadb_satype_mip"))       return SADB_SATYPE_MIP ;
        else if (!strcmp(saType, "sadb_satype_max"))       return SADB_SATYPE_MAX ;
}


int create_base_grouping(struct sadb_msg *msgp, int msglen, char * xpath, sr_val_t **input, int *input_cnt){

    int rc = SR_ERR_OK;
    char full_xpath[MAX_PATH];
    char tmp_xpath[MAX_PATH];
    
    DBG("create_base_grouping .... ");

    /*strcpy(full_xpath,xpath);
    strcat(full_xpath,"/base-list[version='PF_KEY_V2']");
    *input_cnt = 4;
    rc = sr_new_values(*input_cnt, input);
    if (SR_ERR_OK != rc) {
        return rc;
    }
    
    strcpy(tmp_xpath,full_xpath);
    strcat(tmp_xpath,"/version");
    rc = sr_val_set_xpath(&(*input)[0], tmp_xpath);
    if (SR_ERR_OK != rc) {
        return rc;
    }
    (*input)[0].type = SR_STRING_T;
    (*input)[0].data.string_val = "PF_KEY_V2";
    

    strcpy(tmp_xpath,full_xpath);
    strcat(tmp_xpath,"/msg_type");
    rc = sr_val_set_xpath(&(*input)[1], tmp_xpath);
    if (SR_ERR_OK != rc) {
        return rc;
    }
    (*input)[1].type = SR_ENUM_T;
    char * msg_type = NULL;
    if (0 == strcmp("Register", get_sadb_msg_type(msgp->sadb_msg_type)))
        msg_type = "sadb_register";
    else if (0 == strcmp("Acquire", get_sadb_msg_type(msgp->sadb_msg_type)))
        msg_type = "sadb_acquire";
    else if (0 == strcmp("Expire", get_sadb_msg_type(msgp->sadb_msg_type)))
        msg_type = "sadb_expire";
    else {
        printf("ERROR msg_type unknown\n");
        return rc;
    }
    (*input)[1].data.enum_val = msg_type;


    strcpy(tmp_xpath,full_xpath);
    strcat(tmp_xpath,"/msg_satype");
    rc = sr_val_set_xpath(&(*input)[2], tmp_xpath);
    if (SR_ERR_OK != rc) {
        return rc;
    }
    (*input)[2].type = SR_ENUM_T;
    
    if (msgp->sadb_msg_satype == SADB_SATYPE_ESP) {
        (*input)[2].data.enum_val = "sadb_satype_esp";
    } else if (msgp->sadb_msg_satype == SADB_SATYPE_AH) {
       (*input)[2].data.enum_val = "sadb_satype_ah";
    } else {
        printf("ERROR msg_satype unknown: %s\n", get_sadb_satype(msgp->sadb_msg_satype));
        return rc;
    }
    

    strcpy(tmp_xpath,full_xpath);
    strcat(tmp_xpath,"/msg_seq");
    rc = sr_val_set_xpath(&(*input)[3], tmp_xpath);
    if (SR_ERR_OK != rc) {
        return rc;
    }
    (*input)[3].type = SR_UINT32_T;
    (*input)[3].data.uint32_val = msgp->sadb_msg_seq;
    */


	// get policy id and selectors from acquire
	//msglen -= sizeof(struct sadb_msg);
	//int goteof = 0;
	//while (goteof == 0) {
			
		int policy_index = 0;
	    char addr_src[30];
	    char addr_dst[30];
		
		msglen -= sizeof(struct sadb_msg);
	    struct sadb_ext *ext;
	    ext = (struct sadb_ext *)(msgp + 1);

	    while (msglen > 0) {
    
			DBG("create base grupoing msglen : %i", msglen);
		
	        struct sadb_x_policy *policy;
	        struct sockaddr *sa;
	        struct sadb_address *addr;

	        switch (ext->sadb_ext_type) {
	            case SADB_X_EXT_POLICY: 
	                //policy = (struct sadb_x_sa2 *)ext;
					DBG("create base grupoing: SADB_X_EXT_POLICY FOUND!");
	                policy = (struct sadb_x_policy *)ext;
	                policy_index = policy->sadb_x_policy_id;
					DBG("create base grupoing: SADB_X_EXT_POLICY index: %i",policy_index);

	                break;
	            case SADB_EXT_ADDRESS_SRC:
	            case SADB_EXT_ADDRESS_DST:
	                addr = (struct sadb_address *)ext;
	                sa = (struct sockaddr *)(addr + 1);
	                if (addr->sadb_address_exttype == SADB_EXT_ADDRESS_SRC) {
						DBG("create base grupoing: SADB_EXT_ADDRESS_SRC found!");
	                    strcpy(addr_src,sock_ntop(sa, addr->sadb_address_len * 8 - sizeof(*addr)));
						DBG("create base grupoing: SADB_EXT_ADDRESS_SRC addr: %s",addr_src);
					}
	                else { 
						DBG("create base grupoing: SADB_EXT_ADDRESS_DST found!");
	                    strcpy(addr_dst,sock_ntop(sa, addr->sadb_address_len * 8 - sizeof(*addr)));
						DBG("create base grupoing: SADB_EXT_ADDRESS_DST addr: %s",addr_dst);
	                }
	                break;
	            //default: printf("ext type: %i", ext->sadb_ext_type);

	        }
        
	        msglen -= ext->sadb_ext_len << 3;
	        ext = (char *)ext + (ext->sadb_ext_len << 3);
		}
	//    if (msgp->sadb_msg_seq == 0)
	//                goteof = 1;
	//}
	
	// fill xml acquire data
    strcpy(full_xpath,xpath);
    strcat(full_xpath,"/base-list[version='PF_KEY_V2']");
    //strcat(full_xpath,"/base-list");
	
	if (policy_index != 0) // is acquire 
    	*input_cnt = 2;
	else
		*input_cnt = 1;
	
    rc = sr_new_values(*input_cnt, input);
    if (SR_ERR_OK != rc) {
        return rc;
    }
    
    strcpy(tmp_xpath,full_xpath);
    strcat(tmp_xpath,"/version");
    rc = sr_val_set_xpath(&(*input)[0], tmp_xpath);
    if (SR_ERR_OK != rc) {
        return rc;
    }
    (*input)[0].type = SR_STRING_T;
    (*input)[0].data.string_val = "PF_KEY_V2";

	if (policy_index != 0) {
		
		// get rule_number from policy index
		spd_entry_node* spd_node = get_spd_node_by_index(policy_index);
		
    	strcpy(tmp_xpath,full_xpath);
    	strcat(tmp_xpath,"/msg_seq");
    	rc = sr_val_set_xpath(&(*input)[1], tmp_xpath);
    	if (SR_ERR_OK != rc) {
        	return rc;
    	}
    	(*input)[1].type = SR_UINT32_T;
    	(*input)[1].data.uint32_val = spd_node->policy_id;
    }
    

    return SR_ERR_OK;
}










