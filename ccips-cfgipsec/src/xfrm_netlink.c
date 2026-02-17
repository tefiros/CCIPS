/*
 * XFRM Netlink implementation for SAD management
 * Replacement for PF_KEY to support modern algorithms like AES-GCM
 */

#include "xfrm_netlink.h"
#include "utils.h"
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/xfrm.h>
#include <arpa/inet.h>

#define NLMSG_TAIL(nmsg) \
    ((struct rtattr *) (((void *) (nmsg)) + NLMSG_ALIGN((nmsg)->nlmsg_len)))

/* Helper to add an attribute to netlink message */
static int addattr_l(struct nlmsghdr *n, int maxlen, int type, const void *data, int alen)
{
    int len = RTA_LENGTH(alen);
    struct rtattr *rta;

    if (NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len) > maxlen) {
        ERR("addattr_l: message exceeded bound of %d", maxlen);
        return -1;
    }
    rta = NLMSG_TAIL(n);
    rta->rta_type = type;
    rta->rta_len = len;
    if (alen) {
        memcpy(RTA_DATA(rta), data, alen);
    }
    n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len);
    return 0;
}

/* Convert IP string to xfrm_address_t */
static int parse_xfrm_address(const char *ip_str, xfrm_address_t *addr, int *family)
{
    if (strchr(ip_str, ':')) {
        /* IPv6 */
        *family = AF_INET6;
        if (inet_pton(AF_INET6, ip_str, addr->a6) != 1) {
            return -1;
        }
    } else {
        /* IPv4 */
        *family = AF_INET;
        if (inet_pton(AF_INET, ip_str, &addr->a4) != 1) {
            return -1;
        }
    }
    return 0;
}

/* Add SAD entry using XFRM netlink */
int xfrm_add_sa(sad_entry_node *sad_node)
{
    struct {
        struct nlmsghdr n;
        struct xfrm_usersa_info xsinfo;
        char buf[4096];
    } req;
    
    int fd;
    struct sockaddr_nl nladdr;
    int family;
    
    /* Open netlink socket */
    fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_XFRM);
    if (fd < 0) {
        ERR("Failed to open XFRM netlink socket");
        return SR_ERR_OPERATION_FAILED;
    }
    
    memset(&req, 0, sizeof(req));
    memset(&nladdr, 0, sizeof(nladdr));
    
    nladdr.nl_family = AF_NETLINK;
    
    /* Build netlink message */
    req.n.nlmsg_len = NLMSG_LENGTH(sizeof(req.xsinfo));
    req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    req.n.nlmsg_type = XFRM_MSG_NEWSA;
    req.n.nlmsg_seq = 1;
    
    /* Parse source and destination addresses */
    char *src_ip = get_ip(sad_node->local_subnet);
    char *dst_ip = get_ip(sad_node->remote_subnet);
    
    if (parse_xfrm_address(src_ip, &req.xsinfo.saddr, &family) < 0) {
        ERR("Invalid source IP: %s", src_ip);
        close(fd);
        return SR_ERR_OPERATION_FAILED;
    }
    
    if (parse_xfrm_address(dst_ip, &req.xsinfo.id.daddr, &family) < 0) {
        ERR("Invalid destination IP: %s", dst_ip);
        close(fd);
        return SR_ERR_OPERATION_FAILED;
    }
    
    req.xsinfo.family = family;
    
    /* Set SPI */
    req.xsinfo.id.spi = htonl(sad_node->spi);
    
    /* Set protocol (ESP) */
    req.xsinfo.id.proto = sad_node->protocol_parameters;
    
    /* Set mode (transport or tunnel)
     * Map IPSEC_MODE_* constants to XFRM_MODE_* constants
     * IPSEC_MODE_TRANSPORT = 1 -> XFRM_MODE_TRANSPORT = 0
     * IPSEC_MODE_TUNNEL = 2 -> XFRM_MODE_TUNNEL = 1
     */
    if (sad_node->ipsec_mode == 1) {  // IPSEC_MODE_TRANSPORT
        req.xsinfo.mode = XFRM_MODE_TRANSPORT;  // 0
    } else if (sad_node->ipsec_mode == 2) {  // IPSEC_MODE_TUNNEL
        req.xsinfo.mode = XFRM_MODE_TUNNEL;  // 1
    } else {
        WARN("Unknown IPsec mode: %d, defaulting to transport", sad_node->ipsec_mode);
        req.xsinfo.mode = XFRM_MODE_TRANSPORT;
    }
 
    /* Set reqid */
    req.xsinfo.reqid = sad_node->req_id;
    
    /* Set replay window */
    req.xsinfo.replay_window = sad_node->anti_replay_window;
    
    /* Set lifetimes */
    req.xsinfo.lft.soft_byte_limit = sad_node->lft_bytes_soft;
    req.xsinfo.lft.hard_byte_limit = sad_node->lft_bytes_hard;
    req.xsinfo.lft.soft_packet_limit = sad_node->lft_packets_soft;
    req.xsinfo.lft.hard_packet_limit = sad_node->lft_packets_hard;
    req.xsinfo.lft.soft_add_expires_seconds = sad_node->lft_time_soft;
    req.xsinfo.lft.hard_add_expires_seconds = sad_node->lft_time_hard;
    req.xsinfo.lft.soft_use_expires_seconds = sad_node->lft_idle_soft;
    req.xsinfo.lft.hard_use_expires_seconds = sad_node->lft_idle_hard;
    
    /* Add encryption algorithm and key */
    if (sad_node->encryption_alg != SADB_EALG_NONE) {
        unsigned char *enc_key_bytes = hexstr_to_char(sad_node->encryption_key);
        if (enc_key_bytes == NULL) {
            ERR("hexstr_to_char failed for encryption_key");
            close(fd);
            return SR_ERR_OPERATION_FAILED;
        }
        
        size_t hex_len = strlen(sad_node->encryption_key);
        size_t enc_key_len = hex_len / 2;
        
        /* For AES-GCM, use XFRM_AALG_AEAD */
        if (sad_node->encryption_alg == SADB_X_EALG_AES_GCM_ICV8 ||
            sad_node->encryption_alg == SADB_X_EALG_AES_GCM_ICV12 ||
            sad_node->encryption_alg == SADB_X_EALG_AES_GCM_ICV16) {
            
            int icv_len;
            
            /* Determine ICV length */
            if (sad_node->encryption_alg == SADB_X_EALG_AES_GCM_ICV8)
                icv_len = 64;  /* 8 bytes = 64 bits */
            else if (sad_node->encryption_alg == SADB_X_EALG_AES_GCM_ICV12)
                icv_len = 96;  /* 12 bytes = 96 bits */
            else
                icv_len = 128; /* 16 bytes = 128 bits */
            
            /* RFC4106 GCM uses: key_material = key + 4-byte salt
             * Expected key sizes:
             * - AES-128: 20 bytes (16 + 4)
             * - AES-192: 28 bytes (24 + 4)
             * - AES-256: 36 bytes (32 + 4)
             */
            
            /* The key from controller includes both key and salt */
            size_t total_key_len = enc_key_len;
            
            /* Validate key length */
            if (total_key_len != 20 && total_key_len != 28 && total_key_len != 36) {
                WARN("AES-GCM key length is %zu bytes, expected 20, 28, or 36 (key+salt)", total_key_len);
                /* Try to use it anyway, truncating or padding if needed */
                if (total_key_len > 36) {
                    WARN("Truncating key from %zu to 36 bytes", total_key_len);
                    total_key_len = 36;
                } else if (total_key_len < 20) {
                    ERR("Key too short: %zu bytes, minimum is 20", total_key_len);
                    free(enc_key_bytes);
                    close(fd);
                    return SR_ERR_OPERATION_FAILED;
                }
            }
            
            /* Allocate structure with key space */
            size_t aead_size = sizeof(struct xfrm_algo_aead) + total_key_len;
            struct xfrm_algo_aead *aead = malloc(aead_size);
            if (!aead) {
                ERR("Failed to allocate AEAD structure");
                free(enc_key_bytes);
                close(fd);
                return SR_ERR_OPERATION_FAILED;
            }
            
            memset(aead, 0, aead_size);
            strncpy(aead->alg_name, "rfc4106(gcm(aes))", sizeof(aead->alg_name));
            aead->alg_key_len = total_key_len * 8;  /* in bits */
            aead->alg_icv_len = icv_len;
            memcpy(aead->alg_key, enc_key_bytes, total_key_len);
            
            /* Add AEAD attribute */
            if (addattr_l(&req.n, sizeof(req), XFRMA_ALG_AEAD, aead, aead_size) < 0) {
                ERR("Failed to add AEAD algorithm");
                free(aead);
                free(enc_key_bytes);
                close(fd);
                return SR_ERR_OPERATION_FAILED;
            }
            
            INFO("Added AES-GCM AEAD: alg_name=%s, key_len=%zu bytes (%d bits), icv_len=%d bits", 
                 aead->alg_name, total_key_len, aead->alg_key_len, icv_len);
            
            /* Debug: print first 8 bytes of key */
            DBG("Key (first 8 bytes): %02x%02x%02x%02x%02x%02x%02x%02x",
                enc_key_bytes[0], enc_key_bytes[1], enc_key_bytes[2], enc_key_bytes[3],
                enc_key_bytes[4], enc_key_bytes[5], enc_key_bytes[6], enc_key_bytes[7]);
            
            free(aead);
 
        } else {
            /* Traditional encryption algorithm */
            const char *algo_name = NULL;
            
            /* Map SADB algorithm to XFRM algorithm name */
            switch (sad_node->encryption_alg) {
                case SADB_EALG_DESCBC:
                    algo_name = "cbc(des)";
                    break;
                case SADB_EALG_3DESCBC:
                    algo_name = "cbc(des3_ede)";
                    break;
                case SADB_X_EALG_AESCBC:
                    algo_name = "cbc(aes)";
                    break;
                case SADB_X_EALG_AESCTR:
                    algo_name = "rfc3686(ctr(aes))";
                    break;
                default:
                    ERR("Unsupported encryption algorithm: %d", sad_node->encryption_alg);
                    free(enc_key_bytes);
                    close(fd);
                    return SR_ERR_OPERATION_FAILED;
            }
            
            size_t algo_size = sizeof(struct xfrm_algo) + enc_key_len;
            struct xfrm_algo *algo = malloc(algo_size);
            if (!algo) {
                ERR("Failed to allocate encryption algorithm structure");
                free(enc_key_bytes);
                close(fd);
                return SR_ERR_OPERATION_FAILED;
            }
            
            memset(algo, 0, algo_size);
            strncpy(algo->alg_name, algo_name, sizeof(algo->alg_name));
            algo->alg_key_len = enc_key_len * 8;
            memcpy(algo->alg_key, enc_key_bytes, enc_key_len);
            
            if (addattr_l(&req.n, sizeof(req), XFRMA_ALG_CRYPT, algo, algo_size) < 0) {
                ERR("Failed to add encryption algorithm");
                free(algo);
                free(enc_key_bytes);
                close(fd);
                return SR_ERR_OPERATION_FAILED;
            }
            
            INFO("Added encryption: %s, key_len=%zu bits", algo_name, enc_key_len * 8);
            free(algo);
        }
        
        free(enc_key_bytes);
    }
    
    /* Add authentication algorithm and key (only for non-AEAD) */
    if (sad_node->integrity_alg != SADB_AALG_NONE &&
        sad_node->encryption_alg != SADB_X_EALG_AES_GCM_ICV8 &&
        sad_node->encryption_alg != SADB_X_EALG_AES_GCM_ICV12 &&
        sad_node->encryption_alg != SADB_X_EALG_AES_GCM_ICV16) {
        
        unsigned char *int_key_bytes = hexstr_to_char(sad_node->integrity_key);
        if (int_key_bytes == NULL) {
            ERR("hexstr_to_char failed for integrity_key");
            close(fd);
            return SR_ERR_OPERATION_FAILED;
        }
        
        size_t hex_len = strlen(sad_node->integrity_key);
        size_t int_key_len = hex_len / 2;
        
        const char *auth_name = NULL;
        int trunc_len = 0;
        
        /* Map SADB algorithm to XFRM algorithm name */
        switch (sad_node->integrity_alg) {
            case SADB_AALG_MD5HMAC:
                auth_name = "hmac(md5)";
                trunc_len = 96;
                break;
            case SADB_AALG_SHA1HMAC:
                auth_name = "hmac(sha1)";
                trunc_len = 96;
                break;
            case SADB_X_AALG_SHA2_256HMAC:
                auth_name = "hmac(sha256)";
                trunc_len = 128;
                break;
            default:
                ERR("Unsupported integrity algorithm: %d", sad_node->integrity_alg);
                free(int_key_bytes);
                close(fd);
                return SR_ERR_OPERATION_FAILED;
        }
        
        size_t auth_size = sizeof(struct xfrm_algo_auth) + int_key_len;
        struct xfrm_algo_auth *auth = malloc(auth_size);
        if (!auth) {
            ERR("Failed to allocate auth structure");
            free(int_key_bytes);
            close(fd);
            return SR_ERR_OPERATION_FAILED;
        }
        
        memset(auth, 0, auth_size);
        strncpy(auth->alg_name, auth_name, sizeof(auth->alg_name));
        auth->alg_key_len = int_key_len * 8;
        auth->alg_trunc_len = trunc_len;
        memcpy(auth->alg_key, int_key_bytes, int_key_len);
        
        if (addattr_l(&req.n, sizeof(req), XFRMA_ALG_AUTH_TRUNC, auth, auth_size) < 0) {
            ERR("Failed to add authentication algorithm");
            free(auth);
            free(int_key_bytes);
            close(fd);
            return SR_ERR_OPERATION_FAILED;
        }
        
        INFO("Added authentication: %s, key_len=%zu bits, trunc_len=%d bits", 
             auth_name, int_key_len * 8, trunc_len);
        
        free(auth);
        free(int_key_bytes);
    }
    
    /* Send message */
    if (sendto(fd, &req.n, req.n.nlmsg_len, 0, 
               (struct sockaddr *)&nladdr, sizeof(nladdr)) < 0) {
        ERR("Failed to send XFRM netlink message");
        close(fd);
        return SR_ERR_OPERATION_FAILED;
    }
    
    /* Wait for ACK */
    char ack_buf[4096];
    struct nlmsghdr *ack_nh;
    ssize_t len = recv(fd, ack_buf, sizeof(ack_buf), 0);
    
    if (len < 0) {
        ERR("Failed to receive ACK from XFRM");
        close(fd);
        return SR_ERR_OPERATION_FAILED;
    }
    
    ack_nh = (struct nlmsghdr *)ack_buf;
    if (ack_nh->nlmsg_type == NLMSG_ERROR) {
        struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(ack_nh);
        if (err->error != 0) {
            ERR("XFRM returned error: %d (%s)", -err->error, strerror(-err->error));
            close(fd);
            return SR_ERR_OPERATION_FAILED;
        }
    }
    
    close(fd);
    INFO("Successfully added SAD entry via XFRM netlink (SPI=%u)", sad_node->spi);
    return SR_ERR_OK;
}

/* Delete SAD entry using XFRM netlink */
int xfrm_del_sa(sad_entry_node *sad_node)
{
    struct {
        struct nlmsghdr n;
        struct xfrm_usersa_id xsid;
        char buf[512];
    } req;
    
    int fd;
    struct sockaddr_nl nladdr;
    int family;
    
    fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_XFRM);
    if (fd < 0) {
        ERR("Failed to open XFRM netlink socket");
        return SR_ERR_OPERATION_FAILED;
    }
    
    memset(&req, 0, sizeof(req));
    memset(&nladdr, 0, sizeof(nladdr));
    
    nladdr.nl_family = AF_NETLINK;
    
    req.n.nlmsg_len = NLMSG_LENGTH(sizeof(req.xsid));
    req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    req.n.nlmsg_type = XFRM_MSG_DELSA;
    req.n.nlmsg_seq = 1;
    
    char *dst_ip = get_ip(sad_node->remote_subnet);
    
    if (parse_xfrm_address(dst_ip, &req.xsid.daddr, &family) < 0) {
        ERR("Invalid destination IP: %s", dst_ip);
        close(fd);
        return SR_ERR_OPERATION_FAILED;
    }
    
    req.xsid.family = family;
    req.xsid.spi = htonl(sad_node->spi);
    req.xsid.proto = sad_node->protocol_parameters;
    
    if (sendto(fd, &req.n, req.n.nlmsg_len, 0,
               (struct sockaddr *)&nladdr, sizeof(nladdr)) < 0) {
        ERR("Failed to send XFRM delete message");
        close(fd);
        return SR_ERR_OPERATION_FAILED;
    }
    
    char ack_buf[4096];
    ssize_t len = recv(fd, ack_buf, sizeof(ack_buf), 0);
    
    if (len < 0) {
        ERR("Failed to receive ACK from XFRM");
        close(fd);
        return SR_ERR_OPERATION_FAILED;
    }
    
    struct nlmsghdr *ack_nh = (struct nlmsghdr *)ack_buf;
    if (ack_nh->nlmsg_type == NLMSG_ERROR) {
        struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(ack_nh);
        if (err->error != 0) {
            ERR("XFRM delete returned error: %d (%s)", -err->error, strerror(-err->error));
            close(fd);
            return SR_ERR_OPERATION_FAILED;
        }
    }
    
    close(fd);
    INFO("Successfully deleted SAD entry via XFRM netlink (SPI=%u)", sad_node->spi);
    return SR_ERR_OK;
}

