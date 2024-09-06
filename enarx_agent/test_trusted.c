#include <unistd.h>
// #include "utils.h"
// #include "constants.h"
// #include "base/log.h"
// #include "base/pfkeyv2_entry.h"
#include "sad_entry.h"
#include "spd_entry.h"
#include "log.h"
#include <unistd.h>
#include <assert.h>
#include <stdbool.h>
#include "parson.h"
#include "constants.h"
// #include "base/serializers/sad_serializer.h"
// #include "base/serializers/spd_serializer.h"

int exit_application = 0;

// sudo gcc -pthread -g -w -I /usr/include/libnl3/ -o test test.c base/* parson/parson.h parson/parson.c
static void
sigint_handler(int signum)
{
    (void)signum;

    exit_application = 1;
}


int 
main(int argc, char **argv) {

    // pf_exec_register(SADB_SATYPE_ESP);    
    unsigned long long int req_id = 100;

    char *name = "aaa";
    char local_subnet[MAX_IP] = "10.0.0.0/24";
    char remote_subnet[MAX_IP] = "11.0.0.0/24";
    char tunnel_local[MAX_IP] = "10.0.0.61";
    char tunnel_remote[MAX_IP] = "10.0.0.228";

	spd_entry_node *spd_node = create_spd_node();

    strcpy(spd_node->name,name);
    spd_node->policy_dir = IPSEC_DIR_OUTBOUND;
	spd_node->req_id=req_id;

    // Setup subnets
    // Local subnet is the subnet we want to intercconnect
    strcpy(spd_node->local_subnet,local_subnet);
    // Remote subnet is the other subnet of the tunnel that we want to interconnect
    strcpy(spd_node->remote_subnet,remote_subnet);
    // Tunnel local is the ip of the ip used to create the tunnel
    strcpy(spd_node->tunnel_local,tunnel_local);
    // Tunnel remote is the ip exposed by the other end to stablish the tunnel
    strcpy(spd_node->tunnel_remote,tunnel_remote);
    // Protocol we are encapsulating 256 stands for any
    spd_node->inner_protocol = 256;
    // We are not using ports so we set them to 0
    spd_node->srcport = 0;
    spd_node->dstport = 0;

	spd_node->action = IPSEC_POLICY_PROTECT;


    spd_node->ext_seq_num = false;
    spd_node->seq_overflow = false;

    // IPsec mode, we are running this as a tunnel, we setup protocol_params as ESP
    spd_node->ipsec_mode = IPSEC_MODE_TUNNEL;
    // spd_node->protocol_parameters = IPPROTO_ESP;
    spd_node->protocol_parameters = 50;

    // Algorithms configuration (Some random values)
    spd_node->integrity_alg = SADB_AALG_SHA1HMAC;
    spd_node->encryption_alg = SADB_EALG_3DESCBC;

        // TODO understand what those values do
    spd_node->bypass_dscp = false;
    spd_node->ecn = false;
    spd_node->tfc_pad = false;
    spd_node->pfp_flag= false;
    // DF BIT?
    spd_node->df_bit = 0;
    
   


    struct sad_entry_node *sad_node = create_sad_node();
    struct sad_entry_node *sad_node_get;

    // Setup the structure
    
    // First setup the identification variables
    strcpy(sad_node->name,name);
    sad_node->req_id = req_id;
    // To verifify the use of this values
    sad_node->ext_seq_num = false;
    sad_node->seq_overflow = false;
    sad_node->spi = 0;
	sad_node->seq_number_counter = 0;
	sad_node->anti_replay_window = 0;

    // Setup subnets
    // Local subnet is the subnet we want to intercconnect
    strcpy(sad_node->local_subnet,local_subnet);
    // Remote subnet is the other subnet of the tunnel that we want to interconnect
    strcpy(sad_node->remote_subnet,remote_subnet);
    // Tunnel local is the ip of the ip used to create the tunnel
    strcpy(sad_node->tunnel_local,tunnel_local);
    // Tunnel remote is the ip exposed by the other end to stablish the tunnel
    strcpy(sad_node->tunnel_remote,tunnel_remote);
    // Protocol we are encapsulating 256 stands for any
    sad_node->inner_protocol = 256;
    // We are not using ports so we set them to 0
    sad_node->srcport = 0;
    sad_node->dstport = 0;
    // IPsec mode, we are running this as a tunnel, we setup protocol_params as ESP
    sad_node->ipsec_mode = IPSEC_MODE_TUNNEL;
    // sad_node->protocol_parameters = IPPROTO_ESP;
    sad_node->protocol_parameters = 50;
    // Algorithms configuration (Some random values)
    sad_node->integrity_alg = SADB_AALG_SHA1HMAC;
    
    sad_node->encryption_alg = SADB_EALG_3DESCBC;
    sad_node->encryption_key = "af6a404c";
    sad_node->integrity_key = "af6a404c";
	sad_node->encryption_iv = "af6a404c";

    // TODO understand what those values do
    sad_node->bypass_dscp = false;
    sad_node->ecn = false;
    sad_node->tfc_pad = false;

    // DF BIT?
    sad_node->df_bit = 0;
	
    
    // Lifetime stuff
	sad_node->lft_bytes_hard= 10;
	sad_node->lft_bytes_soft= 1000;
	sad_node->lft_bytes_current= 1000;
	sad_node->lft_packets_hard= 1000;
	sad_node->lft_packets_soft= 1000;
	sad_node->lft_packets_current= 1000;
	sad_node->lft_time_hard= 1000;
	sad_node->lft_time_soft= 1000;
	sad_node->lft_time_current= 10;
	sad_node->lft_idle_hard= 60;
	sad_node->lft_idle_soft= 10;
	sad_node->lft_idle_current= 10;


    // if (!cser_raw_store_struct_spd_entry_node(spd_node,))

    // int rc =  pf_addpolicy(spd_node);
    // if (0 != rc) {
    //     ERR("ADD SPD entry: %d", rc);
    //     return rc;     
    // }

    // rc = pf_addsad(sad_node);
    // if (0 != rc) {
    //     ERR("ADD SAD in getSAD_entry: %d", rc);
    //     return rc;     
    // }
    

    // rc = pf_delsad(sad_node);
    // if (0 != rc) {
    //     ERR("ADD SAD in getSAD_entry: %d", rc);
    //     return rc;     
    // }
    // Check for lifetime
    
    char *result = serialize_sad_node(sad_node);
    deserialize_sad_node(result);
    INFO(result);

    // pf_getsad(sad_node);

    // int rc = pf_delsad(sad_node);
    // if (0 != rc) {
    //     ERR("DEL SAD in getSAD_entry: %d", rc);
    //     return rc;     
    // }
    // // printf("Name: %s, spi %s]\n");


    // // // Esto setea un listener para escuchar los cambios
    // // pf_exec_register(SADB_SATYPE_ESP);

    // //     // ------------- ESTO seguro que hay una manera mejor de hacerlo --------------//
    // signal(SIGINT, sigint_handler);
    // signal(SIGPIPE, SIG_IGN);
    // while (!exit_application) {
    //     sleep(1000);  /* or do some more useful work... */
    // }



    INFO("Application exit requested, exiting.");
    return 0;

}


