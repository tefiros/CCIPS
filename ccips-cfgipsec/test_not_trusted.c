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

#include <unistd.h>
#include <signal.h>

#include "utils.h"
#include "log.h"
#include "sysrepo_print.h"
#include "sysrepo_utils.h"
#include "sysrepo_entries.h"
#include "pfkeyv2_entry.h"
#include "pfkeyv2_utils.h"

#define VERSION "2"

int exit_application = 0;

static void sigint_handler(int signum)
{
    (void)signum;

    exit_application = 1;
}

int main(int argc, char **argv)
{

    if ( geteuid() != 0 ) {
        fprintf ( stderr, "Must be root in order to execute cfgipsec2. You are UID=%u, EUID=%u\n", getuid(), geteuid() );
        return 1;
    }

    // Get options
    int foreground = false;
    int c;
    while ( ( c = getopt ( argc, argv, "f:c:v:h" ) ) != -1 ) {
        switch ( c ) {
            case 'f':
                foreground = true; // TBD
                break;
            case 'v':
                if (strcmp(optarg,"0") != 0 && strcmp(optarg,"1") != 0 && strcmp(optarg,"2") != 0) {
                    printf("verbose not valid: %s\n",optarg);
                    exit(EXIT_FAILURE);
                } else if (strcmp(optarg,"0") == 0) {
                    log_level_string(CI_VERB_ERROR);
                } else if (strcmp(optarg,"2") == 0) {
                    log_level_string(CI_VERB_DEBUG);
                }
                break;
            case 'h': {
                fprintf(stderr, "cfgipsec2 version %s \n", VERSION);
                fprintf(stderr, "Usage:\n" );
                fprintf(stderr, "       %s [-c case] [-v verbose_level]\n",argv[0]);
                fprintf(stderr, "\n" );
                fprintf(stderr, "Where:\n" );
                fprintf(stderr, "       - case is `case1` (IKE case) or `case2` (IKE-less case, default)\n" );
                fprintf(stderr, "       - verbose_level is 0: ERROR, 1: INFORMATIONAL (default), 2: DEBUG\n" );
                fprintf(stderr, "" );
                return 0;
            }
            default: {
                fprintf(stderr, "Usage: %s [-c case] [-v verbose_level]\n", argv[0]);
                exit(EXIT_FAILURE);
            }
        }
    }

    //// connect to sysrepo
    sr_conn_ctx_t *connection = NULL;
    sr_session_ctx_t *session = NULL;
    sr_subscription_ctx_t *subscription = NULL; 
	const char *mod_name, *xpath = NULL;

    int rc = SR_ERR_OK;
	//char *module_name = NULL;
	mod_name = "ietf-i2nsf-ikeless";

    DBG("Connect to sysrepo %i",rc);
    rc = sr_connect(0, &connection);
    if (SR_ERR_OK != rc) {
        ERR("Error by sr_connect: %s", sr_strerror(rc));
        goto cleanup;
    }




    /* start session */
    rc = sr_session_start(connection, SR_DS_RUNNING, &session);
    if (SR_ERR_OK != rc) {
        ERR( "Error by sr_session_start: %s", sr_strerror(rc));
        goto cleanup;
    }

    /* read current config */
    printf("\n ========== READING RUNNING CONFIG: ==========\n\n");
    print_current_config(session, mod_name);



    DBG("Subscribing to entries");
    /*subscribe for changes in running config */
    xpath = "/ietf-i2nsf-ikeless:ipsec-ikeless/spd/spd-entry";
    rc = sr_module_change_subscribe(session,mod_name, xpath, spd_entry_change_cb, NULL, 2, 0, &subscription);
    if (SR_ERR_OK != rc) {
        ERR( "sr_module_change_subscribe spd: %s", sr_strerror(rc));
        ERR( "Try to reinstall the ietf-ipsec module running make uninstall then make install.");
        goto cleanup;
    }	
    

    xpath = "/ietf-i2nsf-ikeless:ipsec-ikeless/sad/sad-entry";
    rc = sr_module_change_subscribe(session, mod_name, xpath, sad_entry_change_cb, NULL, 1, 0, &subscription);
    if (SR_ERR_OK != rc) {
        ERR( " sr_module_change_subscribe sad: %s", sr_strerror(rc));
        goto cleanup;
    }
        
    rc = sadb_register(session);
    if (SR_ERR_OK != rc) {
        ERR( "sadb_register: %s", sr_strerror(rc));
        goto cleanup;
    }
    //
    // subscribe for state data
    //
    xpath = "/ietf-i2nsf-ikeless:ipsec-ikeless/sad/sad-entry"; 
    rc = sr_oper_get_items_subscribe(session, mod_name, xpath, sad_state_cb, NULL, 0, &subscription); 
    if (SR_ERR_OK != rc) {
        ERR( " sr_dp_get_items_subscribe sad-state: %s", sr_strerror(rc));
        goto cleanup;
    }

    signal(SIGINT, sigint_handler);
    signal(SIGPIPE, SIG_IGN);
    while (!exit_application) {
        sleep(1000);  /* or do some more useful work... */
    }

    INFO("Application exit requested, exiting.");

    
cleanup:
	sr_disconnect(connection);
    return rc ? EXIT_FAILURE : EXIT_SUCCESS;
}

