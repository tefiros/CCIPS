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
#ifndef CFGIPSEC2SRV_LOG_H_
#define CFGIPSEC2SRV_LOG_H_

#define LOG_ERR 0
#define LOG_INFO 1
#define LOG_DEBUG 2	


extern int verbose_level;


#define CI_VERB_ERROR 0   /**< Print only error messages. */
#define CI_VERB_INFO 1	 /**< Besides errors and warnings, print some other verbose messages. */
#define CI_VERB_DEBUG 2    /**< Print all messages including some development debug messages. */

void set_verbose_level(int level); 
int get_verbose_level();
void ci2log_printf(int level, const char *format, ...);

/*
 * Verbose printing macros
 */
#define ERR(format,args...) ci2log_printf(CI_VERB_ERROR,format,##args);
#define INFO(format,args...) if(verbose_level>=CI_VERB_INFO){ci2log_printf(CI_VERB_INFO,format,##args);}
#define DBG(format,args...) if(verbose_level>=CI_VERB_DEBUG){ci2log_printf(CI_VERB_DEBUG,format,##args);}

#endif 