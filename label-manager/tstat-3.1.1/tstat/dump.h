/*
 *
 * Copyright (c) 2001
 *	Politecnico di Torino.  All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * For bug report and other information please visit Tstat site:
 * http://tstat.polito.it
 *
 * Tstat is deeply based on TCPTRACE. The authors would like to thank
 * Shawn Ostermann for the development of TCPTRACE.
 *
*/
#ifndef DUMP_H_HDR
#define DUMP_H_HDR
//char dump_conf_fname[200];
void dump_init          (void);
void dump_flow_stat     (struct ip *pip, void *pproto, int tproto, 
                         void *pdir, int dir, void *hdr, void *plast);
void dump_flush         (Bool trace_completed);
void dump_create_outdir (char * basedir);
//void dump_restart       (void);
void dump_parse_ini_arg (char *param_name, param_value param_value);
void dump_ini_start_section (void);
void dump_ini_end_section (void);
void dump_ip(void *pip, void *plast);

extern Bool dump_engine;
#endif
