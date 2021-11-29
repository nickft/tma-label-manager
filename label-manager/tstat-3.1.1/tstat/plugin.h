/*
 *
 * Copyright (c) 2001
 *      Politecnico di Torino.  All rights reserved.
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


#ifndef PLUGIN_H
#define PLUGIN_H


struct proto
{
  char tproto;			// transport layer PROTOCOL_type
  char *name;			// upper-layer protocol name
  char *descr;			//         ... and description
  void *(*check) ();		// proto->check(void *pproto, int tproto, void *plast);
  void *(*analyze) ();		// proto->analyze(struct ip *pip, void *pproto, int tproto, ucb *pdir, int dir, void *hdr, void *plast);
  void *(*stat) ();		// proto->stat(void * thisdir, int dir, int tproto)
  void *(*init) ();		// void proto->init();

  struct proto *next;		// next proto
};



int proto_init ();
int proto_register (int tproto, char *name, char *descr, void *(*check) (),
		    void *(*analyze) (), void *(*init) (), void *(*stat) ());
void proto_analyzer (struct ip *pip,	// IP layer
		     void *pproto, int tproto,	// TCP/UDP layer
		     void *pdir, int dir,	// directionality considerations
		     void *plast);
void make_proto_stat (void *thisflow, int tproto);

#endif
