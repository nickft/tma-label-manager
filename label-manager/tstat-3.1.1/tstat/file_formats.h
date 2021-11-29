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


/* 
 * file_formats.h -- Which file formats are supported
 */



/**************************************************************/
/**                                                          **/
/**  Input File Specific Stuff                               **/
/**                                                          **/
/**************************************************************/

struct supported_formats
{
  pread_f *(*test_func) (char *filename);	/* pointer to the tester function       */
  char *format_name;		/* name of the file format              */
  char *format_descr;		/* description of the file format       */
};

/* for each file type GLORP you want to support, provide a      	*/
/* function is_GLORP() that returns NULL if the stdin file is NOT	*/
/* of type GLORP, and returns a pointer to a packet reading routine	*/
/* if it is.  The packet reading routine is of the following type:	*/
/*	int pread_GLORP(						*/
/*	    struct timeval	*ptime,					*/
/*	    int		 	*plen,					*/
/*	    int		 	*ptlen,					*/
/*	    void		**pphys,				*/
/*	    int			*pphystype,				*/
/*	    struct ip		**ppip,					*/
/*	    void		**pplast)				*/
/*   the reader function should return 0 at EOF and 1 otherwise		*/
/* This routine must return ONLY IP packets, but they need not all be	*/
/* TCP packets (if not, they're ignored).				*/


/* install the is_GLORP() routines supported */
struct supported_formats file_formats[] = {
#ifdef GROK_TCPDUMP
  {is_tcpdump, "tcpdump", "tcpdump format -- Public domain program from LBL"},
#endif /* GROK_TCPDUMP */
#ifdef GROK_SNOOP
  {is_snoop, "snoop", "Sun Snoop format -- Distributed with Solaris"},
#endif /* GROK_SNOOP */
#ifdef GROK_ETHERPEEK
  {is_EP, "etherpeek", "etherpeek format -- Mac sniffer program"},
#endif /* GROK_ETHERPEEK */
#ifdef GROK_NETM
  {is_netm, "netmetrix", "Net Metrix format -- Commercial program from HP"},
#endif /* GROK_NETM */
#ifdef GROK_NS
  {is_ns, "ns", "ns format - Network simulator ns2 from LBL"},
#endif /* GROK_NS */
#ifdef GROK_NLANR
  {is_nlanr, "tsh", "tsh format -- NLANL Tsh"},
#endif /* GROK_NLANR */
#ifdef GROK_NETSCOUT
  {is_netscout, "netscout", "NetScout Manager format"},
#endif /* GROK_NETSCOUT */
#ifdef GROK_ERF
  {is_erf, "erf", "Endace Extensible Record format"},
#endif /* GROK_ERF */
#ifdef GROK_DPMI
  {is_DPMI, "DPMI",
   "Distributed Passive Measurement Interface (DPMI) format"},
#endif /* GROK_DPMI */
#ifdef GROK_DAG
  {is_dag, "Dag", "Dag Format"},
#endif /* GROK_DAG */
#ifdef GROK_ERF_LIVE
  {init_erf_live, "Dag live", "Live capture using Endace DAG cards"},
#endif
#ifdef GROK_LIVE_TCPDUMP
  {init_live_tcpdump, "tcpdump live",
   "Live capture using pcap/tcpdump library"},
#endif /* GROK_LIVE_TCPDUMP */
};

#define NUM_FILE_FORMATS (sizeof(file_formats) / sizeof(struct supported_formats))
#ifdef GROK_ERF_LIVE
#ifdef GROK_LIVE_TCPDUMP
#define NUM_LIVE_FORMATS 2
#define ETH_LIVE (NUM_FILE_FORMATS - 1)
#define ERF_LIVE (NUM_FILE_FORMATS - 2)
#else
#define NUM_LIVE_FORMATS 1
#define ERF_LIVE (NUM_FILE_FORMATS - 1)
#endif
#else
#ifdef GROK_LIVE_TCPDUMP
#define NUM_LIVE_FORMATS 1
#define ETH_LIVE (NUM_FILE_FORMATS - 1)
#endif
#endif

#ifndef NUM_LIVE_FORMATS
#define NUM_LIVE_FORMATS 0
#endif
