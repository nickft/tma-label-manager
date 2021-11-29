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



/* probably this is obsoleted by erf.c */

#ifdef GROK_DAG

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "tstat.h"
#include "dagtools.h"

#define DAG2SEC(t)    ((u_int32_t) ((t) >> 32))

/* some global variables */
extern int two_files;
extern char **filenames;
extern Bool internal_wired;
extern Bool coming_in;

/* static buffers for reading */
char *timestring (time_t sec, int utc);

static struct ether_header *pep;
static int edag = 2;		/* EtherDAG compatibility       */

typedef long long ll_t;
typedef struct cell
{
  ll_t ts;
  unsigned crc;
  unsigned header;
  unsigned char pload[48];
}
cell_t;

typedef struct ether
{
  ll_t ts;
  u_short len;
  u_char dst[6];
  u_char src[6];
  u_short etype;
  unsigned pload[40 / sizeof (unsigned)];
}
ether_t;

typedef struct pos
{				/* PoS comes with the new DAG record format */
  ll_t ts;
  unsigned int slen;		/* snap len in this record, must be 64 for now */
  unsigned short dropped;	/* ?? */
  unsigned short wlen;		/* length of the packet on the wire, seems to include FCS */
  unsigned int chdlc;		/* Cisco HDLC header */
  unsigned char pload[44];	/* one more word than ATM and Ether */
}
pos_t;

static unsigned long long
swapll (unsigned long long ull)
{
# if (BYTE_ORDER == BIG_ENDIAN)
  return
    ((ull & 0xff00000000000000LL) >> 56) |
    ((ull & 0x00ff000000000000LL) >> 40) |
    ((ull & 0x0000ff0000000000LL) >> 24) |
    ((ull & 0x000000ff00000000LL) >> 8) |
    ((ull & 0x00000000ff000000LL) << 8) |
    ((ull & 0x0000000000ff0000LL) << 24) |
    ((ull & 0x000000000000ff00LL) << 40) |
    ((ull & 0x00000000000000ffLL) << 56);
# else
  return ull;
# endif
}

typedef enum tt
{
  TT_ATM = 0,
  TT_ETHER = 1,
  TT_POS = 2,
}
tt_t;
static tt_t tt;			/* ATM vs ETHER vs POS          */

int
pread_dag (struct timeval *ptime,
	   int *plen,
	   int *ptlen,
	   void **pphys, int *pphystype, struct ip **ppip, void **pplast)
{
  static cell_t cell1, cell2;
  static cell_t *cell;
  static ether_t *ep;
  static pos_t *pp;
  int len;
  ll_t ts;
  static int r1, r2;
  static Bool keep_going;
  static int cell_size = sizeof (cell1);
  unsigned char *lp = (unsigned char *) &ep->len;

  if (second_file == NULL)
    {
      if (two_files == 2)
	{
	  /* quick hack to use two files toghether... */
	  /* I'll have two files descriptors: stdin (already opened) */
	  /* and second_file, which is going to be opened now... */
	  if ((second_file = fopen (filenames[1], "r")) == NULL)
	    {
	      fprintf (fp_stderr, "can not open second file!: %s\n", strerror(errno));
	      exit (1);
	    }
	  /* skip the first byte */
	  r1 = fread (&cell1, 1, cell_size, stdin);
	  r2 = fread (&cell2, 1, cell_size, second_file);
	  r1 = fread (&cell1, 1, cell_size, stdin);
	  r2 = fread (&cell2, 1, cell_size, second_file);
	  keep_going = (r1 == cell_size) && (r2 == cell_size);
	}
      else
	{
	  second_file = stdin;
	  r1 = fread (&cell1, 1, cell_size, stdin);
	  r2 = fread (&cell2, 1, cell_size, second_file);
	  r1 = fread (&cell1, 1, cell_size, stdin);
	  r2 = fread (&cell2, 1, cell_size, second_file);
	  keep_going = (r1 == cell_size) && (r2 == cell_size);
	}
    }

  /* setting tt to ether now */
  tt = TT_POS;
  while (keep_going)
    {
      if (swapll (cell1.ts) < swapll (cell2.ts))
	{
	  /* use cell1 */
	  ep = (ether_t *) & cell1;
	  pp = (pos_t *) & cell1;
	  cell = &cell1;
	  if (internal_wired)
	    coming_in = TRUE;

	  r1 = fread (&cell1, 1, cell_size, stdin);
	}
      else
	{
	  /* use cell2 */
	  ep = (ether_t *) & cell2;
	  pp = (pos_t *) & cell2;
	  cell = &cell2;
	  if (internal_wired)
	    coming_in = FALSE;

	  r2 = fread (&cell2, 1, cell_size, second_file);
	}
      keep_going = (r1 == cell_size) && (r2 == cell_size);
      /*
       * XXX may want to do some trivial checks here,
       * such as checking for LLC/SNAP or filtering.
       *
       * Timestamps are normalized.
       */
      ts = swapll (cell->ts);
/*
		 fprintf(fp_stdout, " packet time:       %s\n", timestring(DAG2SEC(cell.ts), 0)) ;
*/
      ptime->tv_sec = (cell->ts >> 32);
      ts = (ts & 0xffffffffULL) * 1000 * 1000;
      ts += (ts & 0x80000000ULL) << 1;	/* rounding */
      ptime->tv_usec = (ts >> 32);

      switch (tt)
	{
#ifdef NOT_TESTED
	case TT_ATM:
	  *plen = 48;
	  *ptlen = ntohs (*(unsigned short *) &cell->pload[8 + 2]) + 8;
	  *pphys = pep;
	  *pphystype = PHYS_ETHER;
	  *ppip = (struct ip *) (cell->pload);
	  *pplast = (char *) (cell->pload) + *plen;
	  break;
	case TT_ETHER:
	  /* length field is little endian */
	  len = ((unsigned) lp[1] << 8) + lp[0] - edag;
	  /* EtherDAGs count FCS as well */
	  *plen = min (len, 54);
	  *ptlen = len;
	  *pphys = pep;
	  *pphystype = PHYS_ETHER;
	  *ppip = (struct ip *) (ep->pload);
	  *pplast = (char *) (ep->pload) + *plen;
	  break;
#endif
	case TT_POS:
	  *plen = ntohl (pp->slen) - 20;	/* subtract dag header */
	  *ptlen = ntohl (pp->wlen) - 2;	/* PoS DAGs have the same problem */
	  *pphys = pep;
	  *pphystype = PHYS_ETHER;
	  *ppip = (struct ip *) (pp->pload);
	  *pplast = (char *) (pp->pload) + *plen;
	  break;
	default:
	  fprintf (fp_stderr, "internal error %s line %d\n", __FILE__, __LINE__);
	  exit (1);
	}
      return (1);
    }
  return (0);
}

/*
 * Trace header
 */
struct tracehdr
{
  u_int64_t zeros;		/* all zeros */
  u_int32_t version;		/* cleantrace version */
  u_int64_t starttime;		/* timestamp of first valid pkt */
  u_int64_t endtime;		/* timestamp of last valid pkt */
  u_int32_t pkts;		/* total pkts */
  u_int32_t drops;		/* total of dropped pkts */
  u_int32_t ippkts;		/* total IP pkts */
  u_int64_t bytes;		/* total IP bytes */
  char pop[8];			/* pop name */
  char node[8];			/* IPMON node name */
};

char *
timestring (time_t sec, int utc)
{
  static char timestr[50];
  struct tm *tmval;
  tmval = utc ? gmtime (&sec) : localtime (&sec);
  asctime_r (tmval, timestr);

  sprintf (&timestr[24], " %s", utc ? "UTC" : tmval->tm_zone);
  return timestr;
}

pread_f *
is_dag (char *filename)
{
  struct tracehdr th;
  time_t sec;
  int utc = 0;
  int bw = 0;

/* I've no idea how to identify a dag trace for now. just try use it */

  if (fread (&th, 1, sizeof (struct tracehdr), stdin) < 0)
    {
      rewind (stdin);
      return (NULL);
    }

#ifdef SPRINT
/* Remember to skip the first 64 bytes... */
  rewind (stdin);

  if (th.zeros != 0)
    {
      return (NULL);
    }
  if (debug > 1)
    {
      fprintf (fp_stdout, " Node:             %s\n", th.node);
      sec = DAG2SEC (th.starttime);
      fprintf (fp_stdout, " Start time:       %s\n", timestring (sec, utc));
      sec = DAG2SEC (th.endtime);
      fprintf (fp_stdout, " End time:         %s\n", timestring (sec, utc));
      sec = DAG2SEC (th.endtime - th.starttime);
      fprintf (fp_stdout, " Duration:         %ldh %ldm %lds\n", sec / 3600,
	      (sec % 3600) / 60, sec % 60);
      if (DAG2SEC (th.endtime - th.starttime))
	bw = 8 * th.bytes / DAG2SEC (th.endtime - th.starttime);
      fprintf (fp_stdout, 
          " Drops:            %u (by the DAG card)\n"
	      " Packets:          %u\n"
	      "     IP Packets:   %u\n"
	      "     IP Bytes:     %lld\n"
	      "     Avg. Link Utilization: %d Mbps\n"
	      "------------------------------------------------\n\n",
	      th.drops, th.pkts, th.ippkts, th.bytes, bw / 1000000);
    }
#endif

/* ok ... looks like DAG file */
  pep = MallocZ (sizeof (struct ether_header));
  /* Set up the stuff that shouldn't change */
  pep->ether_type = ETHERTYPE_IP;

  return (pread_dag);
}

#endif /* GROK_DAG */
