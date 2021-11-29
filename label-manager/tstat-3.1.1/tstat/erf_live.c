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

/* Code by Alessandro Finamore and Marco Bosetti 
 * Alessandro Finamore <finale80@libero.it>
 * Marco Bosetti <marco.bosetti@poste.it>
*/

#include "tstat.h"

#ifdef GROK_ERF_LIVE
#include "dagapi.h"
#include "dagutil.h"
#include "dagclarg.h"

#define ERFT_LEGACY       0
#define ERFT_HDLC_POS     1
#define ERFT_ETH          2
#define ERFT_ATM          3
#define ERFT_AAL5         4

typedef struct erf_pos
{
  unsigned hdlc;
  unsigned char pload[1];
} erf_pos_t;

typedef struct erf_eth
{
  unsigned char offset;
  unsigned char pad;
  unsigned char dst[6];
  unsigned char src[6];
  unsigned short etype;
  unsigned char pload[1];
} erf_eth_t;

typedef struct erf_atm
{
  unsigned header;
  unsigned char pload[1];
} erf_atm_t;

typedef struct erf_aal5
{
  unsigned header;
  unsigned char pload[1];
} erf_aal5_t;

typedef struct erf_flags
{
  unsigned char iface:2;
  unsigned char vlen:1;
  unsigned char trunc:1;
  unsigned char rxerror:1;
  unsigned char dserror:1;
  unsigned char pad:2;
} erf_flags_t;

#ifdef HAVE_LONG_LONG
typedef unsigned long long erf_timestamp_t;
#else
typedef unsigned long erf_timestamp_t[2];
#endif

typedef struct erf_record
{
  erf_timestamp_t ts;
  unsigned char type;
  unsigned char erf_flags_t;
  unsigned short rlen;
  unsigned short lctr;
  unsigned short wlen;
  union
  {
    erf_pos_t pos;
    erf_eth_t eth;
    erf_atm_t atm;
  } rec;
} erf_record_t;

void
print_erf_record (erf_record_t * r)
{
#ifdef HAVE_LONG_LONG
  fprintf (fp_stderr, "ts = %lld\n", r->ts);
#else
  fprintf (fp_stderr, "ts = %ld\t", r->ts[0]);
  fprintf (fp_stderr, "ts = %ld\n", r->ts[1]);
#endif
  fprintf (fp_stderr, "type = %d\n", r->type);
  fprintf (fp_stderr, "flags = %d\n", r->erf_flags_t);
  fprintf (fp_stderr, "rlen = %d\n", ntohs (r->rlen));
  fprintf (fp_stderr, "lctr = %d\n", r->lctr);
  fprintf (fp_stderr, "wlen = %d\n", ntohs (r->wlen));
}

#define ERF_HEADER_LEN            16
#define MAX_RECORD_LEN            0x10000	/* 64k */
#define FCS_BITS                  32
#define CAPTURE_DAG_LOCKED        0
#define CAPTURE_DAG_UNLOCKED      1

/* return ERF which start at offset byte from the head of the buffer */
#define GET_ERF(pos)    ((erf_record_t *)((char *)erfbuf_ptr[pos].record + erfbuf_ptr[pos].old))

/*
 * ATM snaplength
 */
#define ATM_SNAPLEN        48

/*
 * Size of ATM payload 
 */
#define ATM_SLEN(h)        ATM_SNAPLEN
#define ATM_WLEN(h)        ATM_SNAPLEN

/*
 * Size of Ethernet payload
 */
#define ETHERNET_WLEN(h)    (ntohs((h)->wlen) - (fcs_bits >> 3))
#define ETHERNET_SLEN(h)     min(ETHERNET_WLEN(h), ntohs((h)->rlen) - ERF_HEADER_LEN - 2)

/*
 * Size of HDLC payload
 */
#define HDLC_WLEN(h)        (ntohs((h)->wlen) - (fcs_bits >> 3))
#define HDLC_SLEN(h)        min(HDLC_WLEN(h), ntohs((h)->rlen) - ERF_HEADER_LEN)

#define MAX_DAG             4	/* max number of supported cards */
/* Structure for information about dag cards:
 * old, new : pointers of internal buffer
 * record   : pointer on the head of the internal buffer 
 * dagfd    : descriptor of the card
 */
typedef struct erfbuf_info
{
  int old;
  int new;
  void *record;
  int dagfd;
} erfbuf_info;

static struct ether_header eth_header;
static erfbuf_info *erfbuf_ptr;
static int ndag;		/* number of DAG activated */
static int fcs_bits = FCS_BITS;
extern Bool internal_wired;
extern Bool coming_in;

/*
 * Convert little-endian to host order.
 */
#ifdef HAVE_LONG_LONG
#define pletohll(p) ((unsigned long long)*((const unsigned char *)(p)+7)<<56|  \
                     (unsigned long long)*((const unsigned char *)(p)+6)<<48|  \
                     (unsigned long long)*((const unsigned char *)(p)+5)<<40|  \
                     (unsigned long long)*((const unsigned char *)(p)+4)<<32|  \
                     (unsigned long long)*((const unsigned char *)(p)+3)<<24|  \
                     (unsigned long long)*((const unsigned char *)(p)+2)<<16|  \
                     (unsigned long long)*((const unsigned char *)(p)+1)<<8|   \
                     (unsigned long long)*((const unsigned char *)(p)+0)<<0)
#else
#define pletohl(p)  ((unsigned long)*((const unsigned char *)(p)+3)<<24|  \
                     (unsigned long)*((const unsigned char *)(p)+2)<<16|  \
                     (unsigned long)*((const unsigned char *)(p)+1)<<8|   \
                     (unsigned long)*((const unsigned char *)(p)+0)<<0)
#endif

int
pread_erf_live (struct timeval *ptime,
		int *plen,
		int *ptlen,
		void **pphys, int *pphystype, struct ip **ppip, void **pplast)
{
  unsigned short ether_type = 0;
  erf_record_t *curr_erf = NULL;
  unsigned int len, old, new;
  Bool erftype_ok = FALSE;
#ifdef HAVE_LONG_LONG
  unsigned long long ts;
#endif
  int dagfd = erfbuf_ptr[0].dagfd;

  /* loop until isn't find an ERF of correct type (ETH, ATM, HDLC)
   * with IP packet inside
   */
  while (!erftype_ok)
    {
      curr_erf = (erf_record_t *) dag_rx_stream_next_record (dagfd, 0);
      if (curr_erf)
	{
	  len = ntohs (curr_erf->rlen);
	  /* User processing here */
	  if (debug > 1)
	    fprintf (fp_stderr, "Got a new packet from the buffer (len = %d)\n",
		     len);
	  if (debug > 2)
	    print_erf_record (curr_erf);

#ifdef HAVE_LONG_LONG
	  ts = pletohll (&curr_erf->ts);

	  ptime->tv_sec = ts >> 32;
	  ts = ((ts & 0xffffffffULL) * 1000 * 1000);
	  ts += (ts & 0x80000000ULL) << 1;	/* rounding */
	  ptime->tv_usec = ts >> 32;
	  if (ptime->tv_usec >= 1000000)
	    {
	      ptime->tv_usec -= 1000000;
	      ptime->tv_sec += 1;
	    }
#else
	  ptime->tv_sec = pletohl (&curr_erf->ts[1]);
	  ptime->tv_usec =
	    (unsigned long) ((pletohl (&curr_erf->ts[0]) * 1000000.0) /
			     0xffffffffUL);
#endif

	  switch (curr_erf->type)
	    {
	    case ERFT_ATM:
	      erftype_ok = TRUE;
	      *ptlen = ATM_SLEN (curr_erf);
	      *plen = ATM_WLEN (curr_erf);
	      *pphys = &eth_header;
	      ether_type =
		ntohs (((unsigned short *) &curr_erf->rec.atm.pload)[3]);
	      *ppip = (struct ip *) &curr_erf->rec.atm.pload[8];	/* skip snap/llc */
	      *pplast = ((char *) *ppip) + *ptlen - 8 - 1;
	      break;
	    case ERFT_ETH:
	      erftype_ok = TRUE;
	      *ptlen = ETHERNET_SLEN (curr_erf);
	      *plen = ETHERNET_WLEN (curr_erf);
	      *pphys = &curr_erf->rec.eth.dst;
	      ether_type = ntohs (curr_erf->rec.eth.etype);
	      *ppip = (struct ip *) &curr_erf->rec.eth.pload[0];
	      *pplast =
		((char *) *ppip) + *ptlen - sizeof (struct ether_header) - 1;
	      break;
	    case ERFT_HDLC_POS:
	      erftype_ok = TRUE;
	      *ptlen = HDLC_SLEN (curr_erf);
	      *plen = HDLC_WLEN (curr_erf);
	      *pphys = &eth_header;
	      /* Detect PPP and convert the Ethertype value */
	      if (ntohs (((unsigned short *) &curr_erf->rec.pos.hdlc)[0]) ==
		  0xff03)
		{
		  if (ntohs (((unsigned short *) &curr_erf->rec.pos.hdlc)[1])
		      == 0x0021)
		    {
		      ether_type = ETHERTYPE_IP;
		    }
		}
	      else
		{
		  ether_type =
		    ntohs (((unsigned short *) &curr_erf->rec.pos.hdlc)[1]);
		}
	      *ppip = (struct ip *) &curr_erf->rec.pos.pload[0];
	      *pplast = ((char *) *ppip) + *ptlen - 4 - 1;
	      break;
	    default:
	      fprintf (fp_stderr, "Unsupported ERF type: %d\n", curr_erf->type);
	    }
	  *pphystype = PHYS_ETHER;

	  /* if it's not IP, then skip it */
	  if (ether_type != ETHERTYPE_IP && ether_type != ETHERTYPE_IPV6)
	    {
	      if (debug > 2)
		fprintf (fp_stderr, "pread_erf: not an IP packet\n");
	      erftype_ok = FALSE;
	    }


	  /* return 0 mean EOF */
	  return 1;
	}
      else
	{			/* rec == NULL */
	  if (errno != EAGAIN)
	    {
	      fprintf (fp_stderr, "dag_get_next_record: %s\n", strerror (errno));
	      exit (1);
	    }
	}
    }
}

int
pread_multi_erf_live (struct timeval *ptime,
		      int *plen,
		      int *ptlen,
		      void **pphys,
		      int *pphystype, struct ip **ppip, void **pplast)
{
  unsigned short ether_type = 0;
  erf_record_t *curr_erf[MAX_DAG];
  erf_record_t *tmp_erf;
  int i, pos_mints, old, new, inc;
  struct timeval mints, currts;
  Bool capture, erftype_ok;
#ifdef HAVE_LONG_LONG
  unsigned long long ts = pletohll (&curr_erf[i]->ts);
#endif

  capture = FALSE;
  erftype_ok = FALSE;

  /* loop until isn't find an ERF of correct type (ETH, ATM, HDLC)
   */
  while (!erftype_ok)
    {
      /* wait until at least one card have new data
       */
      while (!capture)
	{
	  /* control all the card in the set
	   */
	  for (i = 0; i < ndag; ++i)
	    {
	      old = erfbuf_ptr[i].old;
	      new = erfbuf_ptr[i].new;

	      /* old == new if and only if
	       * - it's the first call of the function
	       * - all the packet between the two poiters were processed
	       */
	      if (old == new)
		{
		  new = erfbuf_ptr[i].new =
		    dag_offset (erfbuf_ptr[i].dagfd, &erfbuf_ptr[i].old,
				CAPTURE_DAG_UNLOCKED);
		  if (debug > 1 && (new > old))
		    fprintf (fp_stderr,
			     "Getting a new buffer from the dag card %d with size %d\n",
			     i, new - old);
		}
	      else
		capture = TRUE;
	    }			/* END for */
	}			/* END while(!capture) */

      capture = FALSE;		/* in case we need to loop */

      /* get the first sample among the available one */
      mints.tv_sec = -1;
      mints.tv_usec = -1;
      pos_mints = -1;
      for (i = 0; i < ndag; ++i)
	{
	  if (erfbuf_ptr[i].new != erfbuf_ptr[i].old)
	    {
	      curr_erf[i] = GET_ERF (i);
	      if (debug > 1)
		fprintf (fp_stderr,
			 "Checking new packet from the buffer %d \n", i);
	      if (debug > 2)
		print_erf_record (curr_erf[i]);


#ifdef HAVE_LONG_LONG
	      ts = pletohll (&curr_erf[i]->ts);

	      currts.tv_sec = ts >> 32;
	      ts = ((ts & 0xffffffffULL) * 1000 * 1000);
	      ts += (ts & 0x80000000ULL) << 1;	/* rounding */
	      currts.tv_usec = ts >> 32;
	      if (currts.tv_usec >= 1000000)
		{
		  currts.tv_usec -= 1000000;
		  currts.tv_sec += 1;
		}
#else
	      currts.tv_sec = pletohl (&curr_erf[i]->ts[1]);
	      currts.tv_usec =
		(unsigned long) ((pletohl (&curr_erf[i]->ts[0]) * 1000000.0)
				 / 0xffffffffUL);
#endif
	      if (mints.tv_sec == -1 ||
		  (currts.tv_sec < mints.tv_sec) ||
		  (currts.tv_sec == mints.tv_sec
		   && currts.tv_usec < mints.tv_usec))
		{
		  mints = currts;
		  pos_mints = i;
		}
	    }
	}

      if (internal_wired)
	coming_in = (pos_mints == 0);

      if (mints.tv_sec == -1)
	continue;		/* we didn't get any packets */
      /* process it */
      *ptime = mints;
      tmp_erf = curr_erf[pos_mints];
      inc = ntohs (tmp_erf->rlen);
      if (debug > 1)
	fprintf (fp_stderr, "Got a new packet from the buffer %d (inc = %d)\n",
		 pos_mints, inc);

      /* old point to the next packet */
      if (inc <= 0
	  || erfbuf_ptr[pos_mints].old + inc > erfbuf_ptr[pos_mints].new)
	{
	  if (debug > 0)
	    fprintf (fp_stderr, "Possible loss of packets: inc = %d, %d, %d\n",
		     inc,
		     erfbuf_ptr[pos_mints].old, erfbuf_ptr[pos_mints].new);
	  erfbuf_ptr[pos_mints].old = erfbuf_ptr[pos_mints].new;
	}
      else
	erfbuf_ptr[pos_mints].old += inc;

      switch (tmp_erf->type)
	{
	case ERFT_ATM:
	  erftype_ok = TRUE;
	  *ptlen = ATM_SLEN (tmp_erf);
	  *plen = ATM_WLEN (tmp_erf);
	  *pphys = &eth_header;
	  ether_type =
	    ntohs (((unsigned short *) &tmp_erf->rec.atm.pload)[3]);
	  *ppip = (struct ip *) &tmp_erf->rec.atm.pload[8];	/* skip snap/llc */
	  *pplast = ((char *) *ppip) + *ptlen - 8 - 1;
	  break;
	case ERFT_ETH:
	  erftype_ok = TRUE;
	  *ptlen = ETHERNET_SLEN (tmp_erf);
	  *plen = ETHERNET_WLEN (tmp_erf);
	  *pphys = &tmp_erf->rec.eth.dst;
	  ether_type = ntohs (tmp_erf->rec.eth.etype);
	  *ppip = (struct ip *) &tmp_erf->rec.eth.pload[0];
	  *pplast =
	    ((char *) *ppip) + *ptlen - sizeof (struct ether_header) - 1;
	  break;
	case ERFT_HDLC_POS:
	  erftype_ok = TRUE;
	  *ptlen = HDLC_SLEN (tmp_erf);
	  *plen = HDLC_WLEN (tmp_erf);
	  *pphys = &eth_header;
	  /* Detect PPP and convert the Ethertype value */
	  if (ntohs (((unsigned short *) &tmp_erf->rec.pos.hdlc)[0]) ==
	      0xff03)
	    {
	      if (ntohs (((unsigned short *) &tmp_erf->rec.pos.hdlc)[1]) ==
		  0x0021)
		{
		  ether_type = ETHERTYPE_IP;
		}
	    }
	  else
	    {
	      ether_type =
		ntohs (((unsigned short *) &tmp_erf->rec.pos.hdlc)[1]);
	    }
	  *ppip = (struct ip *) &tmp_erf->rec.pos.pload[0];
	  *pplast = ((char *) *ppip) + *ptlen - 4 - 1;
	  break;
	default:
	  fprintf (fp_stderr, "Unsupported ERF type: %d\n", tmp_erf->type);
	}

      *pphystype = PHYS_ETHER;

      /* if it's not IP, then skip it */
      if (ether_type != ETHERTYPE_IP && ether_type != ETHERTYPE_IPV6)
	{
	  if (debug > 2)
	    fprintf (fp_stderr, "pread_erf: not an IP packet\n");
	  erftype_ok = FALSE;
	}

    }				/* END while(!erftype_ok) */


  /* return 0 would mean EOF */
  return 1;
}


/* initialization function for capture from DAG */
pread_f *
init_erf_live (char *device_list)
{
  void *record;
  int dagfd;
  char *dagname;
  struct timeval maxwait;
  struct timeval poll;

  if (erfbuf_ptr == NULL)
    erfbuf_ptr = (erfbuf_info *) MallocZ (MAX_DAG * sizeof (erfbuf_info));

  dagname = strtok (device_list, " ");
  while (dagname != NULL)
    {
      if ((dagfd = dag_open (dagname)) == -1)
	{
	  fprintf (fp_stderr, 
        "Error: unable to open device \"%s\" in erf_live.c\n", dagname);
	  exit (1);
	}
      if (dag_configure (dagfd, "slen=90 nic rxonly") < 0)
	{
	  fprintf (fp_stderr, 
        "Error: dag_configure %s: %s failed in erf_live.c\n:",
		dagname, strerror (errno));
	  exit (1);
	}

      if (dag_attach_stream (dagfd, 0, 0, 4 * 1024 * 1024) < 0)
	{
	  fprintf (fp_stderr, 
        "Error: dag_attach %s: %s failed in erf_live.c\n", dagname,
		strerror (errno));
	  exit (1);
	}

      if (dag_start_stream (dagfd, 0) < 0)
	{
	  fprintf (fp_stderr, 
        "Error: dag_start %s: %s in erf_live.c\n", dagname,
		strerror (errno));
	  exit (1);
	}

      /* Initialise DAG Polling parameters. */
      timerclear (&maxwait);
      maxwait.tv_usec = 100 * 1000;	/* 100ms timeout */
      timerclear (&poll);
      poll.tv_usec = 10 * 1000;	/* 10ms poll interval */

      /* 32kB minimum data to return */
      dag_set_stream_poll (dagfd, 0, 32 * 1024, &maxwait, &poll);

      erfbuf_ptr[ndag].dagfd = dagfd;
      erfbuf_ptr[ndag].record = record;
      erfbuf_ptr[ndag].new = 0;
      erfbuf_ptr[ndag].old = 0;

      ndag++;
      fprintf (fp_stdout, "Opened capture channel on '%s'\n", dagname);
      dagname = strtok (NULL, " ");
    }

  if (ndag == 1)
    return pread_erf_live;
  return pread_multi_erf_live;
}
#endif
