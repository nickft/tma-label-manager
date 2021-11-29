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

#include <stdio.h>
#include "tstat.h"
#include <string.h>

/* 
** Memory management with freelist instead of malloc and free.
**
*/
extern Bool bayes_engine;


#ifdef MEMDEBUG
long IN_USE_TP = 0;
long IN_USE_SEGMENT = 0;
long IN_USE_QUADRANT = 0;
long IN_USE_PTP_SNAP = 0;
long IN_USE_UDP_PAIR = 0;

long TOT_TP = 0;
long TOT_SEGMENT = 0;
long TOT_QUADRANT = 0;
long TOT_PTP_SNAP = 0;
long TOT_UDP_PAIR = 0;
extern long tot_adx_hash_count, bayes_new_count;

void
memory_debug ()
{
  fprintf (fp_stdout, "Using %ld over %ld TP\t(%ldK) (%ld MAX)\n", 
      IN_USE_TP, TOT_TP, GLOBALS.Max_TCP_Pairs, TOT_TP * sizeof (tcp_pair) >> 10);
  fprintf (fp_stdout, "Using %ld over %ld SEGMENT\t(%ldK)\n", 
      IN_USE_SEGMENT, TOT_SEGMENT, TOT_SEGMENT * sizeof (segment) >> 10);
  fprintf (fp_stdout, "Using %ld over %ld QUADRANT\t(%ldK)\n", 
      IN_USE_QUADRANT, TOT_QUADRANT, TOT_QUADRANT * sizeof (quadrant) >> 10);
  fprintf (fp_stdout, "Using %ld over %ld PTP_SNAP\t(%ldK)\n", 
      IN_USE_PTP_SNAP, TOT_PTP_SNAP, TOT_PTP_SNAP * sizeof (ptp_snap) >> 10);
  fprintf (fp_stdout, "Using %ld over %ld UDP_PAIR\t(%ldK)\n", 
      IN_USE_UDP_PAIR, TOT_UDP_PAIR, TOT_UDP_PAIR * sizeof (udp_pair) >> 10);
  fprintf (fp_stdout, "Using %ld ADX\n", tot_adx_hash_count);
  fprintf (fp_stdout, "Using %ld bayes_classifier\n", bayes_new_count);


}
#endif
/*
**  Function  : void *MMmalloc(size_t size, const char * function_name)
**  Return    : the pointer to the memory of the new allocated block
**  Remarks   : MMmalloc() allocates size bytes and returns a pointer to the
**              allocated memory.  The memory is cleared.
**              If an error occours, an error is printed, including the
**              function name of the calling function.
*/
void *
MMmalloc (size_t size, const char *f_name)
{
  void *temp_pointer;
  if ((temp_pointer = malloc (size)) == NULL)
    {
      /* If problems arise from the memory allocation, an error message is    */
      /* printed before exiting the program execution.                        */
      fprintf (fp_stderr, 
        "\nError:  Memory allocation error in Tstat function %s\n", f_name);
      exit (1);
    }
  memset (temp_pointer, 0, size);
  return temp_pointer;
}

/* Garbage collector for the tcp_pair structs
* Two pointer are used (top and last).
* Alloc and release from last, while top is used to not loose the list ...
*/

static struct tp_list_elem *top_tp_flist = NULL;	/* Pointer to the top of      */
					     /* the 'tplist' free list.    */
static struct tp_list_elem *last_tp_flist = NULL;	/* Pointer to the last used   */
					     /* element list.              */

tcp_pair *
tp_alloc (void)
{
  tcp_pair *ptp_temp;
#ifdef MEMDEBUG
  IN_USE_TP++;
#endif

  if ((last_tp_flist == NULL) || (last_tp_flist->ptp == NULL))
    {				/* The LinkList stack is empty.         */
      /* fprintf (fp_stdout, "FList empty, top == last == NULL\n"); */
      ptp_temp = (tcp_pair *) MMmalloc (sizeof (tcp_pair), "tplist_alloc");
      ptp_temp->c2s.ss = (seqspace *) MallocZ (sizeof (seqspace));
      ptp_temp->s2c.ss = (seqspace *) MallocZ (sizeof (seqspace));
#ifdef MEMDEBUG
      TOT_TP++;
#endif
      if (bayes_engine)
	{
	  ptp_temp->c2s.bc_avgipg = bayes_new (bayes_settings_avgipg);
	  ptp_temp->c2s.bc_pktsize = bayes_new (bayes_settings_pktsize);
	  ptp_temp->s2c.bc_avgipg = bayes_new (bayes_settings_avgipg);
	  ptp_temp->s2c.bc_pktsize = bayes_new (bayes_settings_pktsize);
          ptp_temp->c2s.skype = (skype_stat *) MallocZ (sizeof (skype_stat));
          ptp_temp->s2c.skype = (skype_stat *) MallocZ (sizeof (skype_stat));
	}

      return ptp_temp;
    }
  else
    {				/* The 'tplist' stack is not empty.   */
      ptp_temp = last_tp_flist->ptp;
      last_tp_flist->ptp = NULL;
      if (last_tp_flist->next != NULL)
	last_tp_flist = last_tp_flist->next;
      return ptp_temp;
    }
}

void
tp_release (tcp_pair * released_tcp_pair)
{
  struct tp_list_elem *new_tplist_elem;
  seqspace *sstemp1, *sstemp2;
  struct skype_stat *skypetemp1, *skypetemp2;
  struct bayes_classifier *bctemp1, *bctemp2, *bctemp3, *bctemp4;

#ifdef MEMDEBUG
  IN_USE_TP--;
#endif

  if (released_tcp_pair->ssl_client_subject!=NULL)
   {
     free(released_tcp_pair->ssl_client_subject);
     released_tcp_pair->ssl_client_subject=NULL;
   }

  if (released_tcp_pair->ssl_server_subject!=NULL)
   {
     free(released_tcp_pair->ssl_server_subject);
     released_tcp_pair->ssl_server_subject=NULL;
   }

  if (released_tcp_pair->dns_name!=NULL)
   {
     free(released_tcp_pair->dns_name);
     released_tcp_pair->dns_name=NULL;
   }
  
  memset (released_tcp_pair->c2s.ss, 0, sizeof (seqspace));
  memset (released_tcp_pair->s2c.ss, 0, sizeof (seqspace));
  sstemp1 = released_tcp_pair->c2s.ss;
  sstemp2 = released_tcp_pair->s2c.ss;

  if (released_tcp_pair->c2s.skype!=NULL)
   {
     memset (released_tcp_pair->c2s.skype, 0, sizeof (skype_stat));
     skypetemp1 = released_tcp_pair->c2s.skype;
   }
  else 
    skypetemp1 = NULL;
   
  if (released_tcp_pair->s2c.skype!=NULL)
   {
     memset (released_tcp_pair->s2c.skype, 0, sizeof (skype_stat));
     skypetemp2 = released_tcp_pair->s2c.skype;
   }
  else 
    skypetemp2 = NULL;
   
  bayes_reset0 (bctemp1 = released_tcp_pair->c2s.bc_pktsize);
  bayes_reset0 (bctemp2 = released_tcp_pair->s2c.bc_pktsize);
  bayes_reset0 (bctemp3 = released_tcp_pair->c2s.bc_avgipg);
  bayes_reset0 (bctemp4 = released_tcp_pair->s2c.bc_avgipg);

  memset (released_tcp_pair, 0, sizeof (tcp_pair));

  released_tcp_pair->c2s.skype = skypetemp1;
  released_tcp_pair->s2c.skype = skypetemp2;
  released_tcp_pair->c2s.ss = sstemp1;
  released_tcp_pair->s2c.ss = sstemp2;
  released_tcp_pair->c2s.bc_pktsize = bctemp1;
  released_tcp_pair->s2c.bc_pktsize = bctemp2;
  released_tcp_pair->c2s.bc_avgipg = bctemp3;
  released_tcp_pair->s2c.bc_avgipg = bctemp4;

  if ((last_tp_flist == NULL)
      || ((last_tp_flist->ptp != NULL) && (last_tp_flist->prev == NULL)))
    {

      new_tplist_elem =
	(struct tp_list_elem *) MMmalloc (sizeof (struct tp_list_elem),
					  "tplist_release");
      new_tplist_elem->ptp = released_tcp_pair;
      new_tplist_elem->prev = NULL;
      new_tplist_elem->next = top_tp_flist;
      if (new_tplist_elem->next != NULL)
	new_tplist_elem->next->prev = new_tplist_elem;
      top_tp_flist = new_tplist_elem;
      last_tp_flist = new_tplist_elem;
    }
  else
    {
      if (last_tp_flist->ptp == NULL)
	new_tplist_elem = last_tp_flist;
      else
	new_tplist_elem = last_tp_flist->prev;
      new_tplist_elem->ptp = released_tcp_pair;
      last_tp_flist = new_tplist_elem;
    }
}

void
tp_list_list ()
{
  struct tp_list_elem *new_tplist_elem;

  new_tplist_elem = top_tp_flist;
  fprintf (fp_stdout, "\n\t[top]\n");
  while (new_tplist_elem != NULL)
    {
      fprintf (fp_stdout, "\t|\n");
      if (new_tplist_elem == last_tp_flist)
	fprintf (fp_stdout, "[last]->");
      else
	fprintf (fp_stdout, "\t");
      fprintf (fp_stdout, "[tp_list_elem]->");
      if (new_tplist_elem->ptp != NULL)
	{
	  fprintf (fp_stdout, "[ptp]");
	}
      else
	{
	  fprintf (fp_stdout, "[NULL]");
	}
      fprintf (fp_stdout, "\n");
      new_tplist_elem = new_tplist_elem->next;
    }
  fprintf (fp_stdout, "\n");
}

/* garbage collector for the segment list */

static segment *segment_flist = NULL;	/* Pointer to the top of      */
					/* the 'segment' free list.  */
segment *
segment_alloc (void)
{
  segment *pseg;

#ifdef MEMDEBUG
  IN_USE_SEGMENT++;
#endif
  if (segment_flist == NULL)
    {
      pseg = (segment *) MallocZ (sizeof (segment));
#ifdef MEMDEBUG
      TOT_SEGMENT++;
#endif
    }
  else
    {
      pseg = segment_flist;
      segment_flist = segment_flist->next;
    }
  pseg->next = NULL;
  return pseg;
}

void
segment_release (segment * rel_segment)
{
#ifdef MEMDEBUG
  IN_USE_SEGMENT--;
#endif
  memset (rel_segment, 0, sizeof (segment));
  rel_segment->next = segment_flist;
  segment_flist = rel_segment;
}

void
segment_list_info ()
{
  segment *pseg;
  int i = 0;

  pseg = segment_flist;
  while (pseg != NULL)
    {
      i++;
      pseg = pseg->next;
    }
  fprintf (fp_stdout, "Segments in flist: %d\n", i);
}

/* garbage collector for the Quadrant */

static quadrant *quadrant_flist = NULL;	/* Pointer to the top of      */
					/* the 'quadrant' free list.  */

quadrant *
quadrant_alloc (void)
{
  quadrant *pquad;

#ifdef MEMDEBUG
  IN_USE_QUADRANT++;
#endif
  if (quadrant_flist == NULL)
    {
      pquad = (quadrant *) MallocZ (sizeof (quadrant));
#ifdef MEMDEBUG
      TOT_QUADRANT++;
#endif
    }
  else
    {
      pquad = quadrant_flist;
      quadrant_flist = quadrant_flist->next;
    }
  pquad->next = NULL;
  return pquad;
}

void
quadrant_release (quadrant * rel_quadrant)
{
#ifdef MEMDEBUG
  IN_USE_QUADRANT--;
#endif
  memset (rel_quadrant, 0, sizeof (quadrant));
  rel_quadrant->next = quadrant_flist;
  quadrant_flist = rel_quadrant;
}

void
quadrant_list_info ()
{
  quadrant *pquad;
  int i = 0;

  pquad = quadrant_flist;
  while (pquad != NULL)
    {
      i++;
      pquad = pquad->next;
    }
  fprintf (fp_stdout, "Quadrants in flist: %d\n", i);
}

/* garbage collector for the ptp_snap list */

static ptp_snap *top_ptph_flist = NULL;	/* Pointer to the top of      */
					/* the 'ptp_snap' free list.    */
ptp_snap *
ptph_alloc (void)
{
  struct ptp_snap *new_ptph;

#ifdef MEMDEBUG
  IN_USE_PTP_SNAP++;
#endif

  if (top_ptph_flist == NULL)
    {
      new_ptph = (ptp_snap *) MMmalloc (sizeof (ptp_snap), "ptph_alloc");
#ifdef MEMDEBUG
      TOT_PTP_SNAP++;
#endif
    }
  else
    {
      new_ptph = top_ptph_flist;
      top_ptph_flist = top_ptph_flist->next;
    }
  new_ptph->next = NULL;
  return (new_ptph);
}

void
ptph_release (ptp_snap * rel_ptph)
{
#ifdef MEMDEBUG
  IN_USE_PTP_SNAP--;
#endif
  memset (rel_ptph, 0, sizeof (ptp_snap));
  rel_ptph->next = top_ptph_flist;
  top_ptph_flist = rel_ptph;
}

int
UsingFreedPtpsnap (ptp_snap * my_ptph)
{
  struct ptp_snap *temp_ptph;

  temp_ptph = top_ptph_flist;
  while (temp_ptph)
    {
      if (temp_ptph == my_ptph)
	return (1);
      temp_ptph = temp_ptph->next;
    }
  return (0);
}



/* garbage collection of udp_pair */

static udp_pair *udp_pair_flist = NULL;	/* Pointer to the top of      */
					/* the 'udp_pair' free list.  */

udp_pair *
utp_alloc (void)
{
  udp_pair *pud;

#ifdef MEMDEBUG
  IN_USE_UDP_PAIR++;
#endif
  if (udp_pair_flist == NULL)
    {
      pud = (udp_pair *) MallocZ (sizeof (udp_pair));
      if (bayes_engine)
	{
	  pud->c2s.bc_avgipg = bayes_new (bayes_settings_avgipg);
	  pud->c2s.bc_pktsize = bayes_new (bayes_settings_pktsize);
	  pud->s2c.bc_avgipg = bayes_new (bayes_settings_avgipg);
	  pud->s2c.bc_pktsize = bayes_new (bayes_settings_pktsize);
          pud->c2s.skype = (skype_stat *) MallocZ (sizeof (skype_stat));
          pud->s2c.skype = (skype_stat *) MallocZ (sizeof (skype_stat));
	}

#ifdef MEMDEBUG
      TOT_UDP_PAIR++;
#endif
    }
  else
    {
      pud = udp_pair_flist;
      udp_pair_flist = udp_pair_flist->next;
    }
  pud->next = NULL;

  return (pud);
}

void
utp_release (udp_pair * rel_udp_pair)
{
  struct bayes_classifier *bctemp1, *bctemp2, *bctemp3, *bctemp4;
  struct skype_stat *skypetemp1, *skypetemp2;

#ifdef MEMDEBUG
  IN_USE_UDP_PAIR--;
#endif

  if (rel_udp_pair->dns_name!=NULL)
   {
     free(rel_udp_pair->dns_name);
     rel_udp_pair->dns_name=NULL;
   }

  if (rel_udp_pair->c2s.skype!=NULL)
   {
     memset (rel_udp_pair->c2s.skype, 0, sizeof (skype_stat));
     skypetemp1 = rel_udp_pair->c2s.skype;
   }
  else 
    skypetemp1 = NULL;

  if (rel_udp_pair->s2c.skype!=NULL)
   {
     memset (rel_udp_pair->s2c.skype, 0, sizeof (skype_stat));
     skypetemp2 = rel_udp_pair->s2c.skype;
   }
  else 
    skypetemp2 = NULL;

  bayes_reset0 (bctemp1 = rel_udp_pair->c2s.bc_pktsize);
  bayes_reset0 (bctemp2 = rel_udp_pair->s2c.bc_pktsize);
  bayes_reset0 (bctemp3 = rel_udp_pair->c2s.bc_avgipg);
  bayes_reset0 (bctemp4 = rel_udp_pair->s2c.bc_avgipg);

  memset (rel_udp_pair, 0, sizeof (udp_pair));	/* reset all the fields */
  rel_udp_pair->next = udp_pair_flist;
  udp_pair_flist = rel_udp_pair;

  rel_udp_pair->c2s.skype = skypetemp1;
  rel_udp_pair->s2c.skype = skypetemp2;
  rel_udp_pair->c2s.bc_pktsize = bctemp1;
  rel_udp_pair->s2c.bc_pktsize = bctemp2;
  rel_udp_pair->c2s.bc_avgipg = bctemp3;
  rel_udp_pair->s2c.bc_avgipg = bctemp4;
}
