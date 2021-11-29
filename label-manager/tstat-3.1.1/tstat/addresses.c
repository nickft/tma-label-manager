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

extern Bool histo_engine;
extern Bool adx_engine;
extern unsigned int adx_addr_mask[3];
extern unsigned long adx2_bitrate_delta;
extern unsigned long adx3_bitrate_delta;

struct adx **adx_index_first[3];
struct adx **adx_index_second[3];
struct adx **adx_index_current[3];

/*
 * Manages all the addresses hit count  
*/

long int tot_adx_hash_count[3], tot_adx_list_count[3], adx_search_hash_count[3],
  adx_search_list_count[3];


/* internal prototype */

/* real code */

void
alloc_adx (int idx)
{
  adx_index_first[idx] =
    (struct adx **) MMmalloc (sizeof (struct adx *) * GLOBALS.Max_ADX_Slots,
			      "alloc_adx");
  adx_index_second[idx] =
    (struct adx **) MMmalloc (sizeof (struct adx *) * GLOBALS.Max_ADX_Slots,
			      "alloc_adx");
  adx_index_current[idx] = adx_index_first[idx];
}

int
add_adx (int idx, struct in_addr *adx, int dest, int bytes)
{
  unsigned pos;
  struct adx *temp_adx, *ptr_adx, *prev_ptr_adx;
  unsigned long seed;

//  if (adx_engine == FALSE)
//    return 0;

  seed = (adx->s_addr & adx_addr_mask[idx]);
  adx_search_hash_count[idx]++;
  pos = (seed % GLOBALS.Max_ADX_Slots);

  if (adx_index_current[idx][pos] == NULL)
    {
      tot_adx_hash_count[idx]++;
      adx_search_list_count[idx]++;
      /* Insert the first */
      temp_adx = (struct adx *) MMmalloc (sizeof (struct adx), "add_adx");
      temp_adx->next = NULL;
      temp_adx->ip.s_addr = seed;
      if (dest == SRC_ADX)
	{
	  temp_adx->src_hits = 1;
	  temp_adx->dst_hits = 0;
	  temp_adx->src_bytes = bytes;
	  temp_adx->dst_bytes = 0;
	  temp_adx->max_uprate = 0.0;
	  temp_adx->max_downrate = 0.0;
	}
      else
	{
	  temp_adx->src_hits = 0;
	  temp_adx->dst_hits = 1;
	  temp_adx->src_bytes = 0;
	  temp_adx->dst_bytes = bytes;
	  temp_adx->max_uprate = 0.0;
	  temp_adx->max_downrate = 0.0;
	}
      adx_index_current[idx][pos] = temp_adx;
      return 1;
    }

  /* look for it in the list */
  ptr_adx = adx_index_current[idx][pos];
  while (ptr_adx != NULL)
    {
      adx_search_list_count[idx]++;
      if (ptr_adx->ip.s_addr == seed || ptr_adx->ip.s_addr == 0L)
	{
	  ptr_adx->ip.s_addr = seed;
	  if (dest == SRC_ADX)
	   {
	    ptr_adx->src_hits++;
	    ptr_adx->src_bytes+=bytes;
	   }
	  else
           {
	    ptr_adx->dst_hits++;
	    ptr_adx->dst_bytes+=bytes;
	   }
	  return 1;
	}
      prev_ptr_adx = ptr_adx;
      ptr_adx = ptr_adx->next;
    }

  /* ... or put it in last position */
  tot_adx_list_count[idx]++;
  temp_adx = (struct adx *) MMmalloc (sizeof (struct adx), "add_adx");
  temp_adx->next = NULL;
  temp_adx->ip.s_addr = seed;
  if (dest == SRC_ADX)
    {
      temp_adx->src_hits = 1;
      temp_adx->dst_hits = 0;
      temp_adx->src_bytes = bytes;
      temp_adx->dst_bytes = 0;
      temp_adx->max_uprate = 0.0;
      temp_adx->max_downrate = 0.0;
    }
  else
    {
      temp_adx->src_hits = 0;
      temp_adx->dst_hits = 1;
      temp_adx->src_bytes = 0;
      temp_adx->dst_bytes = bytes;
      temp_adx->max_uprate = 0.0;
      temp_adx->max_downrate = 0.0;
    }
  prev_ptr_adx->next = temp_adx;
  return 1;
}


int
print_adx (int idx, double delta)
{
  int i;
  struct adx *tmp_adx;
  struct stat fbuf;
  FILE *fp;
  char filename[200];
  struct adx **adx_index;
  adx_index = (adx_index_first[idx]==adx_index_current[idx]?adx_index_second[idx]:adx_index_first[idx]);

  if (histo_engine == FALSE || adx_engine == FALSE)
    return 1;

  /* check directory */
  if (stat (curr_data_dir, &fbuf) == -1)
    {
      fprintf (fp_stdout, "Creating output dir %s\n", curr_data_dir);
      mkdir (curr_data_dir, 0775);

    }

  if (idx == EXTERNAL_ADX_HISTO)
   {
     /*print addresses */
     sprintf (filename, "%s/%s", curr_data_dir, "addresses");
     fp = fopen (filename, "w");
   }
  else if (idx == INTERNAL_ADX_HISTO)
   {
     /*print addresses */
     sprintf (filename, "%s/%s", curr_data_dir, "addresses2");
     fp = fopen (filename, "a");
   }
  else 
    return 1;
   
  if (fp == NULL)
    {
      fprintf (fp_stdout, "Could not open file %s\n", filename);
      return 0;
    }

  fprintf (fp, "#Number of packets per subnet (%d.%d.%d.%d NETMASK) \n",
	   adx_addr_mask[idx] & 0x000000ff,
	   (adx_addr_mask[idx] & 0x0000ff00) >> 8,
	   (adx_addr_mask[idx] & 0x00ff0000) >> 16, (adx_addr_mask[idx] & 0xff000000) >> 24);
  if (idx == EXTERNAL_ADX_HISTO)
   {
     fprintf (fp, "#Subnet IP \tsrc_hits \tdst_hits \tsrc_bytes \tdst_bytes\n");
   }
  else
   {
     fprintf (fp, "#Sampling rate: Average %lu [s] - Max %lu [s]\n",adx2_bitrate_delta/1000000,adx3_bitrate_delta/1000000);
     fprintf (fp, "#Subnet IP \tTime \tsrc_hits \tdst_hits \tsrc_bytes \tdst_bytes \tUp Rate [kbps] \tDown Rate [kbps] \tMax Up Rate [kbps] \tMax Down Rate [kbps]\n");
   }
  for (i = 0; i < GLOBALS.Max_ADX_Slots; i++)
    {
      tmp_adx = adx_index[i];
      if (tmp_adx != NULL)
	{
	  if ((tmp_adx->src_hits != 0) || (tmp_adx->dst_hits != 0))
	    {
	      while ((tmp_adx != NULL)
		     && (tmp_adx->src_hits != 0 || tmp_adx->dst_hits != 0))
		{
                  if (idx == EXTERNAL_ADX_HISTO)
		   {
		      fprintf (fp, "%s\t%ld\t%ld\t%llu\t%llu\n", inet_ntoa (tmp_adx->ip),
			   tmp_adx->src_hits, tmp_adx->dst_hits,
                           tmp_adx->src_bytes, tmp_adx->dst_bytes);
		    }
		   else
		    {
		      fprintf (fp, "%s\t%.6f\t%ld\t%ld\t%llu\t%llu\t%.3f\t%.3f\t%.3f\t%.3f\n", inet_ntoa (tmp_adx->ip),
                           (double)current_time.tv_sec + (double) current_time.tv_usec / 1000000.0,
			   tmp_adx->src_hits, tmp_adx->dst_hits,
                           tmp_adx->src_bytes, tmp_adx->dst_bytes,
			   tmp_adx->src_bytes*8.0/delta*1000.,
			   tmp_adx->dst_bytes*8.0/delta*1000.,
			   tmp_adx->max_uprate,tmp_adx->max_downrate);
		    }
		  tmp_adx->src_hits = 0;
		  tmp_adx->dst_hits = 0;
		  tmp_adx->src_bytes = 0;
		  tmp_adx->dst_bytes = 0;
		  tmp_adx->max_uprate = 0.0;
		  tmp_adx->max_downrate = 0.0;
		  tmp_adx->ip.s_addr = 0L;
		  tmp_adx = tmp_adx->next;
		}
	    }
	}

    }
  /* fprintf (fp, "\n"); */
  fclose (fp);
  /* exit with a clean code */
  return (1);
}

void
swap_adx (int idx)
{
  if (adx_index_first[idx] == adx_index_current[idx])
    adx_index_current[idx] = adx_index_second[idx];
  else
    adx_index_current[idx] = adx_index_first[idx];

}

void max_adx(int idx1, int idx2, double delta)
{
  int i;
  struct adx *tmp_adx,*tmp_adx2;
  struct adx **adx_index,**adx2_index;
  adx_index = adx_index_current[idx1];
  adx2_index = (adx_index_first[idx2]==adx_index_current[idx2]?adx_index_second[idx2]:adx_index_first[idx2]);

  for (i = 0; i < GLOBALS.Max_ADX_Slots; i++)
    {
      tmp_adx2 = adx2_index[i];
      if (tmp_adx2 !=NULL)
	{
	  if ((tmp_adx2->src_hits != 0) || (tmp_adx2->dst_hits != 0))
	    {
	      while ((tmp_adx2 != NULL)
		     && (tmp_adx2->src_hits != 0 || tmp_adx2->dst_hits != 0))
		{
		  tmp_adx = adx_index[i];
		  while (tmp_adx!=NULL)
		   {
                     if (tmp_adx->ip.s_addr == tmp_adx2->ip.s_addr)
		      {
                     	tmp_adx->max_uprate = max(tmp_adx->max_uprate,tmp_adx2->src_bytes*8.0/delta*1000.);
                     	tmp_adx->max_downrate = max(tmp_adx->max_downrate,tmp_adx2->dst_bytes*8.0/delta*1000.);
			break;
		      }
		     else 
		       tmp_adx = tmp_adx->next;
		   }
		  tmp_adx2->src_hits = 0;
		  tmp_adx2->dst_hits = 0;
		  tmp_adx2->src_bytes = 0;
		  tmp_adx2->dst_bytes = 0;
		  tmp_adx2->ip.s_addr = 0L;
		  tmp_adx2 = tmp_adx2->next;
		}
	    }
	}
   }
  return;
}
