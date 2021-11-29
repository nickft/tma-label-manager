/*
 *
 * Copyright (c) 2001
 *	Politecnico di Torino.  All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foun on; either version 2 of the License, or
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

extern unsigned long int fcount;
extern Bool printticks;
extern Bool histo_engine;
extern Bool histo_engine_log;
extern Bool adx_engine;
extern Bool adx2_engine;
extern Bool global_histo;

extern unsigned int adx_addr_mask[3];

extern struct L4_bitrates L4_bitrate;
extern struct L7_bitrates L7_bitrate;
extern struct L7_bitrates L7_udp_bitrate;
extern struct HTTP_bitrates HTTP_bitrate;
extern struct WEB_bitrates WEB_bitrate;
extern struct TLS_bitrates TLS_bitrate;


extern struct VIDEO_rates VIDEO_rate;

extern unsigned long tot_conn_TCP;
extern unsigned long tot_conn_UDP;
extern unsigned long adx2_bitrate_delta;
extern unsigned long adx3_bitrate_delta;

/* Pointer to the last valid histo */
struct double_histo_list *hl = NULL;

struct histo_conf
{
  char *fname;
} histo_conf;


struct double_histo_list *
first_histo_list ()
{
  return hl;
}

/*
//===================================================================================
// histo configuration                                                                                   
//-----------------------------------------------------------------------------------
*/

void
histo_set_conf (char *fname)
{
  if (fname)
    histo_conf.fname = strdup (fname);
}


struct double_histo_list *
find_histo (char *hname)
{
  struct double_histo_list *temphp = first_histo_list ();

  while (temphp != NULL)
    {
      if (!strcmp (temphp->name, hname))
	return temphp;

      temphp = temphp->next;
    }
  return NULL;
}

unsigned int validate_adx_mask(char *mask_string,unsigned int default_mask)
{

  struct in_addr adx_net2;
  unsigned int adx_net_mask;

  unsigned int full_local_mask;
  int mask_bits;
  char *err;
  char s[16];
  err = NULL;

  //network mask as a single number
  if (!strchr(mask_string,'.'))
  { 
      err = NULL;
      mask_bits = strtol(mask_string, &err, 10);
      if (*err || mask_bits < 1 || mask_bits > 32) {
      fprintf(fp_stderr, 
            "Warning: Invalid netmask in <adx_mask> or <adx2_mask> histogram option. Using default %d.%d.%d.%d\n",
        default_mask & 0xff,
        (default_mask >> 8 ) & 0x0000ff,
        (default_mask >> 16)  & 0x00ff,
        default_mask >> 24);
      return default_mask;
      }

      if (mask_bits == 0)
  	 full_local_mask = 0;
      else
  	 full_local_mask = 0xffffffff << (32 - mask_bits);

      sprintf(s,"%d.%d.%d.%d",
  	  full_local_mask >> 24,
  	  (full_local_mask >> 16)  & 0x00ff,
  	  (full_local_mask >> 8 ) & 0x0000ff,
  	  full_local_mask & 0xff);
      inet_aton (s, &(adx_net2));
      adx_net_mask = inet_addr(s);
  }
  //mask in dotted format
  else
  {
      if (!inet_aton (mask_string, &(adx_net2))) {
      fprintf(fp_stderr, 
            "Warning: Invalid netmask %s in <adx_mask> or <adx2_mask> histogram option. Using default %d.%d.%d.%d\n",
        mask_string,
        default_mask & 0xff,
        (default_mask >> 8 ) & 0x0000ff,
        (default_mask >> 16)  & 0x00ff,
        default_mask >> 24);
      return default_mask;
      }
      adx_net_mask = inet_addr (mask_string);
  }

//  printf("0x%08x %d.%d.%d.%d\n",adx_net_mask,
//        adx_net_mask & 0xff,
//        (adx_net_mask >> 8 ) & 0x0000ff,
//        (adx_net_mask >> 16)  & 0x00ff,
//        adx_net_mask >> 24
//	);

  return adx_net_mask;
}

void
histo_parse_conf ()
{
  char keyword[512], arg1[512];
  int config_line = 0;
  FILE *conf;
  struct double_histo_list *histo;
  char ch;
  int sample;

  if (!histo_conf.fname)
    {
      return;
    }


  if (!(conf = fopen (histo_conf.fname, "r")))
    {
      fprintf (fp_stderr, "%s: file open error.\n", histo_conf.fname);
      fprintf (fp_stderr, "%s\n", strerror(errno));
      exit (1);
    }

  while (!feof (conf))
    {
      if ((ch = getc (conf)) == EOL)
	continue;
      if (ch == '#')
	{
	  while ((ch = getc (conf)) != EOL);
	  continue;
	}
      else
	{
	  if (feof (conf))
	    break;
	  ungetc (ch, conf);
	}
      fscanf (conf, "%s", keyword);

      config_line++;
      if (!strcmp (keyword, "include"))
	{
	  fscanf (conf, "%s", arg1);
	  if (!strcmp (arg1, "ALL"))
	    {
	      adx_engine = TRUE;
	      adx2_engine = FALSE;
	      histo = first_histo_list ();
	      while (histo != NULL)
		{
		  alloc_histo (histo);
		  histo = histo->next;
		}
	    }
	  else if (!strcmp (arg1, "ADX"))
	    {
	      adx_engine = TRUE;
	      adx2_engine = FALSE;
	    }
	  else if ((histo = find_histo (arg1)) != NULL)
	    {
	      alloc_histo (histo);
	    }
	  else
	    {
	      fprintf (fp_stderr,
		       "HISTO: cannot find histogram <%s> to include at config line <%d>\n",
		       arg1, config_line);
	      fprintf (fp_stderr, "%s\n", strerror(errno));
	      exit (1);
	    }

	}
      else if (!strcmp (keyword, "include_matching"))
	{
	  fscanf (conf, "%s", arg1);
	  histo = first_histo_list ();
	  while (histo != NULL)
	    {
	      if (strstr (histo->name, arg1) != NULL)
		{
		  alloc_histo (histo);
		}
	      histo = histo->next;
	    }
	}
      else if (!strcmp (keyword, "adx_mask"))
	{
	  fscanf (conf, "%s", arg1);
          adx_addr_mask[EXTERNAL_ADX_HISTO] = validate_adx_mask(arg1,ADDR_MASK);
	}
      else if (!strcmp (keyword, "adx2_mask"))
	{
          adx2_engine = TRUE;
	  adx2_bitrate_delta = ADX2_BITRATE_DELTA*1000000;
	  adx3_bitrate_delta = ADX2_MAX_DELTA*1000000;
	  fscanf (conf, "%s", arg1);
          adx_addr_mask[INTERNAL_ADX_HISTO] = validate_adx_mask(arg1,ADDR2_MASK);
          adx_addr_mask[INTERNAL_ADX_MAX] = adx_addr_mask[INTERNAL_ADX_HISTO];
	}
      else if (!strcmp (keyword, "adx2_sample"))
	{
          char *err;
          err = NULL;
	  sample = 0;

	  fscanf (conf, "%s", arg1);
          sample = strtol(arg1, &err, 10);
          if (*err || sample < 1 )
           {
	      fprintf (fp_stderr,
		       "HISTO: wrong sample interval <%d> for adx2_sample at config line <%d>. Using default %d\n",
		       sample, config_line,ADX2_BITRATE_DELTA);
              adx2_bitrate_delta = ADX2_BITRATE_DELTA*1000000;
	   }
	  else
	   {
              adx2_bitrate_delta = sample*1000000;
	   }
	}
      else if (!strcmp (keyword, "adx3_sample"))
	{
          char *err;
          err = NULL;
	  sample = 0;

	  fscanf (conf, "%s", arg1);
          sample = strtol(arg1, &err, 10);
          if (*err || sample < 1 )
           {
	      fprintf (fp_stderr,
		       "HISTO: wrong sample interval <%d> for adx3_sample at config line <%d>. Using default %d\n",
		       sample, config_line,ADX2_MAX_DELTA);
              adx3_bitrate_delta = ADX2_MAX_DELTA*1000000;
	   }
	  else
	   {
              adx3_bitrate_delta = sample*1000000;
	   }

          if (adx3_bitrate_delta>adx2_bitrate_delta)
	   {
	     fprintf (fp_stderr,"HISTO: max sample interval adx3_sample <%lu> is larger than adx2_sample <%lu>. Using adx2_sample value for both\n",
		       adx3_bitrate_delta/1000000, adx2_bitrate_delta/1000000);
  	     adx3_bitrate_delta = adx2_bitrate_delta;
	   }
	}
      else
	{
	  fprintf (fp_stderr,
		   "BAYES: unknown keyword <%s> at config line <%d>\n",
		   keyword, config_line);
	  fprintf (fp_stderr, "%s\n", strerror(errno));
	  exit (1);
	}
      fscanf (conf, "\n");
    }
  fclose (conf);

}

/* Directly set the histo bin value */

void
set_histo (struct double_histo_list *p, int index, double val)
{
  if (p->flag == HISTO_ON)
    p->current_data[index] = val;
}

/* to speed up the code, try to make add_histo inlined */
inline void
__add_histo (struct double_histo_list *p, double val)
{

  int i;
#ifdef HAVE_RRDTOOL
  double oldavg = p->st.avg;
#endif

//  if ((p->flag == HISTO_OFF))
//    return;

  if (isnan (val) || isinf (val))	// ISO_C99 macros aren't defined   
    return;			// ``if(!finite(val)) return;''


#ifdef HAVE_RRDTOOL
  p->st.count++;
  p->st.avg += (val - oldavg) / p->st.count;
  /* var and stdev are calculated on the fly */
  p->st.pseudovar += (val - oldavg) * (val - p->st.avg);
  if (val > p->st.max)
    p->st.max = val;
  if (val < p->st.min)
    p->st.min = val;

#endif

  /* val < min ? put it in the first bin */
  if (val < p->min)
    {
      p->current_data[BIN_LESS_MIN (p)]++;
    }
  else
    /* val > max ? put it in the last bin */
  if (val >= p->max)
    {
      p->current_data[BIN_MORE_MAX (p)]++;
      //  p->current_data[(int) ((p->max - p->min) / p->bin_size + 1)]++;
    }
  else
    {
#ifdef  YOU_ABSOLUTELY_WANT_CLEAN_CODE
/* 
   the code below is clean but untested and 
   not benchmarked at all. it is provided here
   for reference and clarity
*/
      p->current_data[BIN_BETWEEN (p, val)]++;
      p->current_data[BIN_SAMPLE_COUNT (p)]++;

#else
/* 
   the code below is (surprisingly) very efficient 
   so you may want to perform some benchmark before
   using deciding that YOU_ABSOLUTELY_WANT_CLEAN_CODE
*/

      i = ((int) val + p->bin_size - p->min) / (int) p->bin_size;
      p->current_data[i]++;

      /* count the total number of hits */
      p->current_data[BIN_SAMPLE_COUNT (p)]++;
      // p->current_data[(int) ((p->max - p->min) / p->bin_size + 2)]++;
#endif
    }
}


void
alloc_histo (struct double_histo_list *thisto)
{
  thisto->flag = HISTO_ON;
  thisto->first_data =
    (long *) MMmalloc (sizeof (long) * (thisto->bin_num), "alloc_histo");
  thisto->second_data =
    (long *) MMmalloc (sizeof (long) * (thisto->bin_num), "alloc_histo");
  thisto->current_data = thisto->first_data;

// STUPID DUMP BUT BIG ISSUE:
// histograms in naivebayes settigns are possibly created before
// all the options are parsed, thus we cannot know if global_histo
// will be used... so, for the moment I waste memory but avoid SEGV
// In principle, this could be solved by testing another global 
// variable: (global_histo || finished_parsing_arguments)

//  if (global_histo)
  thisto->global_data =
    (int64_t *) MMmalloc (sizeof (int64_t) * (thisto->bin_num),
			  "alloc_histo");
}

/* create the histogram struct to collect data 
   the histogram will
   - start from min,
   - end to max, but max is excluded!!
   - each bin will be bin_size large
   Additional room is available to count samples 
   - smaller than min
   - larger than max
   - count the number of samples
   (max-min)/bin_size MUST be integer
*/
struct double_histo_list *
create_histo (char *name, char *descr, long min, long max, long bin_size)
{
  struct double_histo_list *thisto;
  int num_col;

  if (bin_size == 0)
    {
      fprintf (fp_stderr, 
        "Error: null 'bin_size' param when creating %s histogram \n", name);
      exit (1);
    }

// PROBLEM: at this point, I cannot know if I will make use of RRD of this histo    
//  if(strlen(name) > RRD_NAME_MAXLEN) {
//      fprintf (fp_stderr, 
//          "Error: length of <%s> exceeds by <%d> the maximum <%d> "
//          "allowed by RRDtool: find a shortest name!\n",
//          name, strlen(name)-HISTO_NAME_MAXLEN, HISTO_NAME_MAXLEN);
//      exit(1);
//  }

  if (strlen (name) > HISTO_NAME_MAXLEN)
    {
      fprintf (fp_stderr, 
        "Error: length of <%s> exceeds by <%d> the maximum <%d> "
        "allowed by tstat: find a shortest name!\n",
	    name, strlen (name) - HISTO_NAME_MAXLEN, HISTO_NAME_MAXLEN);
      exit (1);
    }

  if (strlen (descr) > HISTO_DESCR_MAXLEN)
    {
      fprintf (fp_stderr, 
        "Error: length of <%s> exceeds by <%d> the maximum <%d> "
        "allowed by Tstat: find a shortest description!\n",
	    descr, strlen (descr) - HISTO_DESCR_MAXLEN, HISTO_DESCR_MAXLEN);
      exit (1);
    }


  num_col = ((max - min) / bin_size);

  if (max != (min + (num_col * bin_size)))
    {
      fprintf (fp_stderr,
        "Error: wrong 'bin_size' param when creating %s histogram \n", name);
      exit (1);
    }

  if (num_col < 0)
    {
      fprintf (fp_stderr, 
        "Error: wrong 'num_col' param when creating %s histogram \n", name);
      exit (1);
    }

  thisto =
    (struct double_histo_list *) MMmalloc (sizeof (struct double_histo_list),
					   "create_histo");
  strncpy (thisto->name, name, HISTO_NAME_MAXLEN);
  strncpy (thisto->descr, descr, HISTO_DESCR_MAXLEN);
  thisto->min = min;
  thisto->max = max;
  thisto->bin_size = bin_size;

  thisto->bin_num = num_col;	// samples between min and max
  thisto->bin_num += 1;		// samples below min  
  thisto->bin_num += 1;		// samples above max
  thisto->bin_num += 1;		// samples counter 

  /* the real allocation is deferred when we'll know if this histo is going
     to be used or not, i.e., in the 
   */
  thisto->flag = HISTO_OFF;

  thisto->next = hl;
  hl = thisto;

  if (debug > 3)
    fprintf (fp_stderr,
	     "Created histogram %s: [%ld:%ld], %d bins, %ld bin size\n", name,
	     min, max, num_col, bin_size);

  return thisto;
}

void
swap_histo ()			/* also updates the global ststistics */
{
  struct double_histo_list *temphp;
  int i;

  temphp = hl;
  while (temphp != NULL)
    {
      if (temphp->flag == HISTO_ON)
	{
	  if (global_histo)
	    for (i = 0; i < temphp->bin_num; i++)
	      temphp->global_data[i] += (u_int64_t) temphp->current_data[i];

#if 0
	  struct double_histo_list *phisto = temphp;
	  u_int64_t tot =
	    (u_int64_t) phisto->global_data[BIN_SAMPLE_COUNT (phisto)] +
	    (u_int64_t) phisto->global_data[BIN_LESS_MIN (phisto)] +
	    (u_int64_t) phisto->global_data[BIN_MORE_MAX (phisto)];

	  double pdf, CDF = 0.0;
	  if (tot > 0)
	    fprintf (fp_stdout, "%s#SAMPLES: <min=%.0f valid=%.0f >max=%.0f tot=A%0.f\n",
		    phisto->name,
		    (double) phisto->global_data[BIN_LESS_MIN (phisto)],
		    (double) phisto->global_data[BIN_SAMPLE_COUNT (phisto)],
		    (double) phisto->global_data[BIN_MORE_MAX (phisto)],
		    (double) tot);
#endif
	  if (temphp->current_data == temphp->first_data)
	    temphp->current_data = temphp->second_data;
	  else
	    temphp->current_data = temphp->first_data;
	}

      temphp = temphp->next;
    }

#ifdef DEBUG_THREAD
  fprintf (fp_stdout, "All histos swapped!\n");
#endif

}

/* Return the pointer to the unused histo */
long *
whats_frozen (struct double_histo_list *histo)
{

  if (histo->current_data == histo->first_data)
    return (histo->second_data);
  else
    return (histo->first_data);
}


int
clear_all_histo ()
{
  struct double_histo_list *temphp;

  temphp = hl;
  while (temphp != NULL)
    {
      if (temphp->flag == HISTO_ON)
	clear_histo (temphp);
      temphp = temphp->next;
    }
  return 1;
}

int
clear_histo (struct double_histo_list *phisto)
{
  int i;
  long *frozen;

  frozen = whats_frozen (phisto);
  for (i = 0; i < phisto->bin_num; i++)
    frozen[i] = 0;

  return 1;
}


void
print_all_histo_definition ()
{
  struct double_histo_list *temphp;

  fprintf (fp_stdout, "#name\tmin\tbin_size\tmax\tdescription\n");
  temphp = hl;
  while (temphp != NULL)
    {
      print_histo_definition (temphp, temphp->name);
      temphp = temphp->next;
    }
}

void
print_histo_definition (struct double_histo_list *phisto, char *titolo)
{
  fprintf (fp_stdout, "%s\t", phisto->name);
  fprintf (fp_stdout, "%ld\t%ld\t%ld\t", phisto->min, phisto->bin_size, phisto->max);
  fprintf (fp_stdout, "%s\n", phisto->descr);
}

void
fake_histo_bitrate_update (struct double_histo_list *phisto,
			   double elapsed_time, unsigned long long bitrate[], int num_elem)
{
  int i;
  double tot=0;
  if (phisto->flag == HISTO_OFF)
    return;

  /* we want kbit/s so divide ms and multiply by 8 (byte -> bit) */
  if (elapsed_time == 0.0)
    return;
    
  for(i=0; i<num_elem; i++)
  {
//    set_histo (phisto, i+1, bitrate[i] * 8.0 / elapsed_time);
//    tot+= bitrate[i] * 8.0 / elapsed_time;
    /* Converted to rate to bit/s, so multiply by 1000.0 */
    set_histo (phisto, i+1, bitrate[i] * 8000.0 / elapsed_time);
    tot+= bitrate[i] * 8000.0 / elapsed_time;
  }
  /* set the total value correctly */
  /* recall than in histo[num+1] we count the hit number... */
  set_histo (phisto, BIN_SAMPLE_COUNT(phisto), tot);

  /* update global bitrates */
  if (global_histo)
    {
      if (strstr (phisto->name, "in"))
	{
	  add_histo (g_tcp_bitrate_in, phisto->current_data[1]);
	  add_histo (g_udp_bitrate_in, phisto->current_data[2]);
	  add_histo (g_icmp_bitrate_in, phisto->current_data[3]);
	  add_histo (g_other_bitrate_in,
		     phisto->current_data[7]
		     - phisto->current_data[6]
		     - phisto->current_data[5]
		     - phisto->current_data[4]
		     - phisto->current_data[3]
		     - phisto->current_data[2] - phisto->current_data[1]);
	}
      else if (strstr (phisto->name, "out"))
	{
	  add_histo (g_tcp_bitrate_out, phisto->current_data[1]);
	  add_histo (g_udp_bitrate_out, phisto->current_data[2]);
	  add_histo (g_icmp_bitrate_out, phisto->current_data[3]);
	  add_histo (g_other_bitrate_out,
		     phisto->current_data[7]
		     - phisto->current_data[6]
		     - phisto->current_data[5]
		     - phisto->current_data[4]
		     - phisto->current_data[3]
		     - phisto->current_data[2] - phisto->current_data[1]);
	}
      else
	{
	  add_histo (g_tcp_bitrate_loc, phisto->current_data[1]);
	  add_histo (g_udp_bitrate_loc, phisto->current_data[2]);
	  add_histo (g_icmp_bitrate_loc, phisto->current_data[3]);
	  add_histo (g_other_bitrate_loc,
		     phisto->current_data[7]
		     - phisto->current_data[6]
		     - phisto->current_data[5]
		     - phisto->current_data[4]
		     - phisto->current_data[3]
		     - phisto->current_data[2] - phisto->current_data[1]);
	}
    }
}

int
print_all_histo (int flag)
{
  struct double_histo_list *temphp;
  temphp = hl;
#ifdef HAVE_RRDTOOL
   /*---------------------------------------------------------*/
  /* RRDtools                                                */
  //if (flag <= 2)
  if (rrd_engine)
    rrdtool_update_all ();
   /*---------------------------------------------------------*/
#endif
  while (temphp != NULL)
    {
      if ((histo_engine || global_histo) && histo_engine_log && 
           temphp->flag == HISTO_ON)
	print_histo (temphp, temphp->name, flag);
      temphp = temphp->next;
    }
  return 1;
}

int
print_histo (struct double_histo_list *phisto, char *titolo, int flag)
{
  long min, max, bin_size, i;
  struct stat fbuf;
  FILE *fp;
  char filename[200] = "";
  char *dirname;
  char *timestamp;
  long *frozen;

  min = phisto->min;
  max = phisto->max;
  bin_size = phisto->bin_size;

  /* check directory status */
  dirname = (flag == HISTO_PRINT_GLOBAL) ? global_data_dir : curr_data_dir;

  if (stat (dirname, &fbuf) == -1)
    {
        timestamp = Timestamp();
      if (printticks) {
        fprintf (fp_stdout, "\r(%s) Creating output dir %s\n", timestamp, dirname);
        fflush(stdout);
      }
      else 
	fprintf (fp_stderr, "(%s) Creating output dir %s\n", timestamp, dirname);
      mkdir (dirname, 0775);
    }

  sprintf (filename, "%s/%s", dirname, titolo);
  fp = fopen (filename, "w");

  if (fp == NULL)
    {
      if (printticks)
	fprintf (fp_stderr, "\rCould not open file %s\n", filename);
      else
	fprintf (fp_stderr, "Could not open file %s\n", filename);
      return 0;
    }

  fprintf (fp, "#%s\n", phisto->descr);
  fprintf (fp, "#RANGE: min=%ld bin_size=%ld max=%ld\n", min, bin_size, max);

  if (flag == HISTO_PRINT_GLOBAL)
    {
      u_int64_t tot = ((u_int64_t) phisto->
		       global_data[BIN_SAMPLE_COUNT (phisto)] +
		       (u_int64_t) phisto->
		       global_data[BIN_LESS_MIN (phisto)] +
		       (u_int64_t) phisto->
		       global_data[BIN_MORE_MAX (phisto)]);
      double pdf, CDF = 0.0;
      fprintf (fp, "#SAMPLES: <min=%.0f valid=%.0f >max=%.0f tot=%.0f\n",
	       (double) phisto->global_data[BIN_LESS_MIN (phisto)],
	       (double) phisto->global_data[BIN_SAMPLE_COUNT (phisto)],
	       (double) phisto->global_data[BIN_MORE_MAX (phisto)],
	       (double) tot);

      for (i = 0; i <= BIN_MORE_MAX (phisto); i++)
	{
	  pdf = ((double) phisto->global_data[i] / (double) tot);
	  CDF += pdf;
	  if (pdf > 0.0)
	    fprintf (fp, "%ld %e %e\n", (min + (i - 1) * bin_size), pdf, CDF);
	}

    }
  else if (flag == HISTO_PRINT_CURRENT)
    {
      /* print the frozen data */
      frozen = whats_frozen (phisto);
      for (i = 0; i <= BIN_MORE_MAX (phisto); i++)
	if (frozen[i] != 0)	/* just skip zeros to compact this */
	  fprintf (fp, "%ld %ld\n", (min + (i - 1) * bin_size), frozen[i]);
    }
  else
    {
      fprintf (fp_stderr, "histo: no idea what to print!\n");
      exit (1);
    }

  fclose (fp);
  return 1;
}

//        /* not used, but may be usefull in the future... */
//
//        int
//        print_text_histo (struct double_histo_list *phisto, char *titolo,
//                          char *labels)
//        {
//          double min, max, bin_size;
//          int  i;
//          char *llabels;
//          long *frozen;
//
//          min = phisto->min;
//          max = phisto->max;
//          bin_size = phisto->bin_size;
//          llabels = labels;
//
//          fprintf (fp_stdout, 
//              "\nResults for [%f:%f] with %d steps (%f)\n", min, max, phisto->bin_num,
//               bin_size);
//          fprintf (fp_stdout, "*** %s ***\n", titolo);
//
//          /* print the frozen data */
//          frozen = whats_frozen (phisto);
//
//          for (i = 0; i < phisto->bin_num; i++)
//            {
//              /* stampo la riga */
//              while ((*llabels != '!') && (*llabels != '\0'))
//                {
//                  fprintf (fp_stdout, "%c", *llabels);
//                  llabels++;
//                }
//              if (*llabels != '\0')
//                {
//                  llabels++;
//                }
//              else
//                {
//                  fprintf (fp_stdout, "Val");
//                }
//              fprintf (fp_stdout, "\t:%ld\n", frozen[i]);
//            }
//          return 1;
//        }
//
//        /*
//        *  dynamic histo 
//        */
//
//        int
//        print_dhisto (struct dhisto *phisto, char *titolo, char *labels)
//        {
//          struct dato *elem;
//          double min, max, bin_size;
//          int num_col, i;
//          char *llabels;
//
//
//          min = phisto->min;
//          max = phisto->max;
//          bin_size = phisto->bin_size;
//          elem = phisto->data;
//          llabels = labels;
//
//          num_col = ((max - min) / bin_size) + 2;
//
//          fprintf (fp_stdout, 
//              "\nResults for [%f:%f] with %d steps (%f)\n", min, max, num_col, 
//               bin_size);
//          fprintf ("*** %s ***\n", titolo);
//          for (i = 1; i <= num_col; i++)
//            {
//              while ((*llabels != '!') && (*llabels != '\0'))
//                {
//                  fprintf (fp_stdout, "%c", *llabels);
//                  llabels++;
//                }
//              if (*llabels != '\0')
//                {
//                  llabels++;
//                }
//              else
//                {
//                  fprintf (fp_stdout, "Val");
//                }
//              fprintf (fp_stdout, ":\t%d\n", elem->val);
//              elem = elem->next;
//            }
//          return 1;
//        }
//
//        int
//        add_dhisto (struct dhisto *phisto, double val)
//        {
//          double min, max, bin_size;
//          int num_col, i, j;
//          struct dato *elem;
//
//          min = phisto->min;
//          max = phisto->max;
//          bin_size = phisto->bin_size;
//          elem = phisto->data;
//
//          num_col = (max - min) / bin_size;
//
//          if (val < min)
//            {
//              elem->val++;
//              return 1;
//            }
//
//          for (i = 1; i <= num_col; i++)
//            {
//              if (val <= (min + (bin_size * i)))
//                {
//                  elem = phisto->data;
//                  for (j = 1; j <= i; j++)
//                    {
//                      elem = elem->next;
//                    }
//                  elem->val++;
//                  return 1;
//                }
//            }
//
//          elem = phisto->data;
//
//          elem = elem->next;
//          for (j = 1; j < num_col; j++)
//            {
//              elem = elem->next;
//            }
//          elem = elem->next;
//
//          elem->val++;
//          return 1;
//        }
//
//        struct dhisto *
//        create_dhisto2 (double min, double max, int num_col)
//        {
//          double bin_size;
//          struct dhisto *htemp;
//
//          bin_size = (max - min) / num_col;
//
//          htemp = create_dhisto (min, max, bin_size);
//
//          if (!htemp)
//            {
//              return 0;
//            }
//          else
//            {
//              return htemp;
//            }
//        }
//
//        struct dhisto *
//        create_dhisto (double min, double max, double bin_size)
//        {
//          struct dhisto *htemp;
//          struct dato *elem, *temp_dato;
//          int i, num_col;
//
//          htemp = (struct dhisto *) malloc (sizeof (struct dhisto));
//          htemp->min = min;
//          htemp->max = max;
//          htemp->bin_size = bin_size;
//          htemp->data = NULL;
//
//          elem = htemp->data;
//
//          num_col = ((max - min) / bin_size);
//
//          if (max != (min + (num_col * bin_size)))
//            {
//              fprintf (fp_stdout, "Wrong bin_size=%f values!\n", bin_size);
//              return 0;
//            }
//
//
//          /* Recall that we use 2 bins to store values smaller than the min and
//           * larger than the max limit
//           */
//
//          /* The first one is here */
//          temp_dato = (struct dato *) malloc (sizeof (struct dato));
//          temp_dato->val = 0;
//          temp_dato->next = NULL;
//          elem = temp_dato;
//          htemp->data = temp_dato;
//
//
//          /* ... now add the remaining bins */
//
//          for (i = 0; i <= num_col; i++)
//            {
//
//              /* Go to the last bin */
//              while (elem->next != NULL)
//                {
//                  elem = elem->next;
//                }
//
//              /* add a data to the tail */
//              temp_dato = (struct dato *) malloc (sizeof (struct dato));
//              temp_dato->val = 0;
//              temp_dato->next = NULL;
//              elem->next = temp_dato;
//
//            }
//
//          return htemp;
//        }
//
//
//
//
//


/*
*   histo management
*/

void
create_all_histo (void)
{
  struct timeval prof_tm;

/*-------------------------------------------------------------*/
/* NOTE                                                        */
/*      variable name MUST be SHORTER (<) than 20              */
/*      char, otherwise RRD will complain without              */
/*      further explaining the error                           */
/*-------------------------------------------------------------*/

/*-------------------------------------------------------------*/
/* NOTE 2                                                      */
/*      histograms collects values from min to max             */
/*      max is excluded!!!                                     */
/*      values smaller than min  and larger or equal to max    */
/*      will be counted in separate bins.                      */
/*-------------------------------------------------------------*/

  /* IP histograms */

  ip_protocol_in = create_histo ("ip_protocol_in",
				 "IP protocol - incoming packets", 0, 255, 1);
  ip_protocol_out = create_histo ("ip_protocol_out",
				  "IP protocol - outgoing packets", 0, 255,
				  1);
  ip_protocol_loc =
    create_histo ("ip_protocol_loc", "IP protocol - local packets", 0, 255,
		  1);

  ip_bitrate_in = create_histo ("ip_bitrate_in",
				"IP bitrate [bit/s] - incoming packets", 0,
				4, 1);
  ip_bitrate_out =
    create_histo ("ip_bitrate_out", "IP bitrate [bit/s] - outgoing packets",
		  0, 4, 1);
  ip_bitrate_loc =
    create_histo ("ip_bitrate_loc", "IP bitrate [bit/s] - local packets", 0,
		  4, 1);
  ip_bitrate_c_in = create_histo ("ip_bitrate_c_in",
				"IP bitrate [bit/s] - cloud incoming packets", 0,
				4, 1);
  ip_bitrate_c_out =
    create_histo ("ip_bitrate_c_out", "IP bitrate [bit/s] - cloud outgoing packets",
		  0, 4, 1);
  ip_bitrate_nc_in = create_histo ("ip_bitrate_nc_in",
				"IP bitrate [bit/s] - non-cloud incoming packets", 0,
				4, 1);
  ip_bitrate_nc_out =
    create_histo ("ip_bitrate_nc_out", "IP bitrate [bit/s] - non-cloud outgoing packets",
		  0, 4, 1);

  ip_len_out = create_histo ("ip_len_out",
			     "IP packet length [byte] - outgoing packets", 0,
			     1504, 4);
  ip_len_in =
    create_histo ("ip_len_in", "IP packet length [byte] - incoming packets",
		  0, 1504, 4);
  ip_len_loc =
    create_histo ("ip_len_loc", "IP packet length [byte] - local packets", 0,
		  1504, 4);

  ip_ttl_out =
    create_histo ("ip_ttl_out", "IP TTL - outgoing packtes", 0, 255, 1);
  ip_ttl_in =
    create_histo ("ip_ttl_in", "IP TTL - incoming packets", 0, 255, 1);
  ip_ttl_loc =
    create_histo ("ip_ttl_loc", "IP TTL - local packets", 0, 255, 1);

  ip_tos_out =
    create_histo ("ip_tos_out", "IP TOS - outgoing packets", 0, 255, 1);
  ip_tos_in =
    create_histo ("ip_tos_in", "IP TOS - incoming packets", 0, 255, 1);
  ip_tos_loc =
    create_histo ("ip_tos_loc", "IP TOS - local packets", 0, 255, 1);

//IPv6 statistics
#ifdef SUPPORT_IPV6

  ip6_protocol_in =
    create_histo ("ip6_protocol_in",
		  "IPv6 protocol - incoming packets protocol type", 0, 256,
		  1);
  ip6_hop_limit_in =
    create_histo ("ip6_hop_limit_in",
		  "IPv6 protocol - incoming packets hop limit", 0, 70, 1);
  ip6_plen_in =
    create_histo ("ip6_plen_in",
		  "IPv6 protocol - incoming packets payload length", 0, 1504,
		  16);

  ip6_protocol_out =
    create_histo ("ip6_protocol_out",
		  "IPv6 protocol - outgoing packets protocol type", 0, 256,
		  1);
  ip6_hop_limit_out =
    create_histo ("ip6_hop_limit_out",
		  "IPv6 protocol - outgoing packets hop limit", 0, 70, 1);
  ip6_plen_out =
    create_histo ("ip6_plen_out",
		  "IPv6 protocol - outgoing packets payload length", 0, 1504,
		  16);

  ip6_protocol_loc =
    create_histo ("ip6_protocol_loc",
		  "IPv6 protocol -  local packets protocol type", 0, 256, 1);
  ip6_hop_limit_loc =
    create_histo ("ip6_hop_limit_loc",
		  "IPv6 protocol - local packets hop limit", 0, 70, 1);
  ip6_plen_loc =
    create_histo ("ip6_plen_loc",
		  "IPv6 protocol - local packets payload length", 0, 1504,
		  16);

  icmpv6_type_in =
    create_histo ("icmpv6_type_in", "ICMPv6 protocol - incoming traffic type",
		  1, 143, 1);
  icmpv6_type_loc =
    create_histo ("icmpv6_type_loc", "ICMPv6 protocol - local traffic type",
		  1, 143, 1);
  icmpv6_type_out =
    create_histo ("icmpv6_type_out",
		  "ICMPv6 protocol - outgoing traffic type", 1, 143, 1);
#endif

//IPv6 statistics


  /* TCP segment histograms */

  tcp_port_src_in = create_histo ("tcp_port_src_in",
				  "TCP source port - incoming segments", 0,
				  65536, 1);
  tcp_port_src_out = create_histo ("tcp_port_src_out",
				   "TCP source port - outgoing segments", 0,
				   65536, 1);
  tcp_port_src_loc = create_histo ("tcp_port_src_loc",
				   "TCP source port - local segments", 0,
				   65536, 1);
  tcp_port_dst_in = create_histo ("tcp_port_dst_in",
				  "TCP destination port - incoming segments",
				  0, 65536, 1);
  tcp_port_dst_out =
    create_histo ("tcp_port_dst_out",
		  "TCP destination port - outgoing segments", 0, 65536, 1);
  tcp_port_dst_loc =
    create_histo ("tcp_port_dst_loc", "TCP destination port - local segments",
		  0, 65536, 1);

  tcp_port_synsrc_in =
    create_histo ("tcp_port_synsrc_in",
		  "TCP source port of SYN segments - incoming segments", 0,
		  65536, 1);
  tcp_port_synsrc_out =
    create_histo ("tcp_port_synsrc_out",
		  "TCP source port of SYN segments - outgoing segments", 0,
		  65536, 1);
  tcp_port_synsrc_loc =
    create_histo ("tcp_port_synsrc_loc",
		  "TCP source port of SYN segments - local segments", 0,
		  65536, 1);
  tcp_port_syndst_in =
    create_histo ("tcp_port_syndst_in",
		  "TCP destination port of SYN segments - incoming segments",
		  0, 65536, 1);
  tcp_port_syndst_out =
    create_histo ("tcp_port_syndst_out",
		  "TCP destination port of SYN segments - outgoing segments",
		  0, 65536, 1);
  tcp_port_syndst_loc =
    create_histo ("tcp_port_syndst_loc",
		  "TCP destination port of SYN segments - local segments", 0,
		  65536, 1);

  tcp_bitrate_in = create_histo ("tcp_bitrate_in",
				  "TCP application bitrate [bit/s] - incoming segments", 0,
				  L7_FLOW_TOT, 1);
  tcp_bitrate_out = create_histo ("tcp_bitrate_out",
				   "TCP application bitrate [bit/s] - outgoing segments", 0,
				   L7_FLOW_TOT, 1);
  tcp_bitrate_loc = create_histo ("tcp_bitrate_loc",
				   "TCP application bitrate [bit/s] - local segments", 0,
				   L7_FLOW_TOT, 1);

  tcp_bitrate_c_in = create_histo ("tcp_bitrate_c_in",
				  "TCP application bitrate [bit/s] - cloud incoming segments", 0,
				  L7_FLOW_TOT, 1);
  tcp_bitrate_c_out = create_histo ("tcp_bitrate_c_out",
				   "TCP application bitrate [bit/s] - cloud outgoing segments", 0,
				   L7_FLOW_TOT, 1);
  tcp_bitrate_nc_in = create_histo ("tcp_bitrate_nc_in",
				  "TCP application bitrate [bit/s] - non-cloud incoming segments", 0,
				  L7_FLOW_TOT, 1);
  tcp_bitrate_nc_out = create_histo ("tcp_bitrate_nc_out",
				   "TCP application bitrate [bit/s] - non-cloud outgoing segments", 0,
				   L7_FLOW_TOT, 1);

  /* TCP flow histograms */

  tcp_opts_SACK = create_histo ("tcp_opts_SACK", "TCP option: SACK", 1, 4, 1);
  tcp_opts_WS =
    create_histo ("tcp_opts_WS", "TCP option: WindowScale", 1, 4, 1);
  tcp_opts_TS =
    create_histo ("tcp_opts_TS", "TCP option: Timestamp", 1, 4, 1);
  tcp_opts_MPTCP = create_histo ("tcp_opts_MPTCP", "TCP option: MPTCP", 1, 4, 1);

  tcp_mss_a =
    create_histo ("tcp_mss_a", "TCP declared client MSS [byte]", 0, 1600, 4);
  tcp_mss_b =
    create_histo ("tcp_mss_b", "TCP declared server MSS [byte]", 0, 1600, 4);
  tcp_mss_used =
    create_histo ("tcp_mss_used", "TCP negotiated MSS [byte]", 0, 1600, 4);

  tcp_win_min =
    create_histo ("tcp_win_ini", "TCP initial RWND [byte]", 0, 65536, 256);
  tcp_win_avg =
    create_histo ("tcp_win_avg", "TCP average RWND [byte]", 0, 65536, 256);
  tcp_win_max =
    create_histo ("tcp_win_max", "TCP max RWND [byte]", 0, 65536, 256);

  tcp_cwnd =
    create_histo ("tcp_cwnd", "TCP in-flight-size [byte]", 0, 65536, 256);

  tcp_cl_p_out =
    create_histo ("tcp_cl_p_out",
		  "TCP flow length [packet] - outgoing flows", 0, 1000, 1);

  tcp_cl_p_in =
    create_histo ("tcp_cl_p_in",
		  "TCP flow length [packet] - incoming flows", 0, 1000, 1);
  tcp_cl_p_loc =
    create_histo ("tcp_cl_p_loc",
		  "TCP flow length [packet] - local flows", 0, 1000, 1);

  tcp_cl_p_c2s =
    create_histo ("tcp_cl_p_c2s",
		  "TCP flow length [packet] - clientflows", 0, 1000, 1);

  tcp_cl_p_s2c =
    create_histo ("tcp_cl_p_s2c",
		  "TCP flow length [packet] - server flows", 0, 1000, 1);


  tcp_cl_b_s_out =
    create_histo ("tcp_cl_b_s_out",
		  "TCP flow length [byte] - fine granularity histogram - outgoing flows",
		  0, 50000, 50);
  tcp_cl_b_s_in =
    create_histo ("tcp_cl_b_s_in",
		  "TCP flow length [byte] - fine granularity histogram - incoming flows",
		  0, 50000, 50);
  tcp_cl_b_s_loc =
    create_histo ("tcp_cl_b_s_loc",
		  "TCP flow length [byte] - fine granularity histogram - local flows",
		  0, 50000, 50);

  tcp_cl_b_l_out =
    create_histo ("tcp_cl_b_l_out",
		  "TCP flow length [byte] - coarse granularity histogram - outgoing flows",
		  0, 50000000, 50000);

  tcp_cl_b_l_in =
    create_histo ("tcp_cl_b_l_in",
		  "TCP flow length [byte] - coarse granularity histogram - incoming flows",
		  0, 50000000, 50000);
  tcp_cl_b_l_loc =
    create_histo ("tcp_cl_b_l_loc",
		  "TCP flow length [byte] - coarse granularity histogram - local flows",
		  0, 50000000, 50000);

  tcp_cl_b_s_c2s =
    create_histo ("tcp_cl_b_s_c2s",
		  "TCP flow length [byte] - fine granularity histogram - client flows",
		  0, 50000, 50);

  tcp_cl_b_s_s2c =
    create_histo ("tcp_cl_b_s_s2c",
		  "TCP flow length [byte] - fine granularity histogram - server flows",
		  0, 50000, 50);
  tcp_cl_b_l_c2s =
    create_histo ("tcp_cl_b_l_c2s",
		  "TCP flow length [byte] - coarse granularity histogram - client flows",
		  0, 50000000, 50000);
  tcp_cl_b_l_s2c =
    create_histo ("tcp_cl_b_l_s2c",
		  "TCP flow length [byte] - coarse granularity histogram - server flows",
		  0, 50000000, 50000);

  tcp_rtt_min_out =
    create_histo ("tcp_rtt_min_out",
		  "TCP flow minimum RTT [ms] - outgoing flows", 0, 2000, 1);
  tcp_rtt_min_in =
    create_histo ("tcp_rtt_min_in",
		  "TCP flow minimum RTT [ms]- incoming flows", 0, 2000, 1);
  tcp_rtt_min_loc =
    create_histo ("tcp_rtt_min_loc", "TCP flow minimum RTT - local flows", 0,
		  2000, 1);
  tcp_rtt_min_c2s =
    create_histo ("tcp_rtt_min_c2s",
		  "TCP flow minimum RTT [ms] - client flows", 0, 2000, 1);
  tcp_rtt_min_s2c =
    create_histo ("tcp_rtt_min_s2c",
		  "TCP flow minimum RTT [ms] - server flows", 0, 2000, 1);
  tcp_rtt_avg_out =
    create_histo ("tcp_rtt_avg_out",
		  "TCP flow average RTT [ms] - outgoing flows", 0, 2000, 1);
  tcp_rtt_avg_in =
    create_histo ("tcp_rtt_avg_in",
		  "TCP flow average RTT [ms] - incoming flows", 0, 2000, 1);
  tcp_rtt_avg_loc =
    create_histo ("tcp_rtt_avg_loc",
		  "TCP flow average RTT [ms] - local flows", 0, 2000, 1);
  tcp_rtt_avg_c2s =
    create_histo ("tcp_rtt_avg_c2s",
		  "TCP flow average RTT [ms] - client flows", 0, 2000, 1);
  tcp_rtt_avg_s2c =
    create_histo ("tcp_rtt_avg_s2c",
		  "TCP flow average RTT [ms] - server flows", 0, 2000, 1);

  tcp_rtt_c_avg_out =
    create_histo ("tcp_rtt_c_avg_out",
		  "TCP flow average RTT [ms] - cloud outgoing flows", 0, 2000, 1);
  tcp_rtt_c_avg_in =
    create_histo ("tcp_rtt_c_avg_in",
		  "TCP flow average RTT [ms] - cloud incoming flows", 0, 2000, 1);

  tcp_rtt_nc_avg_out =
    create_histo ("tcp_rtt_nc_avg_out",
		  "TCP flow average RTT [ms] - non-cloud outgoing flows", 0, 2000, 1);
  tcp_rtt_nc_avg_in =
    create_histo ("tcp_rtt_nc_avg_in",
		  "TCP flow average RTT [ms] - non-cloud incoming flows", 0, 2000, 1);

/* v1.2.0 ---------------------------------------------------------------------------*/

  tcp_rtt_max_out =
    create_histo ("tcp_rtt_max_out",
		  "TCP flow maximum RTT [ms] - outgoing flows", 0, 2000, 1);
  tcp_rtt_max_in =
    create_histo ("tcp_rtt_max_in",
		  "TCP flow maximum RTT [ms] - incoming flows", 0, 2000, 1);
  tcp_rtt_max_loc =
    create_histo ("tcp_rtt_max_loc",
		  "TCP flow maximum RTT [ms] - local flows", 0, 2000, 1);
  tcp_rtt_max_c2s =
    create_histo ("tcp_rtt_max_c2s",
		  "TCP flow maximum RTT [ms] - client flows", 0, 2000, 1);
  tcp_rtt_max_s2c =
    create_histo ("tcp_rtt_max_s2c",
		  "TCP flow maximum RTT [ms] - server flows", 0, 2000, 1);

  tcp_rtt_stdev_out =
    create_histo ("tcp_rtt_stdev_out",
		  "TCP flow RTT standard deviation [ms] - outgoing flows", 0,
		  2000, 1);
  tcp_rtt_stdev_in =
    create_histo ("tcp_rtt_stdev_in",
		  "TCP flow RTT standard deviation [ms] - incoming flows", 0,
		  2000, 1);
  tcp_rtt_stdev_loc =
    create_histo ("tcp_rtt_stdev_loc",
		  "TCP flow RTT standard deviation [ms] - local flows", 0,
		  2000, 1);
  tcp_rtt_stdev_c2s =
    create_histo ("tcp_rtt_stdev_c2s",
		  "TCP flow RTT standard deviation [ms] - client flows", 0,
		  2000, 1);
  tcp_rtt_stdev_s2c =
    create_histo ("tcp_rtt_stdev_s2c",
		  "TCP flow RTT standard deviation [ms] - server flows", 0,
		  2000, 1);

  tcp_rtt_cnt_out = create_histo ("tcp_rtt_cnt_out",
				  "TCP flow RTT valid samples - outgoing flows",
				  0, 200, 1);
  tcp_rtt_cnt_in =
    create_histo ("tcp_rtt_cnt_in",
		  "TCP flow RTT valid samples - incoming flows", 0, 200, 1);
  tcp_rtt_cnt_loc =
    create_histo ("tcp_rtt_cnt_loc",
		  "TCP flow RTT valid samples - local flows", 0, 200, 1);
  tcp_rtt_cnt_c2s =
    create_histo ("tcp_rtt_cnt_c2s",
		  "TCP flow RTT valid samples - client flows", 0, 200, 1);
  tcp_rtt_cnt_s2c =
    create_histo ("tcp_rtt_cnt_s2c",
		  "TCP flow RTT valid samples - server flows", 0, 200, 1);

  tcp_anomalies_in =
    create_histo ("tcp_anomalies_in",
		  "TCP total number of anomalies - incoming flows", 0,
		  NUM_TCP_ANOMALIES, 1);
  tcp_anomalies_out =
    create_histo ("tcp_anomalies_out",
		  "TCP total number of anomalies - outgoing flows", 0,
		  NUM_TCP_ANOMALIES, 1);
  tcp_anomalies_loc =
    create_histo ("tcp_anomalies_loc",
		  "TCP total number of anomalies - local flows", 0,
		  NUM_TCP_ANOMALIES, 1);
  tcp_anomalies_c2s =
    create_histo ("tcp_anomalies_c2s",
		  "TCP total number of anomalies - client flows", 0,
		  NUM_TCP_ANOMALIES, 1);
  tcp_anomalies_s2c =
    create_histo ("tcp_anomalies_s2c",
		  "TCP total number of anomalies - server flows", 0,
		  NUM_TCP_ANOMALIES, 1);

  tcp_rtx_RTO_in = create_histo ("tcp_rtx_RTO_in",
				 "TCP Number of RTO Retransmission - incoming flows",
				 0, 100, 1);
  tcp_rtx_RTO_out =
    create_histo ("tcp_rtx_RTO_out",
		  "TCP Number of RTO Retransmission - outgoing flows", 0, 100,
		  1);
  tcp_rtx_RTO_loc =
    create_histo ("tcp_rtx_RTO_loc",
		  "TCP Number of RTO Retransmission - local flows", 0, 100,
		  1);
  tcp_rtx_RTO_c2s =
    create_histo ("tcp_rtx_RTO_c2s",
		  "TCP Number of RTO Retransmission - client flows", 0, 100,
		  1);
  tcp_rtx_RTO_s2c =
    create_histo ("tcp_rtx_RTO_s2c",
		  "TCP Number of RTO Retransmission - server flows", 0, 100,
		  1);

  tcp_rtx_FR_in = create_histo ("tcp_rtx_FR_in",
				"TCP number of FR Retransmission - incoming flows",
				0, 100, 1);
  tcp_rtx_FR_out =
    create_histo ("tcp_rtx_FR_out",
		  "TCP Number of FR Retransmission - outgoing flows", 0, 100,
		  1);
  tcp_rtx_FR_loc =
    create_histo ("tcp_rtx_FR_loc",
		  "TCP Number of FR Retransmission - local flows", 0, 100, 1);
  tcp_rtx_FR_c2s =
    create_histo ("tcp_rtx_FR_c2s",
		  "TCP Number of FR Retransmission - client flows", 0, 100,
		  1);
  tcp_rtx_FR_s2c =
    create_histo ("tcp_rtx_FR_s2c",
		  "TCP number of FR Retransmission - server flows", 0, 100,
		  1);

  tcp_reordering_in = create_histo ("tcp_reordering_in",
				    "TCP number of packet reordering - incoming flows",
				    0, 100, 1);
  tcp_reordering_out =
    create_histo ("tcp_reordering_out",
		  "TCP number of packet reordering - outgoing flows", 0, 100,
		  1);
  tcp_reordering_loc =
    create_histo ("tcp_reordering_loc",
		  "TCP number of packet reordering - local flows", 0, 100, 1);
  tcp_reordering_c2s =
    create_histo ("tcp_reordering_c2s",
		  "TCP number of packet reordering - client flows", 0, 100,
		  1);
  tcp_reordering_s2c =
    create_histo ("tcp_reordering_s2c",
		  "TCP number of packet reordering - server flows", 0, 100,
		  1);

  tcp_net_dup_in = create_histo ("tcp_net_dup_in",
				 "TCP number of Network duplicates - incoming flows",
				 0, 100, 1);
  tcp_net_dup_out =
    create_histo ("tcp_net_dup_out",
		  "TCP number of Network duplicates - outgoing flows", 0, 100,
		  1);
  tcp_net_dup_loc =
    create_histo ("tcp_net_dup_out",
		  "TCP number of Network duplicates - local flows", 0, 100,
		  1);
  tcp_net_dup_c2s =
    create_histo ("tcp_net_dup_c2s",
		  "TCP number of Network duplicates - client flows", 0, 100,
		  1);
  tcp_net_dup_s2c =
    create_histo ("tcp_net_dup_s2c",
		  "TCP number of Network duplicates - server flows", 0, 100,
		  1);

  tcp_unknown_in = create_histo ("tcp_unknown_in",
				 "TCP number of unknown anomalies - incoming flows",
				 0, 100, 1);
  tcp_unknown_out =
    create_histo ("tcp_unknown_out",
		  "TCP number of unknown anomalies - outgoing flows", 0, 100,
		  1);
  tcp_unknown_loc =
    create_histo ("tcp_unknown_loc",
		  "TCP number of unknown anomalies - local flows", 0, 100, 1);
  tcp_unknown_c2s =
    create_histo ("tcp_unknown_c2s",
		  "TCP number of unknown anomalies - client flows", 0, 100,
		  1);
  tcp_unknown_s2c =
    create_histo ("tcp_unknown_s2c",
		  "TCP number of unknown anomalies - server flows", 0, 100,
		  1);

  tcp_flow_ctrl_in = create_histo ("tcp_flow_control_in",
				   "TCP number of Flow Control - incoming flows",
				   0, 100, 1);
  tcp_flow_ctrl_out =
    create_histo ("tcp_flow_ctrl_out",
		  "TCP number of Flow Control - outgoing flows", 0, 100, 1);
  tcp_flow_ctrl_loc =
    create_histo ("tcp_flow_ctrl_loc",
		  "TCP number of Flow Control - local flows", 0, 100, 1);
  tcp_flow_ctrl_c2s =
    create_histo ("tcp_flow_ctrl_c2s",
		  "TCP number of Flow Control - client flows", 0, 100, 1);
  tcp_flow_ctrl_s2c =
    create_histo ("tcp_flow_ctrl_s2c",
		  "TCP number of Flow Control - server flows", 0, 100, 1);

  tcp_unnrtx_RTO_in = create_histo ("tcp_unnecessary_rtx_RTO_in",
				    "TCP number of Unneeded RTO retransmission - incoming flows",
				    0, 100, 1);
  tcp_unnrtx_RTO_out =
    create_histo ("tcp_unnrtx_RTO_out",
		  "TCP number of Unneeded RTO retransmission - outgoing flows",
		  0, 100, 1);
  tcp_unnrtx_RTO_loc =
    create_histo ("tcp_unnrtx_RTO_loc",
		  "TCP number of Unneeded RTO retransmission - local flows",
		  0, 100, 1);
  tcp_unnrtx_RTO_c2s =
    create_histo ("tcp_unnrtx_RTO_c2s",
		  "TCP number of Unneeded RTO retransmission - client flows",
		  0, 100, 1);
  tcp_unnrtx_RTO_s2c =
    create_histo ("tcp_unnrtx_RTO_s2c",
		  "TCP number of Unneeded RTO retransmission - server flows",
		  0, 100, 1);

  tcp_unnrtx_FR_in = create_histo ("tcp_unnecessary_rtx_FR_in",
				   "TCP number of Unneeded FR retransmission - incoming flows",
				   0, 100, 1);
  tcp_unnrtx_FR_out =
    create_histo ("tcp_unnrtx_FR_out",
		  "TCP number of Unneeded FR retransmission - outgoing flows",
		  0, 100, 1);
  tcp_unnrtx_FR_loc =
    create_histo ("tcp_unnrtx_FR_loc",
		  "TCP number of Unneeded FR retransmission - local flows", 0,
		  100, 1);
  tcp_unnrtx_FR_c2s =
    create_histo ("tcp_unnrtx_FR_c2s",
		  "TCP number of Unneeded FR retransmission - client flows",
		  0, 100, 1);
  tcp_unnrtx_FR_s2c =
    create_histo ("tcp_unnrtx_FR_s2c",
		  "TCP number of Unneeded FR retransmission - server flows",
		  0, 100, 1);

  tcp_tot_time = create_histo ("tcp_tot_time",
			       "TCP flow lifetime [ms]", 0, 720000, 50);
  tcp_thru_c2s = create_histo ("tcp_thru_c2s",
			       "TCP throughput [kbps] - client flows", 0,
			       1000, 1);
  tcp_thru_s2c = create_histo ("tcp_thru_s2c", 
                               "TCP throughput [kbps] - server flows", 0,
		               1000, 1);

  tcp_thru_lf_c2s = create_histo ("tcp_thru_lf_c2s",
			       "TCP throughput [kbps] - client large flows", 0,
			       20000, 10);
  tcp_thru_lf_s2c = create_histo ("tcp_thru_lf_s2c", 
                               "TCP throughput [kbps] - server large flows", 0,
		               20000, 10);
		  
  tcp_thru_lf_c_c2s = create_histo ("tcp_thru_lf_c_c2s",
			       "TCP throughput [kbps] - cloud client large flows", 0,
			       20000, 10);
  tcp_thru_lf_c_s2c = create_histo ("tcp_thru_lf_c_s2c",
                               "TCP throughput [kbps] - cloud server large flows", 0,
		               20000, 10);

  tcp_thru_lf_nc_c2s = create_histo ("tcp_thru_lf_nc_c2s",
			       "TCP throughput [kbps] - non-cloud client large flows", 0,
			       20000, 10);
  tcp_thru_lf_nc_s2c = create_histo ("tcp_thru_lf_nc_s2c",
                               "TCP throughput [kbps] - non-cloud server large flows", 0,
		               20000, 10);

  tcp_interrupted =
    create_histo ("tcp_interrupted", "TCP Early interrupted flows", 0, 1, 1);



  /* UDP histograms */


  udp_cl_p_out = create_histo ("udp_cl_p_out",
			       "UDP flow length [packet] - outgoing", 0,
			       1000, 1);
  udp_cl_p_in =
    create_histo ("udp_cl_p_in", "UDP flow length [packet] - incoming", 0,
		  1000, 1);
  udp_cl_p_loc =
    create_histo ("udp_cl_p_loc", "UDP flow length [packet] - local", 0,
		  1000, 1);

  udp_cl_b_s_out = create_histo ("udp_cl_b_s_out",
				 "UDP flow length [byte] - outgoing", 0,
				 50000, 50);
  udp_cl_b_s_in = create_histo ("udp_cl_b_s_in",
				"UDP flow length [byte] - incoming", 0,
				50000, 50);
  udp_cl_b_s_loc = create_histo ("udp_cl_b_s_loc",
				 "UDP flow length [byte] - local", 0,
				 50000, 50);
  udp_cl_b_l_out =
    create_histo ("udp_cl_b_l_out", "UDP flow length [byte] - outgoing", 0,
		  50000000, 50000);
  udp_cl_b_l_in =
    create_histo ("udp_cl_b_l_in", "UDP flow length [byte] - incoming", 0,
		  50000000, 50000);
  udp_cl_b_l_loc =
    create_histo ("udp_cl_b_l_loc", "UDP flow length [byte] - local", 0,
		  50000000, 50000);

  udp_tot_time = create_histo ("udp_tot_time",
			       "UDP flow lifetime [ms]", 0, 720000, 50);

  udp_port_dst_in = create_histo ("udp_port_dst_in",
				  "UDP destination post - incoming packets",
				  0, 65536, 1);
  udp_port_dst_out =
    create_histo ("udp_port_dst_out",
		  "UDP destination port - outgoing packets", 0, 65536, 1);
  udp_port_dst_loc =
    create_histo ("udp_port_dst_loc",
		  "UDP destination port - local packets", 0, 65536, 1);
  udp_port_flow_dst =
    create_histo ("udp_port_flow_dst",
		  "UDP destination port per flow", 0, 65536, 1);


  /* stream histograms */

  mm_type_in =
    create_histo ("mm_type_in", "stream type - incoming flows", 0, 8, 1);
  mm_type_out =
    create_histo ("mm_type_out", "stream type - outgoing flows", 0, 8, 1);
  mm_type_loc =
    create_histo ("mm_type_loc", "stream type - local flows", 0, 8, 1);

  mm_uni_multi_in =
    create_histo ("mm_uni_multi_in",
		  "unicast/multicast flows - incoming flows", 0, 1, 1);
  mm_uni_multi_out =
    create_histo ("mm_uni_multi_out",
		  "unicast/multicast flows - outgoing flows", 0, 1, 1);
  mm_uni_multi_loc =
    create_histo ("mm_uni_multi_loc",
		  "unicast/multicast flows - local flows", 0, 1, 1);

  mm_rtp_pt_in = create_histo ("mm_rtp_pt_in", "RTP payload type", 0, 128, 1);
  mm_rtp_pt_out = create_histo ("mm_rtp_pt_out",
				"RTP payload type", 0, 128, 1);
  mm_rtp_pt_loc = create_histo ("mm_rtp_pt_loc",
				"RTP payload type", 0, 128, 1);

  mm_tot_time_in =
    create_histo ("mm_tot_time_in",
		  "stream flow lifetime [s] - incoming flows", 0, 5400, 1);
  mm_tot_time_out =
    create_histo ("mm_tot_time_out",
		  "stream flow lifetime [s] - outgoing flows", 0, 5400, 1);
  mm_tot_time_loc =
    create_histo ("mm_tot_time_loc",
		  "stream flow lifetime [s] - local flows", 0, 5400, 1);

  mm_tot_time_s_in =
    create_histo ("mm_tot_time_s_in",
		  "short stream flow lifetime [ms] - incoming flows", 0,
		  SHORT_MM_TOT_TIME, 1);
  mm_tot_time_s_out =
    create_histo ("mm_tot_time_s_out",
		  "short stream flow lifetime [ms] - outgoing flows", 0,
		  SHORT_MM_TOT_TIME, 1);
  mm_tot_time_s_loc =
    create_histo ("mm_tot_time_s_loc",
		  "short stream flow lifetime [ms] - local flows", 0,
		  SHORT_MM_TOT_TIME, 1);

  mm_cl_p_out =
    create_histo ("mm_cl_p_out",
		  "long stream flow length [packet] - outgoing flows", 0,
		  50000, 10);
  mm_cl_p_in =
    create_histo ("mm_cl_p_in",
		  "long stream flow length [packet] - incoming flows", 0,
		  50000, 10);
  mm_cl_p_loc =
    create_histo ("mm_cl_p_loc",
		  "long stream flow length [packet] - local flows", 0, 50000,
		  10);
  mm_cl_b_out =
    create_histo ("mm_cl_b_out",
		  "long stream flow length [bytes] - outgoing flows", 0,
		  100000000, 50000);
  mm_cl_b_in =
    create_histo ("mm_cl_b_in",
		  "long stream flow length [bytes] - incoming flows", 0,
		  100000000, 50000);
  mm_cl_b_loc =
    create_histo ("mm_cl_b_loc",
		  "long stream flow length [bytes] - local flows", 0,
		  100000000, 50000);
  mm_cl_p_s_out =
    create_histo ("mm_cl_p_s_out",
		  "short stream flow length [packet] - outgoing flows", 0,
		  SHORT_MM_CL_P, 1);
  mm_cl_p_s_in =
    create_histo ("mm_cl_p_s_in",
		  "short stream flow length [packet] - incoming flows", 0,
		  SHORT_MM_CL_P, 1);
  mm_cl_p_s_loc =
    create_histo ("mm_cl_p_s_loc",
		  "short stream flow length [packet] - local flows", 0,
		  SHORT_MM_CL_P, 1);
  mm_cl_b_s_out =
    create_histo ("mm_cl_b_s_out",
		  "short stream flow length [bytes] - outgoing flows", 0,
		  SHORT_MM_CL_B, 100);
  mm_cl_b_s_in =
    create_histo ("mm_cl_b_s_in",
		  "short stream flow length [bytes] - incoming flows", 0,
		  SHORT_MM_CL_B, 100);
  mm_cl_b_s_loc =
    create_histo ("mm_cl_b_s_loc",
		  "short stream flow length [bytes] - local flows", 0,
		  SHORT_MM_CL_B, 100);

  mm_avg_bitrate_out =
    create_histo ("mm_avg_bitrate_out",
		  "stream bitrate [kbit/s] - outgoing flows", 0, 10000, 10);
  mm_avg_bitrate_in =
    create_histo ("mm_avg_bitrate_in",
		  "stream bitrate [kbit/s] - incoming flows", 0, 10000, 10);
  mm_avg_bitrate_loc =
    create_histo ("mm_avg_bitrate_loc",
		  "stream bitrate [kbit/s] - local flows", 0, 10000, 10);
  mm_avg_ipg_in =
    create_histo ("mm_avg_ipg_in",
		  "stream average IPG [0.1 ms]- incoming flows", 0, 5000, 1);
  mm_avg_ipg_out =
    create_histo ("mm_avg_ipg_out",
		  "stream average IPG [0.1 ms] - outgoing flows", 0, 5000, 1);
  mm_avg_ipg_loc =
    create_histo ("mm_avg_ipg_loc",
		  "stream average IPG [0.1 ms] - local flows", 0, 5000, 1);
  mm_avg_jitter_in =
    create_histo ("mm_avg_jitter_in",
		  "stream average jitter [0.1 ms] - incoming flows", 0, 5000,
		  1);
  mm_avg_jitter_out =
    create_histo ("mm_avg_jitter_out",
		  "stream average jitter [0.1 ms] - outgoing flows", 0, 5000,
		  1);
  mm_avg_jitter_loc =
    create_histo ("mm_avg_jitter_loc",
		  "stream average jitter [0.1 ms] - local flows", 0, 5000, 1);
  mm_n_oos_in =
    create_histo ("mm_n_oos_in",
		  "stream number of out-of-sequence packets - incoming flows",
		  0, 100, 1);
  mm_n_oos_out =
    create_histo ("mm_n_oos_out",
		  "stream number of out-of-sequence packets - outgoing flows",
		  0, 100, 1);
  mm_n_oos_loc =
    create_histo ("mm_n_oos_loc",
		  "stream number of out-of-sequence packets - local flows", 0,
		  100, 1);
  mm_p_oos_in =
    create_histo ("mm_p_oos_in",
		  "stream prob of out-of-sequence packets - incoming flows",
		  0, 1000, 1);
  mm_p_oos_out =
    create_histo ("mm_p_oos_out",
		  "stream prob of out-of-sequence packets - outgoing flows",
		  0, 1000, 1);
  mm_p_oos_loc =
    create_histo ("mm_p_oos_loc",
		  "stream prob of out-of-sequence packets - local flows", 0,
		  1000, 1);
  mm_p_dup_in =
    create_histo ("mm_p_dup_in",
		  "stream prob of duplicate packets - incoming flows ", 0,
		  1000, 1);
  mm_p_dup_out =
    create_histo ("mm_p_dup_out",
		  "stream prob of duplicate packets - outgoing flows", 0,
		  1000, 1);
  mm_p_dup_loc =
    create_histo ("mm_p_dup_loc",
		  "stream prob of duplicate packets - local flows", 0, 1000,
		  1);
  mm_p_lost_in =
    create_histo ("mm_p_lost_in",
		  "stream prob of lost packets - incoming flows ", 0, 1000,
		  1);
  mm_p_lost_out =
    create_histo ("mm_p_lost_out",
		  "stream prob of lost packets - outgoing flows", 0, 1000, 1);
  mm_p_lost_loc =
    create_histo ("mm_p_lost_loc",
		  "stream prob of lost packets - local flows", 0, 1000, 1);
  mm_p_late_in =
    create_histo ("mm_p_late_in",
		  "stream prob of late packets - incoming flows ", 0, 1000,
		  1);
  mm_p_late_out =
    create_histo ("mm_p_late_out",
		  "stream prob of late packets - outgoing flows", 0, 1000, 1);
  mm_p_late_loc =
    create_histo ("mm_p_late_loc",
		  "stream prob of late packets - local flows", 0, 1000, 1);
  mm_burst_loss_in =
    create_histo ("mm_burst_loss_in",
		  "stream burst length [packet]- incoming flows ", 0, 20, 1);
  mm_burst_loss_out =
    create_histo ("mm_burst_loss_out",
		  "stream burst length [packet] - outgoing flows", 0, 20, 1);
  mm_burst_loss_loc =
    create_histo ("mm_burst_loss_loc",
		  "stream burst length [packet] - local flows", 0, 20, 1);


  mm_reord_p_n_in =
    create_histo ("mm_reord_p_n_in",
		  "stream number of reordered packets - incoming flows ", 0,
		  0, 1);
  mm_reord_p_n_out =
    create_histo ("mm_reord_p_n_out",
		  "stream number of reordered packets - outgoing flows", 0, 0,
		  1);
  mm_reord_p_n_loc =
    create_histo ("mm_reord_p_n_loc",
		  "stream number of reordered packets - local flows", 0, 0,
		  1);
  mm_reord_delay_in =
    create_histo ("mm_reord_delay_in",
		  "stream delay of reordered packets - incoming flows ", 0,
		  100, 1);
  mm_reord_delay_out =
    create_histo ("mm_reord_delay_out",
		  "stream delay of reordered packets - outgoing flows", 0,
		  100, 1);
  mm_reord_delay_loc =
    create_histo ("mm_reord_delay_loc",
		  "stream delay of reordered packets - local flows", 0, 100,
		  1);
  mm_oos_p_in =
    create_histo ("mm_oos_p_in",
		  "stream number of out of sequence packets - incoming flows",
		  0, 0, 1);
  mm_oos_p_out =
    create_histo ("mm_oos_p_out",
		  "stream number of out of sequence packets - outgoing flows",
		  0, 0, 1);
  mm_oos_p_loc =
    create_histo ("mm_oos_p_loc",
		  "stream number of out of sequence packets - local flows",
		  0, 0, 1);


  /* RTCP histograms */

  rtcp_cl_p_out = create_histo ("rtcp_cl_p_out",
				"RTCP flow length [packet] - outgoing flows",
				0, 3000, 1);
  rtcp_cl_p_in = create_histo ("rtcp_cl_p_in",
			       "RTCP flow length [packet] - incoming flows",
			       0, 3000, 1);
  rtcp_cl_p_loc = create_histo ("rtcp_cl_p_loc",
				"RTCP flow length [packet] - local flows",
				0, 3000, 1);

  rtcp_cl_b_out = create_histo ("rtcp_cl_b_out",
				"RTCP flow length [bytes] - outgoing flows",
				0, 3000, 1);
  rtcp_cl_b_in = create_histo ("rtcp_cl_b_in",
			       "RTCP flow length [bytes] - incoming flows",
			       0, 3000, 1);
  rtcp_cl_b_loc = create_histo ("rtcp_cl_b_loc",
				"RTCP flow length [bytes] - local flows",
				0, 3000, 1);

  rtcp_avg_inter_in =
    create_histo ("rtcp_avg_inter_in",
		  "RTCP interarrival delay - incoming flows", 0, 5000, 1);
  rtcp_avg_inter_out =
    create_histo ("rtcp_avg_inter_out",
		  "RTCP interarrival delay - outgoing flows", 0, 5000, 1);
  rtcp_avg_inter_loc =
    create_histo ("rtcp_avg_inter_loc",
		  "RTCP interarrival delay - local flows", 0, 5000, 1);
  /* RTCP decoding histograms */
  rtcp_rtt_in =
    create_histo ("rtcp_rtt_in",
		  "RTCP round trip time [ms] - incoming flows", 0, 3000, 1);
  rtcp_rtt_loc =
    create_histo ("rtcp_rtt_loc",
		  "RTCP round trip time [ms] - local flows", 0, 3000, 1);
  rtcp_rtt_out =
    create_histo ("rtcp_rtt_out",
		  "RTCP round trip time [ms] - outgoing flows", 0, 3000, 1);

  rtcp_jitter_in =
    create_histo ("rtcp_jitter_in",
		  "RTCP jitter during interval - incoming flows", 0, 1000, 1);
  rtcp_jitter_loc =
    create_histo ("rtcp_jitter_loc",
		  "RTCP jitter during interval - local flows", 0, 1000, 1);
  rtcp_jitter_out =
    create_histo ("rtcp_jitter_out",
		  "RTCP jitter during interval - outgoing flows", 0, 1000, 1);

  rtcp_lost_in =
    create_histo ("rtcp_lost_in",
		  "RTCP lost packets during interval - incoming flows", 0,
		  1000, 1);
  rtcp_lost_loc =
    create_histo ("rtcp_lost_loc",
		  "RTCP lost packets during interval - local flows", 0, 1000,
		  1);
  rtcp_lost_out =
    create_histo ("rtcp_lost_out",
		  "RTCP lost packets during interval - outgoing flows", 0,
		  1000, 1);

  rtcp_dup_in =
    create_histo ("rtcp_dup_in",
		  "RTCP duplicated packets during interval - incoming flows",
		  0, 1000, 1);
  rtcp_dup_loc =
    create_histo ("rtcp_dup_loc",
		  "RTCP duplicated packets during interval - local flows", 0,
		  1000, 1);
  rtcp_dup_out =
    create_histo ("rtcp_dup_out",
		  "RTCP duplicated packets during interval - outgoing flows",
		  0, 1000, 1);

  rtcp_f_lost_in =
    create_histo ("rtcp_f_lost_in",
		  "RTCP fraction of lost packets during interval [%.] - incoming flows",
		  0, 1000, 1);
  rtcp_f_lost_loc =
    create_histo ("rtcp_f_lost_loc",
		  "RTCP fraction of lost packets during interval [%.] - local flows",
		  0, 1000, 1);
  rtcp_f_lost_out =
    create_histo ("rtcp_f_lost_out",
		  "RTCP fraction of lost packets during interval [%.] - outgoing flows",
		  0, 1000, 1);

  rtcp_t_lost_in =
    create_histo ("rtcp_t_lost_in",
		  "RTCP lost packets per flow - incoming flows", 0, 10000,
		  10);
  rtcp_t_lost_loc =
    create_histo ("rtcp_t_lost_loc",
		  "RTCP lost packets per flow - local flows", 0, 10000, 10);
  rtcp_t_lost_out =
    create_histo ("rtcp_t_lost_out",
		  "RTCP lost packets per flow - outgoing flows", 0, 10000,
		  10);

  rtcp_mm_cl_p_in =
    create_histo ("rtcp_mm_cl_p_in",
		  "RTCP associated MM flow length [pkts] - incoming flows", 0,
		  50000, 10);
  rtcp_mm_cl_p_loc =
    create_histo ("rtcp_mm_cl_p_loc",
		  "RTCP associated MM flow length [pkts] - local flows", 0,
		  50000, 10);
  rtcp_mm_cl_p_out =
    create_histo ("rtcp_mm_cl_p_out",
		  "RTCP associeted MM flow length [pkts] - outgoing flows", 0,
		  50000, 10);

  rtcp_mm_cl_b_in =
    create_histo ("rtcp_mm_cl_b_in",
		  "RTCP assocaited MM flow length [bytes] - incoming flows",
		  0, 100000000, 50000);
  rtcp_mm_cl_b_loc =
    create_histo ("rtcp_mm_cl_b_loc",
		  "RTCP associated MM flow length [bytes] - local flows", 0,
		  100000000, 50000);
  rtcp_mm_cl_b_out =
    create_histo ("rtcp_mm_cl_b_out",
		  "RTCP associated MM flow length [bytes] - outgoing flows",
		  0, 100000000, 50000);

  rtcp_mm_bt_in =
    create_histo ("rtcp_mm_bt_in",
		  "RTCP associated MM flow avg bitrate during interval [kbit/s] - incoming flows",
		  0, 5000, 1);
  rtcp_mm_bt_loc =
    create_histo ("rtcp_mm_bt_loc",
		  "RTCP associated MM flow avg bitrate during interval [kbit/s] - local flows",
		  0, 5000, 1);
  rtcp_mm_bt_out =
    create_histo ("rtcp_mm_bt_out",
		  "RTCP associated MM flow average bitrate during interval [kbit/s] - outgoing flows",
		  0, 5000, 1);

  rtcp_bt_in =
    create_histo ("rtcp_bt_in",
		  "RTCP average bitrate [bit/s] - incoming flows", 0, 10000,
		  10);
  rtcp_bt_loc =
    create_histo ("rtcp_bt_loc", "RTCP average bitrate [bit/s] - local flows",
		  0, 10000, 10);
  rtcp_bt_out =
    create_histo ("rtcp_bt_out",
		  "RTCP average bitrate [bit/s] - outgoing flows", 0, 10000,
		  10);

  /* MISC histograms */

  L4_flow_number =
    create_histo ("L4_flow_number",
		  "Number of tracked TCP/UDP flow", 0,
		  L4_FLOW_TOT, 1);
  L7_TCP_num_out =
    create_histo ("L7_TCP_num_out",
		  "Number of tracked TCP flow per applications - outgoing flows",
                  0, L7_FLOW_TOT, 1);

  L7_TCP_num_in =
    create_histo ("L7_TCP_num_in",
		  "Number of tracked TCP flow per applications - incoming flows ",
                   0, L7_FLOW_TOT, 1);

  L7_TCP_num_loc =
    create_histo ("L7_TCP_num_loc",
		  "Number of tracked TCP flow per applications - local flows",
                   0, L7_FLOW_TOT, 1);

  L7_TCP_num_c_out =
    create_histo ("L7_TCP_num_c_out",
		  "Number of tracked TCP flow per applications - cloud outgoing flows",
                  0, L7_FLOW_TOT, 1);

  L7_TCP_num_c_in =
    create_histo ("L7_TCP_num_c_in",
		  "Number of tracked TCP flow per applications - cloud incoming flows ",
                   0, L7_FLOW_TOT, 1);

  L7_TCP_num_nc_out =
    create_histo ("L7_TCP_num_nc_out",
		  "Number of tracked TCP flow per applications - non-cloud outgoing flows",
                  0, L7_FLOW_TOT, 1);

  L7_TCP_num_nc_in =
    create_histo ("L7_TCP_num_nc_in",
		  "Number of tracked TCP flow per applications - non-cloud incoming flows ",
                   0, L7_FLOW_TOT, 1);

  L7_UDP_num_out =
    create_histo ("L7_UDP_num_out",
		  "Number of tracked UDP flow per applications - outgoing flows",
                  0, L7_FLOW_TOT, 1);

  L7_UDP_num_in =
    create_histo ("L7_UDP_num_in",
		  "Number of tracked UDP flow per applications - incoming flows ",
                   0, L7_FLOW_TOT, 1);

  L7_UDP_num_loc =
    create_histo ("L7_UDP_num_loc",
		  "Number of tracked UDP flow per applications - local flows",
                   0, L7_FLOW_TOT, 1);

  L7_UDP_num_c_out =
    create_histo ("L7_UDP_num_c_out",
		  "Number of tracked UDP flow per applications - cloud outgoing flows",
                  0, L7_FLOW_TOT, 1);

  L7_UDP_num_c_in =
    create_histo ("L7_UDP_num_c_in",
		  "Number of tracked UDP flow per applications - cloud incoming flows ",
                   0, L7_FLOW_TOT, 1);

  L7_UDP_num_nc_out =
    create_histo ("L7_UDP_num_nc_out",
		  "Number of tracked UDP flow per applications - non-cloud outgoing flows",
                  0, L7_FLOW_TOT, 1);

  L7_UDP_num_nc_in =
    create_histo ("L7_UDP_num_nc_in",
		  "Number of tracked UDP flow per applications - non-cloud incoming flows ",
                   0, L7_FLOW_TOT, 1);

  udp_bitrate_in = create_histo ("udp_bitrate_in",
				  "UDP application bitrate [bit/s] - incoming segments", 0,
				  L7_FLOW_TOT, 1);
  udp_bitrate_out = create_histo ("udp_bitrate_out",
				   "UDP application bitrate [bit/s] - outgoing segments", 0,
				   L7_FLOW_TOT, 1);
  udp_bitrate_loc = create_histo ("udp_bitrate_loc",
				   "UDP application bitrate [bit/s] - local segments", 0,
				   L7_FLOW_TOT, 1);
  udp_bitrate_c_in = create_histo ("udp_bitrate_c_in",
				  "UDP application bitrate [bit/s] - cloud incoming segments", 0,
				  L7_FLOW_TOT, 1);
  udp_bitrate_c_out = create_histo ("udp_bitrate_c_out",
				   "UDP application bitrate [bit/s] - cloud outgoing segments", 0,
				   L7_FLOW_TOT, 1);
  udp_bitrate_nc_in = create_histo ("udp_bitrate_nc_in",
				  "UDP application bitrate [bit/s] - non-cloud incoming segments", 0,
				  L7_FLOW_TOT, 1);
  udp_bitrate_nc_out = create_histo ("udp_bitrate_nc_out",
				   "UDP application bitrate [bit/s] - non-cloud outgoing segments", 0,
				   L7_FLOW_TOT, 1);

  L7_HTTP_num_out =
    create_histo ("L7_HTTP_num_out",
		  "Number of tracked HTTP flows - outgoing flows",
                  0, HTTP_LAST_TYPE, 1);

  L7_HTTP_num_in =
    create_histo ("L7_HTTP_num_in",
		  "Number of tracked HTTP flows - incoming flows ",
                   0, HTTP_LAST_TYPE, 1);

  L7_HTTP_num_loc =
    create_histo ("L7_HTTP_num_loc",
		  "Number of tracked HTTP flows - local flows",
                   0, HTTP_LAST_TYPE, 1);

  L7_HTTP_num_c_out =
    create_histo ("L7_HTTP_num_c_out",
		  "Number of tracked HTTP flows - cloud outgoing flows",
                  0, HTTP_LAST_TYPE, 1);

  L7_HTTP_num_c_in =
    create_histo ("L7_HTTP_num_c_in",
		  "Number of tracked HTTP flows - cloud incoming flows ",
                   0, HTTP_LAST_TYPE, 1);

  L7_HTTP_num_nc_out =
    create_histo ("L7_HTTP_num_nc_out",
		  "Number of tracked HTTP flows - non-cloud outgoing flows",
                  0, HTTP_LAST_TYPE, 1);

  L7_HTTP_num_nc_in =
    create_histo ("L7_HTTP_num_nc_in",
		  "Number of tracked HTTP flows - non-cloud incoming flows ",
                   0, HTTP_LAST_TYPE, 1);

  http_bitrate_in = create_histo ("http_bitrate_in",
				  "HTTP content bitrate [bit/s] - incoming segments", 0,
				  HTTP_LAST_TYPE, 1);
  http_bitrate_out = create_histo ("http_bitrate_out",
				   "HTTP content bitrate [bit/s] - outgoing segments", 0,
				   HTTP_LAST_TYPE, 1);
  http_bitrate_loc = create_histo ("http_bitrate_loc",
				   "HTTP content bitrate [bit/s] - local segments", 0,
				   HTTP_LAST_TYPE, 1);
  http_bitrate_c_in = create_histo ("http_bitrate_c_in",
				  "HTTP content bitrate [bit/s] - cloud incoming segments", 0,
				  HTTP_LAST_TYPE, 1);
  http_bitrate_c_out = create_histo ("http_bitrate_c_out",
				   "HTTP content bitrate [bit/s] - cloud outgoing segments", 0,
				   HTTP_LAST_TYPE, 1);
  http_bitrate_nc_in = create_histo ("http_bitrate_nc_in",
				  "HTTP content bitrate [bit/s] - cloud incoming segments", 0,
				  HTTP_LAST_TYPE, 1);
  http_bitrate_nc_out = create_histo ("http_bitrate_nc_out",
				   "HTTP content bitrate [bit/s] - cloud outgoing segments", 0,
				   HTTP_LAST_TYPE, 1);

  L7_VIDEO_num_out =
    create_histo ("L7_VIDEO_num_out",
		  "Number of tracked VIDEO flows - outgoing flows",
                  0, VIDEO_LAST_TYPE, 1);

  L7_VIDEO_num_in =
    create_histo ("L7_VIDEO_num_in",
		  "Number of tracked VIDEO flows - incoming flows ",
                   0, VIDEO_LAST_TYPE, 1);

  L7_VIDEO_num_loc =
    create_histo ("L7_VIDEO_num_loc",
		  "Number of tracked VIDEO flows - local flows",
                   0, VIDEO_LAST_TYPE, 1);

  L7_VIDEO_num_c_out =
    create_histo ("L7_VIDEO_num_c_out",
		  "Number of tracked VIDEO flows - cloud outgoing flows",
                  0, VIDEO_LAST_TYPE, 1);

  L7_VIDEO_num_c_in =
    create_histo ("L7_VIDEO_num_c_in",
		  "Number of tracked VIDEO flows - cloud incoming flows ",
                   0, VIDEO_LAST_TYPE, 1);

  L7_VIDEO_num_nc_out =
    create_histo ("L7_VIDEO_num_nc_out",
		  "Number of tracked VIDEO flows - non-cloud outgoing flows",
                  0, VIDEO_LAST_TYPE, 1);

  L7_VIDEO_num_nc_in =
    create_histo ("L7_VIDEO_num_nc_in",
		  "Number of tracked VIDEO flows - non-cloud incoming flows ",
                   0, VIDEO_LAST_TYPE, 1);

  video_rate_in = create_histo ("video_rate_in",
				  "VIDEO content bitrate [bit/s] - incoming segments", 0,
				  VIDEO_LAST_TYPE, 1);
  video_rate_out = create_histo ("video_rate_out",
				   "VIDEO content bitrate [bit/s] - outgoing segments", 0,
				   VIDEO_LAST_TYPE, 1);
  video_rate_loc = create_histo ("video_rate_loc",
				   "VIDEO content bitrate [bit/s] - local segments", 0,
				   VIDEO_LAST_TYPE, 1);
  video_rate_c_in = create_histo ("video_rate_c_in",
				  "VIDEO content bitrate [bit/s] - cloud incoming segments", 0,
				  VIDEO_LAST_TYPE, 1);
  video_rate_c_out = create_histo ("video_rate_c_out",
				   "VIDEO content bitrate [bit/s] - cloud outgoing segments", 0,
				   VIDEO_LAST_TYPE, 1);
  video_rate_nc_in = create_histo ("video_rate_nc_in",
				  "VIDEO content bitrate [bit/s] - cloud incoming segments", 0,
				  VIDEO_LAST_TYPE, 1);
  video_rate_nc_out = create_histo ("video_rate_nc_out",
				   "VIDEO content bitrate [bit/s] - cloud outgoing segments", 0,
				   VIDEO_LAST_TYPE, 1);




  L7_WEB_num_out =
    create_histo ("L7_WEB_num_out",
		  "Number of tracked Web 2.0 flows - outgoing flows",
                  0, WEB_LAST_TYPE, 1);

  L7_WEB_num_in =
    create_histo ("L7_WEB_num_in",
		  "Number of tracked Web 2.0 flows - incoming flows ",
                   0, WEB_LAST_TYPE, 1);

  L7_WEB_num_loc =
    create_histo ("L7_WEB_num_loc",
		  "Number of tracked Web 2.0 flows - local flows",
                   0, WEB_LAST_TYPE, 1);

  web_bitrate_in = create_histo ("web_bitrate_in",
				  "Web 2.0 content bitrate [bit/s] - incoming segments", 0,
				  WEB_LAST_TYPE, 1);
  web_bitrate_out = create_histo ("web_bitrate_out",
				   "Web 2.0 content bitrate [bit/s] - outgoing segments", 0,
				   WEB_LAST_TYPE, 1);
  web_bitrate_loc = create_histo ("web_bitrate_loc",
				   "Web 2.0 content bitrate [bit/s] - local segments", 0,
				   WEB_LAST_TYPE, 1);

  L7_TLS_num_out =
    create_histo ("L7_TLS_num_out",
		  "Number of tracked TLS flows - outgoing flows",
                  0, TLS_LAST_TYPE, 1);

  L7_TLS_num_in =
    create_histo ("L7_TLS_num_in",
		  "Number of tracked TLS flows - incoming flows ",
                   0, TLS_LAST_TYPE, 1);

  L7_TLS_num_loc =
    create_histo ("L7_TLS_num_loc",
		  "Number of tracked TLS flows - local flows",
                   0, TLS_LAST_TYPE, 1);

  tls_bitrate_in = create_histo ("tls_bitrate_in",
				  "TLS content bitrate [bit/s] - incoming segments", 0,
				  TLS_LAST_TYPE, 1);
  tls_bitrate_out = create_histo ("tls_bitrate_out",
				   "TLS content bitrate [bit/s] - outgoing segments", 0,
				   TLS_LAST_TYPE, 1);
  tls_bitrate_loc = create_histo ("tls_bitrate_loc",
				   "TLS content bitrate [bit/s] - local segments", 0,
				   TLS_LAST_TYPE, 1);

  /* Microsoft messenger  classification */

#if defined(MSN_CLASSIFIER) || defined(YMSG_CLASSIFIER) || defined(XMPP_CLASSIFIER)
  chat_flow_num =
    create_histo ("chat_flow_num", "Number of tracked IM flow", 0,
                   MAX_CHAT_FLOW_NUM, 1);
#endif

  /* Global bitrate */
  if (global_histo)
    {
      g_tcp_bitrate_in =
	create_histo ("g_tcp_bitrate_in",
		      "Global TCP bitrate IN [kbit/s]", 0, 1000000, 100);
      g_tcp_bitrate_loc =
	create_histo ("g_tcp_bitrate_loc",
		      "Global TCP bitrate LOC [kbit/s]", 0, 1000000, 100);
      g_tcp_bitrate_out =
	create_histo ("g_tcp_bitrate_out",
		      "Global TCP bitrate OUT [kbit/s]", 0, 1000000, 100);
      g_udp_bitrate_in =
	create_histo ("g_udp_bitrate_in",
		      "Global UDP bitrate IN [kbit/s]", 0, 1000000, 100);
      g_udp_bitrate_loc =
	create_histo ("g_udp_bitrate_loc",
		      "Global UDP bitrate LOC [kbit/s]", 0, 1000000, 100);
      g_udp_bitrate_out =
	create_histo ("g_udp_bitrate_out",
		      "Global UDP bitrate OUT [kbit/s]", 0, 1000000, 100);
      g_icmp_bitrate_in =
	create_histo ("g_icmp_bitrate_in",
		      "Global ICMP bitrate IN [kbit/s]", 0, 1000000, 100);
      g_icmp_bitrate_loc =
	create_histo ("g_icmp_bitrate_loc",
		      "Global ICMP bitrate LOC [kbit/s]", 0, 1000000, 100);
      g_icmp_bitrate_out =
	create_histo ("g_icmp_bitrate_out",
		      "Global ICMP bitrate OUT [kbit/s]", 0, 1000000, 100);
      g_other_bitrate_in =
	create_histo ("g_other_bitrate_in",
		      "Global OTHER bitrate IN [kbit/s]", 0, 1000000, 100);
      g_other_bitrate_loc =
	create_histo ("g_other_bitrate_loc",
		      "Global OTHER bitrate LOC [kbit/s]", 0, 1000000, 100);
      g_other_bitrate_out =
	create_histo ("g_other_bitrate_out",
		      "Global OTHER bitrate OUT [kbit/s]", 0, 1000000, 100);
    }

    /* profiling */
    profile_cpu = create_histo("profile_cpu", "cpu load [clock/time]", 0, PROFILE_CPU_TOT, 1);
    gettimeofday(&prof_tm, NULL);
    AVE_init(&ave_win_usr_cpu, "usr cpu load", prof_tm);
    AVE_init(&ave_win_sys_cpu, "sys cpu load", prof_tm);
    max_cpu = 0;

    profile_flows =
        create_histo("profile_flows", "flows handled", 0, PROFILE_FLOWS_TOT, 1);
    AVE_init(&active_flows_win_TCP, "active flows TCP", current_time);
    AVE_init(&active_flows_win_UDP, "active flows UDP", current_time);
    AVE_init(&missed_flows_win_TCP, "missed flows TCP", current_time);
    AVE_init(&missed_flows_win_UDP, "missed flows UDP", current_time);

    profile_tcpdata =
        create_histo("profile_tcpdata", "tcp data volume", 0, PROFILE_TCPDATA_TOT, 1);
    tcpdata_received_total = 0.0;
    tcpdata_missed_total = 0.0;

    profile_trash =
        create_histo("profile_trash", "trash TCP packets", 0, 1, 1);

}

extern struct bitrates bitrate;

void
update_fake_histos ()
{
  struct timeval prof_tm;
  double sys_cpu, usr_cpu;
  double elapsed_time = elapsed (last_time_step, current_time) / 1000.0;
  fake_histo_bitrate_update (ip_bitrate_in, elapsed_time, L4_bitrate.in, 4);
  fake_histo_bitrate_update (ip_bitrate_out, elapsed_time, L4_bitrate.out, 4);
  fake_histo_bitrate_update (ip_bitrate_loc, elapsed_time, L4_bitrate.loc, 4);
  fake_histo_bitrate_update (ip_bitrate_c_in, elapsed_time, L4_bitrate.c_in, 4);
  fake_histo_bitrate_update (ip_bitrate_c_out, elapsed_time, L4_bitrate.c_out, 4);
  fake_histo_bitrate_update (ip_bitrate_nc_in, elapsed_time, L4_bitrate.nc_in, 4);
  fake_histo_bitrate_update (ip_bitrate_nc_out, elapsed_time, L4_bitrate.nc_out, 4);

  fake_histo_bitrate_update (tcp_bitrate_in, elapsed_time, L7_bitrate.in, L7_FLOW_TOT);
  fake_histo_bitrate_update (tcp_bitrate_out, elapsed_time, L7_bitrate.out, L7_FLOW_TOT);
  fake_histo_bitrate_update (tcp_bitrate_loc, elapsed_time, L7_bitrate.loc, L7_FLOW_TOT);
  fake_histo_bitrate_update (tcp_bitrate_c_in, elapsed_time, L7_bitrate.c_in, L7_FLOW_TOT);
  fake_histo_bitrate_update (tcp_bitrate_c_out, elapsed_time, L7_bitrate.c_out, L7_FLOW_TOT);
  fake_histo_bitrate_update (tcp_bitrate_nc_in, elapsed_time, L7_bitrate.nc_in, L7_FLOW_TOT);
  fake_histo_bitrate_update (tcp_bitrate_nc_out, elapsed_time, L7_bitrate.nc_out, L7_FLOW_TOT);

  fake_histo_bitrate_update (udp_bitrate_in, elapsed_time, L7_udp_bitrate.in, L7_FLOW_TOT);
  fake_histo_bitrate_update (udp_bitrate_out, elapsed_time, L7_udp_bitrate.out, L7_FLOW_TOT);
  fake_histo_bitrate_update (udp_bitrate_loc, elapsed_time, L7_udp_bitrate.loc, L7_FLOW_TOT);
  fake_histo_bitrate_update (udp_bitrate_c_in, elapsed_time, L7_udp_bitrate.c_in, L7_FLOW_TOT);
  fake_histo_bitrate_update (udp_bitrate_c_out, elapsed_time, L7_udp_bitrate.c_out, L7_FLOW_TOT);
  fake_histo_bitrate_update (udp_bitrate_nc_in, elapsed_time, L7_udp_bitrate.nc_in, L7_FLOW_TOT);
  fake_histo_bitrate_update (udp_bitrate_nc_out, elapsed_time, L7_udp_bitrate.nc_out, L7_FLOW_TOT);

  fake_histo_bitrate_update (http_bitrate_in, elapsed_time, HTTP_bitrate.in, HTTP_LAST_TYPE);
  fake_histo_bitrate_update (http_bitrate_out, elapsed_time, HTTP_bitrate.out, HTTP_LAST_TYPE);
  fake_histo_bitrate_update (http_bitrate_loc, elapsed_time, HTTP_bitrate.loc, HTTP_LAST_TYPE);
  fake_histo_bitrate_update (http_bitrate_c_in, elapsed_time, HTTP_bitrate.c_in, HTTP_LAST_TYPE);
  fake_histo_bitrate_update (http_bitrate_c_out, elapsed_time, HTTP_bitrate.c_out, HTTP_LAST_TYPE);
  fake_histo_bitrate_update (http_bitrate_nc_in, elapsed_time, HTTP_bitrate.nc_in, HTTP_LAST_TYPE);
  fake_histo_bitrate_update (http_bitrate_nc_out, elapsed_time, HTTP_bitrate.nc_out, HTTP_LAST_TYPE);

  fake_histo_bitrate_update (web_bitrate_in, elapsed_time, WEB_bitrate.in, WEB_LAST_TYPE);
  fake_histo_bitrate_update (web_bitrate_out, elapsed_time, WEB_bitrate.out, WEB_LAST_TYPE);
  fake_histo_bitrate_update (web_bitrate_loc, elapsed_time, WEB_bitrate.loc, WEB_LAST_TYPE);

  fake_histo_bitrate_update (tls_bitrate_in, elapsed_time, TLS_bitrate.in, TLS_LAST_TYPE);
  fake_histo_bitrate_update (tls_bitrate_out, elapsed_time, TLS_bitrate.out, TLS_LAST_TYPE);
  fake_histo_bitrate_update (tls_bitrate_loc, elapsed_time, TLS_bitrate.loc, TLS_LAST_TYPE);

  fake_histo_bitrate_update (video_rate_in, elapsed_time, VIDEO_rate.in, VIDEO_LAST_TYPE);
  fake_histo_bitrate_update (video_rate_out, elapsed_time, VIDEO_rate.out, VIDEO_LAST_TYPE);
  fake_histo_bitrate_update (video_rate_loc, elapsed_time, VIDEO_rate.loc, VIDEO_LAST_TYPE);
  fake_histo_bitrate_update (video_rate_c_in, elapsed_time, VIDEO_rate.c_in, VIDEO_LAST_TYPE);
  fake_histo_bitrate_update (video_rate_c_out, elapsed_time, VIDEO_rate.c_out, VIDEO_LAST_TYPE);
  fake_histo_bitrate_update (video_rate_nc_in, elapsed_time, VIDEO_rate.nc_in, VIDEO_LAST_TYPE);
  fake_histo_bitrate_update (video_rate_nc_out, elapsed_time, VIDEO_rate.nc_out, VIDEO_LAST_TYPE);

#ifdef MSN_CLASSIFIER
  msn_get_average ();
#endif
#ifdef YMSG_CLASSIFIER
  ymsg_get_average ();
#endif
#ifdef XMPP_CLASSIFIER
  jabber_get_average ();
#endif
  /* profile */
    
    /*
  printf("tcp:%f udp:%f\n", 
    AVE_get_stat(current_time, &active_flows_win_TCP),
    AVE_get_stat(current_time, &active_flows_win_UDP));
*/

  if (profile_flows->flag == HISTO_ON) {
      set_histo(profile_flows, PROFILE_FLOWS_ACTIVE_TCP, AVE_get_stat(current_time, &active_flows_win_TCP));
      set_histo(profile_flows, PROFILE_FLOWS_ACTIVE_UDP, AVE_get_stat(current_time, &active_flows_win_UDP));
      // set_histo(profile_flows, PROFILE_FLOWS_MISSED_TCP, AVE_get_stat(current_time, &missed_flows_win_TCP));
      // set_histo(profile_flows, PROFILE_FLOWS_MISSED_UDP, AVE_get_stat(current_time, &missed_flows_win_UDP));
      set_histo(profile_flows, PROFILE_FLOWS_MISSED_TCP, missed_flows_win_TCP.n);
      set_histo(profile_flows, PROFILE_FLOWS_MISSED_UDP, missed_flows_win_UDP.n);
      missed_flows_win_TCP.n = 0;
      missed_flows_win_UDP.n = 0;
  }

  if (profile_cpu -> flag == HISTO_ON) {
      gettimeofday(&prof_tm, NULL);
      usr_cpu = AVE_get_stat(prof_tm, &ave_win_usr_cpu);
      sys_cpu = AVE_get_stat(prof_tm, &ave_win_sys_cpu);
      set_histo(profile_cpu, PROFILE_CPU_USR, (int)(usr_cpu + 0.5));
      set_histo(profile_cpu, PROFILE_CPU_SYS, (int)(sys_cpu + 0.5));
      set_histo(profile_cpu, PROFILE_CPU_MAX, (int)(max_cpu - usr_cpu - sys_cpu + 0.5));
      ave_win_usr_cpu.n = 0;
      ave_win_sys_cpu.n = 0;
      max_cpu = 0;
      //printf("usr:%ld sys:%ld max:%ld\n", 
      //  profile_cpu -> current_data[PROFILE_CPU_USRSYS],
      //  profile_cpu -> current_data[PROFILE_CPU_SYS],
      //  profile_cpu -> current_data[PROFILE_CPU_MAX]);
  }

  if (profile_tcpdata->flag == HISTO_ON) {
      // printf("%f %f\n",tcpdata_received_total, tcpdata_missed_total);
      set_histo(profile_tcpdata, PROFILE_TCPDATA_RECEIVED, tcpdata_received_total);
      set_histo(profile_tcpdata, PROFILE_TCPDATA_MISSED, tcpdata_missed_total);
      tcpdata_received_total = 0.0;
      tcpdata_missed_total = 0.0;
  }

}
