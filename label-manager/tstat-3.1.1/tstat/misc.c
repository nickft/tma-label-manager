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

/* Function to estimate the average of an birth and death process n(t) */

#define DEBUG_AVERAGE 2

void
AVE_init (win_stat * stat, char *name, timeval tc)
{

  stat->tot = 0;
  stat->n = 0;
  stat->t = tc;
  stat->t0 = tc;
  strncpy (stat->name, name, 20); /* stat->name is char[20] */
  stat->name[19]='\0';            /* force null termination, 
                                     just to stay on the safe side... */ 
}

void
AVE_arrival (timeval tc, win_stat * stat)
{

  stat->tot += elapsed (stat->t, tc) / 1000.0 * stat->n;
  stat->n++;
  if (debug > DEBUG_AVERAGE)
    fprintf (fp_stdout, 
        "new arrival %s: n:%.3f - tot: %f (elapsed = %f)\n", 
        stat->name, stat->n, stat->tot, elapsed (stat->t, tc));
  stat->t = tc;

}

void
AVE_departure (timeval tc, win_stat * stat)
{

  stat->tot += elapsed (stat->t, tc) / 1000.0 * stat->n;
  stat->n--;
  if (debug > DEBUG_AVERAGE)
    fprintf (fp_stdout,
        "new departure %s: n:%.3f - tot: %f (elapsed = %f)\n", 
        stat->name, stat->n, stat->tot, elapsed (stat->t, tc));
  stat->t = tc;
}

void
AVE_new_step (timeval tc, win_stat *stat, double val)
{
  stat->tot += elapsed (stat->t, tc) / 1000.0 * stat->n;
  stat->n = val;
  if (debug > DEBUG_AVERAGE)
    fprintf (fp_stdout, 
        "new step %s: n:%.3f - tot: %f (elapsed = %f)\n", 
        stat->name, stat->n, stat->tot, elapsed (stat->t, tc));
  stat->t = tc;
}


double
AVE_get_stat (timeval tc, win_stat * stat)
{
  stat->tot += elapsed (stat->t, tc) / 1000.0 * stat->n;
  double avg = stat->tot / elapsed (stat->t0, tc) * 1000;
  if (debug > DEBUG_AVERAGE)
    fprintf (fp_stdout,
        "new stat %s: n:%.3f - tot: %f (elapsed = %f) AVG: %f\n",
	    stat->name, stat->n, stat->tot, elapsed (stat->t, tc), avg);
  stat->tot = 0;
  stat->t = tc;
  stat->t0 = tc;
  return avg;
}

int in_out_loc(int internal_src, int internal_dst, int dir)
{
   if(internal_src && !internal_dst)
   {
     if(dir == C2S)
        return OUT_FLOW;
     else
        return IN_FLOW;
   } else
   if(!internal_src && internal_dst)
   {
     if(dir == C2S)
        return IN_FLOW;
     else
        return OUT_FLOW;
   } else
      if(internal_src && internal_dst)
   {
        return LOC_FLOW;
   } else
#ifndef LOG_UNKNOWN
    return EXT_FLOW;
#else
    return LOC_FLOW;
#endif
}


/* YouTube ID conversion functions */

const char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const char hex16[] = "0123456789abcdef";

/* Convert YouTube VideoID (11-chars) in the 16-chars ID*/
void id11to16(char *id16, char *id11)
{
  static unsigned char b[16];
  int i,j;
  char *p,*q;
  int basep,baseq;

  if (strlen(id11)!=11)
   {
//     strncpy(id16,id11,12);
     strncpy(id16,"--",12);
     return;
   }

  i=0;j=0;
  while (i<10)
   {
     p = strchr(b64,id11[i]);
     basep = p - b64;
     
     q = strchr(b64,id11[i+1]);
     baseq = q - b64;
     
     b[j] = (basep & 0x3f) >> 2;
     b[j+1] = (basep & 0x03 ) << 2 | ((baseq & 0x3f)>> 4);
     b[j+2] = (baseq & 0x0f);
     i+=2; j+=3;
   }
  p = strchr(b64,id11[10]);
  basep = p - b64;
     
  b[15] = (basep & 0x3f) >> 2;
  
  for (i=0;i<16;i++)
   {
     id16[i]=hex16[b[i]];
   }
  id16[16]='\0';

}

/* Convert YouTube VideoID (16-chars) in the 11-chars ID*/
void id16to11(char *id11, char *id16)
{
  static unsigned char a[11];
  static unsigned char b[16];
  int i,j;

  if (strlen(id16)!=16)
   {
//     strncpy(id11,id16,12);
     strncpy(id11,"--",12);
     return;
   }
  
  for (i=0;i<16;i++)
   {
     if (id16[i]>='a' && id16[i]<='f')
       b[i]=id16[i]-'a'+10;
     else
       b[i]=id16[i]-'0';
   }

  i=0;j=0;
  
  while (i<10)
   {
  a[i] = (b[j] << 2) | (b[j+1] >> 2) ;
  a[i+1] = ((b[j+1] & 0x03 ) << 4 ) | b[j+2] ;
  i+=2; j+=3;
   }
  a[10] = (b[15] << 2) ;
  
  for (i=0;i<11;i++)
   {
     id11[i]=b64[a[i]];
   }
  id11[11]='\0';
}
