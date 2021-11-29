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


#include "tstat.h"

extern Bool zlib_logs;

static inline void tv_sub (struct timeval *plhs, struct timeval rhs);
void tv_add (struct timeval *plhs, struct timeval rhs);
Bool tv_same (struct timeval lhs, struct timeval rhs);


double
Average (double sum, int count)
{
  return ((double) sum / ((double) count + .0001));
}



double
Stdev (double sum, double sum2, int n)
{
  double term;
  double term1;
  double term2;
  double retval;

  if (n <= 2)
    return (0.0);

  term1 = sum2;
  term2 = (sum * sum) / (double) n;
  term = term1 - term2;
  term /= (double) (n - 1);
  retval = sqrt (term);

/* fprintf(fp_stdout, "Stdev(%f,%f,%d) is %f\n", sum,sum2,n,retval); */

  return (retval);
}

/* Possibly use this macro instead of tv_lt() ?*/
#define tv_lessthen(lhs,rhs) (((lhs).tv_sec<(rhs).tv_sec)||(((lhs).tv_sec==(rhs).tv_sec)&&((lhs).tv_usec<(rhs).tv_usec)))

/* return elapsed time in microseconds */
/* (time2 - time1) */
double
elapsed (struct timeval time1, struct timeval time2)
{
  struct timeval etime;

  /*sanity check, some of the files have packets out of order */
  if (tv_lt (time2, time1))
    {
      return (0.0);
    }

  etime = time2;
  tv_sub (&etime, time1);

  return (time2double (etime));
}



/* subtract the rhs from the lhs, result in lhs */
inline void
tv_sub (struct timeval *plhs, struct timeval rhs)
{
  if (plhs->tv_usec >= rhs.tv_usec)
    {
      plhs->tv_usec -= rhs.tv_usec;
    }
  else if (plhs->tv_usec < rhs.tv_usec)
    {
      plhs->tv_usec += US_PER_SEC - rhs.tv_usec;
      plhs->tv_sec -= 1;
    }
  plhs->tv_sec -= rhs.tv_sec;
}


/* add the RHS to the LHS, answer in *plhs */
void
tv_add (struct timeval *plhs, struct timeval rhs)
{
  plhs->tv_sec += rhs.tv_sec;
  plhs->tv_usec += rhs.tv_usec;

  if (plhs->tv_usec >= US_PER_SEC)
    {
      plhs->tv_usec -= US_PER_SEC;
      plhs->tv_sec += 1;
    }
}


/* are the 2 times the same? */
Bool
tv_same (struct timeval lhs, struct timeval rhs)
{
  return ((lhs.tv_sec == rhs.tv_sec) && (lhs.tv_usec == rhs.tv_usec));
}


/*  1: lhs >  rhs */
/*  0: lhs == rhs */
/* -1: lhs <  rhs */
int
tv_cmp (struct timeval lhs, struct timeval rhs)
{
  if (lhs.tv_sec > rhs.tv_sec)
    {
      return (1);
    }

  if (lhs.tv_sec < rhs.tv_sec)
    {
      return (-1);
    }

  /* ... else, seconds are the same */
  if (lhs.tv_usec > rhs.tv_usec)
    return (1);
  else if (lhs.tv_usec == rhs.tv_usec)
    return (0);
  else
    return (-1);
}



char *
elapsed2str (double etime)
{
  static char buf[80];
  u_long etime_secs;
  u_long etime_usecs;

  etime_secs = etime / 1000000.0;
  etime_usecs = 1000000 * (etime / 1000000.0 - (double) etime_secs);
  sprintf (buf, "%lu:%02lu:%02lu.%06lu",
	   etime_secs / (60 * 60),
	   etime_secs % (60 * 60) / 60,
	   (etime_secs % (60 * 60)) % 60, etime_usecs);
  return (buf);
}

char *
get_basename (char *filename)
{
  char *temp, *base;

  base = (char *) (malloc (100));

  strncpy (base, filename, 100);
  temp = strstr (filename, "/");
  while (temp != NULL)
    {
      temp++;
      strncpy (base, temp, 100);
      temp = strstr (temp, "/");
    }

  strcat (base, ".out");
  return (base);
}

#ifdef HAVE_ZLIB
int wfprintf(FILE *stream, const char* format, ... ) {
static char buffer[8192];
        int err;
        va_list args;
        va_start( args, format );
        vsnprintf( buffer,8192, format, args );
        va_end( args );
	
        if (!zlib_logs)
	 {
           err = fputs(buffer, (FILE *)stream);
	 }
	else
	 {
           err= gzputs( (gzFile*)stream, buffer );
	 }
  return err;
}
#endif
