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
 * Simple hash implementation using single table, not resizeable, from
 * the top of my head.
 */

# include <fcntl.h>


typedef struct hashdag
{
  unsigned key;
  void *data;
  struct hash *next;
}
hash_t;

typedef struct hashstat
{
  unsigned find1;
  unsigned find2;
  unsigned count;
}
hashstat_t;

extern int hash_create (unsigned size);
extern void hash_destroy (void);

extern hash_t *hash_find (unsigned key);
extern hash_t *hash_enter (unsigned key);
extern int hash_delete (unsigned key);
extern hash_t *hash_walk (int start);
extern void hash_clearstat (void);

extern hashstat_t hashstat;

/*
 * Progress reporting
 */
void progress_init (int level, off_t total, char *name, char *dir);
void progress_finish (void);

extern off_t progress_bytes;	/* the current size */

/*
 * Internet checksum computation
 */
unsigned short in_chksum (unsigned short *buf, int len);

/*
 * Converts a string of form YYYYMMMDD-HHMMSS into a UNIX time_t.
 */
extern time_t trtime (char *s);

/*
 * Reporting support
 */
extern void panic (char *fmt, ...)
  __attribute__ ((noreturn, format (printf, 1, 2)));
