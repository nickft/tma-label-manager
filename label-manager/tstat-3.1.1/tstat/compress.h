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

#define COMP_HDR_SIZE (8*1024)	/* number of bytes from a compressed file that */
				/* we save into a real file for header check, */
				/* the rest we read from a pipe (if long) */


/* How to identify various comp formats */
#define COMP_MAX_ARGS 20	/* maximum args that you can specify */
struct comp_formats
{
  char *comp_suffix;		/* how to recognize these files         */
  char *comp_descr;		/* description of the file format       */
  char *comp_bin;		/* name of the binary (full path preferred) */
  char *comp_args[COMP_MAX_ARGS];	/* arguments to pass */
};

/*
 * compression format table:
 * Don't forget:!!!
 *  1) Leave the last line of NULLs alone
 *  2) arg 1 MUST be the name of the program
 *  3) last arg MUST be NULL
 *  4) only the first suffix match is used
 *  5) an arg of "%s" will be replaced with the file name,
 *     don't forget to include it!
 *  6) don't forget the "dot" in the suffix (if there is one)
 */

struct comp_formats supported_comp_formats[] = {
/*   SUFFIX    DESCRIPTION	    BINARY NAME	   ARGS TO EXECV	*/
/*   -----   --------------------   -----------   ----------------------*/
#ifdef GUNZIP
  {".gz", "Gnu gzip format", GUNZIP, {"gunzip", "-c", "%s", NULL}},
  {".Z", "Unix compress format", GUNZIP, {"gunzip", "-c", "%s", NULL}},
#endif /* GUNZIP */

#ifdef Z7Z
  {".7z", "7zip format", Z7Z, {"7z", "e", "-so", "%s", NULL}},
#endif /* 7Z */

#ifdef UNCOMPRESS
  {".Z", "Unix compress format", UNCOMPRESS,
   {"uncompress", "-c", "%s", NULL}},
#endif /* UNCOMPRESS */

#ifdef BUNZIP2
  {".bz2", "bzip2 format", BUNZIP2, {"bunzip2", "-c", "%s", NULL}},
  {".bz", "bzip2 format", BUNZIP2, {"bunzip2", "-c", "%s", NULL}},
#endif /* BUNZIP2 */
};

#define NUM_COMP_FORMATS (sizeof(supported_comp_formats) / sizeof(struct comp_formats))
