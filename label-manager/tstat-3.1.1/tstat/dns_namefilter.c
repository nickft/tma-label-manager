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
*  This file implements the filtering rules based on strings.
*  It read the list of DNS names to be used as filters from a file.
*  Each row must have an entry <domain.name include>
*  where domain.name can be any string, and include may be 0|1
*  if include == 1, the matched flow will be dumped
*  if include == 0, the matched flow will be not dumped
*  the last line can be a wildcard "ANY.ANY" to set default behaviour.
*  By default, anything that is not matched is dumped
*  lines starting with '#' are skipped
*  for example:
*
*  ANY.ANY 0
*  google.com 1
*  apple.com 1
*
*  would dump all flows *google.com and *.apple.com.
*  The search stops at the first match, so that
*
*  ANY.ANY 0
*  mail.google.com 0
*  google.com 1
*
*  results in dumping only *.google.com but not mail.google.com 
*
*/

#include "tstat.h"

#define MAX_DOMAIN_NAMES 256
#define BUF_SIZE 80

typedef struct
{
  int  num_entries;
  Bool default_value;
  Bool enabled;
  char *name[MAX_DOMAIN_NAMES];
  Bool filter[MAX_DOMAIN_NAMES];
  int  len[MAX_DOMAIN_NAMES];
} DNS_filter;

DNS_filter DNS_filters;

/* Prototypes for DNS filtering */
int  init_DNSfilter (char *filename, Bool enable);
Bool check_DNSname (char *name);
void enable_DNSfilter (Bool enable);

char * readline2(FILE *fp, int skip_comment, int skip_void_lines) {
    static char *buf = NULL;
    static int buf_size = 0;
    static int next_pos = 0;
    char *tmp, curr_c;
    int comment_started = 0;

    if (buf == NULL) {
        buf = malloc(BUF_SIZE * sizeof(char));
        buf_size = BUF_SIZE;
        next_pos = 0;
    }

    buf[0] = '\0';
    next_pos = 0;
    while (1) {
        if (next_pos + 1 == buf_size) {
            buf_size += BUF_SIZE;
            tmp = malloc(buf_size * sizeof(char));
            strcpy(tmp, buf);
            free(buf);
            buf = tmp;
        }

        curr_c = fgetc(fp);
        if (feof(fp)) {
            buf[next_pos] = '\0';
            break;
        }

        comment_started |= skip_comment && (curr_c == '#');
        if (!comment_started || curr_c == '\n') {
            buf[next_pos] = curr_c;
            buf[next_pos + 1] = '\0';
            next_pos++;
        }

        if (curr_c == '\n') {
            if (buf[0] == '\n' && skip_void_lines) {
                buf[0] = '\0';
                next_pos = 0;
                comment_started = 0;
                continue;
            }
            else
                break;
       }
    }

    if (buf[0] == '\0')
        return NULL;
    return buf;
}

void enable_DNSfilter (Bool enable)
{
      DNS_filters.enabled = enable;
}

int init_DNSfilter (char *filename, Bool enabled)
{
  FILE *fp;
  char *line = NULL;
  char tmpname[BUF_SIZE] = "";
  int filter;
  int len, i;

  if (!enabled)
    {
      DNS_filters.enabled = 0;
      DNS_filters.default_value = 1;
      DNS_filters.num_entries = 0;
      return 1;
    }

  fp = fopen (filename, "r");
  if (!fp)
    {
      fprintf (fp_stderr, "Unable to open file '%s'\n", filename);
      return 0;
    }

  /* By default, everything is included */
  DNS_filters.default_value = 1;

  i = 0;
  while (1)
    {
      /* use readline to skip comments */
      line = readline (fp,1,1);
      if (!line)
	    break;

      len = strlen (line);
      if (line[len - 1] == '\n')
        line[len - 1] = '\0';

      sscanf (line, "%s %uc", (char *) tmpname, &filter);

      len = strlen (tmpname);
      if (len == 0)
       {
	     fprintf (fp_stderr,
		      "Unable to parse file '%s' - empty string found - %s (%s)\n",
		      filename, line, tmpname);
	     return 0;
       }

      if (filter != 0 && filter != 1)
	   {
	     fprintf (fp_stderr,
		   "Unable to parse file '%s' - invalid values for '%s' (%d) - must be [0|1]\n",
		   filename, tmpname, filter);
	     return 0;
	   }

      if (strncmp (tmpname, "ANY.ANY", 7) == 0)
	   {
	     DNS_filters.default_value = filter;
	     if (debug > 1)
	      {
	        fprintf (fp_stderr,"FilterDNS: setting DEFAULT (ANY.ANY) to %d\n",filter);
	      }
	   }
      else
	   {
	     if (debug > 1)
	      {
	        fprintf (fp_stderr, "FilterDNS: setting %s (len=%d) to %d\n", tmpname, len, filter);
	      }
	     if (DNS_filters.name[i]!=NULL)
	      { 
            /* We trust that DNS_filters.name[i] is not NULL only if it was allocated before by the strdup() */
	        free(DNS_filters.name[i]);
	        DNS_filters.name[i]=NULL;
	      }
	     DNS_filters.name[i] = strdup(tmpname);
	     DNS_filters.filter[i] = filter;
	     DNS_filters.len[i] = len;
	     i++;
	     if (i == MAX_DOMAIN_NAMES)
	      {
	        fprintf (fp_stderr,
		       "Maximum number of domain names (%d) exceeded when reading file '%s'\n",
		       MAX_DOMAIN_NAMES, filename);
	        return 0;
	      }
	    }
    }

  if (debug > 0)
    {
      fprintf (fp_stderr,"Successfully initialized %d DNS filters read from %s\n", i, filename);
    }
  DNS_filters.num_entries = i;
  DNS_filters.enabled = 1;
  return 1;
}

/*
* Simple linear search here - with 1000 entries, it is requires a negligible amount of time 
* So no need to spend time optimizing here 
*/

Bool check_DNSname (char *name)
{
  int i;
  int len;

  if (!DNS_filters.enabled)
    return (1); /* Here we might have default_value, but what enabling/disabling when a 
                   configuration with ANY.ANY 0 has been provided? */
   
  if (name == NULL)
    return (DNS_filters.default_value);
    
  for (i = 0; i < DNS_filters.num_entries; i++)
    {

      len = strlen (name);
      if (len >= DNS_filters.len[i])
	   {
	     /* extract the last part of the name to see if we have a match */
	     if (strncmp(&name[(len - DNS_filters.len[i])], DNS_filters.name[i],
	                 DNS_filters.len[i]) == 0)
	      {
	        return DNS_filters.filter[i];
	      }
	   }
    }
  return (DNS_filters.default_value);
}
