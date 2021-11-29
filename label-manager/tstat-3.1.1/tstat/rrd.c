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
 * v1.2.0 memory leak fixed
*/

#ifdef HAVE_RRDTOOL

#ifdef RRD_THREADED
#define _GNU_SOURCE
#include <fcntl.h>
#include <unistd.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#endif

#include <assert.h>
#include "tstat.h"

extern Bool histo_engine;
extern Bool live_flag;

/* increase the threshold to get rid of proto dbg msg */
#define RRD_DEBUG_LEVEL 1
#define RRD_DEBUG (RRD_DEBUG_LEVEL>0 && debug>=RRD_DEBUG_LEVEL)
extern int debug;

void rrdtool_str2argv (char *buf);
void rrdtool_init ();
void rrdtool_parse_config ();
void rrdtool_parse_line (char *line);
void rrdtool_update_all ();
void rrdtool_create_all ();
void rrdtool_update (struct double_histo_list *h);
void rrdtool_create (struct double_histo_list *h);
void rrdtool_update_command (const char *name, const char *what, double val);
void rrdtool_create_command (const char *name, const char *what);
void histo_parse_rrdconf (void);

/* these two are taken from rrd_tool.c */
int rrdtool_count_args (char *aLine);
int rrdtool_create_args (char *pName, char *aLine, int argc, char **argv);

#ifdef RRD_THREADED
int command_pipe[2];
void * call_rrd_update(void*arg);
pthread_t write_thread;
#endif

typedef struct _rrd
{
  struct _conf
  {
    char path[1024];		/* of the rrd files to be created */
    char file[1024];		/* of Tstat/RRDtool configuration file */
    int line;			/* of the Tstat/RRDtool configuration file */
  } conf;
  char cmd[4096];		/* for system() calls */
  char buf[4096];		/* to read files/pipes lines */
  char file[1024];		/* the rrdfile we will be working on:
				   sprintf("%s/%s.%s",rrd.conf.path,histo->name,statistical_var) */
  int fake_update;		/* so that ``update'' actually quit after ``creates'' */
  int fatal;			/* whether rrd errors are fatal */
  struct stat fbuf;
  int status;
  FILE *pipe;

  unsigned long time_update;

  int argc;
#define MAX_RRD_ARGV 20
  char *argv[MAX_RRD_ARGV];

} rrd_struct;

rrd_struct rrd;


/* 
 void rrdtool_str2argv (char *buf); 
 splits buf into (rrd_argc, rrd_argv)  for rrdlib 
 */


/*============================================================================*
  rrdtool_set_{conf,path}  
  rrdtool_init()
*-----------------------------------------------------------------------------*/

void
rrdtool_set_conf (char *file)
{
  sprintf (rrd.conf.file, "%s", file);
}

void
rrdtool_set_path (char *path)
{
  sprintf (rrd.conf.path, "%s", path);
}

void
rrdtool_init ()
{
  int i;

#ifdef RRD_THREADED
  pipe(command_pipe);
  fcntl(command_pipe[1], F_SETPIPE_SZ, 1048576);
#endif
  
  rrd_clear_error ();
  rrd.fatal = 1;
  rrdtool_parse_config ();
  rrd.time_update = 0;

  for (i = 0; i < MAX_RRD_ARGV; i++)
    rrd.argv[i] = (char *) malloc (512);

#ifdef RRD_THREADED    

  /* Create the thread which writes RRD on disk (the consumer) */
  pthread_create (&write_thread, NULL, (void *) &call_rrd_update, (void *) NULL);

#else

  /* we rather want to create this now...    */
  /* but we need to wait for the first entry */
  /* so this is deferred to update           */
  /*            rrdtool_create_all();        */

#endif


}


/*============================================================================*
	parse configurations
*-----------------------------------------------------------------------------*/
void
rrdtool_parse_config (void)
{
  FILE *conf;

  if (RRD_DEBUG)
    fprintf (fp_stderr, "rrdtool: delayed-parsing of config file <%s>\n",
	     rrd.conf.file);
  if (!(conf = fopen (rrd.conf.file, "r")))
    {
      fprintf (fp_stderr, "%s: file open error.\n", rrd.conf.file);
      fprintf (fp_stderr, "%s\n", strerror(errno));
      exit (1);
    }

  while (!feof (conf))
    {
      fgets (rrd.buf, 1024, conf);
      rrd.conf.line++;
      if (index (rrd.buf, '#') == NULL)
	rrdtool_parse_line (rrd.buf);

      /* if(index(rrd.buf,"#") != NULL) {
         if(RRD_DEBUG) fprintf (fp_stderr, "\rignoring line %d (%s)", rrd.conf.line, rrd.buf);
         } else {
         if(RRD_DEBUG) fprintf (fp_stderr, "\rparsing line %d (%s)", rrd.conf.line, rrd.buf);            
         rrdtool_parse_line(rrd.buf);
         } */
    }
  if (RRD_DEBUG)
    fprintf (fp_stderr, "\rrrdtool: config file succesfully parsed (%d lines)\n",
	     rrd.conf.line);
}


/* shitty C makes it harder than perl */
void
rrdtool_parse_line (char *line)
{
  int iidx = 0, fidx = 0;
  char str[1024];
  int ivec[256];
  double fvec[256];
  char name[1024];
  struct double_histo_list *histo;
  char *pstr;
  /* find the histo named name (i.e., the first arg on the line) */

  char idxStr[1024] = "";
  char prcStr[1024] = "";

  if (RRD_DEBUG)
    fprintf (fp_stderr, "Parsing line %3d: ", rrd.conf.line);
  pstr = strtok (line, " ");
  sscanf (pstr, "%s", name);
  histo = find_histo (name);
  if (histo == NULL)
    {
      fprintf (fp_stderr,
	       "rrdtool: variable <%s> unknown while processing <%s>\n", name,
	       rrd.conf.file);
      exit (1);
    }
  else if (RRD_DEBUG)
    {
      fprintf (fp_stderr, "%s\t", name);
    }


  histo->conf.rrd = TRUE;

  if (histo->flag == HISTO_OFF)
    {
      /* need to create the histo!! */
      alloc_histo (histo);
    }

  while ((pstr = strtok (NULL, " ")))
    {
      sscanf (pstr, "%s", str);

      if ((strcmp (str, name) == 0) || (strcmp (str, " ") == 0))
	{
	  /* nothing to do */

	}
      else if (strcmp (str, "hit") == 0)
	{
	  histo->conf.hit = TRUE;
	  if (RRD_DEBUG)
	    fprintf (fp_stderr, "hit,");

	}
      else if (strcmp (str, "avg") == 0)
	{
	  histo->conf.avg = TRUE;
	  if (RRD_DEBUG)
	    fprintf (fp_stderr, "avg,");

	}
      else if (strcmp (str, "min") == 0)
	{
	  histo->conf.min = TRUE;
	  if (RRD_DEBUG)
	    fprintf (fp_stderr, "min,");

	}
      else if (strcmp (str, "max") == 0)
	{
	  histo->conf.max = TRUE;
	  if (RRD_DEBUG)
	    fprintf (fp_stderr, "max,");

	}
      else if (strcmp (str, "var") == 0)
	{
	  histo->conf.var = TRUE;
	  if (RRD_DEBUG)
	    fprintf (fp_stderr, "var,");

	}
      else if (strcmp (str, "stdev") == 0)
	{
	  histo->conf.stdev = TRUE;
	  if (RRD_DEBUG)
	    fprintf (fp_stderr, "stdev,");

	}
      else if (strstr (str, "idx:"))
	{
	  sprintf (idxStr, "%s", str);
	}
      else if (strstr (str, "prc:"))
	{
	  sprintf (prcStr, "%s", str);
	}
      else
	{
	  fprintf (fp_stderr,
		   "rrdtool: unknown token <%s> unknown while processing <%s> line %d\n",
		   str, rrd.conf.file, rrd.conf.line);
	  exit (1);
	}
    }

  if (strstr (idxStr, "idx:"))
    {
      char *substr = strtok (idxStr, ":,");	/* this gives ``idx'' ... */
      substr = strtok (NULL, ",");	/* ... so we skip it */

      while (substr != NULL)
	{
	  if (!strcmp (substr, "other"))
	    {
	      histo->conf.idxoth = TRUE;
	    }
	  else
	    {
	      ivec[iidx++] = atoi (substr);
	    }
	  substr = strtok (NULL, ",");
	}
      histo->conf.idxno = iidx;
      histo->conf.idx = (int *) malloc (sizeof (int) * histo->conf.idxno);
      if (RRD_DEBUG)
	fprintf (fp_stderr, "idx:");
      for (iidx = 0; iidx < histo->conf.idxno; iidx++)
	{
	  histo->conf.idx[iidx] = ivec[iidx];
	  if (RRD_DEBUG)
	    fprintf (fp_stderr, "%d:", ivec[iidx]);
	}
      if (debug && histo->conf.idxoth)
	fprintf (fp_stderr, "other ");

    }

  if (strstr (prcStr, "prc:"))
    {
      char *substr = strtok (prcStr, ":,");	/* this gives ``prc'' ... */
      substr = strtok (NULL, ",");	/* ... so we skip it */

      while (substr != NULL)
	{
	  fvec[fidx++] = atof (substr);
	  substr = strtok (NULL, ",");
	}
      histo->conf.prcno = fidx;
      histo->conf.prc =
	(double *) malloc (sizeof (double) * histo->conf.prcno);
      if (RRD_DEBUG)
	fprintf (fp_stderr, "prc:");
      for (fidx = 0; fidx < histo->conf.prcno; fidx++)
	{
	  histo->conf.prc[fidx] = fvec[fidx];
	  if (RRD_DEBUG)
	    fprintf (fp_stderr, "%f:", fvec[fidx]);
	}
    }

  if (RRD_DEBUG)
    fprintf (fp_stderr, "\n");

}


/*============================================================================*
	tstat update/create frontend 
*-----------------------------------------------------------------------------*/

void
rrdtool_update_all ()
{
  struct double_histo_list *temphp;

  rrd.time_update = (unsigned long) current_time.tv_sec;

  temphp = first_histo_list ();
  while (temphp != NULL)
    {
      rrdtool_update (temphp);
      temphp = temphp->next;
    }

}

void
rrdtool_create_all ()
{
  struct double_histo_list *temphp;
  temphp = first_histo_list ();
  while (temphp != NULL)
    {
      rrdtool_create (temphp);
      temphp = temphp->next;
    }
}

void
rrdtool_update (struct double_histo_list *h)
{
  struct rrdconf *conf = &h->conf;
  long *frozen = whats_frozen (h);
  int pos;
  int i, j, idx;
  int num;
  double prc, cdf;


  if (!conf->rrd)
    return;

  /* do not update more than once in the same instant */
  if (h->st.last.tv_sec >= current_time.tv_sec)
    return;
  h->st.last = current_time;

  if (conf->hit)
    rrdtool_update_command (h->name, "hit", h->st.count);
  if (conf->avg)
    rrdtool_update_command (h->name, "avg", h->st.avg);
  if ((conf->min) && (h->st.min <= 1E90))
    rrdtool_update_command (h->name, "min", h->st.min);
  if ((conf->max) && (h->st.max > -1E90))
    rrdtool_update_command (h->name, "max", h->st.max);
  if (conf->var || conf->stdev)
    {
      double var = h->st.pseudovar / (h->st.count - 1);
      if (conf->var)
	rrdtool_update_command (h->name, "var", var);
      if (conf->stdev)
	rrdtool_update_command (h->name, "stdev", sqrt (var));
    }

  num = ((int) ((h->max - h->min) / h->bin_size)) + 1;

  if (conf->prcno)
    for (i = 0; i < conf->prcno; i++)
      {
	prc = conf->prc[i];
	if ((double) ((int) prc) == (double) prc)
	  {
	    sprintf (rrd.buf, "prc%.0f", conf->prc[i]);	/* prefer prc95 to prc95.000 */
	  }
	else
	  {
	    sprintf (rrd.buf, "prc%.3f", conf->prc[i]);	/* case prc99.999 */
	  }
	/* we do it the lazy way ... */
	prc = prc * frozen[num + 1] / 100;	/* get the hit number to stop at */
	cdf = 0.0;
	for (j = 0; j < num; j++)
	  {
	    if ((cdf += frozen[j]) >= prc)
	      {
		rrdtool_update_command (h->name, rrd.buf,
					h->min + (j - 1) * h->bin_size);
		break;
	      }
	  }
      }

  /* since we decrement frozen[num + 1], the following
     block MUST NOT be moved, otherwise percentile estimate
     is broken */
  if (conf->idxno)
    for (i = 0; i < conf->idxno; i++)
      {
	/* need to translate the index position in case bin_size != 1 */
	idx = conf->idx[i];
	pos = (idx - h->min) / h->bin_size + 1;
	sprintf (rrd.buf, "idx%d", idx);
	rrdtool_update_command (h->name, rrd.buf, frozen[pos]);
	/* recall than in histo[num+1] we count the hit number... */
	frozen[num + 1] -= frozen[pos];
      }
  if (conf->idxoth)
    rrdtool_update_command (h->name, "idxoth", frozen[num + 1]);

  /* we now reset the stats as we reset the counters... 
     so that the min, var, max, etc stats are local to a specific
     time interval (otherwise min would be the minimum since rrdtool
     first started...) */
  h->st.count = 0;
  h->st.avg = 0.0;
  h->st.max = -1.e99;
  h->st.min = 1.e99;
  h->st.pseudovar = 0;
}


void
rrdtool_create (struct double_histo_list *h)
{
  struct rrdconf conf = h->conf;
  int i, idx;
  double prc;

  if (!conf.rrd)
    return;
  if (conf.avg)
    rrdtool_create_command (h->name, "avg");
  if (conf.min)
    rrdtool_create_command (h->name, "min");
  if (conf.max)
    rrdtool_create_command (h->name, "max");
  if (conf.var)
    rrdtool_create_command (h->name, "var");
  if (conf.idxoth)
    rrdtool_create_command (h->name, "idxoth");
  if (conf.stdev)
    rrdtool_create_command (h->name, "stdev");
  h->st.last.tv_sec = 0;	/* last update field */

  if (h->conf.idxno)
    for (i = 0; i < h->conf.idxno; i++)
      {
	idx = h->conf.idx[i];
	sprintf (rrd.buf, "idx%d", idx);
	rrdtool_create_command (h->name, rrd.buf);
      }
  if (h->conf.prcno)
    for (i = 0; i < h->conf.prcno; i++)
      {
	prc = h->conf.prc[i];
	if ((double) ((int) prc) == (double) prc)
	  {
	    sprintf (rrd.buf, "prc%.0f", prc);	/* prefer prc95 to prc95.000 */
	  }
	else
	  {
	    sprintf (rrd.buf, "prc%.3f", prc);	/* case prc99.999 */
	  }
	rrdtool_create_command (h->name, rrd.buf);
      }
}


/*============================================================================*
	rrd update/create library calls
*-----------------------------------------------------------------------------*/
void
rrdtool_str2argv (char *str)
{
  char *str_end;
  char *str_orig = str;
  int i = 0;


  while (*str)
    {
      while (*str == ' ')
	*(str++) = '\0';

      if (*str)
	{
	  str_end = str;
	  while (*str_end && (*str_end != ' '))
	    str_end++;

	  snprintf (rrd.argv[i], str_end - str + 1, "%s", str);
	  i++;

	  str = str_end;
	}
    }

  if ((rrd.argc = i) > MAX_RRD_ARGV)
    {
      fprintf (fp_stderr,
	       "rrdtool: MAX_RRD_ARGV=%d exceeded (%d) in rrdtool_str2argv(%s)\n",
	       MAX_RRD_ARGV, rrd.argc, str_orig);
      exit (1);
    }

  //if(RRD_DEBUG)
  //for(i=0;  i<rrd.argc; i++) 
  //      fprintf(fp_stdout, "\t%d: \%s\n",i, rrd_argv[i]);
}

// doens't deallocate!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
// void
// rrdtool_str2argv_malloc (char *buf, int *pargc, char ***pargv)
// {
//   char **argv;
//   int nargs = 0;
// 
//   /* discard the original string, use a copy */
//   buf = strdup (buf);
// 
//   /* (very pessimistically) make the argv array */
//   argv = malloc (sizeof (char *) * ((strlen (buf) / 2) + 1));
// 
//   /* skip leading blanks */
//   while ((*buf != '\00') && (isspace ((int) *buf)))
//     {
//       if (debug > 10)
//      fprintf (fp_stdout, "skipping isspace('%c')\n", *buf);
//       ++buf;
//     }
// 
//   argv[0] = '\0';
//   /* break into args */
//   for (nargs = 0; *buf != '\00'; ++nargs)
//     {
//       char *stringend;
//       argv[nargs] = buf;
// 
//       /* search for separator */
//       while ((*buf != '\00') && (!isspace ((int) *buf)))
//      {
//        if (debug > 10)
//          fprintf (fp_stdout, "'%c' (%d) is NOT a space\n", *buf, (int) *buf);
//        ++buf;
//      }
//       stringend = buf;
// 
//       /* skip spaces */
//       while ((*buf != '\00') && (isspace ((int) *buf)))
//      {
//        if (debug > 10)
//          fprintf (fp_stdout, "'%c' (%d) IS a space\n", *buf, (int) *buf);
//        ++buf;
//      }
// 
//       *stringend = '\00';    /* terminate the previous string */
// 
//       if (debug > 10)
//      fprintf (fp_stdout, "  argv[%d] = '%s'\n", nargs, argv[nargs]);
//     }
// 
//   *pargc = nargs;
//   *pargv = argv;
// }
// 


void
rrdtool_create_command (const char *name, const char *what)
{
  // rrd_create needs the time of the first entry, so it
  // called at the time of the first update; therefore, we
  // need to backup the original rrd entry -- in order not 
  // overwrite the update command contained in rrd.cmd  
  rrd_struct temp_rrd = rrd;

  if (RRD_DEBUG)
    fprintf (fp_stderr, "rrdtool: create(%s,%s)\n", name, what);
#ifdef RRD_TREE
  sprintf (temp_rrd.file, "%s/%s", rrd.conf.path, name, what);
  struct stat fbuf;
  if (!((stat (temp_rrd.file, &fbuf) == 0) && S_ISDIR (fbuf.st_mode)))
    {
      mkdir (temp_rrd.file, 0775);
      if (debug > 1)
	fprintf (fp_stderr, "RRDtool database path <%s> created\n",
		 temp_rrd.file);
    }
  sprintf (temp_rrd.file, "%s/%s/%s.rrd", rrd.conf.path, name, what);
#else
  sprintf (temp_rrd.file, "%s/%s.%s.rrd", rrd.conf.path, name, what);
#endif

  rrd.time_update = (unsigned long) current_time.tv_sec;

  if (stat (temp_rrd.file, &temp_rrd.fbuf) == 0)
    {
      if (debug > 1)
	fprintf (fp_stderr, "rrdtool: skip create <%s> ... already existent\n",
		 temp_rrd.file);
      return;			/* already called ? */
    }


  /* MTRG-like behavior for on-line usage */
  sprintf (temp_rrd.cmd,
        "create %s --step %lu --start %ld DS:%s:GAUGE:%lu:U:U %s %s %s %s",
        temp_rrd.file, (unsigned long) (GLOBALS.Max_Time_Step / 1000000),
        (long) rrd.time_update - 10, name, (unsigned long) (GLOBALS.Max_Time_Step / 500000),
	   RRA_DAILY, RRA_WEEKLY, RRA_MONTHLY, RRA_YEARLY);
  if (debug > 1)
    fprintf (fp_stderr, "rrdtool: rrd_create('%s')\n", temp_rrd.cmd);

  optind = 0;
  opterr = 0;
  rrdtool_str2argv (temp_rrd.cmd);
  rrd_create (rrd.argc, rrd.argv);

  if (rrd_test_error ())
    {
      fprintf (fp_stderr, "rrdtool: create command:\n%s\n", temp_rrd.cmd);
      fprintf (fp_stderr, "rrdtool: create error!\n%s\n", rrd_get_error ());
      if (temp_rrd.fatal)
	exit (1);
      rrd_clear_error ();
    }
}




void
rrdtool_update_command (const char *name, const char *what, double val)
{
  if (RRD_DEBUG)
    fprintf (fp_stderr, "rrdtool: update(%s,%s,%f)\n", name, what, val);
#ifdef RRD_TREE
  sprintf (rrd.file, "%s/%s/%s.rrd", rrd.conf.path, name, what);
#else
  sprintf (rrd.file, "%s/%s.%s.rrd", rrd.conf.path, name, what);
#endif

  /* at the first call of this function, all the needed rrd 
     files are created with the start time set appropriately */
  if (stat (rrd.file, &rrd.fbuf) == -1)
    rrdtool_create_all ();

  if (rrd.time_update == 0)
    rrd.time_update = (unsigned long) current_time.tv_sec;

#ifdef RRD_THREADED    /* Write the RRD command in the pipe, execution and disk writing performed by secondary thread */
  sprintf (rrd.cmd, "update %s %ld:%f\n", rrd.file, rrd.time_update, val);
  if (RRD_DEBUG)
    fprintf (fp_stderr, "rrdtool: rrd_update('%s')\n", rrd.cmd);
  
  write (command_pipe[1],rrd.cmd, strlen(rrd.cmd) );
#else    /* Execute the RRD command immediately on database files */
  sprintf (rrd.cmd, "update %s %ld:%f", rrd.file, rrd.time_update, val);
  if (RRD_DEBUG)
    fprintf (fp_stderr, "rrdtool: rrd_update('%s')\n", rrd.cmd);

  optind = 0;
  opterr = 0;
  rrdtool_str2argv (rrd.cmd);
  rrd_update (rrd.argc, rrd.argv);

  if (rrd_test_error ())
    {
      fprintf (fp_stderr, "rrdtool: update command:\n%s\n", rrd.cmd);
      fprintf (fp_stderr, "rrdtool: update error!\n%s\n", rrd_get_error ());
      if (rrd.fatal)
	exit (1);
      rrd_clear_error ();
    }
#endif
  
}

#ifdef RRD_THREADED
void * call_rrd_update(void*arg){
	char buffer [2000];
	int i = 0;
	time_t t;
	srand((unsigned) time(&t));

	/* Open pipe as a stream */
	FILE * buffer_pipe = fdopen(command_pipe[0], "r");
	rrd_clear_error ();

	/* Infinite loop on pipe */
	while(1){

		/* Sleep 10ms in order not to saturate the disk write capacity */
		usleep(10000);
		fgets(buffer,2000,buffer_pipe);

		/* Replace \n with \0 */
		buffer[strlen(buffer)-1]= '\0';

		/* Execute update */
		rrdtool_str2argv(buffer);
		optind = 0; 
		opterr = 0;
		rrd_update (rrd.argc, rrd.argv);
	
		/* Check errors */
		if (rrd_test_error ())
		{
			fprintf (fp_stderr, "rrdtool: update command:\n'%s'\n", buffer);
			fprintf (fp_stderr, "rrdtool: update error!\n%s\n", rrd_get_error ());
			if (rrd.fatal)
				exit (1);
			rrd_clear_error ();
		}
		
	}
	return NULL;
}
#endif

/*-----------------------------------------------------------*/
#endif
