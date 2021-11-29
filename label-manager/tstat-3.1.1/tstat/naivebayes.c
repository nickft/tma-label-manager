/*
 *
 * Copyright (c) 2001
 *      Politecnico di Torino.  All rights reserved.
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
 * Naivebayes is deeply based on Reverend Thomas Bayes (1702-1761) theory. 
 *
*/
#include <stdio.h>
#include <libgen.h>
#include <limits.h>

#include "tstat.h"

#ifndef max
#define max(a,b) ((a)>(b)?(a):(b))
#endif

// end of line
#define EOL  0xa

// infinite (for practical purposes)
#define INF  1e99

// logarithm
#define LOG(x)    log10( (x) )


extern int debug;
char buf[1024];
FILE *debugf = NULL;

void bayes_parse (const char *buf);
double *bayes_file2vec (const char *fname, int *len, double min_th, Bool);
void bayes_check (struct bayes_settings *settings, FILE * stream);



#if BAYES_BELIEF_HISTO

struct double_histo_list *nbc_wmaxb;
struct double_histo_list *nbc_emaxb;
struct double_histo_list *nbc_validity;

void
bayes_histo_init ()
{
  nbc_wmaxb = create_histo ("nbc_WmaxB",
			    "10x classifier->max_belief ", -200, 0, 1);

  nbc_emaxb = create_histo ("nbc_EmaxB",
			    "10x classifier->mean_max_belief ", -200, 0, 1);

  nbc_validity = create_histo ("nbc_validity",
			       "100x valid_samples/total_samples", 0, 100, 1);
}

#endif

/* 
    ____________________________  
   /				\ 
  /   load settings   __________/ 
  \__________________/.:nonsns:.  
 				  
*/


struct bayes_settings *
bayes_init (char *config_file, char *prefix, void *(*feat2code) ())
{
  FILE *conf;
  char keyword[512], arg1[512], arg2[512], prefix_string[512];
  int config_line = 0;
  int class_num = 0;
  char ch;
  int i;
  struct bayes_settings *settings;

#if BAYES_BELIEF_HISTO
  if (nbc_wmaxb == NULL)
    bayes_histo_init ();
#endif

  if (debugf == NULL)
    debugf = stdout;

  if (BAYES_DBG (0))
    fprintf (fp_stderr, "BAYES: parsing of config file <%s>\n", config_file);

  if (prefix == NULL)
    prefix_string[0] = '\0';
  else
    sprintf (prefix_string, "%s.", prefix);

  settings =
    (struct bayes_settings *) MMmalloc (sizeof (struct bayes_settings),
					"struct bayes_settings");
  settings->name = strdup (config_file);
  settings->new_line = 0;	// no newline in bayes_dump
  settings->auto_other = 0;	// no automatic RestOfTheWorld class generation 
  settings->window_size = -1;	// use all samples (no windowing)
  settings->use_log = 1;	// use sum of logarithms rather than probability products    
  settings->normalize = 1;	// renormalization   

  settings->avg_threshold = 1;	// by default, 3dB above to the uniform threshold  
  settings->win_threshold = 1;	// log10(class_len)/sample_num, set  below
  settings->prc_threshold = 0.95;

  //  settings->min_threshold = 8.841383e-119; // minimum threshold, to avoid log(0)
  //                               // why did I choose this stupid number ? beacause 
  //                               // exp(-100e) = -271.8281828, meaning that 
  //                               // log(8.841383e-119) = -100e = -2.718282e+02 :)
  settings->min_threshold = 1e-33;	// minimum threshold, to avoid log(0)


  if (!(conf = fopen (config_file, "r")))
    {
      fprintf (fp_stderr, "%s: file open error.\n", config_file);
      fprintf (fp_stderr, "%s\n", strerror(errno));
      exit (1);
    }

  //===================================================================================
  //  pass1: parses OPTIONS and gather number of CLASSES 
  //----------------------------------------------------------------------------------- 
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
      if (!strcmp (keyword, "WINDOW_SIZE"))
	{
	  fscanf (conf, "%s", arg1);
	  settings->window_size = atoi (arg1);

	}
      else if (!strcmp (keyword, "AUTO_OTHER"))
	{
	  fscanf (conf, "%s", arg1);
	  settings->auto_other = atoi (arg1);

	}
      else if (!strcmp (keyword, "CLASS_LEN"))
	{
	  fscanf (conf, "%s", arg1);
	  settings->class_len = atoi (arg1);

	}
      else if (!strcmp (keyword, "MIN_THRESHOLD"))
	{
	  fscanf (conf, "%s", arg1);
	  settings->min_threshold = atof (arg1);

	}
      else if (!strcmp (keyword, "WIN_THRESHOLD"))
	{
	  fscanf (conf, "%s", arg1);
	  settings->win_threshold = atof (arg1);

	}
      else if (!strcmp (keyword, "PRC_THRESHOLD"))
	{
	  fscanf (conf, "%s", arg1);
	  settings->prc_threshold = atof (arg1);

	}
      else if (!strcmp (keyword, "AVG_THRESHOLD"))
	{
	  fscanf (conf, "%s", arg1);
	  settings->avg_threshold = atof (arg1);

	}
      else if (!strcmp (keyword, "NORMALIZE"))
	{
	  fscanf (conf, "%s", arg1);
	  settings->normalize = atoi (arg1);

	}
      else if (!strcmp (keyword, "USE_LOG"))
	{
	  fscanf (conf, "%s", arg1);
	  settings->use_log = atoi (arg1);

	}
      else if (!strcmp (keyword, "FEATURE"))
	{
	  fscanf (conf, "%s", arg1);
	  settings->feature_name = strdup (arg1);
	  settings->feature = (int) feat2code (arg1);
	}
      else if (!strcmp (keyword, "DISCRETE") ||
	       !strcmp (keyword, "GAUSSIAN") ||
	       !strcmp (keyword, "GAUSSIAN+"))
	{

	  while (!feof (conf) && (ch != EOL))
	    ch = getc (conf);
	  class_num++;
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


  if (settings->auto_other)
    class_num++;
  settings->class_num = class_num;
  settings->class_weight =
    (double *) MMmalloc (class_num * sizeof (double),
			 "struct bayes_settings: class_weight");
  settings->class_dlen =
    (int *) MMmalloc (class_num * sizeof (int),
		      "struct bayes_settings: class_len");
  settings->class_name =
    (char **) MMmalloc (class_num * sizeof (char *),
			"struct bayes_settings: class_name");
  settings->class_type =
    (int *) MMmalloc (class_num * sizeof (int),
		      "struct bayes_settings: class_type");
  settings->class_dpdf =
    (double **) MMmalloc (class_num * sizeof (double *),
			  "struct bayes_settings: class_dpdf");
  settings->class_gpdf =
    (struct bayes_gaussian *) MMmalloc (class_num *
					sizeof (struct bayes_gaussian),
					"struct bayes_settings: class_gpdf");

#if BAYES_BELIEF_HISTO
  settings->histo_argmax =
    (struct double_histo_list **) MMmalloc ((class_num + 2) *
					    sizeof (struct double_histo_list
						    *),
					    "struct bayes_settings: histo_argmax");
  // +1 for aggregated histogram
  settings->histo_belief =
    (struct double_histo_list **) MMmalloc ((class_num + 2) *
					    sizeof (struct double_histo_list
						    *),
					    "struct bayes_settings: histo_belief");
  // +1 for MAX histogram    
#endif // BAYES_BELIEF_HISTO

  //===================================================================================
  //  pass2: read and store CLASS_NAMES, CLASS_WEIGHT
  //-----------------------------------------------------------------------------------
  if (!(conf = fopen (config_file, "r")))
    {
      fprintf (fp_stderr, "%s: file open error.\n", config_file);
      fprintf (fp_stderr, "%s\n", strerror(errno));
      exit (1);
    }

  class_num = 0;
  config_line = 0;
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

      if (BAYES_DBG (1))
	fprintf (fp_stderr, "BAYES: config[%d]='%s ...'\n", config_line,
		 keyword);

      if (!strcmp (keyword, "WINDOW_SIZE") ||
	  !strcmp (keyword, "AUTO_OTHER") ||
	  !strcmp (keyword, "MIN_THRESHOLD") ||
	  !strcmp (keyword, "WIN_THRESHOLD") ||
	  !strcmp (keyword, "PRC_THRESHOLD") ||
	  !strcmp (keyword, "AVG_THRESHOLD") ||
	  !strcmp (keyword, "CLASS_LEN") ||
	  !strcmp (keyword, "NORMALIZE") ||
	  !strcmp (keyword, "FEATURE") || !strcmp (keyword, "USE_LOG"))
	{
	  // already parsed
	  fscanf (conf, "%s", arg1);
	}
      else if (!strcmp (keyword, "DISCRETE"))
	{
	  // DISCRETE class P{class} 
	  settings->class_type[class_num] = BAYES_DISCRETE;

	  fscanf (conf, "%s", arg1);
	  settings->class_name[class_num] = strdup (arg1);

	  fscanf (conf, "%s", arg2);
	  settings->class_weight[class_num] = (!strcmp (arg2, "=")) ?
	    1.0 / (double) settings->class_num : atof (arg2);

	  class_num++;

	}
      else if (!strcmp (keyword, "GAUSSIAN"))
	{
	  // GAUSSIAN class P{class} N m1 s1
	  settings->class_type[class_num] = BAYES_GAUSSIAN;

	  fscanf (conf, "%s", arg1);
	  settings->class_name[class_num] = strdup (arg1);

	  fscanf (conf, "%s", arg2);
	  settings->class_weight[class_num] = (!strcmp (arg2, "=")) ?
	    1.0 / (double) settings->class_num : atof (arg2);

	  settings->class_gpdf[class_num].n = 1;

	  settings->class_gpdf[class_num].w =
	    (double *) MMmalloc (sizeof (double),
				 "bayes_settings.class_gpdf.w");
	  settings->class_gpdf[class_num].w[0] = 1.0;

	  fscanf (conf, "%s", arg2);
	  settings->class_gpdf[class_num].m =
	    (double *) MMmalloc (sizeof (double),
				 "bayes_settings.class_gpdf.m");
	  settings->class_gpdf[class_num].m[0] = atof (arg2);

	  fscanf (conf, "%s", arg2);
	  settings->class_gpdf[class_num].s =
	    (double *) MMmalloc (sizeof (double),
				 "bayes_settings.class_gpdf.s");
	  settings->class_gpdf[class_num].s[0] = atof (arg2);

	  class_num++;

	}
      else if (!strcmp (keyword, "GAUSSIAN+"))
	{
	  // GAUSSIAN+ class P{class} N (w1,m1,s1) .. (wN,mN,sN)
	  char weight[128], mu[128], sigma[128];
	  int num;
	  settings->class_type[class_num] = BAYES_GAUSSIAN;

	  fscanf (conf, "%s", arg1);
	  settings->class_name[class_num] = strdup (arg1);
	  if (BAYES_DBG (1))
	    fprintf (fp_stderr, "GAUSS: class_name %s\n", arg1);

	  fscanf (conf, "%s", arg2);
	  settings->class_weight[class_num] = atof (arg2);
	  if (BAYES_DBG (1))
	    fprintf (fp_stderr, "GAUSS: class_w %s\n", arg2);

	  fscanf (conf, "%s", arg2);
	  num = atoi (arg2);
	  if (BAYES_DBG (1))
	    fprintf (fp_stderr, "GAUSS: num_gauss %s %d\n", arg2, num);

	  settings->class_gpdf[class_num].n = num;
	  settings->class_gpdf[class_num].w =
	    (double *) MMmalloc (num * sizeof (double),
				 "bayes_settings.class_gpdf.w");
	  settings->class_gpdf[class_num].s =
	    (double *) MMmalloc (num * sizeof (double),
				 "bayes_settings.class_gpdf.s");
	  settings->class_gpdf[class_num].m =
	    (double *) MMmalloc (num * sizeof (double),
				 "bayes_settings.class_gpdf.m");

	  for (i = 0; i < num; i++)
	    {
	      ch = getc (conf);	// first parens
	      ch = getc (conf);	// first parens
	      fscanf (conf, "%s %s %s", weight, mu, sigma);
	      sigma[strlen (sigma) - 1] = ' ';	// AWFUL trick to get rid of last parens
	      settings->class_gpdf[class_num].w[i] = atof (weight);
	      settings->class_gpdf[class_num].s[i] = atof (sigma);
	      settings->class_gpdf[class_num].m[i] = atof (mu);

	      if (BAYES_DBG (1))
		fprintf (fp_stderr,
			 "GAUSS: g[%d/%d] = (%s %s %s) -> (%f,%f,%f)\n", i,
			 settings->class_gpdf[class_num].n, weight, mu, sigma,
			 settings->class_gpdf[class_num].w[i],
			 settings->class_gpdf[class_num].m[i],
			 settings->class_gpdf[class_num].s[i]);
	    }
	  class_num++;

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


  double Pcheck = 0.0;
  for (class_num = 0; class_num < settings->class_num; class_num++)
    Pcheck += settings->class_weight[class_num];

  if (settings->auto_other)
    {
      settings->class_name[settings->class_num - 1] = strdup ("AUTO_OTHER");
      settings->class_type[settings->class_num - 1] = BAYES_DISCRETE;
      settings->class_weight[settings->class_num - 1] = 1 - Pcheck;
    }
  else if (Pcheck < 1 && (BAYES_DBG (0)))
    {
      fprintf (fp_stderr, "BAYES: sum P{class} = %g < 1\n", 1.0 - Pcheck);
    }

  //===================================================================================
  //  pass3: read and check FEATURES
  //-----------------------------------------------------------------------------------
  char *path = strdup (config_file);
  char *dir = strdup (dirname (path));
  int class_len = 0;
  for (class_num = 0; class_num < settings->class_num - settings->auto_other;
       class_num++)
    {
      if (settings->class_type[class_num] == BAYES_DISCRETE)
	{
	  sprintf (buf, "%s/%s.DAT", dir, settings->class_name[class_num]);

	  settings->class_dpdf[class_num] =
	    (double *) bayes_file2vec (buf,
				       &settings->class_dlen[class_num],
				       settings->min_threshold,
				       settings->use_log);

	  settings->class_len =
	    (settings->class_len <
	     settings->class_dlen[class_num]) ? settings->
	    class_dlen[class_num] : settings->class_len;
	}
    }
  class_len = settings->class_len;

  if (settings->win_threshold > 0)
    {
      settings->win_threshold = log10 (class_len) / settings->window_size + 3;
      settings->avg_threshold = log10 (class_len) / settings->window_size + 3;
    }

  for (class_num = 0; class_num < settings->class_num - settings->auto_other;
       class_num++)
    {
      if (settings->class_type[class_num] == BAYES_GAUSSIAN)
	{
	  if (BAYES_DBG (0))
	    fprintf (debugf, "Creating GAUSSIAN mixture <%s/%s.GAUSS>\n", dir,
		     settings->class_name[class_num]);

	  int i;
	  FILE *fp;
	  sprintf (buf, "%s/%s.GAUSS", dir, settings->class_name[class_num]);
	  fp = fopen (buf, "w");
	  for (i = 0; i < class_len; i++)
	    fprintf (fp, "%e\n", bayes_eval_pdf (settings, class_num, i));
	  fclose (fp);
	}
    }

#if BAYES_BELIEF_HISTO
  for (class_num = 0; class_num < settings->class_num; class_num++)
    {
      if (BAYES_DBG (0))
	fprintf (debugf, "Creating histograms of class <%s>\n",
		 settings->class_name[class_num]);

      sprintf (buf, "%sbelief.%s.%s", prefix_string,
	       settings->feature_name, settings->class_name[class_num]);
      settings->histo_belief[class_num] = create_histo (buf,
							"10x Rescaled Bayes Belief ",
							-200, 0.0, 1);

      sprintf (buf, "%sargmax.%s.%s", prefix_string,
	       settings->feature_name, settings->class_name[class_num]);
      settings->histo_argmax[class_num] = create_histo (buf,
							"Belief Argmax Percentage",
							0, 100, 1);
    }
  sprintf (buf, "%sbelief.%s.MAX", prefix_string, settings->feature_name);
  settings->histo_belief[settings->class_num] = create_histo (buf,
							      "10x Rescaled Bayes Belief",
							      -200, 0.0, 1);

  sprintf (buf, "%sargmax.%s.ALL", prefix_string, settings->feature_name);
  settings->histo_argmax[settings->class_num] = create_histo (buf,
							      "Belief Argmax Percentage",
							      0, 100, 1);
#endif // BAYES_BELIEF_HISTO

//===================================================================================
// automatic generated complementary class
//-----------------------------------------------------------------------------------
// given #C classes Ci having feature's X distribution P{X|Ci}
// I define a complementary class !C such that 
//    
//      P{X|!C} = [ max(\sum_i P{X|Ci}) - \sum_i P{X|Ci} ] / Const,
// where 
//      Const = 1 / (support(X)*max(\sum_i P{X|Ci}) - #C)
//
//-----------------------------------------------------------------------------------

  if (settings->auto_other)
    {
      FILE *fp;

      int class_other = settings->class_num - 1;
      settings->class_dlen[class_other] =
	settings->class_dlen[class_other - 1];
      settings->class_dpdf[class_other] =
	(double *) MMmalloc (settings->class_dlen[class_other] *
			     sizeof (double), "bayes_settings: auto_other");

      sprintf (buf, "%s/%s.DAT", dir, "autoclass");
      fp = fopen (buf, "w");

      double xmax = 0.0, sum = 0.0;
      for (i = 0; i < settings->class_dlen[class_other]; i++)
	{
	  double x = 0.0;
	  for (class_num = 0;
	       class_num < settings->class_num - settings->auto_other;
	       class_num++)
	    x += settings->class_dpdf[class_num][i] / (class_other - 1);

	  xmax = max (xmax, x);
	  settings->class_dpdf[class_num][i] = -x;
	}
      xmax += settings->min_threshold;	// avoid log( 0 );

      for (i = 0; i < settings->class_dlen[class_other]; i++)
	{
	  settings->class_dpdf[class_num][i] += xmax;
	  sum += settings->class_dpdf[class_num][i];
	}

      for (i = 0; i < settings->class_dlen[class_other]; i++)
	{
	  settings->class_dpdf[class_num][i] /= sum;
	}

      // imposing minimum threshold 
      sum = 0.0;
      for (i = 0; i < settings->class_dlen[class_other]; i++)
	{
	  settings->class_dpdf[class_num][i] =
	    max (settings->min_threshold, settings->class_dpdf[class_num][i]);
	  sum += settings->class_dpdf[class_num][i];
	}

      // renormalizing
      for (i = 0; i < settings->class_dlen[class_other]; i++)
	{
	  settings->class_dpdf[class_num][i] /= sum;
	  fprintf (fp, "%e\n", settings->class_dpdf[class_num][i]);
	}
      fclose (fp);
    }


  if (BAYES_DBG (0))
    {
      bayes_check (settings, stderr);
      fprintf (fp_stderr,
	       "\rBAYES: config file succesfully parsed (I can't believe it!)\n");
    }

  return settings;
}



/* 
    ____________________________  
   /				\ 
  / new/done classifier ________/ 
  \__________________/.:nonsns:.  
 				  
*/
long bayes_new_count = 0;

struct bayes_classifier *
bayes_new (struct bayes_settings *settings)
{
  struct bayes_classifier *classifier;

#ifdef MEMDEBUG
  bayes_new_count++;
#endif // MEMDEBUG
  classifier =
    (struct bayes_classifier *) MMmalloc (sizeof (struct bayes_classifier),
					  "struct bayes_classifier");

  classifier->settings = settings;

  if (BAYES_DBG (2))
    fprintf (fp_stderr, "bc->settings[%p] = %s\n", settings, settings->name);

  classifier->belief =
    (double *) MMmalloc ((settings->class_num + 1) * sizeof (double),
			 "struct bayes_classifier: belief");
  classifier->mean_belief =
    (double *) MMmalloc (settings->class_num * sizeof (double),
			 "struct bayes_classifier: mean_belief");
  classifier->argmax_count =
    (int *) MMmalloc (settings->class_num * sizeof (int),
		      "struct bayes_classifier: argmax_count");

  bayes_reset (classifier, BAYES_RESET_ZERO);
  return classifier;
}


void
bayes_done (struct bayes_classifier *classifier)
{
  free (classifier->belief);
  free (classifier->mean_belief);
  free (classifier);
}



//===================================================================================
// @v = map { chomp } `cat $fname` #but C is stubborn                                                                             
//-----------------------------------------------------------------------------------
double *
bayes_file2vec (const char *fname, int *len, double min_th, Bool use_log)
{
  FILE *f;
  double *vec;
  char buf[64], ch;
  int i;
  size_t size = 0;

  if (BAYES_DBG (0))
    fprintf (debugf, "BAYES: file2vec (%s)\n", fname);

  //===================================================================================
  //  pass1: estimate size
  //-----------------------------------------------------------------------------------
  if (!(f = fopen (fname, "r")))
    {
      fprintf (fp_stderr, "%s: file open error.\n", fname);
      fprintf (fp_stderr, "%s\n", strerror(errno));
      exit (1);
    }


  while (!feof (f))
    {
      if ((ch = getc (f)) == EOL)
	continue;
      if (ch == '#')
	{
	  while ((ch = getc (f)) != EOL);
	  continue;
	}
      else
	{
	  if (feof (f))
	    break;
	  ungetc (ch, f);
	}
      fscanf (f, "%s\n", buf);
      size++;
    }

  //===================================================================================
  //  pass2: allocate and load
  //-----------------------------------------------------------------------------------
  if (BAYES_DBG (1))
    fprintf (fp_stderr, "BAYES: file2vec (reading %d elements)\n", size);

  vec = (double *) MMmalloc (size * sizeof (double), "file2vec");

  rewind (f);

  size = 0;
  double check = 0.0;
  while (!feof (f))
    {
      if ((ch = getc (f)) == EOL)
	continue;
      if (ch == '#')
	{
	  while ((ch = getc (f)) != EOL);
	  continue;
	}
      else
	{
	  if (feof (f))
	    break;
	  ungetc (ch, f);
	}

      fscanf (f, "%s\n", buf);
      check += (vec[size] = (double) atof (buf));
      if (BAYES_DBG (2))
	fprintf (debugf, "%d = %f (%s = %f)\n ", size, vec[size], buf,
		 atof (buf));

      size++;
      fscanf (f, "\n");
    }
  fclose (f);

  if (BAYES_DBG (0))
    fprintf (debugf, "BAYES: file2vec (read %d elements)\n", size);

  if (fabs (check - 1.0) > 1e-12)
    {
      if (BAYES_DBG (0))
	{
	  fprintf (fp_stderr, "BAYES: warning, file(%s) is NOT a pdf!\n", fname);
	  fprintf (fp_stderr,
		   "BAYES: normalizing %d elements over their sum=%f\n", size,
		   check);
	}
      for (i = 0; i < size; i++)
	vec[i] /= check;
    }


  if (BAYES_DBG (0))
    fprintf (debugf, "BAYES: imposing min_th (%e)\n", min_th);

  check = 0.0;
  for (i = 0; i < size; i++)
    {
      vec[i] = max (min_th, vec[i]);
      check += vec[i];
    }
  for (i = 0; i < size; i++)
    vec[i] /= check;


  if (use_log)
    {
      if (BAYES_DBG (0))
	fprintf (debugf, "BAYES: getting log(p)\n");

      for (i = 0; i < size; i++)
	vec[i] = LOG (vec[i]);
    }

  *len = size;


  if (BAYES_DBG (0))
    {
      fprintf (debugf, "---------------------------------\n");
      char buf[512];
      sprintf (buf, "%s.CHECK", fname);
      if ((f = fopen (buf, "w")))
	{
	  for (i = 0; i < size; i++)
	    fprintf (f, "%e\n", vec[i]);
	  fclose (f);
	}
    }

  return vec;
}



/* 
    ____________________________  
   /				\ 
  /  evaluate pdf     __________/ 
  \__________________/.:nonsns:.  

   depending if discrete, gaussian or multigaussian
    				  
*/

double
bayes_eval_pdf (struct bayes_settings *settings, int class_num, int index)
{

#ifdef BAYES_SAFE
  if (class_num > settings->class_num)
    {
      fprintf (fp_stderr, "%s only has %d classes (and you asked for %d)\n",
	       settings->name, settings->class_num, class_num);
      fprintf (fp_stderr, "%s\n", strerror(errno));
      exit (1);
    }
#endif //BAYES_SAFE

  if (settings->class_type[class_num] == BAYES_DISCRETE)
    {
      if (index >= settings->class_dlen[class_num])
	{
#ifdef BAYES_SAFE
	  fprintf (fp_stderr,
		   "%s: class %d only has %d indexes (and you asked for %d)\n",
		   settings->name, settings->class_num,
		   settings->class_dlen[class_num], index);
	  fprintf (fp_stderr, "%s\n", strerror(errno));
	  exit (1);
#endif //BAYES_SAFE
          return settings->min_threshold;
	}
      return settings->class_dpdf[class_num][index];
    }

  if (settings->class_type[class_num] == BAYES_GAUSSIAN)
    {
      double p = 0.0, round;
      int i;

      for (i = 0; i < settings->class_gpdf[class_num].n; i++)
	{
	  p += settings->class_gpdf[class_num].w[i] *
	    CONST_OneOverSqrt2Pi / settings->class_gpdf[class_num].s[i] *
	    exp (-(((double) index) - settings->class_gpdf[class_num].m[i]) *
		 (((double) index) -
		  settings->class_gpdf[class_num].m[i]) / (2.0 *
							   settings->
							   class_gpdf
							   [class_num].s[i] *
							   settings->
							   class_gpdf
							   [class_num].s[i]));
	}
      round = (p < settings->min_threshold ? settings->min_threshold : p);

      return (settings->use_log ? LOG (round) : round);
    }

  return -1.0;
}






/* 
    ____________________________  
   /				\ 
  / reset classifier  __________/ 
  \__________________/.:nonsns:.  
 				  
   reset windowed estimate, or reset to 0 
   (allow classifier to be reused by other flows)

   also update histograms
*/

void
bayes_reset (struct bayes_classifier *classifier, int action)
{
  int class_num;
  if (classifier == NULL)
    return;

  if (action == BAYES_RESET_ZERO)
    {
#if BAYES_BELIEF_HISTO
      add_histo (nbc_emaxb, 10.0 * classifier->mean_max_belief);
      add_histo (nbc_validity,
		 100.0 * (double) classifier->valid_samples /
		 (double) classifier->total_samples);
#endif // BAYES_BELIEF_HISTO

      classifier->mean_max_belief = 0.0;
      classifier->window_num = 0;
      classifier->sample_num = 0;
      classifier->aboveth_counter = 0;
      classifier->argmax = -1;
      classifier->valid_samples = 0;
      classifier->total_samples = 0;
    }

  for (class_num = 0; class_num < classifier->settings->class_num;
       class_num++)
    {
      if (action == BAYES_RESET_ZERO)
	{
	  classifier->argmax_count[class_num] = 0;
	  classifier->mean_belief[class_num] = 0.0;
	}

      classifier->belief[class_num] = (classifier->settings->use_log) ?
	LOG (classifier->settings->class_weight[class_num]) :
	classifier->settings->class_weight[class_num];
    }
  classifier->sample_num = 0;
}


/* 
    ____________________________  
   /				\ 
  /   add samples     __________/ 
  \__________________/.:nonsns:.  

  add new sample to a classifier, and update belief estimates

*/

int
bayes_sample (struct bayes_classifier *classifier, int sample)
{
  int class_num;
  int class_MAX = classifier->settings->class_num;
  double class_sum = 0.0;

  if (BAYES_DBG (0))
    fprintf (fp_stderr, "bc->settings[%p].%s( sample= %d ), (s:%ld w:%ld)\n",
	     classifier->settings,
	     (classifier->settings) ? classifier->settings->name : NULL,
	     sample, classifier->sample_num, classifier->window_num);


  //===================================================================================
  // evaluate belief
  //-----------------------------------------------------------------------------------
  for (class_num = 0; class_num < classifier->settings->class_num;
       class_num++)
    {
      double pdf = bayes_eval_pdf (classifier->settings, class_num, sample);

      if (classifier->settings->use_log)
	{
	  classifier->belief[class_num] += (pdf);
	}
      else
	{
	  classifier->belief[class_num] *= (pdf);
	  class_sum += classifier->belief[class_num];
	}
    }
  if (!classifier->settings->use_log && classifier->settings->normalize)
    for (class_num = 0; class_num < classifier->settings->class_num;
	 class_num++)
      classifier->belief[class_num] /= class_sum;


  //===================================================================================
  //  decide whether to update
  //-----------------------------------------------------------------------------------
  classifier->sample_num++;
  Bool to_be_updated = abs (classifier->settings->window_size == 1) ||
    (classifier->settings->window_size > 0 &&
     (classifier->sample_num >= classifier->settings->window_size) &&
     !(classifier->sample_num % classifier->settings->window_size));

  if (!to_be_updated)
    return -1;


  //===================================================================================
  //  evaluate argmax, mean beliefs, validity percentage, ...
  //-----------------------------------------------------------------------------------
  int argmax = -1;
  double max = -INF;

  // one more window full of data
  classifier->window_num++;

  for (class_num = 0; class_num < classifier->settings->class_num;
       class_num++)
    {
      // maximum belief
      double x =
	classifier->belief[class_num] / ((double) classifier->sample_num);
      argmax = my_finite (x) && (x > max) ? class_num : argmax;
      max = my_finite (x) && (x > max) ? x : max;

      // mean beliefs
      classifier->mean_belief[class_num] +=
	(classifier->belief[class_num] / ((double) classifier->sample_num) -
	 classifier->mean_belief[class_num]) /
	((double) classifier->window_num);

    }
  classifier->belief[class_MAX] = classifier->belief[argmax];

  if (classifier->belief[argmax] > classifier->settings->win_threshold)
    {
      classifier->aboveth_counter++;
    }
  classifier->aboveth_percentage =
    (double) classifier->aboveth_counter / (double) classifier->window_num;


  // validity of the belief
  classifier->total_samples++;
  classifier->valid_samples++;
  if ((argmax == -1) || (sample > classifier->settings->class_len))
    {
      // update validity percentage and quit
      classifier->valid_samples--;
      goto RESET_AND_QUIT;
    }

  // update  mean max belief 
  classifier->mean_max_belief +=
    (classifier->belief[argmax] / ((double) classifier->sample_num) -
     classifier->mean_max_belief) / ((double) classifier->window_num);

  // count the number of times you would have classified this flow as (argmax)
  classifier->argmax_count[argmax]++;

  int flow_argmax = 0;
  for (class_num = 1; class_num < classifier->settings->class_num;
       class_num++)
    if (classifier->argmax_count[class_num] >
	classifier->argmax_count[flow_argmax])
      flow_argmax = class_num;
  classifier->argmax = flow_argmax;	// who is the argmax so far?


//===================================================================================
//  tracing and histograms                                                                                   
//-----------------------------------------------------------------------------------

//#define BAYES_TRACE_WINDOW
#ifdef BAYES_TRACE_WINDOW
  if (!strcmp (classifier->settings->feature_name, "AVGIPG"))
    {
      for (class_num = 0; class_num < classifier->settings->class_num;
	   class_num++)
	fprintf (fp_stdout,
		 class_num == argmax ? "[%-5.2f] " : class_num ==
		 argmax2nd ? "(%-5.2f) " : "%-7.2f ",
		 classifier->belief[class_num] /
		 ((double) classifier->sample_num));

      fprintf (fp_stdout, "%f %f ", classifier->mean_max_belief,
	       classifier->valid_percentage);
      fprintf (fp_stdout, "%d/%d\n", classifier->valid_samples,
	       classifier->total_samples);
    }
#endif // BAYES_TRACE_WINDOW

#if BAYES_BELIEF_HISTO
  add_histo (classifier->settings->
	     histo_belief[classifier->settings->class_num],
	     ((double) classifier->belief[argmax] /
	      ((double) classifier->sample_num) * 10.0));

  add_histo (nbc_wmaxb,
	     classifier->belief[argmax] / ((double) classifier->sample_num) *
	     10.0);

  for (class_num = 0; class_num < classifier->settings->class_num;
       class_num++)
    add_histo (classifier->settings->histo_belief[class_num],
	       ((double) classifier->belief[class_num] /
		((double) classifier->sample_num) * 10.0));

#endif // BAYES_BELIEF_HISTO



RESET_AND_QUIT:
  // update validity percentage
  classifier->valid_percentage =
    (double) classifier->valid_samples / (double) classifier->total_samples;

  if (classifier->settings->window_size > 0)
    bayes_reset (classifier, BAYES_RESET_WINDOW);

  return classifier->total_samples;
}


/* 
    ____________________________  
   /				\ 
  /   check           __________/ 
  \__________________/.:nonsns:.  

  for debug purposes  
 				  
*/

void
bayes_check (struct bayes_settings *bs, FILE * stream)
{
  int i, j;

  if (!stream)
    {
      stream = stdout;
    }
  fprintf (stream, "BayesSettings[%s] = {\n", bs->name);
  fprintf (stream,
	   "\tuse_log = %d,\n\tnormalize = %d,\n\tauto_other = %d,\n\tmin_threshold = %e,\n\twindow_size = %d,\n",
	   bs->use_log, bs->normalize, bs->auto_other, bs->min_threshold,
	   bs->window_size);
  fprintf (stream, "\tclasses[%d] = [\n ", bs->class_num);
  for (i = 0; i < bs->class_num; i++)
    {
      if (bs->class_type[i] == BAYES_DISCRETE)
	{
	  fprintf (stream,
		   "\t\tP{ %s }=%f\n\t\t   DISCRETE[%d] = [ %e .. %e ]\n",
		   bs->class_name[i], bs->class_weight[i], bs->class_dlen[i],
		   bs->class_dpdf[i][0],
		   bs->class_dpdf[i][bs->class_dlen[i] - 1]);
	}
      else if (bs->class_type[i] == BAYES_GAUSSIAN)
	{
	  fprintf (stream, "\t\tP{ %s }=%f\n\t\t   GAUSSIAN[%d] = { \n",
		   bs->class_name[i], bs->class_weight[i],
		   bs->class_gpdf[i].n);
	  for (j = 0; j < bs->class_gpdf[i].n; j++)
	    fprintf (stream, "\t\t\t(%f,%f,%f) \n",
		     bs->class_gpdf[i].w[j], bs->class_gpdf[i].m[j],
		     bs->class_gpdf[i].s[j]);
	  fprintf (stream, "\t\t},\n");
	}
      else
	{
	  fprintf (stream, "\t\tUnknown class type %s", bs->class_name[i]);
	}
    }
  fprintf (stream, "\t],\n}\n");
}


//===================================================================================
// bayes factor 
//      http://en.wikipedia.org/wiki/Bayes_factor
//
// The logarithm of K is sometimes called the weight of evidence given by x for M1 over
// M2, measured in bits, nats, or bans, according to whether the logarithm is 
// taken to base 2, base e, or base 10.
//
// A value of K > 1 means that the data indicate that M1 is more
// likely than M2 and vice versa. Note that classical hypothesis
// testing gives one hypothesis (or model) preferred status (the
// 'null hypothesis'), and only considers evidence against it.
// Harold Jeffreys gave a scale for interpretation of K:
//
//    K                 dB      Strength of evidence
//    < 1:1           < 0       Negative (supports M2)
//    1:1 to 3:1      0 to 5    Barely worth mentioning
//    3:1 to 12:1     5 to 11   Positive
//    12:1 to 150:1   11 to 22  Strong
//    > 150:1             > 22  Very strong
//
//-----------------------------------------------------------------------------------   
