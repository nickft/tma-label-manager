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
 * We all need to thank Tommy for its bright ideas :) 
 *
*/

#ifndef NAIVEBAYES_H
#define NAIVEBAYES_H


/* increase the threshold to get rid of dbg msg */
#define BAYES_PANIC 	0
#define BAYES_DBG_LEVEL 2
#define BAYES_DBG(n)  (BAYES_PANIC || (BAYES_DBG_LEVEL && debug>=BAYES_DBG_LEVEL+n))
#define BAYES_DEBUG   (BAYES_PANIC || (BAYES_DBG_LEVEL && debug>=BAYES_DBG_LEVEL))

#define BAYES_MARGIN_FACTOR_REL  2
#define BAYES_MARGIN_FACTOR_ABS  5

struct bayes_gaussian {
     int n;
     double *w, *m, *s;
} bayes_gaussian;


#define CONST_OneOverSqrt2Pi 0.398942280401433
//			     1/sqrt(2*pi)

struct bayes_settings {
     char    * name;  	
     int       id; // useless, but ...
     
     Bool      use_log;        // default Yes
     Bool      normalize;      // default Yes
     Bool      auto_other;     // default Yes
     double    min_threshold;  // default 1-e20
     int       window_size;    // default -1

     // thresholds, to compare,  over all classes at the j-th window
     double    avg_threshold;    // E[max_i(belief_i,j)] 
     double    win_threshold;    //   max_i(belief_i,j)  
     double    prc_threshold;    // P{max_i(belief_i,j)>win_th} 



     char    * feature_name;     
     int       feature;        // converted from string by void *(*feat2code)()
     int       new_line;

     int       class_num;
     int       class_len;
     char   ** class_name;
     double  * class_weight;
     double ** class_dpdf; // discrete
     int     * class_dlen; // length of dpdf vector
     struct bayes_gaussian *
     	       class_gpdf; // gaussian	 

#define BAYES_BELIEF_HISTO 0
     struct double_histo_list ** histo_belief;
     struct double_histo_list ** histo_argmax;

	       
#define BAYES_DISCRETE 0
#define BAYES_GAUSSIAN 1	        
     int     * class_type;
} bayes_settings;


// this is a single-feature  per-flow structure 
struct bayes_classifier {
     struct     bayes_settings *settings;     

     double     mean_max_belief;  // only takes into account valid (non -INF) values
     int	argmax;
     double   * belief;  	  // instantaneous values (current window)
     double   * mean_belief;  	  // per-class running average
     
     double 	aboveth_percentage; // perc. of times argmax is above win_threshold
     int	aboveth_counter;    // number of times argmax is above win_threshold
     
     double 	valid_percentage; // measured as the ratio of valid over total samples     
     int 	valid_samples;    // number of valid windows 
     int 	total_samples;	  // overall number of windows
     
     long 	sample_num;       // number of samples within the current window
     long       window_num;	  // equal to total samples when window_size=1
     				  
     int      * argmax_count;	  // number of windows ``won'' by a given class      	
     
} bayes_classifier;




struct bayes_settings   * bayes_init(char *config_file, char *prefix, void *(*feat2code)());       
struct bayes_classifier * bayes_new(struct bayes_settings *bs);
void   bayes_done(struct bayes_classifier *bc);
double bayes_eval_pdf(struct bayes_settings * settings, int class_num, int index);
int bayes_sample(struct bayes_classifier *classifier, int sample);
void bayes_reset(struct bayes_classifier *classifier, int action);


#define bayes_belief(bc, class) \
	( bc->belief[class] )
	
#define bayes_mean_belief(bc, class) \
	( bc->mean_belief[class] )


#define BAYES_RESET_ZERO	0
#define BAYES_RESET_WINDOW	1
#define bayes_reset0(bc) \
		bayes_reset( ((bc)), BAYES_RESET_ZERO) 


 
#endif





