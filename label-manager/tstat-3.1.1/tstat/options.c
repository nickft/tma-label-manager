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
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

u_int32_t http_full_url = 0;
extern int log_level;
extern int video_level;
extern Bool force_create_new_outfiles;
extern Bool strict_privacy;

static int old_tcplog_level;
static int old_videolog_level;
static int old_http_full_url;

void options_parse_start_section(void) {
    extern int globals_set;

    if (globals_set!=0)
     {
       fprintf(fp_stderr,"ini reader: [options] section only valid in the runtime configuration context\n");
       exit(1);
     }

    old_tcplog_level = log_level;
    old_videolog_level = video_level;
    old_http_full_url = http_full_url;
}

char *log_level_to_str(int level)
{
  static char log_level_text[80];

  strcpy(log_level_text,"Core");
  
  if (level & TCP_LOG_END_TO_END)
    strcat (log_level_text," + End_to_end");

  if (level & TCP_LOG_LAYER7)
    strcat (log_level_text," + Layer7");

  if (level & TCP_LOG_P2P)
    strcat (log_level_text," + P2P");

  if (level & TCP_LOG_OPTIONS)
    strcat (log_level_text," + Options");

  if (level & TCP_LOG_ADVANCED)
    strcat (log_level_text," + Advanced");

  return log_level_text;
}

char *video_level_to_str(int level)
{
  static char log_level_text[100];

  strcpy(log_level_text,"Core");
  
  if (level & VIDEO_LOG_END_TO_END)
    strcat (log_level_text," + End_to_end");

  if (level & VIDEO_LOG_LAYER7)
    strcat (log_level_text," + Layer7");

  if (level & VIDEO_LOG_VIDEOINFO)
    strcat (log_level_text," + VideoInfo");

  if (level & VIDEO_LOG_YOUTUBE)
    strcat (log_level_text," + YouTube");

  if (level & VIDEO_LOG_OPTIONS)
    strcat (log_level_text," + Options");

  if (level & VIDEO_LOG_ADVANCED)
    strcat (log_level_text," + Advanced");

  return log_level_text;
}

void options_parse_end_section(void) {

    if (old_tcplog_level != log_level || current_time.tv_sec == 0) {
        fprintf(fp_stdout, "[%s] TCP log level set to %d (%s)\n", 
            Timestamp(), log_level, log_level_to_str(log_level));
    }

    if (old_tcplog_level != log_level) {
        force_create_new_outfiles = TRUE;
    }
   old_tcplog_level = log_level;

    if (old_videolog_level != video_level || current_time.tv_sec == 0) {
        fprintf(fp_stdout, "[%s] Video log level set to %d (%s)\n", 
            Timestamp(), video_level,video_level_to_str(video_level));
    }

    if (old_videolog_level != video_level) {
        force_create_new_outfiles = TRUE;
    }
   old_videolog_level = log_level;


    if (old_http_full_url != http_full_url ) {
        fprintf(fp_stdout, "(%s) %s HTTP URL log\n", 
            Timestamp(), (http_full_url==0) ? "Disabling" : 
                         ((http_full_url==1) ? "Enabling partial" : "Enabling full"));
    }

    if (old_http_full_url != http_full_url) {
        force_create_new_outfiles = TRUE;
    }
   old_http_full_url = http_full_url;

}

void options_parse_ini_arg(char *param_name, param_value param_value) {

    //check protocol name 
    if (strcmp(param_name, "tcplog_end_to_end") == 0)
     {
       if (param_value.value.ivalue >= 0) 
         {
            if (param_value.value.ivalue) 
              log_level |= TCP_LOG_END_TO_END;
            else
              log_level &= ~TCP_LOG_END_TO_END; 
         }
       else
        {
            fprintf(fp_stderr, "runtime conf: warning: '%s = %d' Invalid value ignored\n", 
                param_name, param_value.value.ivalue);
        }
     }
    else if (strcmp(param_name, "tcplog_layer7") == 0)
     {
       if (param_value.value.ivalue >= 0) 
         {
            if (param_value.value.ivalue) 
              log_level |= TCP_LOG_LAYER7;
            else
              log_level &= ~TCP_LOG_LAYER7; 
         }
       else
        {
            fprintf(fp_stderr, "runtime conf: warning: '%s = %d' Invalid value ignored\n", 
                param_name, param_value.value.ivalue);
        }
     }
    else if (strcmp(param_name, "tcplog_p2p") == 0)
     {
       if (param_value.value.ivalue >= 0) 
         {
            if (param_value.value.ivalue) 
              log_level |= TCP_LOG_P2P;
            else
              log_level &= ~TCP_LOG_P2P; 
         }
       else
        {
            fprintf(fp_stderr, "runtime conf: warning: '%s = %d' Invalid value ignored\n", 
                param_name, param_value.value.ivalue);
        }
     }
    else if (strcmp(param_name, "tcplog_options") == 0)
     {
       if (param_value.value.ivalue >= 0) 
         {
            if (param_value.value.ivalue) 
              log_level |= TCP_LOG_OPTIONS;
            else
              log_level &= ~TCP_LOG_OPTIONS; 
         }
       else
        {
            fprintf(fp_stderr, "runtime conf: warning: '%s = %d' Invalid value ignored\n", 
                param_name, param_value.value.ivalue);
        }
     }
    else if (strcmp(param_name, "tcplog_advanced") == 0)
     {
       if (param_value.value.ivalue >= 0) 
         {
            if (param_value.value.ivalue) 
              log_level |= TCP_LOG_ADVANCED;
            else
              log_level &= ~TCP_LOG_ADVANCED; 
         }
       else
        {
            fprintf(fp_stderr, "runtime conf: warning: '%s = %d' Invalid value ignored\n", 
                param_name, param_value.value.ivalue);
        }
     }
    else if (strcmp(param_name, "videolog_end_to_end") == 0)
     {
       if (param_value.value.ivalue >= 0) 
         {
            if (param_value.value.ivalue) 
              video_level |= VIDEO_LOG_END_TO_END;
            else
              video_level &= ~VIDEO_LOG_END_TO_END; 
         }
       else
        {
            fprintf(fp_stderr, "runtime conf: warning: '%s = %d' Invalid value ignored\n", 
                param_name, param_value.value.ivalue);
        }
     }
    else if (strcmp(param_name, "videolog_layer7") == 0)
     {
       if (param_value.value.ivalue >= 0) 
         {
            if (param_value.value.ivalue) 
              video_level |= VIDEO_LOG_LAYER7;
            else
              video_level &= ~VIDEO_LOG_LAYER7; 
         }
       else
        {
            fprintf(fp_stderr, "runtime conf: warning: '%s = %d' Invalid value ignored\n", 
                param_name, param_value.value.ivalue);
        }
     }
    else if (strcmp(param_name, "videolog_videoinfo") == 0)
     {
       if (param_value.value.ivalue >= 0) 
         {
            if (param_value.value.ivalue) 
              video_level |= VIDEO_LOG_VIDEOINFO;
            else
              video_level &= ~VIDEO_LOG_VIDEOINFO; 
         }
       else
        {
            fprintf(fp_stderr, "runtime conf: warning: '%s = %d' Invalid value ignored\n", 
                param_name, param_value.value.ivalue);
        }
     }
    else if (strcmp(param_name, "videolog_youtube") == 0)
     {
       if (param_value.value.ivalue >= 0) 
         {
            if (param_value.value.ivalue) 
              video_level |= VIDEO_LOG_YOUTUBE;
            else
              video_level &= ~VIDEO_LOG_YOUTUBE; 
         }
       else
        {
            fprintf(fp_stderr, "runtime conf: warning: '%s = %d' Invalid value ignored\n", 
                param_name, param_value.value.ivalue);
        }
     }
    else if (strcmp(param_name, "videolog_options") == 0)
     {
       if (param_value.value.ivalue >= 0) 
         {
            if (param_value.value.ivalue) 
              video_level |= VIDEO_LOG_OPTIONS;
            else
              video_level &= ~VIDEO_LOG_OPTIONS; 
         }
       else
        {
            fprintf(fp_stderr, "runtime conf: warning: '%s = %d' Invalid value ignored\n", 
                param_name, param_value.value.ivalue);
        }
     }
    else if (strcmp(param_name, "videolog_advanced") == 0)
     {
       if (param_value.value.ivalue >= 0) 
         {
            if (param_value.value.ivalue) 
              video_level |= VIDEO_LOG_ADVANCED;
            else
              video_level &= ~VIDEO_LOG_ADVANCED; 
         }
       else
        {
            fprintf(fp_stderr, "runtime conf: warning: '%s = %d' Invalid value ignored\n", 
                param_name, param_value.value.ivalue);
        }
     }
    else if (strcmp(param_name, "httplog_full_url") == 0) {
        if (param_value.value.ivalue >= 0 && param_value.value.ivalue<=2) {
            http_full_url = param_value.value.ivalue;
	    if ( strict_privacy && http_full_url!=0)
	    {
              fprintf(fp_stderr, "runtime conf: warning: Must be '%s = 0' while Strict Private mode is enabled\n", 
                param_name);
              fprintf(fp_stderr, "              Invalid value ignored\n");
	      http_full_url = 0;
	    }
        }
       else
        {
            fprintf(fp_stderr, "runtime conf: warning: '%s = %d' Invalid value ignored\n", 
                param_name, param_value.value.ivalue);
        }
    }

    else {
        fprintf(fp_stderr, "runtime conf err: '%s' - not valid command \n", param_name);
        exit(1);
    }
}

