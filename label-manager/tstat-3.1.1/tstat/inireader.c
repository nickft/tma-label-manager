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
#include "dump.h"
#include "options.h"
#include "globals.h"
#include <string.h>

typedef void ini_section_handler(char * param_name, param_value param_value);
typedef void ini_section_limit(void);

struct ini_section {
    char *name;
    ini_section_handler *handler;
    ini_section_limit *handler_start;
    ini_section_limit *handler_end;
};

static struct ini_section ini_sections[] = {
    {"[dump]", dump_parse_ini_arg, dump_ini_start_section, dump_ini_end_section},
    {"[log]", log_parse_ini_arg, log_parse_start_section, log_parse_end_section},
    {"[options]",options_parse_ini_arg,options_parse_start_section,options_parse_end_section},
    {"[globals]",globals_parse_ini_arg,globals_parse_start_section,globals_parse_end_section},
};
#define INI_SECTION_LEN (sizeof(ini_sections) / sizeof(struct ini_section))
#define BUF_SIZE 80
#define INI_PARAM_VALUE_DEFAULT -1000

char * readline(FILE *fp, int skip_comment, int skip_void_lines) {
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

void ini_read(char *fname) {
    FILE *fp;
    char *line, *word, *param_name;
    param_value param_value;
    int i, len;
    struct ini_section *curr_section;

    fp = fopen(fname, "r");
    if (fp == NULL) {
        fprintf (fp_stderr, "inireader: '%s' - No such file\n", fname);
        exit(1);
    }

    curr_section = NULL;
    while (1) {
        line = readline(fp, 0, 0);
        if (line == NULL)
            break;

        word = strtok(line, " \t\n");
        param_name = NULL;
        param_value.value.ivalue = INI_PARAM_VALUE_DEFAULT;
	param_value.type = INTEGER;
        while(word != NULL) {
            //skip comments and void lines
            if (word[0] == '#' || word[0] == '\0')
                break;
           
            //search for the handler related to the current section
            if (word[0] == '[') { 
                //look if the previous section has an end handler
                if (curr_section && curr_section->handler_end) {
                    curr_section->handler_end();
                }

                curr_section = NULL;
                for (i = 0; i < INI_SECTION_LEN; i++) {
                    if (strcasecmp(word, ini_sections[i].name) == 0)
                        break;
                }
                if (i == INI_SECTION_LEN) {
                    fprintf (fp_stderr, "inireader: '%s' - syntax error\n", word);
                    exit(1);
                }
                curr_section = &ini_sections[i];
                if (curr_section->handler_start) {
                    curr_section->handler_start();
                    break;
                }
            }
            //parse section parameter and call handler
            else if (word[0] != '=') {
                if (!param_name)
                    param_name = word;
                else if (param_value.value.ivalue == INI_PARAM_VALUE_DEFAULT) {
                    len = strlen(word);
                    if (len>2 && word[0]=='0' && tolower(word[1])=='x')
                     {
                       for (i = 2; i < len && isxdigit(word[i]); i++)
                        ;
                       if (i != len) {
                         fprintf (fp_stderr, "inireader: '%s' - syntax error\n", word);
                         exit(1);
                        }
                       sscanf(word,"%x",&param_value.value.ivalue);
                     }
                    else
                     {
		      int floating = 0;
                      for (i = 0; i < len && ( isdigit(word[i]) || word[i]=='.' ); i++)
		       {
			 if (word[i]=='.') floating++;
		       }
		       
                      if (i != len || floating>1) {
                        fprintf (fp_stderr, "inireader: '%s' - syntax error\n", word);
                        exit(1);
                       }
                      if (floating==1)
		       {
			 param_value.type = DOUBLE;
			 param_value.value.dvalue = atof(word);
                       }
                      else
		       {
			 param_value.type = INTEGER;
                         param_value.value.ivalue = atoi(word);
		       }
		     }
                }
                else {
                    fprintf (fp_stderr, "inireader: '%s' - syntax error\n", word);
                    exit(1);
                }

            }
            word = strtok(NULL, " \t\n");
        }

        if (curr_section && 
            curr_section->handler != NULL && 
            param_name != NULL) 
        {
            if (param_value.value.ivalue == INI_PARAM_VALUE_DEFAULT)
                param_value.value.ivalue = 1;
            curr_section->handler(param_name, param_value);
        }
    }

    if (curr_section && curr_section->handler_end) {
        curr_section->handler_end();
    }
    else if (curr_section==NULL) {
        fprintf (fp_stderr, "inireader: warning - No section header in file '%s' - File ignored\n", fname);
    }

    fclose(fp);
}

