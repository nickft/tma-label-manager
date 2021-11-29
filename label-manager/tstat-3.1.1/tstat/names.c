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
 * name.c -- name binding stuff
 * 
 * Author:	Shawn Ostermann
 * Date:	Tue Nov  1, 1994
 */

#include "tstat.h"
#include <stdarg.h>


/* local routines */


char *
ServiceName (portnum port)
{
  static char port_buf[6];

  sprintf (port_buf, "%hu", port);
  return (port_buf);
}


/* turn an ipaddr into a printable format */
/* N.B. - result comes from static memory, save it before calling back! */
char *
HostAddr (ipaddr ipaddress)
{
  char *adr;

#ifdef SUPPORT_IPV6
  if (ADDR_ISV6 (&ipaddress))
    {
      static char adrv6[INET6_ADDRSTRLEN];
      my_inet_ntop (AF_INET6, (char *) ipaddress.un.ip6.s6_addr,
		    adrv6, INET6_ADDRSTRLEN);
      adr = adrv6;
    }
  else
#endif
    adr = inet_ntoa (ipaddress.un.ip4);

  return (adr);
}



char *
HostName (ipaddr ipaddress)
{
  char *adr;

  adr = HostAddr (ipaddress);
  return (adr);
}

char *
Timestamp (void) {
    static timeval last_time;
    static char * last_time_string;

    if (current_time.tv_sec == last_time.tv_sec && 
        current_time.tv_usec == last_time.tv_usec && 
        current_time.tv_sec != 0 &&
        current_time.tv_sec != -1)
        return last_time_string;
    last_time = current_time;
    if (last_time.tv_sec == 0 || last_time.tv_sec == -1)
        last_time_string = "-";
    else {
        last_time_string = ctime(&current_time.tv_sec);
        last_time_string[strlen(last_time_string) - 1] = '\0';
    }
    return last_time_string;
}

static char *buf = NULL;
static int buf_size = 0;
#define BUFFER_SIZE 80

char * sprintf_safe(const char *format, ...) {
    va_list ap;
    int n;

    //first allocation
    if (!buf) {
        buf_size += BUFFER_SIZE;
        buf = MMmalloc(buf_size * sizeof(char), "sprintf_safe");
    }

    while(1) {
        buf[0] = '\0';

        // write into the buffer safely
        va_start(ap, format);
        n = vsnprintf(buf, buf_size, format, ap);
        va_end(ap);
        if (n < buf_size) 
            break;
        
        // if the buffer is full (because there isn't enough space
        // or is dimension is exactly the same as required) 
        // the buffer is exanded and a rewrited
        free(buf);
        buf_size += BUFFER_SIZE;
        buf = MMmalloc(buf_size * sizeof(char), "sprintf_safe");
        //printf("realloc: %d\n", buf_size);
    }
    //printf("%s\n", buf);
    return buf;
}
