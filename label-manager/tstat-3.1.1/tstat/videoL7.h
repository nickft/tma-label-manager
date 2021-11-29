/*
 *
 * Copyright (c) 2001-2008
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

#ifndef _VIDEOL7_H_
#define _VIDEOL7_H_

#include <sys/types.h>

/* Number of maximum packets inspected
 * in order to classify a flow as video   */
#define MAX_HTTP_STREAMING_DEPTH 5

#define HINIBBLE(b) (((b) >> 4) & 0x0F)
#define LONIBBLE(b) ((b) & 0x0F)

/* Keyword definitions for fast compare */
/* considering both byte orders         */

#if(BYTE_ORDER == BIG_ENDIAN)

/*Flash header*/
#define VL7_FLV  	0x464C5601UL
#define VL7_FLV2  	0x1200034BUL

/* AVI header */
#define AVI  		0x53494646UL

/* WEBM header */
#define WEBM  		0x1A45DFA3UL

/* ASF header */
#define WMV_1  		0x3026B275UL
#define WMV_2  		0xA6D900AAUL


/* MPEG header */
#define MPEG  		0x000001B3UL

/* OGG header */
#define OGG  		0x4F676753FUL

#else

/*Flash header*/
#define VL7_FLV  	0x01564C46UL
#define VL7_FLV2  	0x4B030012UL

/* AVI header */
#define AVI  		0x46464952UL

/* WEBM header */
#define WEBM  		0xA3DF451AUL

/* ASF header */
#define WMV_1  		0x75B22630UL
#define WMV_2  		0xAA00D9A6UL

/* OGG header */
#define OGG  		0x5367674FUL


#endif
/* end Keyword definitions */

#endif
