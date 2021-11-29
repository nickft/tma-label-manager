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

/* Here you find the parameters which can be modified to tune Tstat
   performance and/or histogram creation periods */

/* Param dealing with the address hit counters */
#define MAX_ADX_SLOTS 70001	/* hash size for the ip addresses hit counter */
#define ADDR_MASK 0x00ffffff	/* mask to count IP addresses - inet order */
#define ADDR2_MASK 0x00ffffff	/* mask to count internal IP addresses bitrate - inet order */

/* Max number of ethernet MACs to check if the frame is incoming or outgoing */
#define MAX_INTERNAL_ETHERS  20

/* Max number of nets to check if ip is internal or external */
#define MAX_INTERNAL_HOSTS  100
#define MAX_CLOUD_HOSTS  100
#define MAX_CRYPTO_HOSTS  40
#define MAX_WHITE_HOSTS  100

/*
* Maximum number of segment recorded for each quadrant of a flow;
* setting this too small will affect the rexmit statistics, but leaving it
* unlimited will pose a serious scalability problem, as the ordered list
* of segments may grow too large, consuming too much memory and time when
* looking for a segment. Probably should never be necessary to store more
* than a number of segments larger than one hundred, since the
* sliding window of TCP is usually much smaller than that (except if you
* use TCP versions which allow very large windows ...)
*/
/* #define MAX_SEG_PER_QUAD -1  to track all segments */
/* #define MAX_SEG_PER_QUAD 10 for light segment tracking at high load */
#define MAX_SEG_PER_QUAD 100 /* deep segment tracking, suitable for light load */



/* TCP_IDLE_TIME in microseconds: timeout to consider a TCP flow closed if no
segments are observed since TCP_IDLE_TIME */
/* 5 min */
#define TCP_IDLE_TIME 300000000
/* 10 min */
/*#define TCP_IDLE_TIME 600000000 */

/* UDP_IDLE_TIME in microseconds: timeout to consider a UDP flow closed if no
segments are observed since UDP_IDLE_TIME */
/* 200s */
#define UDP_IDLE_TIME 200000000   /* 200 s */
//#define UDP_IDLE_TIME 10000000 /* 10s */


/* TCP_SINGLETON_TIME in microseconds: timeout to consider a TCP flow closed if 
no segments are observed for TCP_SINGLETON_TIME after the initial SYN segment 
Used only if WIPE_TCP_SINGLETON is defined
*/
#define TCP_SINGLETON_TIME 10000000   /* 10 s */

/* UDP_SINGLETON_TIME in microseconds: timeout to consider a UDP flow closed if
no segments are observed for UDP_SINGLETON_TIME after the first segment
Used only if WIPE_TCP_SINGLETON is defined
*/
#define UDP_SINGLETON_TIME 10000000   /* 10 s */

// RUNTIME_CONFIG_IDLE * RUNTIME_MTIME_COUNTER = amount of time to wait before re-load 'runtime.conf'
#define RUNTIME_CONFIG_IDLE   21.0    /* amount of time between to check of 'runtime.conf' */
#define RUNTIME_MTIME_COUNTER 3       /* no. of consecutive times 'runtime.conf' is found unchanged before re-load the file */
//#define RUNTIME_CONFIG_IDLE 1       
//#define RUNTIME_MTIME_COUNTER 1

/* Define how often garbage collection scans the whole flow table */
/* Historically, this is set to half TCP_SINGLETON_TIME */
#define GARBAGE_PERIOD (TCP_SINGLETON_TIME/2)

/* Define granularity of garbage collection splitting. 
 The flow table is not scanned in one time,
 but the workload is done in GARBAGE_SPLIT_RATIO times
 IMPORTANT: it must be a divisor of GARBAGE_PERIOD,
 MAX_TCP_PAIRS and MAX_UDP_PAIRS  */
#define GARBAGE_SPLIT_RATIO 10000

/* Define the interval for garbage collection routine to be fired */
// #define GARBAGE_FIRE_TIME (GARBAGE_PERIOD/GARBAGE_SPLIT_RATIO)  

/* maximum number of concurrent TCP connection stored in the vector TTP 
Increase this number on high speed network will help ...*/
#define MAX_TCP_PAIRS 180000
/* Each time the garbage collection is fired, it scans MAX_TCP_PAIRS_BURST tcp flows */
// #define MAX_TCP_PAIRS_BURST (MAX_TCP_PAIRS / GARBAGE_SPLIT_RATIO)

/* maximum number of concurrent UDP connection stored in the vector UTP 
Increase this number on high speed network will help ...*/
#define MAX_UDP_PAIRS 360000
/* Each time the garbage collection is fired, it scans MAX_UDP_PAIRS_BURST upd flows */
// #define MAX_UDP_PAIRS_BURST (MAX_UDP_PAIRS / GARBAGE_SPLIT_RATIO)

/* max depth of the linear serch in the previous vector... */
#define LIST_SEARCH_DEPT 200

/* connection records are stored in a hash table.  Buckets are linked	*/
/* lists sorted by most recent access.					*/
/* oughta be prime  and larger than MAX_TCP_PAIRS */
#define HASH_TABLE_SIZE 2000003

/* Histograms will be saved every MAX_TIME_STEP microseconds... 
   please, note that changing this may affect the RRD definition as well. 

   Updates will be performed at every MAX_TIME_STEP (5 minutes) both RRD
   and HISTOGRAM are updated.
   
*/
#define MAX_TIME_STEP 300000000.0     // 5min
//#define MAX_TIME_STEP 60000000.0      // 1min
//#define MAX_TIME_STEP 30000000.0      // 30sec
/* 300000000 = 5 min */
/* 900000000 = 15 min */
/* #define MAX_TIME_STEP 900000000.0 */

/* A new directory tree will be created every DIRS MAX_TIME_STEPs */
/*  4 = 1 hour if MAX_TIME_STEP = 15m */
/* 12 = 1 hour if MAX_TIME_STEP =  5m */
#define DIRS 12
//#define DIRS 1

#ifndef MAXFLOAT
#define MAXFLOAT 3.40282347e+38F
#endif

/* Euristic to detect dup TCP/UDP packets. */
/* May be useful when the original trace has some NETWORK dups*/
/* Discard tcp/udp packets with: */
/* - same IP_ID */
/* - same TCP/UDP checksum */
/* - interarrival time smaller than MIN_DELTA_T_XXX_DUP_PKT */
/* - same IP length */ 

#define MIN_DELTA_T_UDP_DUP_PKT 1000.0 /* microsec (previously 50us) */
#define CHECK_UDP_DUP
#define MIN_DELTA_T_TCP_DUP_PKT 2000.0 /* microsec (previously 50us) */
#define CHECK_TCP_DUP

/* Until Tstat 2.1 the fixed snaplen size for pcap live captures was */
/* hardcoded in tcpdump.h.                                           */
/* Now it can be selected from the command line (-E) and the default */
/* value is hardcoded here. Make large enough to keep all options.   */
/* Advanced features, like YouTube and BitTorrent characterization,  */
/* require a large snaplen, e.g. 550 bytes */
#define DEFAULT_SNAPLEN 550

/* RTP parameters */
#define RTP_WIN 16		/* sliding window size used to track RTP
				   flows. MUST BE a power of 2!!! */
#define OVERFLOW_TH 2000	/* threshold to consider rtp segment as out
				   of sequence */

/* Entropy threshold to detect encrypted flows */
#define ENTROPY_SAMPLE    60    /* Number of bytes in each packet payload 
                                   used to compute the nibble entropy */
#define ENTROPY_THRESHOLD 3.7   /* Empirically tested that nibble entropy 
                                   over about 100 random samples is larger
				   than 3.7 with 99% probability */

/* Secondary address histogram sample rate */
#define ADX2_BITRATE_DELTA 60   /* 60 sec */
#define ADX2_MAX_DELTA      1   /*  1 sec */

#define RATE_SAMPLING 1000000   /* 1 sec */

#define MAX_CRYPTO_CACHE_SIZE 130000  /* Enough to maintain an entry in the
                                         LRU cache for a few hours */
/* Size of the DNS cache */
#define DNS_CACHE_SIZE 100000   /* 500,000 used on large probes */
#ifdef SUPPORT_IPV6
#define DNS_CACHE_SIZE_IPV6 1000   /* possibly a small cache  */
#endif