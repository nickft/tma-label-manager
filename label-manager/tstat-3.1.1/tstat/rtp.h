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
#ifndef RTP_H
#define RTP_H


#include <sys/param.h>
#include <sys/time.h>

#ifdef __ANDROID__
#include <sys/endian.h>
#undef swap16
#undef swap32
#endif

#define VALID_VERSION 2		/*the version must be 2 */
#define VALID_PT      127	/* the PT must be equal or smaller than  127 */

#define RTCP_MAX_PT  204	/* maximum value of PT for the RTCP packet */
#define RTCP_MIN_PT  200	/* minimum value of PT for the RTCP packet */

/* RTCP error codes */
#define NO_ERROR 0
#define E_TRUNCATED 1 		/* RTCP header is truncated */
#define E_TOOMANYRR 2 		/* Too many reports (tstat currently manages only 1 RR */

/* RTP standard content encodings for video */
#define RTP_PT_BVC		22	/* Berkeley video codec */

#define RTP_PT_RGB8		23	/* 8-bit dithered RGB */
#define RTP_PT_HDCC		24	/* SGI proprietary */
#define RTP_PT_CELLB		25	/* Sun CellB */
#define RTP_PT_JPEG		26	/* JPEG */
#define RTP_PT_CUSEEME		27	/* Cornell CU-SeeMe */
#define RTP_PT_NV		28	/* Xerox PARC nv */
#define RTP_PT_PICW		29	/* BB&N PictureWindow */
#define RTP_PT_CPV		30	/* Concept/Bolter/Viewpoint codec */
#define RTP_PT_H261		31	/* ITU H.261 */
#define RTP_PT_MPEG		32	/* MPEG-I & MPEG-II */
#define RTP_PT_MP2T		33	/* MPEG-II either audio or video */

#define RTP_PT_H261_COMPAT 127

/* RTP standard content encodings for audio */
#define RTP_PT_PCMU		0
#define RTP_PT_CELP		1
#define RTP_PT_G711		2
#define RTP_PT_GSM		3
#define RTP_PT_G723		4
#define RTP_PT_DVI4_8000	5
#define RTP_PT_DVI4_16000	6
#define RTP_PT_LPC		7
#define RTP_PT_PCMA		8
#define RTP_PT_G722		9
#define RTP_PT_L16_2		10
#define RTP_PT_L16_1		11
#define RTP_PT_QCELP		12
#define RTP_PT_CN		13
#define RTP_PT_MPA		14
#define RTP_PT_G728		15
#define RTP_PT_DVI4_11025	16
#define RTP_PT_DVI4_22050	17
#define RTP_PT_G729		18

/* topix */
#define UNKNOWN_RTP_PAYLOAD_TYPE 128
/* end topix */

#define RTP_LITTLE_ENDIAN 1

struct rtphdr
{
#if RTP_BIG_ENDIAN
  unsigned int v:2;		/* protocol version */
  unsigned int p:1;		/* padding flag */
  unsigned int x:1;		/* header extension flag */
  unsigned int cc:4;		/* CSRC count */
  unsigned int m:1;		/* marker bit */
  unsigned int pt:7;		/* payload type */
#elif RTP_LITTLE_ENDIAN
  unsigned int cc:4;		/* CSRC count */
  unsigned int x:1;		/* header extension flag */
  unsigned int p:1;		/* padding flag */
  unsigned int v:2;		/* protocol version */
  unsigned int pt:7;		/* payload type */
  unsigned int m:1;		/* marker bit */
#else
#error Define one of RTP_LITTLE_ENDIAN or RTP_BIG_ENDIAN
#endif
  u_int16_t seqno;		/* sequence number */
  u_int32_t ts;			/* timestamp */
  u_int32_t ssrc;		/* synchronization source */

};
typedef struct rtphdr rtphdr;

struct rtcp_SR
{
  u_int64_t ntp_ts;
  u_int32_t rtp_ts;
  u_int32_t tx_p;
  u_int32_t tx_b;
};

struct rtcp_RR
{
  u_int32_t ssrc;
#if RTP_BIG_ENDIAN
  u_int32_t c_lost:24;
  u_int32_t f_lost:8;
#else
  u_int32_t f_lost:8;
  u_int32_t c_lost:24;
#endif
  u_int32_t max_seqno_rx;
  u_int32_t jitter;
  u_int32_t lsr;
  u_int32_t dlsr;
};

/* functions prototypes for proto_register */

struct rtphdr *getrtp (struct udphdr *pudp, int tproto, void *prtp,
		       void *plast);
void rtp_flow_stat (struct ip *pip, void *pproto, int tproto, void *pdir,
		    int dir, void *hdr, void *last);

// oldstlyle:
//      void rtpdotrace (ucb * thisdir, struct rtphdr *prtp, int dir, struct ip *pip);


void init_rtp (ucb * thisdir, int dir, struct udphdr *pudp,
	       struct rtphdr *prtp, void *plast);
void rtp_check (ucb * thisdir, struct rtphdr *prtp, int dir, struct ip *pip, void *plast);
void rtcp_check (ucb * thisdir, int dir, struct rtphdr *prtp, void *plast);
void rtp_stat (ucb * thisdir, struct rtp *f_rtp, struct rtphdr *prtp, int dir,
	       struct ip *pip, void *plast);
void rtcp_stat (ucb * thisdir, int dir, struct rtphdr *prtp, void *plast);
void make_rtp_conn_stats (void * thisdir, int tproto);

u_int16_t swap16 (u_int16_t val);
u_int32_t swap32 (u_int32_t val);
int32_t swap24 (u_int32_t val);
int det_freq (struct rtphdr *prtp);


#endif
