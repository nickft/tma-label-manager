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

/* we want LONG LONG in some places */
#if SIZEOF_UNSIGNED_LONG_LONG_INT >= 8
#define HAVE_LONG_LONG
typedef unsigned long long int u_llong;
typedef long long int llong;
#else /* LONG LONG */
typedef unsigned long int u_llong;
typedef long int llong;
#endif /* LONG LONG */

/* type for a TCP sequence number, ACK, FIN, or SYN */
typedef u_int32_t seqnum;

/* length of a segment */
typedef u_long seglen;

/* type for a quadrant number */
typedef u_char quadnum;		/* 1,2,3,4 */

/* type for a TCP port number */
typedef u_short portnum;

/* type for an IP address */
/* IP address can be either IPv4 or IPv6 */
typedef struct ipaddr
{
  u_char addr_vers;		/* 4 or 6 */
  union
  {
    struct in_addr ip4;
#ifdef SUPPORT_IPV6
    struct in6_addr ip6;
#endif
  }
  un;
}
ipaddr;


/* type for a timestamp */
typedef struct timeval timeval;
#define ZERO_TIME(ptv)(((ptv)->tv_sec == 0) && ((ptv)->tv_usec == 0))
#define time2double(t) ((double) (t).tv_sec * 1000000 + (double) (t).tv_usec)

/* type for a Boolean */
typedef u_char Bool;
#define TRUE	1
#define FALSE	0
#define BOOL2STR(b) (b)?"TRUE":"FALSE"

/* ACK types */
enum t_ack
{ NORMAL = 1,			/* no retransmits, just advance */
  AMBIG = 2,			/* segment ACKed was rexmitted */
  CUMUL = 3,			/* doesn't advance */
  TRIPLE = 4,			/* triple dupack */
  NOSAMP = 5
};				/* covers retransmitted segs, no rtt sample */

/* type for an internal file pointer */
typedef struct mfile MFILE;

extern unsigned long int fcount;	/* total flow number number */

/* first and last packet timestamp */
extern timeval first_packet;
extern timeval last_packet;

/* counters */
// LM
extern u_long tcp_trace_count_outgoing;
extern u_long tcp_trace_count_incoming;
extern u_long tcp_trace_count_local;
extern u_long udp_trace_count;

/* incoming/outgoing based on Ethernet MAC addresses */
typedef struct eth_filter
{
  int tot_internal_eth;
  // uint8_t addr[MAX_INTERNAL_ETHERS][6];
  uint8_t **addr;
} eth_filter;

/* Skype */
/* may be carried over TCP/UDP */

typedef struct deltaT_stat
{
  timeval last_time;
  double sum;
  int n;
} deltaT_stat;

typedef struct random_stat
{
  int rnd_bit_histo[N_RANDOM_BIT_VALUES][N_BLOCK];	// fa il CHI indipendentemente sui primi 6 blocchi
  int rnd_n_samples;
} random_stat;

  /* DB start */
#ifdef MSN_CLASSIFIER
typedef struct msn_stat
{

  timeval login;
  timeval logout;
  timeval start_chat;
  timeval end_chat;

  /* signaling flags */

  unsigned MSN_VER_count:1;
  unsigned MSN_CVR_count:1;
  unsigned MSN_USR_count:1;
  unsigned MSN_XFR_count:1;
  unsigned MSN_GCF_count:1;
  unsigned MSN_RNG_count:1;
  unsigned MSN_ANS_count:1;
  unsigned MSN_IRO_count:1;
  unsigned MSN_BYE_count:1;
  unsigned MSN_OUT_count:1;
  unsigned POST_count:1;
  unsigned arrived:1;
  unsigned departed:1;

  /* message counters */

  unsigned MSN_CAL_count:3;
  unsigned MSN_JOI_count:3;
  unsigned MSN_MSG_count;
  unsigned MSN_MSG_A_count;
  unsigned MSN_MSG_D_count;
  unsigned MSN_MSG_N_count;
  unsigned MSN_MSG_U_count;
  unsigned MSN_MSG_Y_count;

  unsigned MSN_PNG_count;
  unsigned MSN_QNG_count;
  unsigned MSN_CHL_count;
  unsigned MSN_QRY_count;

  int MFT;			/* Msn Flow Type */
  char MSNPversion[8];

} msn_stat;
#endif

#ifdef YMSG_CLASSIFIER
typedef struct ymsg_stat
{

  unsigned YMSG_AUTH_RESP_count:1;
  unsigned YMSG_LIST_count:1;
  unsigned YMSG_SKINNAME_count:1;
  unsigned YMSG_NOTIFY_count;
  unsigned YMSG_MESSAGE_count;
  unsigned YMSG_P2Pcheck_count:1;
  unsigned YMSG_P2P_count:1;

  int YFT;			/* Yahoo! Flow Type */
  int YMSGPversion;

} ymsg_stat;
#endif

#ifdef XMPP_CLASSIFIER
typedef struct jabber_stat
{

  unsigned PRESENCE_count:1;
  unsigned MESSAGE_count;

  int JFT;			/* Jabber Flow Type */
 /* int XMPPversion; */

} jabber_stat;
#endif
 /* DB end */

typedef struct skype_stat
{
  /* valid for both TCP/UDP */
  struct win
  {
    timeval start;
    int pktsize_max;
    int pktsize_min;
    int bytes;
  } win;

  /* Count pure video packets and audio or audio+video packets */
  int video_pkts;
  int audiovideo_pkts;
  int skype_type;
  Bool first_pkt_done;

  /* valid for UDP only */
  int pkt_type_num[TOTAL_SKYPE_KNOWN_TYPE];	/* count the number of
						   different known types */
  u_int32_t OUT_data_block;	/* signature for the SKYPE_OUT_DATA */

  deltaT_stat stat[TOTAL_SKYPE_KNOWN_TYPE];
  random_stat random;
  Bool early_classification;
  /*
#ifdef RUNTIME_SKYPE
  timeval LastSkypePrint_time;
#else
#ifdef RUNTIME_SKYPE_RESET
  timeval LastSkypePrint_time;
#endif
#endif
    */
} skype_stat;

/* Skype */

#ifdef P2P_DETAILS
typedef struct p2p_stat
{
  int pkt_type_num[10];  /*  [EDK,KAD,KADU,GNU,BT,DC,KAZAA,PPLIVE,SOPCAST,TVANTS] */
  int total_pkt;
} p2p_stat;
#endif

#ifdef OLD
/* test 2 IP addresses for equality */
#define IP_SAMEADDR(addr1,addr2) (((addr1).s_addr) == ((addr2).s_addr))

/* copy IP addresses */
#define IP_COPYADDR(toaddr,fromaddr) ((toaddr).s_addr = (fromaddr).s_addr)
#endif

typedef struct segment
{
  seqnum seq_firstbyte;		/* seqnumber of first byte */
  seqnum seq_lastbyte;		/* seqnumber of last byte */
  u_char retrans;		/* retransmit count */
  u_int acked;			/* how MANY times has has it been acked? */
  timeval time;			/* time the segment was sent */
  /* LM start - add field to implement an heuristic to identify 
     loss packets within a flow
   */
  u_short ip_id;		/* 16 bit ip identification field  */
  char type_of_segment;
  /* LM stop */
  struct segment *next;
  struct segment *prev;
}
segment;

typedef struct quadrant
{
  segment *seglist_head;
  segment *seglist_tail;
  Bool full;
  u_long no_of_segments;
  struct quadrant *prev;
  struct quadrant *next;
}
quadrant;

typedef struct seqspace
{
  quadrant *pquad[4];
}
seqspace;

typedef struct upper_protocols
{
  timeval f_http;
  timeval f_rtsp;
  timeval f_rtp;
  timeval f_icy;
} upper_protocols;

/* Only store the size for the first 4 messages */
#define MAX_COUNT_MESSAGES 10
#ifdef PACKET_STATS
#define MAX_COUNT_SEGMENTS 10
#endif

typedef struct tcb
{
  struct bayes_classifier *bc_avgipg;
  struct bayes_classifier *bc_pktsize;

  /* parent pointer */
  struct stcp_pair *ptp;

  seqnum highest_seqno;		/* to identify the end of the data */
  Bool data_to_be_acked;	/* true if waiting for an ack */
  timeval payload_start_time;	/* time of first data pkt ... */
  timeval payload_end_time;	/* time of last valid ack... */
  timeval ack_start_time;	/* time of first ack (not syn) */

  /* TCP information */
  seqnum ack;
  seqnum seq;
  seqnum syn;
  seqnum fin;
  seqnum fin_seqno;
  seqnum windowend;
  timeval time;

  /* TCP options */
  u_int mss;
  Bool f1323_ws;		/* did he request 1323 window scaling? */
  Bool f1323_ts;		/* did he request 1323 timestamps? */
  Bool fsack_req;		/* did he request SACKs? */
  Bool mptcp_req;		/* did he request MPTCP? */
  u_char window_scale;

  /* statistics added */
  u_long ip_bytes;		/* bytes (Hdr IP + Payload IP) sent including SYN-FIN and rexmits */
  u_long data_bytes;
  u_long data_pkts;
  u_long data_pkts_push;
  u_long unique_bytes;		/* bytes sent (-FIN/SYN), excluding rexmits */
  u_int rexmit_bytes;
  u_int rexmit_pkts;
  u_long ack_pkts;
  u_long pureack_pkts;		/* mallman - pure acks, no data */
  u_int win_max;
  u_int win_min;
  u_int win_tot;
  u_int win_curr;
  u_int win_zero_ct;
  u_int max_seq;
  u_long packets;
  u_char syn_count;
  u_char fin_count;
  Bool closed;
  u_char reset_count;		/* resets SENT */
  u_int min_seg_size;
  u_int max_seg_size;
  u_int out_order_pkts;		/* out of order packets */
  u_int sacks_sent;		/* sacks returned */

  /* .a.c. cwnd stats */
  u_int cwnd_max;
  u_int cwnd_flag;

  /* did I detect any "bad" tcp behavior? */
  /* at present, this means: */
  /*  - SYNs retransmitted with different sequence numbers */
  /*  - FINs retransmitted with different sequence numbers */
  Bool bad_behavior;

  /* added for initial window stats (for Mallman) */
  u_int initialwin_bytes;	/* initial window (in bytes) */
  u_int initialwin_segs;	/* initial window (in segments) */
  Bool data_acked;		/* has any non-SYN data been acked? */

  /* added for (estimated) congestions window stats (for Mallman) */
  u_long cwin_max;
  u_long cwin_min;

  /* RTT stats for singly-transmitted segments */
  double rtt_last;		/* RTT as of last good ACK (microseconds) */
  u_long rtt_min;
  u_long rtt_max;
  double rtt_sum;		/* for averages */
  double rtt_sum2;		/* sum of squares, for stdev */
  double srtt;			/* smoothed RTT estimation */
  double rttvar;		/* smoothed stdv estimation */
  u_int rtt_count;		/* for averages */
/* MGM */
  /* Duplicated and rtx counters */
  u_int rtx_RTO;
  u_int rtx_FR;
  u_int reordering;
  u_int net_dup;
  u_int unknown;
  u_int flow_control;
  u_int unnecessary_rtx_FR;
  u_int unnecessary_rtx_RTO;
    /*LM*/ u_int ttl_min;
  u_int ttl_max;
  /* TOPIX */
  u_llong ttl_tot;
  double sum_jitter;
  float max_jitter;
  float min_jitter;
  double sum_delta_t;
  int n_delta_t;
  /* end TOPIX */

  /* ACK Counters */
  u_long rtt_cumack;		/* segments only cumulativly ACKed */
  u_long rtt_nosample;		/* segments ACKED, but after retransmission */
  /* of earlier segments, so sample isn't */
  /* valid */
  u_long rtt_unkack;		/* unknown ACKs  ??? */
  u_long rtt_dupack;		/* duplicate ACKs */
  u_long rtt_triple_dupack;	/* triple duplicate ACKs */
  /* retransmission information */
  seqspace *ss;			/* the sequence space */
  u_long retr_max;		/* maximum retransmissions ct */
  u_long retr_min_tm;		/* minimum retransmissions time */
  u_long retr_max_tm;		/* maximum retransmissions time */
  double retr_tm_sum;		/* for averages */
  double retr_tm_sum2;		/* sum of squares, for stdev */
  u_long retr_tm_count;		/* for averages */

//  /* Instantaneous throughput info */
//  timeval thru_firsttime;	/* time of first packet this interval */
//  u_long thru_bytes;		/* number of bytes this interval */
//  u_long thru_pkts;		/* number of packets this interval */
//  timeval thru_lasttime;	/* time of previous segment */

  /* data transfer time stamps - mallman */
  timeval first_data_time;
  timeval last_data_time;


  /* for tracking unidirectional idle time */
  timeval last_time;		/* last packet SENT from this side */

  upper_protocols u_protocols;
  skype_stat *skype;
#ifdef MSN_CLASSIFIER
    msn_stat msn;
#endif
#ifdef YMSG_CLASSIFIER
  ymsg_stat ymsg;
#endif
#ifdef XMPP_CLASSIFIER
  jabber_stat jabber;
#endif

#ifdef CHECK_TCP_DUP
  /* dupe verify */
  u_short last_ip_id;		/* 16 bit ip identification field  */
  u_short last_len;		/* length of the last packet  */
  u_short last_checksum;        /* checksum of the last packet */
#endif

/* Count TCP messages, as separated by PSH or FIN*/
 seqnum msg_last_seq;
 u_int msg_count;
 u_int msg_size[MAX_COUNT_MESSAGES];

/* Store information on the first MAX_COUNT_SEGMENTS segments */
#ifdef PACKET_STATS
 u_int seg_count;
 u_int seg_size[MAX_COUNT_SEGMENTS];
 double last_seg_time;
 double seg_intertime[MAX_COUNT_SEGMENTS];
 double data_pkts_sum2;
 double seg_intertime_sum;
 double seg_intertime_sum2;
#endif

 timeval rate_last_sample;
 double rate_left_edge;
 double rate_right_edge;
 double rate_min;
 double rate_max;
 double rate_sum;		/* for averages */
 double rate_sum2;		/* sum of squares, for stdev */
 u_int  rate_samples;		/* for averages */
 u_int  rate_empty_samples;
 u_int  rate_bytes;
 u_int  rate_empty_streak;
 u_int  rate_begin_bytes[10];
}
tcb;


typedef u_long hash;

typedef struct
{
  ipaddr a_address;
  ipaddr b_address;
  portnum a_port;
  portnum b_port;
  hash hash;
}
tcp_pair_addrblock;

enum state_type
{ UNKNOWN_TYPE = 0,
  RTSP_COMMAND,
  RTSP_RESPONSE,
  HTTP_COMMAND,
  HTTP_RESPONSE,
#ifdef MSN_CLASSIFIER
  MSN_VER_C2S,
  MSN_VER_S2C,
  MSN_USR_C2S,
  MSN_USR_S2C,
  MSN_ANS_COMMAND,
  MSN_IRO_COMMAND,
#endif
#ifdef YMSG_CLASSIFIER
  YMSGP,
#endif  
#ifdef XMPP_CLASSIFIER
  XMPP,
#endif  
  SMTP_OPENING,
  POP3_OPENING,
  IMAP_OPENING,
  IMAP_COMMAND,
  SSL_HANDSHAKE,
  SSL_DATA,
  SSH_SERVER,
  RTMP_HANDSHAKE,
  IGNORE_FURTHER_PACKETS
};

enum npnalpn {
    TLS_EMPTY  =   0,
    NPN_EMPTY  =   1,
    NPN_HTTP   =   2,
    NPN_SPDY   =   4,
    NPN_H2     =   8,
    ALPN_EMPTY =  16,
    ALPN_HTTP  =  32,
    ALPN_SPDY  =  64,
    ALPN_H2    = 128,
};

enum video_content
{
	VIDEO_NOT_DEFINED = 0,				/*  0 - Unclassified  		*/
	VIDEO_FLV,							/*  1 - FLV 		*/
	VIDEO_MP4,							/*  2 - MP4 		*/
	VIDEO_AVI,							/*  3 - AVI 		*/
	VIDEO_WMV,							/*  4 - WMV 		*/
	VIDEO_MPEG,							/*  5 - MPEG 		*/
	VIDEO_WEBM,							/*  6 - WEBM 		*/
	VIDEO_3GPP,							/*  7 - 3GPP 		*/
	VIDEO_OGG,							/*  8 - OGG 		*/
	VIDEO_QUICKTIME,					/*  9 - QUICKTIME 		*/
	VIDEO_ASF,							/*  10 - x-ms-asf		*/
	VIDEO_UNKNOWN,						/*  11 - Unclassified VIDEO 		*/
        VIDEO_HLS,                                             /* 12 - HLS Stream (SkyGo) */
        VIDEO_NFF,                                             /* 13 - NDS File Format / Cisco Videoscape (Sky+ VOD Stream) */
	VIDEO_LAST_TYPE
};


struct video_metadata {
  double duration;

  u_int32_t totalFrames;
  double framerate;

  u_int32_t width;
  u_int32_t height;

  double starttime;
  double totalduration;
  double videodatarate;
  double audiodatarate;
  double totaldatarate;

  u_int32_t bytelength;
};

struct sstreaming_meta {
	enum state_type state;
	enum video_content video_content_type;
	enum video_content video_payload_type;

	struct video_metadata metadata;
	int packets;
};


enum http_content
{
  HTTP_GET = 0,		/*  0 - Unclassified GET command 		*/
  HTTP_POST,		/*  1 - Unclassified POST command 		*/
  HTTP_MSN,		/*  2 - MSN Chat command tunneled over HTTP (POST) */
  HTTP_RTMPT,		/*  3 - RTMPT - RTMP over HTTP Tunnel (POST) 	*/
  HTTP_YOUTUBE_VIDEO,	/*  4 - YouTube video content download (GET) 	*/
  HTTP_VIDEO_CONTENT,	/*  5 - FLV or MP4 video content download (GET) */
  HTTP_VIMEO,		/*  6 - Vimeo video content download (GET) 	*/
  HTTP_WIKI,		/*  7 - Wikipedia (GET) 			*/
  HTTP_RAPIDSHARE,	/*  8 - RapidShare file download (GET) 		*/
  HTTP_MEGAUPLOAD,	/*  9 - MegaUpload file download (GET) 		*/
  HTTP_FACEBOOK,	/* 10 - Facebook-related connections (GET/POST) */
  HTTP_ADV,		/* 11 - Site advertisement (GET) 		*/
  HTTP_FLICKR,		/* 12 - Flickr photo download (GET) 		*/
  HTTP_GMAPS,		/* 13 - GoogleMaps images (GET) 		*/
  HTTP_NETFLIX,         /* 14 - Netflix (GET) 				*/
  HTTP_YOUTUBE_SITE,	/* 15 - YouTube site content download (GET) 	*/
  HTTP_SOCIAL,      	/* 16 - Localized social-networking connections */
                        /*      Nasza-Klasa (PL), IWIW (HU) (GET/POST) 	*/
  HTTP_FLASHVIDEO,      /* 17 - Generic FLV video download (GET) 	*/
  HTTP_MEDIAFIRE,       /* 18 - MediaFire file download (GET) 		*/
  HTTP_HOTFILE,      	/* 19 - Hotfile.com file download (GET) 	*/
  HTTP_STORAGE,       	/* 20 - Storage.to file download (GET) 		*/
  HTTP_YOUTUBE_204,	/* 21 - YouTube "pre-loading" (GET) 		*/
  HTTP_YOUTUBE_VIDEO204, /* 22 - YouTube "pre-loading" and video (GET)  */
  HTTP_YOUTUBE_SITE_DIRECT, /* 23 - YouTube site direct video access (GET) */
  HTTP_YOUTUBE_SITE_EMBED, /* 24 - YouTube embedded video access (GET) */
  HTTP_TWITTER,         /* 25 - Twitter (not-encrypted) */
  HTTP_DROPBOX,         /* 26 - Dropbox */
  HTTP_LAST_TYPE
};

enum web_category
{
  WEB_GET = 0,	      /* 0 - Unclassified GET command 			*/
  WEB_POST,	      /* 1 - Unclassified POST command 			*/
  WEB_STORAGE,        /* 2 - Rapidshare, Megaupload, Mediafire		*/
  WEB_YOUTUBE,        /* 3 - YouTube only video 			*/
  WEB_VIDEO,          /* 4 - Other Video services 			*/
  WEB_SOCIAL,         /* 5 - Facebook, and other social networking 	*/ 
  WEB_OTHER,          /* 6 - All other identified traffic 		*/
  WEB_NETFLIX,        /* 7 - Netflix video                              */
  WEB_LAST_TYPE
};

enum tls_category
{
  TLS_OTHER = 0,      /* 0 - Unclassified TLS site 			*/
  TLS_GOOGLE,         /* 1 - Google services (excluded YouTube)		*/
  TLS_YOUTUBE,        /* 2 - YouTube 					*/
  TLS_FACEBOOK,       /* 3 - Facebook					*/
  TLS_NETFLIX,        /* 4 - Netflix 					*/
  TLS_DROPBOX,        /* 5 - Dropbox 					*/
  TLS_MICROSOFT,      /* 6 - Microsoft services (Live.com) 		*/
  TLS_APPLE,          /* 7 - Apple and iCloud 				*/
  TLS_LAST_TYPE
};

struct flv_metadata {
  double duration;
  double starttime;
  double totalduration;
  u_int32_t width;
  u_int32_t height;
  double videodatarate;
  double audiodatarate;
  double totaldatarate;
  double framerate;
  u_int32_t bytelength;
};

struct stcp_pair
{

  /* endpoint identification */
  tcp_pair_addrblock addr_pair;

  /* connection naming information */
  Bool internal_src;
  Bool internal_dst;

  /* connection information */
  unsigned long int id_number;
  timeval first_time;
  timeval last_time;
  u_long packets;
  tcb c2s;
  tcb s2c;

  /*streaming information (Topix) */
  u_int32_t con_type;
  enum state_type state;
  u_int32_t p2p_type;
  u_int32_t p2p_sig_count;
  u_int32_t p2p_data_count;
  u_int32_t p2p_msg_count;
  u_int32_t p2p_c2s_count;
  u_int32_t p2p_c2c_count;
  enum state_type p2p_state;
  unsigned char rtp_pt;
  Bool ignore_dpi;
  enum http_content http_data;
  int  http_request_count;
  int  http_response_count;
  char http_ytid[50];
  char http_ytitag[4];
  int  http_ytseek;
  int  http_ytredir_mode;
  int  http_ytredir_count;
  struct flv_metadata http_meta;
  char http_response[4];
  int  http_ytmobile; /* Mobile device 0=desktop 1=Other 2=Apple 3=Android */
  int  http_ytstream;   

  /* obfuscate ed2k identification */
  unsigned state_11:1;
  unsigned state_11_83:1;
  unsigned state_11_83_55:1;
  unsigned state_11_55:1;
  unsigned state_22:1;
  unsigned state_22_18:1;
  unsigned state_6:1;
  unsigned state_6_46:1;

  /* Entropy evaluation to detect encrypted data */
  u_int16_t nibbles_l[16];
  u_int16_t nibble_l_count;
  u_int16_t nibbles_h[16];
  u_int16_t nibble_h_count;
  u_int16_t nibble_packet_count;
  double entropy_l;
  double entropy_h;
  u_int16_t entropy_l_valid;
  u_int16_t entropy_h_valid;

  /* rtmp identification */
  unsigned state_rtmp_c2s_seen:1;
  unsigned state_rtmp_s2c_seen:1;
  unsigned state_rtmp_c2s_hand:1;
  unsigned state_rtmp_s2c_hand:1;

  struct sstreaming_meta streaming;

  /* Cloud identification */
  Bool cloud_src;
  Bool cloud_dst;

  /* Cloud identification */
  Bool crypto_src;
  Bool crypto_dst;
  
  char   *ssl_client_subject;
  char   *ssl_server_subject;
  enum npnalpn ssl_client_npnalpn;
  enum npnalpn ssl_server_npnalpn;
  timeval ssl_client_data_time;
  timeval ssl_server_data_time;
  timeval ssl_client_before_data_time;
  timeval ssl_server_before_data_time;
  seqnum  ssl_client_data_byte;
  seqnum  ssl_server_data_byte;
  Bool    ssl_client_data_seen;
  Bool    ssl_server_data_seen;
  Bool    ssl_sessionid_reuse;

  enum tls_category tls_service;

  /* DNS reverse lookup */
  char* dns_name;
  ipaddr  dns_server;
  timeval request_time;
  timeval response_time;
  
  /* Exclude packets from this flow when generating the tcp_complete.pcap */
   Bool stop_dumping_tcp;
};
typedef struct stcp_pair tcp_pair;

typedef struct tcphdr tcphdr;

typedef struct ptp_snap
{
  tcp_pair_addrblock addr_pair;	/* just a copy */
  struct ptp_snap *next;
  tcp_pair *ptp;
  tcp_pair **ttp_ptr;
}
ptp_snap;

extern int num_tcp_pairs;	/* how many pairs are in use */
extern tcp_pair **ttp;		/* array of pointers to allocated pairs */

/* What UDP payload is in this flow */
enum udp_type
{ UDP_UNKNOWN = 0,
  FIRST_RTP,
  FIRST_RTCP,
  RTP,
  RTCP,
  SKYPE_E2E,
  SKYPE_OUT, 
  SKYPE_SIG, 
  P2P_EDK, 
  P2P_KAD,
  P2P_KADU,
  P2P_GNU, 
  P2P_BT,
  P2P_DC, 
  P2P_KAZAA,
  P2P_PPLIVE,
  P2P_SOPCAST,
  P2P_TVANTS,
  P2P_OKAD,
  DNS,
  P2P_UTP,
  P2P_UTPBT,
  UDP_VOD,
  P2P_PPSTREAM,
  TEREDO,
  UDP_SIP,
  UDP_DTLS,
  UDP_QUIC,
  LAST_UDP_PROTOCOL
};

#define print_udp_type \
{ \
 enum udp_type temp; \
 temp = UDP_UNKNOWN; \
 printf("UNKNOWN = %d\n",temp); \
 temp = FIRST_RTP; \
 printf("FIRST_RTP = %d\n",temp); \
 temp = FIRST_RTCP; \
 printf("FIRST_RTCP = %d\n",temp); \
 temp = RTP; \
 printf("RTP = %d\n",temp); \
 temp = RTCP; \
 printf("RTCP = %d\n",temp); \
 temp = SKYPE_E2E; \
 printf("SKYPE_E2E = %d\n",temp); \
 temp = SKYPE_OUT; \
 printf("SKYPE_OUT = %d\n",temp); \
 temp = SKYPE_SIG; \
 printf("SKYPE_SIG = %d\n",temp); \
 temp = P2P_EDK; \
 printf("P2P_EDK = %d\n",temp); \
 temp = P2P_KAD; \
 printf("P2P_KAD = %d\n",temp); \
 temp = P2P_KADU; \
 printf("P2P_KADU = %d\n",temp); \
 temp = P2P_GNU; \
 printf("P2P_GNU = %d\n",temp); \
 temp = P2P_BT; \
 printf("P2P_BT = %d\n",temp); \
 temp = P2P_DC; \
 printf("P2P_DC = %d\n",temp); \
 temp = P2P_KAZAA; \
 printf("P2P_KAZAA = %d\n",temp); \
 temp = P2P_PPLIVE; \
 printf("P2P_PPLIVE = %d\n",temp); \
 temp = P2P_SOPCAST; \
 printf("P2P_SOPCAST = %d\n",temp); \
 temp = P2P_TVANTS; \
 printf("P2P_TVANTS = %d\n",temp); \
 temp = P2P_OKAD; \
 printf("P2P_OKAD = %d\n",temp); \
 temp = DNS; \
 printf("DNS = %d\n",temp); \
 temp = P2P_UTP; \
 printf("P2P_UTP = %d\n",temp); \
 temp = P2P_UTPBT; \
 printf("P2P_UTPBT = %d\n",temp); \
 temp = UDP_VOD; \
 printf("UDP_VOD = %d\n",temp); \
 temp = P2P_PPSTREAM; \
 printf("P2P_PPSTREAM = %d\n",temp); \
 temp = TEREDO; \
 printf("TEREDO = %d\n",temp); \
 temp = UDP_SIP; \
 printf("UDP_SIP = %d\n",temp); \
 temp = UDP_DTLS; \
 printf("UDP_DTLS = %d\n",temp); \
 temp = UDP_QUIC; \
 printf("UDP_QUIC = %d\n",temp); \
}



typedef struct rtp
{

  u_int16_t packets_win[RTP_WIN];	/* the sliding window vector used to track
				   seqnum */
  Bool w;			/* true if we got a full window */
  u_int16_t initial_seqno;
  u_int16_t largest_seqno;
  u_long pnum;			/* number of segments */
  u_int32_t ssrc;
  timeval first_time;
  timeval last_time;
  long int n_out_of_sequence;
  double sum_delta_t;
  int n_delta_t;
  int transit;
  u_int32_t first_ts;
  u_int32_t largest_ts;
  double jitter;
  float jitter_max;
  float jitter_min;
  long int n_dup;
  long int n_late;
  long int n_lost;
  int burst;
  u_llong data_bytes;
  /* topix */
  unsigned char pt;
  int bogus_reset_during_flow; /* some Cisco implementation reset seqno ... */
  /* end topix */
} rtp;


typedef struct rtcp
{
  u_long pnum;			/* number of segments */
  u_int64_t initial_data_bytes;
  double sum_delta_t;		/* total interarrival time so far */
  timeval first_time;
  timeval last_time;
  u_int32_t ssrc;

  timeval last_SR;
  u_int32_t last_SR_id;
  u_int32_t tx_p;
  u_int32_t tx_b;

  double jitter_sum;
  double jitter_max;
  double jitter_min;
  u_int32_t jitter_samples;

  double rtt_sum;
  double rtt_max;
  double rtt_min;
  u_int32_t rtt_samples;

  int32_t c_lost;
  u_int8_t f_lost;
  double f_lost_sum;
  int rtcp_header_error;
} rtcp;


enum obfuscate_udp_state
{ 
  OUDP_UNKNOWN = 0,
  OUDP_REQ43,
  OUDP_RES52_K25,
  OUDP_REQ59,
  OUDP_RES68_K25,
  OUDP_SIZEX_22,
  OUDP_SIZEX_52,
  OUDP_SIZE_IN_46_57
};

enum uTP_udp_state
{
  UTP_UNKNOWN=0,
  UTP_SYN_SEEN,
  UTP_DATA_SEEN,
  UTP_ACK_SEEN,
  UTP_SYN_SENT,
  UTP_DATA_SENT,
  UTP_ACK_SENT
};

enum QUIC_udp_state
{
  QUIC_UNKNOWN=0,
  QUIC_OPENV_SENT,
  QUIC_OPEN_SENT,
  QUIC_DATA_SENT
};

/* minimal support for UDP "connections" */
typedef struct ucb
{
  struct bayes_classifier *bc_avgipg;
  struct bayes_classifier *bc_pktsize;

  /* parent pointer */
  struct sudp_pair *pup;

  timeval first_pkt_time;	/* time of the first pkt seen */
  timeval last_pkt_time;	/* time of the last pkt seen */
  enum udp_type type;
  enum obfuscate_udp_state kad_state;
  Bool obfuscate_state;
  u_short obfuscate_last_len;
  enum uTP_udp_state uTP_state;
  int uTP_conn_id;
  int uTP_syn_seq_nr;
  Bool is_uTP;
  enum QUIC_udp_state QUIC_state;
  char QUIC_conn_id[8];
  int QUIC_seq_nr;
  Bool is_QUIC;

  int VOD_scrambled_sig[2];
  u_short VOD_count;
  Bool first_VOD;
  Bool is_VOD;

  union
  {
    rtp rtp;
    rtcp rtcp;
  } flow;
  /* statistics added */
  u_llong data_bytes;
  u_llong packets;
    /*TOPIX*/ u_int ttl_min;
  u_int ttl_max;
  u_llong ttl_tot;
  /*end TOPIX */

  /* skype */
  skype_stat *skype;
  int lastnumpkt;
  /* end skype */

#ifdef P2P_DETAILS
  int is_p2p;
  p2p_stat p2p;
#endif

#ifdef CHECK_UDP_DUP
  /* dupe verify */
  u_short last_ip_id;		/* 16 bit ip identification field  */
  u_short last_len;		/* length of the last packet  */
  u_short last_checksum;        /* checksum of the last packet */
#endif
}
ucb;


typedef tcp_pair_addrblock udp_pair_addrblock;

struct sudp_pair
{
  /* endpoint identification */
  udp_pair_addrblock addr_pair;

  /* connection naming information */
  Bool internal_src;
  Bool internal_dst;

  /* connection information */
  timeval first_time;
  timeval last_time;
  u_llong packets;
  ucb c2s;
  ucb s2c;

  enum obfuscate_udp_state kad_state;

  /* Cloud identification */
  Bool cloud_src;
  Bool cloud_dst;

  /* Crypto identification */
  Bool crypto_src;
  Bool crypto_dst;

  /* linked list of usage */
  struct sudp_pair *next;

  /* DNS reverse lookup */
  char *dns_name;
  ipaddr  dns_server;
  timeval request_time;
  timeval response_time;
};
typedef struct sudp_pair udp_pair;
typedef struct udphdr udphdr;

struct L4_bitrates
{
  unsigned long long in[4];
  unsigned long long out[4];
  unsigned long long loc[4];
  unsigned long long c_in[4];
  unsigned long long c_out[4];
  unsigned long long nc_in[4];
  unsigned long long nc_out[4];
};

struct L7_bitrates
{
  unsigned long long in[L7_FLOW_TOT];  /* unsigned long long in[L7_FLOW_TOT] */
  unsigned long long out[L7_FLOW_TOT]; /* unsigned long long out[L7_FLOW_TOT] */
  unsigned long long loc[L7_FLOW_TOT]; /* unsigned long long loc[L7_FLOW_TOT] */
  unsigned long long c_in[L7_FLOW_TOT];  /* unsigned long long in[L7_FLOW_TOT] */
  unsigned long long c_out[L7_FLOW_TOT]; /* unsigned long long out[L7_FLOW_TOT] */
  unsigned long long nc_in[L7_FLOW_TOT];  /* unsigned long long in[L7_FLOW_TOT] */
  unsigned long long nc_out[L7_FLOW_TOT]; /* unsigned long long out[L7_FLOW_TOT] */
};

struct HTTP_bitrates
{
  unsigned long long in[HTTP_LAST_TYPE];  /* unsigned long long in[L7_FLOW_TOT] */
  unsigned long long out[HTTP_LAST_TYPE]; /* unsigned long long out[L7_FLOW_TOT] */
  unsigned long long loc[HTTP_LAST_TYPE]; /* unsigned long long loc[L7_FLOW_TOT] */
  unsigned long long c_in[HTTP_LAST_TYPE];  /* unsigned long long in[L7_FLOW_TOT] */
  unsigned long long c_out[HTTP_LAST_TYPE]; /* unsigned long long out[L7_FLOW_TOT] */
  unsigned long long nc_in[HTTP_LAST_TYPE];  /* unsigned long long in[L7_FLOW_TOT] */
  unsigned long long nc_out[HTTP_LAST_TYPE]; /* unsigned long long out[L7_FLOW_TOT] */
};

struct VIDEO_rates
{
  unsigned long long in[VIDEO_LAST_TYPE];  /* unsigned long long in[L7_FLOW_TOT] */
  unsigned long long out[VIDEO_LAST_TYPE]; /* unsigned long long out[L7_FLOW_TOT] */
  unsigned long long loc[VIDEO_LAST_TYPE]; /* unsigned long long loc[L7_FLOW_TOT] */
  unsigned long long c_in[VIDEO_LAST_TYPE];  /* unsigned long long in[L7_FLOW_TOT] */
  unsigned long long c_out[VIDEO_LAST_TYPE]; /* unsigned long long out[L7_FLOW_TOT] */
  unsigned long long nc_in[VIDEO_LAST_TYPE];  /* unsigned long long in[L7_FLOW_TOT] */
  unsigned long long nc_out[VIDEO_LAST_TYPE]; /* unsigned long long out[L7_FLOW_TOT] */
};


struct WEB_bitrates
{
  unsigned long long in[WEB_LAST_TYPE];  /* unsigned long long in[L7_FLOW_TOT] */
  unsigned long long out[WEB_LAST_TYPE]; /* unsigned long long out[L7_FLOW_TOT] */
  unsigned long long loc[WEB_LAST_TYPE]; /* unsigned long long loc[L7_FLOW_TOT] */
};

struct TLS_bitrates
{
  unsigned long long in[TLS_LAST_TYPE];  /* unsigned long long in[L7_FLOW_TOT] */
  unsigned long long out[TLS_LAST_TYPE]; /* unsigned long long out[L7_FLOW_TOT] */
  unsigned long long loc[TLS_LAST_TYPE]; /* unsigned long long loc[L7_FLOW_TOT] */
};

#ifdef HAVE_RRDTOOL
/*-----------------------------------------------------------*/
/* RRDtools 				                     */

struct rrdconf
{
  Bool rrd;			/* boolean: whether to use rrd on this histo */
  Bool avg, min, max, var, stdev, idxoth, hit;	/* statistical var to dump */
  int *idx;			/* indexes to dump */
  int idxno;
  double *prc;			/* percentiles to dump */
  int prcno;
};

struct rrdstat
{
  double avg, min, max, pseudovar;	/* actual values of the statistical var to dump */
  long count;
  timeval last;
};
/*-----------------------------------------------------------*/
#endif


/* Struct to evaluate the average of n(t) */
typedef struct win_stat
{
  char name[20];		/* name of observed struct */
  timeval t0;			/* Initial time of this observation window */
  timeval t;			/* Last measurement time */
  double n;             /* Last measurement value */
  double tot;			/* Integral of n(t) */

} win_stat;

enum ip_direction {
 DEFAULT_NET     = 0,
 SRC_IN_DST_IN   = 1,
 SRC_IN_DST_OUT  = 2,
 SRC_OUT_DST_IN  = 3,
 SRC_OUT_DST_OUT = 4
};

/* Struct mirroring the constants defined in param.h */

struct global_parameters {
 int Max_ADX_Slots;

 int Max_Internal_Ethers;
 int Max_Internal_Hosts;
 int Max_Cloud_Hosts;
 int Max_Crypto_Hosts;
 int Max_White_Hosts;

 int Max_Seg_Per_Quad;
 
 int TCP_Idle_Time;
 int UDP_Idle_Time;
 int TCP_Singleton_Time;
 int UDP_Singleton_Time;
 
 int GC_Cycle_Time;
 int GC_Split_Ratio;
 int GC_Fire_Time; /* We keep it global, but as a derived value */

 double Runtime_Config_Idle;
 int Runtime_Mtime_Counter;

 int Max_TCP_Pairs;
 int Max_UDP_Pairs;
 
 int List_Search_Dept;
 
 int Hash_Table_Size;

 double Max_Time_Step;
 
 int Dirs;

 double Min_Delta_T_UDP_Dup_Pkt;
 double Min_Delta_T_TCP_Dup_Pkt;

 int Entropy_Sample;
 double Entropy_Threshold;
 
 int Rate_Sampling;

 int Max_Crypto_Cache_Size;

 int DNS_Cache_Size;
#ifdef SUPPORT_IPV6 
 int DNS_Cache_Size_IPv6;
#endif
};

typedef struct param_value
{
  enum   { INTEGER, DOUBLE, STRING } type;
  union  {
  int    ivalue;
  double dvalue;
  char   *svalue;
  } value;
} param_value;
