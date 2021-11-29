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
 * v1.2.0 memcpy optimization
*/
/* define the FLOW number for the histo hit */
#define L4_FLOW_TCP             0
#define L4_FLOW_UDP             1
#define L4_FLOW_TOT             2

#define L7_FLOW_HTTP            0
#define L7_FLOW_RTP             1
#define L7_FLOW_RTCP            2
#define L7_FLOW_ICY             3
#define L7_FLOW_RTSP            4

#define L7_FLOW_SKYPE_E2E       5
#define L7_FLOW_SKYPE_E2O       6
#define L7_FLOW_SKYPE_TCP       7

#define L7_FLOW_MSN             8
#define L7_FLOW_XMPP            9
#define L7_FLOW_YMSG            10

#define L7_FLOW_EDK             11
#define L7_FLOW_KAD             12
#define L7_FLOW_KADU            13
#define L7_FLOW_GNU             14
#define L7_FLOW_BIT             15
#define L7_FLOW_UTP             16
#define L7_FLOW_DC              17
#define L7_FLOW_APPLE           18
#define L7_FLOW_SOUL            19
#define L7_FLOW_WINMX           20
#define L7_FLOW_ARES            21
#define L7_FLOW_MUTE            22
#define L7_FLOW_WASTE           23
#define L7_FLOW_XDCC            24

#define L7_FLOW_SMTP            25
#define L7_FLOW_POP3            26
#define L7_FLOW_IMAP            27
#define L7_FLOW_OBF		28


#define L7_FLOW_PPLIVE          29
#define L7_FLOW_SOPCAST         30
#define L7_FLOW_TVANTS          31

#define L7_FLOW_SKYPE_SIG       32

#define L7_FLOW_SSL		33

#define L7_FLOW_OBF_KAD		34

/*
// Redefined to L7_FLOW_KAZAA after being unused for a long time
#define L7_FLOW_UNKNOWN         35
*/
#define L7_FLOW_KAZAA           35

#define L7_FLOW_DNS             36
#define L7_FLOW_SSH             37

#define L7_FLOW_RTMP            38
#define L7_FLOW_MSE             39

#define L7_FLOW_VOD		40

#define L7_FLOW_PPSTREAM	41
#define L7_FLOW_TEREDO		42
#define L7_FLOW_SIP		43
#define L7_FLOW_DTLS		44
#define L7_FLOW_QUIC		45

#define L7_FLOW_UNKNOWN         49    /* Unknown is set to the largest ID */
#define L7_FLOW_TOT             50    /* Large to leave space for future  */
				      /* protocol types */


#define VIDEO_FLOW_TRUE			0
#define VIDEO_FLOW_RTMP			1
#define VIDEO_FLOW_NOT_VIDEO	2
#define VIDEO_FLOW_TOT			3
