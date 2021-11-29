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
 *
*/


#ifndef PROTOCOL_H
#define PROTOCOL_H

/* Transport layer protocol */
#define PROTOCOL_TCP  1
#define PROTOCOL_UDP  2
#define PROTOCOL_BOTH 3
#define proto_description(type) \
    ( type == PROTOCOL_TCP ? "TCP" : type == PROTOCOL_UDP ? "UDP" : "TCP/UDP" )


/* Upper Level protocols (bitmask)*/
#define UNKNOWN_PROTOCOL  0
#define HTTP_PROTOCOL     1
#define RTSP_PROTOCOL     2
#define RTP_PROTOCOL      4
#define ICY_PROTOCOL      8
#define RTCP_PROTOCOL    16
#define MSN_PROTOCOL     32
#define YMSG_PROTOCOL    64
#define XMPP_PROTOCOL   128
#define P2P_PROTOCOL    256
#define SKYPE_PROTOCOL  512
#define SMTP_PROTOCOL  1024
#define POP3_PROTOCOL  2048
#define IMAP_PROTOCOL  4096
#define SSL_PROTOCOL   8192
#define OBF_PROTOCOL  16384
#define SSH_PROTOCOL  32768
#define RTMP_PROTOCOL 65536
#define MSE_PROTOCOL 131072

/* IP address classes */
#define UNICAST       0
#define MULTICAST     1
#define LB_MULTICAST  0xE0000000UL	//224.0.0.0
#define UB_MULTICAST  0xF0000000UL	//240.0.0.0


#endif
