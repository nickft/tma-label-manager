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
 * ipv6.h:
 *
 * Structures for IPv6 packets
 *
 */
#include <sys/types.h>
#include <netinet/icmp6.h>

/* just guessing... */
#if !defined(IPPROTO_NONE) && !defined(IPPROTO_FRAGMENT) && !defined(IPPROTO_DSTOPTS) && !defined(INET6_ADDRSTRLEN)
/* when IPv6 is more widely/standardly deployed, these constants won't need to be
   here.  In the mean time, here's the stuff we need... */
#define IPV6NOTFOUND

//minimum lenght of IPv6 packet=40 BYTES
#define MIN_IPV6_LENGHT 40



/* header types */
#define	IPPROTO_HOPOPTS		0	/* Hop by hop header for v6 */
#define	IPPROTO_IPV6		41	/* IPv6 encapsulated in IP */
#define	IPPROTO_ROUTING		43	/* Routing header for IPv6 */
#define	IPPROTO_FRAGMENT	44	/* Fragment header for IPv6 */
#define	IPPROTO_ICMPV6		58	/* ICMP for IPv6 */
#define	IPPROTO_NONE		59	/* No next header for IPv6 */
#define	IPPROTO_DSTOPTS		60	/* Destinations options */

/* other constants we need */
#define INET6_ADDRSTRLEN        46	/* IPv6 Address length in a string format */

/* this is SOMETIMES already defined */
#ifndef AF_INET6
#define AF_INET6                24	/* Internet Protocol, V6 */
#endif /* AF_INET6 */



/*
 * IPv6 address data structure.
 */
typedef struct in6_addr
{
  u_char s6_addr[16];		/* IPv6 address */
}
in6_addr;


#endif /* notdef IPPROTO_NONE */

/* Newest protocols might not be defined */
#if !defined(IPPROTO_MH)
#define IPPROTO_MH			135 /* IPv6 mobility header.  */
#endif

/*
 * IPv6 datagram header 
 */
struct ipv6
{
  u_int ip6_ver_tc_flabel;	/* first 4  bits = version #, 
				   next  4  bits = Trafic class,
				   next  24 bits = flow label */
  u_short ip6_lngth;		/* Payload length */
  u_char ip6_nheader;		/* Next Header */
  u_char ip6_hlimit;		/* Hop Limit */
  struct in6_addr ip6_saddr;	/* Source Address */
  struct in6_addr ip6_daddr;	/* Destination Address */
};


/* IPv6 extension header format */
struct ipv6_ext
{
  u_char ip6ext_nheader;	/* Next Header */
  u_char ip6ext_len;		/* number of bytes in this header */
  u_char ip6ext_data[1];	/* optional data */
};


/* IPv6 fragmentation header */
struct ipv6_ext_frag
{
  u_char ip6ext_fr_nheader;	/* Next Header */
  u_char ip6ext_fr_res;		/* (reserved) */
  u_short ip6ext_fr_offset;	/* fragment offset(13),res(2),M(1) */
  u_long ip6ext_fr_ID;		/* ID field */
};


void IPv6_support (struct ip *pip, void * plast, int ip_direction);
void ICMPv6_support(char * next, int internal_srcv6, int internal_dstv6);
int LoadInternalNetsv6 (char *file, struct in6_addr *internal_net_listv6, int *internal_net_mask_size, int * tot_internal_nets);
int LoadCryptoNetsv6 (char *file, struct in6_addr *crypto_net_listv6, int *crypto_net_mask_size, int * tot_crypto_nets);
int internal_ipv6(struct in6_addr adx);
int cloud_ipv6(struct in6_addr adx);
int crypto_ipv6(struct in6_addr adx);
char * findheader_ipv6 ( void *pplast,struct ip *pip,unsigned int * proto_type);
/* tcptrace's IPv6 access routines */
struct tcphdr *gettcp (struct ip *pip, void **pplast);
struct udphdr *getudp (struct ip *pip, void **pplast);
int gethdrlength (struct ip *pip, void *plast);
int getpayloadlength (struct ip *pip, void *plast);
struct ipv6_ext *ipv6_nextheader (void *pheader0, u_char * pnextheader);
char *ipv6_header_name (u_char nextheader);
char *my_inet_ntop (int af, const char *src, char *dst, size_t size);
