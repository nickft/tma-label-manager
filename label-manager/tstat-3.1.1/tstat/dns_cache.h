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

#include "dnscache/DNSCache.h"
#include "dnscache/DNSEntry.h"
#ifdef SUPPORT_IPV6
#include "dnscache/DNSCache_ipv6.h"
#include "dnscache/DNSEntry_ipv6.h"
#endif

struct DNS_data* get_dns_entry(
		unsigned long int client_ip,
		unsigned long int server_ip);

unsigned char* reverse_lookup(unsigned long int client_ip, unsigned long int server_ip);

#ifdef SUPPORT_IPV6
struct DNS_data_IPv6* get_dns_entry_ipv6(
		struct in6_addr *client_ip,
		struct in6_addr *server_ip);

unsigned char* reverse_lookup_ipv6(struct in6_addr *client_ip, struct in6_addr *server_ip);
#endif

/*
unsigned long int dns_server(unsigned long int client_ip, unsigned long int server_ip);
*/
