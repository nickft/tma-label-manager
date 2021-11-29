/*
 * DNSCache.h
 *
 *  Created on: Oct 12, 2011
 *      Author: Ignacio Bermudez
 *  Modified on May 2016 by Maurizio M. Munafo' to manage IPv6 addresses
 */

#ifndef DNSCACHE_IPV6_H_
#define DNSCACHE_IPV6_H_

#include "DNSEntry_ipv6.h"

//#ifdef __cplusplus
//namespace cache {
//#endif


#ifdef __cplusplus
extern "C"{
#endif
	void cacheInitialize_ipv6(int);
	int insert_ipv6(
			unsigned char* hostname,
			struct my_in6_addr client_ip,
			struct my_in6_addr* server_ip_list,
			int number_of_servers,
			//unsigned long int dns_server,
			struct in6_addr dns_server,
			timeval request_time,
			timeval response_time);
	struct DNS_data_IPv6* getEntry_ipv6(
			struct my_in6_addr client_ip,
			struct my_in6_addr server_ip);
	unsigned char* get_ipv6(
			struct my_in6_addr,
			struct my_in6_addr);
	struct in6_addr* get_dns_server_ipv6(
			struct my_in6_addr *client_ip,
			struct my_in6_addr *server_ip);
#ifdef __cplusplus
}
#endif

//#ifdef __cplusplus
//}
//#endif

#endif /* DNSCACHE_IPV6_H_ */
