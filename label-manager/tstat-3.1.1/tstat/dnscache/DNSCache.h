/*
 * DNSCache.h
 *
 *  Created on: Oct 12, 2011
 *      Author: Ignacio Bermudez
 */

#ifndef DNSCACHE_H_
#define DNSCACHE_H_

#include "DNSEntry.h"

//#ifdef __cplusplus
//namespace cache {
//#endif


#ifdef __cplusplus
extern "C"{
#endif
	void cacheInitialize(int);
	int insert(
			unsigned char* hostname,
			unsigned long int client_ip,
			unsigned long int* server_ip_list,
			int number_of_servers,
			//unsigned long int dns_server,
			struct in_addr dns_server,
			timeval request_time,
			timeval response_time);
	struct DNS_data* getEntry(
			unsigned long int client_ip,
			unsigned long int server_ip);
	unsigned char* get(
			unsigned long int,
			unsigned long int);
	struct in_addr* get_dns_server(
			unsigned long int client_ip,
			unsigned long int server_ip);
#ifdef __cplusplus
}
#endif

//#ifdef __cplusplus
//}
//#endif

#endif /* DNSCACHE_H_ */
