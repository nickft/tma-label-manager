/*
 * DNSCache.cpp
 *
 * This module provide public methods
 * to be called from a C/C++ program.
 * C code must be compiled together
 * using a C++ compiler as g++.
 *
 * When it's called from C, since it isn't
 * an object oriented language, the function
 * cacheInitialize must be called first specifying
 * the maximum number of DNS entries the cache can
 * have.
 *
 * Input for the cache are
 * hostname, client_ip, and an array with server ip
 * addresses returned by the DNS server.
 *
 * To query the cache just ask for client_ip and
 * any server_ip, it returns a hostname if it
 * finds it in the cache, else it returns a NULL
 * that must be checked from C to avoid further
 * segmentation faults when using that piece of
 * data.
 *
 *  Created on: Oct 12, 2011
 *      Author: Ignacio Bermudez
 *  Modified on May 2016 by Maurizio M. Munafo' to manage IPv6 addresses
 */

#include "DNSCache_ipv6.h"
//#include "DNSEntry.h"
#include <map>

std::map <struct my_in6_addr, std::map <struct my_in6_addr, DNSEntryIPv6 *> > ipv6_hashtable;
unsigned int pointer_ipv6 = 0;
int size_ipv6;
DNSEntryIPv6 *cyclicList_ipv6;

void cacheInitialize_ipv6(int s){
	DNSEntryIPv6 nullEntry;
	cyclicList_ipv6 = new DNSEntryIPv6 [s];
	for(int i=0;i<s;i++){
		cyclicList_ipv6[i] = nullEntry;
	}
	size_ipv6 = s;
}

int insert_ipv6(
		unsigned char* hostname,
		struct my_in6_addr client_ip,
		struct my_in6_addr *servers,
		int n_servers,
		//unsigned long int dns_server,
		struct in6_addr dns_server,
		timeval request_time,
		timeval response_time){
	DNSEntryIPv6 entry (
			hostname,
			client_ip,
			servers,
			n_servers,
			dns_server,
			request_time,
			response_time);

	DNSEntryIPv6 &lastEntry = cyclicList_ipv6[pointer_ipv6%size_ipv6];
	lastEntry.deleteReferences(ipv6_hashtable);
	cyclicList_ipv6[pointer_ipv6%size_ipv6] = entry;
	for(unsigned int i=0; i<n_servers/sizeof(servers[0]);i++){
		ipv6_hashtable[client_ip][servers[i]] = &cyclicList_ipv6[pointer_ipv6%size_ipv6];
	}
	pointer_ipv6++;
	if (pointer_ipv6%size_ipv6==0) 
	 {
	   pointer_ipv6 = 0;
	   return size_ipv6;
	 }
	return 0;
}

struct DNS_data_IPv6* getEntry_ipv6(struct my_in6_addr client_ip, struct my_in6_addr server_ip){
	if(ipv6_hashtable.count(client_ip)>0){
		std::map<struct my_in6_addr, DNSEntryIPv6*> &server_map = ipv6_hashtable[client_ip];
		if(server_map.count(server_ip)>0){
			DNSEntryIPv6 entry = *server_map[server_ip];
			return entry.getDNSData();
		}
	}
	return NULL;
}


unsigned char* get_ipv6(struct my_in6_addr client_ip, struct my_in6_addr server_ip){
	if(ipv6_hashtable.count(client_ip)>0){
		std::map<struct my_in6_addr, DNSEntryIPv6*> &server_map = ipv6_hashtable[client_ip];
		if(server_map.count(server_ip)>0){
			DNSEntryIPv6 entry = *server_map[server_ip];
			return entry.getHostname();
		}
	}
	return NULL;
}

struct in6_addr* get_dns_server_ipv6(struct my_in6_addr client_ip, struct my_in6_addr server_ip){
	if(ipv6_hashtable.count(client_ip)>0){
			std::map<struct my_in6_addr, DNSEntryIPv6*> &server_map = ipv6_hashtable[client_ip];
			if(server_map.count(server_ip)>0){
				DNSEntryIPv6 entry = *server_map[server_ip];
				return entry.getDNSServer();
			}
		}
	return NULL;
}

