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
 */

#include "DNSCache.h"
//#include "DNSEntry.h"
#include <map>

std::map <unsigned long int, std::map <unsigned long int, DNSEntry *> > ip_hashtable;
unsigned int pointer = 0;
int size;
DNSEntry *cyclicList;

void cacheInitialize(int s){
	DNSEntry nullEntry;
	cyclicList = new DNSEntry [s];
	for(int i=0;i<s;i++){
		cyclicList[i] = nullEntry;
	}
	size = s;
}

int insert(
		unsigned char* hostname,
		unsigned long int client_ip,
		unsigned long int *servers,
		int n_servers,
		//unsigned long int dns_server,
		struct in_addr dns_server,
		timeval request_time,
		timeval response_time){
	DNSEntry entry (
			hostname,
			client_ip,
			servers,
			n_servers,
			dns_server,
			request_time,
			response_time);

	DNSEntry &lastEntry = cyclicList[pointer%size];
	lastEntry.deleteReferences(ip_hashtable);
	cyclicList[pointer%size] = entry;
	for(unsigned int i=0; i<n_servers/sizeof(servers[0]);i++){
		ip_hashtable[client_ip][servers[i]] = &cyclicList[pointer%size];
	}
	pointer++;
	if (pointer%size==0) 
	 {
	   pointer = 0;
	   return size;
	 }
	return 0;
}

struct DNS_data* getEntry(unsigned long int client_ip, unsigned long int server_ip){
	if(ip_hashtable.count(client_ip)>0){
		std::map<unsigned long int, DNSEntry*> &server_map = ip_hashtable[client_ip];
		if(server_map.count(server_ip)>0){
			DNSEntry entry = *server_map[server_ip];
			return entry.getDNSData();
		}
	}
	return NULL;
}


unsigned char* get(unsigned long int client_ip, unsigned long int server_ip){
	if(ip_hashtable.count(client_ip)>0){
		std::map<unsigned long int, DNSEntry*> &server_map = ip_hashtable[client_ip];
		if(server_map.count(server_ip)>0){
			DNSEntry entry = *server_map[server_ip];
			return entry.getHostname();
		}
	}
	return NULL;
}

struct in_addr* get_dns_server(unsigned long int client_ip, unsigned long int server_ip){
	if(ip_hashtable.count(client_ip)>0){
			std::map<unsigned long int, DNSEntry*> &server_map = ip_hashtable[client_ip];
			if(server_map.count(server_ip)>0){
				DNSEntry entry = *server_map[server_ip];
				return entry.getDNSServer();
			}
		}
	return NULL;
}

