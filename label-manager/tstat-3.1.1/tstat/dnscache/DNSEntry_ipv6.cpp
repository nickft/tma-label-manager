/*
 * DNSEntry.cpp
 *
 *	An entry are put in the cyclic list
 *	of the DNS cache.
 *	It can remove references to itself from
 *	the ip_hashtable map.
 *
 *  Created on: Oct 13, 2011
 *      Author: Ignacio Bermudez
 *  Modified on May 2016 by Maurizio M. Munafo' to manage IPv6 addresses
 */

#include "DNSEntry_ipv6.h"
#include <cstring>

struct DNS_data_IPv6 dns_data_ipv6;

void DNSEntryIPv6::deleteReferences(IPv6Hashtable& ip_hashtable){
	if(client_ip==NULL){
		destroyEntry();
		return;
	}
	if(ip_hashtable.count(*client_ip)==0)
		return;
	ServerIPv6Hashtable &server_map = ip_hashtable[*client_ip];
	for(unsigned int i=0; i<(*n_servers)/sizeof(servers[0]) ; i++){
		server_map.erase(servers[i]);
	}
	if(server_map.empty()){
		ip_hashtable.erase(*client_ip);
	}
	destroyEntry();
}

//unsigned long int DNSEntry::getDNSServer(){
//	return *this->dns_server;
//}

struct in6_addr* DNSEntryIPv6::getDNSServer(){
	return this->dns_server;
}


unsigned char* DNSEntryIPv6::getHostname(){
    char *fqdn = strdup((const char *)hostname);
	return (unsigned char *)fqdn;
}

struct DNS_data_IPv6* DNSEntryIPv6::getDNSData()
{
	dns_data_ipv6.hostname = strdup((const char *)hostname);
	dns_data_ipv6.response_time = *response_time;
	dns_data_ipv6.request_time = *request_time;
	dns_data_ipv6.dns_server = *dns_server;
	return &dns_data_ipv6;
}

DNSEntryIPv6::DNSEntryIPv6(
		unsigned char* hostname,
		struct my_in6_addr client_ip,
		struct my_in6_addr *servers,
		int n_servers,
		//unsigned long dns_server,
		struct in6_addr dns_server,
		timeval request_time,
		timeval response_time) {
	/*
	 * Allocate Memory
	 */
	int fqdn_len = std::strlen((const char *)hostname)+1;
	this->hostname = new unsigned char [fqdn_len];
	this->servers = new struct my_in6_addr[n_servers/sizeof(struct in6_addr)];
	this->client_ip = new struct my_in6_addr;
	this->n_servers = new int;
	//this->dns_server = new unsigned long int;
	this->dns_server = new struct in6_addr;
	this->request_time = new struct timeval;
	this->response_time = new struct timeval;
	/*
	 * Fill memory
	 */
	std::memcpy(this->hostname,hostname,fqdn_len);
	std::memcpy(this->servers,servers,n_servers);
	*this->client_ip = client_ip;
	*this->n_servers = n_servers;
	*this->dns_server = dns_server;
	*this->response_time = response_time;
	*this->request_time = request_time;
}

DNSEntryIPv6::DNSEntryIPv6(){
	hostname = NULL;
	client_ip = NULL;
	n_servers = NULL;
	servers = NULL;
	dns_server = NULL;
	request_time = NULL;
	response_time = NULL;
}

void DNSEntryIPv6::destroyEntry(){
	delete hostname;
	delete servers;
	delete client_ip;
	delete n_servers;
	delete dns_server;
	delete request_time;
	delete response_time;
}

DNSEntryIPv6::~DNSEntryIPv6() {
}
