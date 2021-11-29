/*
 * DNSEntry.h
 *
 *  Created on: Oct 13, 2011
 *      Author: Ignacio Bermudez
 *
 */

#ifndef DNSENTRY_H_
#define DNSENTRY_H_

#ifdef __cplusplus
#include <map>
#include <time.h>
#include <sys/time.h>
#include <netinet/in.h>

extern "C"{
#endif
struct DNS_data{
	char *hostname;
	timeval request_time;
	timeval response_time;
	struct in_addr dns_server;
};
#ifdef __cplusplus
}



class DNSEntry {
	typedef std::map<unsigned long int, DNSEntry*> ServerHashtable;
	typedef std::map<unsigned long int, ServerHashtable > IPHashtable;
private:
	unsigned char *hostname;
	unsigned long int *client_ip;
	unsigned long int *servers;
	int *n_servers;
	struct in_addr* dns_server;
	timeval* response_time;
	timeval* request_time;
public:
	void deleteReferences(IPHashtable&);
	void destroyEntry();
	DNSEntry(
			unsigned char * fqdn,
			unsigned long int client_ip,
			unsigned long int* server_ip_list,
			int n_servers,
			struct in_addr dns_server,
			timeval request_time,
			timeval response_time);
	DNSEntry();
	virtual ~DNSEntry();
	unsigned char* getHostname();
	struct in_addr* getDNSServer();
	struct DNS_data* getDNSData();
};

#endif
#endif /* DNSENTRY_H_ */
