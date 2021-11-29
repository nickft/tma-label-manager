/*
 * DNSEntry.h
 *
 *  Created on: Oct 13, 2011
 *      Author: Ignacio Bermudez
 *  Modified on May 2016 by Maurizio M. Munafo' to manage IPv6 addresses
 *
 */

#ifndef DNSENTRY_IPV6_H_
#define DNSENTRY_IPV6_H_

#ifdef __cplusplus
#include <map>
#include <time.h>
#include <sys/time.h>
#include <string.h>
#include <netinet/in.h>

extern "C"{
#endif
struct DNS_data_IPv6{
	char *hostname;
	timeval request_time;
	timeval response_time;
	struct in6_addr dns_server;
};

/*
Instead of the 'unsigned long int' used for IPv4 addresses, 
we need to use the in6_addr default struct (128 bits) as a key. 
Since <map> needs an object for which the '<' operator is defined, 
we cannot use in6_addr directly, so we wrap it in the my_in6_addr struct
for which we overload the '<' operator.
*/
struct my_in6_addr{
        struct in6_addr address;
#ifdef __cplusplus
        bool operator<(const struct my_in6_addr &rhs) const
         {
	   // memcmp should be enough to define an ordering over my_in6_addr
	   return (memcmp(&address,&rhs.address,sizeof(struct in6_addr)) < 0 );
	 }
#endif	
};

#ifdef __cplusplus
}



class DNSEntryIPv6 {
	typedef std::map<struct my_in6_addr, DNSEntryIPv6*> ServerIPv6Hashtable;
	typedef std::map<struct my_in6_addr, ServerIPv6Hashtable > IPv6Hashtable;
private:
	unsigned char *hostname;
	struct my_in6_addr *client_ip;
	struct my_in6_addr *servers;
	int *n_servers;
	struct in6_addr* dns_server;
	timeval* response_time;
	timeval* request_time;
public:
	void deleteReferences(IPv6Hashtable&);
	void destroyEntry();
	DNSEntryIPv6(
			unsigned char * fqdn,
			struct my_in6_addr client_ip,
			struct my_in6_addr* server_ip_list,
			int n_servers,
			struct in6_addr dns_server,
			timeval request_time,
			timeval response_time);
	DNSEntryIPv6();
	virtual ~DNSEntryIPv6();
	unsigned char* getHostname();
	struct in6_addr* getDNSServer();
	struct DNS_data_IPv6* getDNSData();
};

#endif
#endif /* DNSENTRY_IPV6_H_ */
