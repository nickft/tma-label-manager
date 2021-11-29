#ifndef CRYPTO_H
#define CRYPTO_H
#include <inttypes.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

void      initialize_crypto(int , char *, char *);
void      encrypt_init(char *, int );
uint32_t  encrypt_ip(uint32_t );
void      store_crypto_ip(struct in_addr *);
in_addr_t retrieve_crypto_ip(struct in_addr *);
char      *HostNameEncrypted(ipaddr );

#ifdef SUPPORT_IPV6
void      encrypt_ipv6(struct in6_addr *,struct in6_addr *);
void      store_crypto_ipv6(struct in6_addr *);
struct in6_addr *retrieve_crypto_ipv6(struct in6_addr *);
#endif

#define CPKEY_RANDOM 1
#define CPKEY_FILE   2
#define CPKEY_FILE64 3
#define CPKEY_CLI    4

#endif
