#ifdef __ANDROID__

/* Get definition of `struct ether_addr'.  */

#include <netinet/ether.h>

char *ether_ntoa_r (const struct ether_addr *, char *);
char *ether_ntoa (const struct ether_addr *);
struct ether_addr *ether_aton_r (const char *, struct ether_addr *);
struct ether_addr *ether_aton (const char *);

#endif
