#ifndef _YMSG_H_
#define _YMSG_H_

#include <sys/types.h>


/* Keyword definitions for fast compare */
/* considering both byte orders         */

#if(BYTE_ORDER == BIG_ENDIAN)
#define YMSG 0x594d5347UL
#else
#define YMSG 0x47534d59UL
#endif


enum ymsg_flow_type
{ YFT_UNKNOWN = 0, YMSG_LOGIN, YMSG_PRESENCE, YMSG_CHAT, YMSG_PRESENCE_CHAT,
  YMSG_P2P, YMSG_YMSG = 9
};

#endif
