#ifndef _JABBER_H_
#define _JABBER_H_

#include <sys/types.h>


/* Keyword definitions for fast compare */
/* considering both byte orders         */

#if(BYTE_ORDER == BIG_ENDIAN)
#define XMPP_SMELL 0x3c737472UL		/* <str */
#define XMPP_PRESENCE 0x3c707265UL	/* <pre */
#define XMPP_MESSAGE 0x3c6d6573UL	/* <mes */
#else
#define XMPP_SMELL 0x7274733cUL		/* <str */
#define XMPP_PRESENCE 0x6572703cUL	/* <pre */
#define XMPP_MESSAGE 0x73656d3cUL	/* <mes */
#endif


enum jabber_flow_type
{ JFT_UNKNOWN = 0, JABBER_LOGIN, JABBER_PRESENCE, JABBER_CHAT
};

#endif
