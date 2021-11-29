#ifndef _MSN_H_
#define _MSN_H_

#include <sys/types.h>

/* define this if you want the unknown MSN commands to be logged */
/* #define MSN_OTHER_COMMANDS */


/* Max len of the command counter to skip */
#define MAX_COUNTER_NAME 4

/* Keyword definitions for fast compare */
/* considering both byte orders         */

#if(BYTE_ORDER == BIG_ENDIAN)
#define VER 0x56455220UL
#define CVR 0x43565220UL
#define USR 0x55535220UL
#define XFR 0x58465220UL
#define GCF 0x47434620UL
#define PNG 0x504e470dUL
#define QNG 0x514e4720UL
#define CHL 0x43484c20UL
#define QRY 0x51525920UL
#define CAL 0x43414c20UL
#define JOI 0x4a4f4920UL
#define RNG 0x524e4720UL
#define ANS 0x414e5320UL
#define IRO 0x49524f20UL
#define MSG 0x4d534720UL
#define UUM 0x55554d20UL
#define UBM 0x55424d20UL
#define ACK 0x41434b20UL
#define BYE 0x42594520UL
#define OUT 0x4f555420UL
#define OUT_SB 0x4f55540dUL
#else
#define VER 0x20524556UL
#define CVR 0x20525643UL
#define USR 0x20525355UL
#define XFR 0x20524658UL
#define GCF 0x20464347UL
#define PNG 0x0d474e50UL
#define QNG 0x20474e51UL
#define CHL 0x204c4843UL
#define QRY 0x20595251UL
#define CAL 0x204c4143UL
#define JOI 0x20494f4aUL
#define RNG 0x20474e52UL
#define ANS 0x20534e41UL
#define IRO 0x204f5249UL
#define MSG 0x2047534dUL
#define UUM 0x204d5555UL
#define UBM 0x204d4255UL
#define ACK 0x204b4341UL
#define BYE 0x20455942UL
#define OUT 0x2054554fUL
#define OUT_SB 0x0d54554fUL
#endif


enum msn_flow_type
{ MFT_UNKNOWN =
    0, MSN_LOGIN, MSN_PRESENCE, MSN_CHAT, MSN_HTTP_TUNNELING, MSN_CHAT_CALLER,
  MSN_CHAT_CALLED
};

#endif
