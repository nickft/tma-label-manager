/* Android misses the _BSD_SOURCE version of tcphrd, so we must */
/* redefine it */

#ifdef __ANDROID__

typedef u_int32_t tcp_seq;
/*
 * TCP header.
 * Per RFC 793, September, 1981.
 */
struct tcphdr
  {
    u_int16_t th_sport;         /* source port */
    u_int16_t th_dport;         /* destination port */
    tcp_seq th_seq;             /* sequence number */
    tcp_seq th_ack;             /* acknowledgement number */
#  if __BYTE_ORDER == __LITTLE_ENDIAN
    u_int8_t th_x2:4;           /* (unused) */
    u_int8_t th_off:4;          /* data offset */
#  endif
#  if __BYTE_ORDER == __BIG_ENDIAN
    u_int8_t th_off:4;          /* data offset */
    u_int8_t th_x2:4;           /* (unused) */
#  endif
    u_int8_t th_flags;
#  define TH_FIN        0x01
#  define TH_SYN        0x02
#  define TH_RST        0x04
#  define TH_PUSH       0x08
#  define TH_ACK        0x10
#  define TH_URG        0x20
    u_int16_t th_win;           /* window */
    u_int16_t th_sum;           /* checksum */
    u_int16_t th_urp;           /* urgent pointer */
};

# define TCPOPT_EOL             0
# define TCPOPT_NOP             1
# define TCPOPT_MAXSEG          2
# define TCPOLEN_MAXSEG         4
# define TCPOPT_WINDOW          3
# define TCPOLEN_WINDOW         3
# define TCPOPT_SACK_PERMITTED  4               /* Experimental */
# define TCPOLEN_SACK_PERMITTED 2
# define TCPOPT_SACK            5               /* Experimental */
# define TCPOPT_TIMESTAMP       8
# define TCPOLEN_TIMESTAMP      10
# define TCPOLEN_TSTAMP_APPA    (TCPOLEN_TIMESTAMP+2) /* appendix A */

# define TCPOPT_TSTAMP_HDR      \
    (TCPOPT_NOP<<24|TCPOPT_NOP<<16|TCPOPT_TIMESTAMP<<8|TCPOLEN_TIMESTAMP)

#endif /* __ANDROID__ */
