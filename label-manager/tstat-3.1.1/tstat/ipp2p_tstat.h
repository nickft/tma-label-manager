/*
This code is derived from IPP2P, an extension to iptables to identify P2P 
traffic, written by Eicke Friedrich and Klaus Degner <ipp2p@ipp2p.org>
Original code available at http://ipp2p.org/
*/

#ifndef __IPT_IPP2P_H

#define __IPT_IPP2P_H
#define IPP2P_VERSION "0.8.2"

struct ipt_p2p_info {
    int cmd;
    int debug;
};

#endif //__IPT_IPP2P_H

#define SHORT_HAND_IPP2P	1	/* --ipp2p switch */
//#define SHORT_HAND_DATA               4 /* --ipp2p-data switch*/
#define SHORT_HAND_NONE		5	/* no short hand */

#define IPP2P_EDK           1
#define IPP2P_DATA_KAZAA    2
#define IPP2P_DATA_EDK      3
#define IPP2P_DATA_DC       4
#define IPP2P_DC            5
#define IPP2P_DATA_GNU      6
#define IPP2P_GNU           7
#define IPP2P_KAZAA         8
#define IPP2P_BIT           9
#define IPP2P_APPLE         10
#define IPP2P_SOUL          11
#define IPP2P_WINMX         12
#define IPP2P_ARES          13
#define IPP2P_MUTE          14
#define IPP2P_WASTE         15
#define IPP2P_XDCC          16
#define IPP2P_KAD           17
#define IPP2P_KADU          18
#define IPP2P_PPLIVE		19
#define IPP2P_SOPCAST		20
#define IPP2P_TVANTS		21
#define IPP2P_DNS		    22
#define IPP2P_PPSTREAM      23
#define IPP2P_TEREDO		24
#define IPP2P_SIP		    25
#define IPP2P_DTLS		    26
#define IPP2P_QUIC		    27

int search_all_edk (const unsigned char *, const int, int);
int search_kazaa (const unsigned char *, const int, int);
int search_edk (const unsigned char *, const int, int);
int search_dc (const unsigned char *, const int, int);
int search_all_dc (const unsigned char *, const int, int);
int search_gnu (const unsigned char *, const int, int);
int search_all_gnu (const unsigned char *, const int, int);
int search_all_kazaa (const unsigned char *, const int, int);
int search_bittorrent (const unsigned char *, const int, int);
int search_apple (const unsigned char *, const int, int);
int search_soul (const unsigned char *, const int, int);
int search_winmx (const unsigned char *, const int, int);
int search_ares (const unsigned char *, const int, int);
int search_mute (const unsigned char *, const int, int);
int search_waste (const unsigned char *, const int, int);
int search_xdcc (const unsigned char *, const int, int);

int udp_search_kazaa (unsigned char *, const int, int);
int udp_search_bit (unsigned char *, const int, int);
int udp_search_gnu (unsigned char *, const int, int);
int udp_search_edk (unsigned char *, const int, int);
int udp_search_directconnect (unsigned char *, const int, int);
int udp_search_pplive (unsigned char *, const int, int);
int udp_search_sopcast (unsigned char *, const int, int);
int udp_search_tvants (unsigned char *, const int, int);
int udp_search_dns (unsigned char *, const int, int);
int udp_search_ppstream (unsigned char *, const int, int);
int udp_search_teredo (unsigned char *, const int, int);
int udp_search_sip (unsigned char *, const int, int);
int udp_search_dtls (unsigned char *, const int, int);
int udp_search_quic (unsigned char *, const int, int);

struct udpmatch
{
  int command;
  int short_hand;		/*for functions included in short hands */
  int packet_len;
  int (*function_name) (unsigned char *, const int, int);
};

struct tcpmatch
{
  int command;
  int short_hand;		/*for functions included in short hands */
  int packet_len;
  int (*function_name) (const unsigned char *, const int, int);
};
