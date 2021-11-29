/*
 *
 * Copyright (c) 2001
 *	Politecnico di Torino.  All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * For bug report and other information please visit Tstat site:
 * http://tstat.polito.it
 *
 * Tstat is deeply based on TCPTRACE. The authors would like to thank
 * Shawn Ostermann for the development of TCPTRACE.
 *
*/


#define	SWAPLONG(y) \
((((y)&0xff)<<24) | (((y)&0xff00)<<8) | (((y)&0xff0000)>>8) | (((y)>>24)&0xff))
#define	SWAPSHORT(y) \
	( (((y)&0xff)<<8) | (((y)&0xff00)>>8) )



/* (from bpf.h)
 * Data-link level type codes.
 */

/* Note - Tue Feb 13, 2001
   We're having trouble with the standard DLT_type because some OS versions,
   insist on renumbering these to different values.  To avoid the problem,
   we're hijacking the types a little and adding the PCAP_ prefix.  The
   constants all correspond to the "true" pcap numbers, so this should
   fix the problem */

/* currently supported */
#define PCAP_DLT_NULL		0	/* no link-layer encapsulation */
#define PCAP_DLT_EN10MB		1	/* Ethernet (10Mb) */
#define PCAP_DLT_IEEE802	6	/* IEEE 802 Networks */
#define PCAP_DLT_SLIP		8	/* Serial Line IP */
#define PCAP_DLT_PPP            9	/* Point-to-Point Protocol */
#define PCAP_DLT_FDDI		10	/* FDDI */
#define PCAP_DLT_ATM_RFC1483	11	/* LLC/SNAP encapsulated atm */
#define PCAP_DLT_RAW		12	/* raw IP */
#define PCAP_DLT_C_HDLC         104	/* Cisco HDLC */
#define PCAP_DLT_IEEE802_11     105	/* IEEE 802.11 wireless */
#define PCAP_DLT_LINUX_SLL      113	/* Linux cooked socket */
#define PCAP_DLT_PRISM2         119	/* Prism2 raw capture header */
#define PCAP_DLT_IEEE802_11_RADIO 127	/* 802.11 plus WLAN header */
#define	PCAP_DLT_8021Q		/* 802.1q encapsulation */

/* NOT currently supported */
/* (mostly because I don't have an example file, send me one...) */
#define PCAP_DLT_EN3MB		2	/* Experimental Ethernet (3Mb) */
#define PCAP_DLT_AX25		3	/* Amateur Radio AX.25 */
#define PCAP_DLT_PRONET		4	/* Proteon ProNET Token Ring */
#define PCAP_DLT_CHAOS		5	/* Chaos */
#define PCAP_DLT_ARCNET		7	/* ARCNET */
#define PCAP_DLT_SLIP_BSDOS	13	/* BSD/OS Serial Line IP */
#define PCAP_DLT_PPP_BSDOS	14	/* BSD/OS Point-to-point Protocol */



/* tcpdump file header */
#define TCPDUMP_MAGIC 0xa1b2c3d4

struct dump_file_header
{
  u_int magic;
  u_short version_major;
  u_short version_minor;
  int thiszone;			/* gmt to local correction */
  u_int sigfigs;		/* accuracy of timestamps */
  u_int snaplen;		/* max length saved portion of each pkt */
  u_int linktype;		/* data link type (PCAP_DLT_*) */
};


/*
 * Each packet in the dump file is prepended with this generic header.
 * This gets around the problem of different headers for different
 * packet interfaces.
 */
struct packet_header
{
  u_int ts_secs;		/* time stamp -- seconds */
  u_int ts_usecs;		/* time stamp -- useconds */
  u_int caplen;			/* length of portion present */
  u_int len;			/* length of this packet (off wire) */
};

struct pcap_pkthdr pcap_current_hdr;
unsigned char *pcap_current_buf;


#ifdef BY_HAND
static void
swap_hdr (struct dump_file_header *pdfh)
{
  pdfh->version_major = SWAPSHORT (pdfh->version_major);
  pdfh->version_minor = SWAPSHORT (pdfh->version_minor);
  pdfh->thiszone = SWAPLONG (pdfh->thiszone);
  pdfh->sigfigs = SWAPLONG (pdfh->sigfigs);
  pdfh->snaplen = SWAPLONG (pdfh->snaplen);
  pdfh->linktype = SWAPLONG (pdfh->linktype);
}

static void
swap_phdr (struct packet_header *pph)
{
  pph->caplen = SWAPLONG (pph->caplen);
  pph->len = SWAPLONG (pph->len);
  pph->ts_secs = SWAPLONG (pph->ts_secs);
  pph->ts_usecs = SWAPLONG (pph->ts_usecs);
}
#endif /* BY_HAND */
