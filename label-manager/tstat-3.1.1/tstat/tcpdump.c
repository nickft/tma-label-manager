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


#include <stdio.h>
#include <fcntl.h>
#include "tstat.h"

#ifdef GROK_TCPDUMP

#include "tcpdump.h"
#include <pcap.h>

extern Bool filter_specified;
extern Bool live_flag;
extern char *filter_filename;
extern char *dev;
extern eth_filter mac_filter; 
extern Bool internal_dhost;
extern Bool internal_shost;
extern Bool internal_eth (uint8_t *eth_addr, eth_filter *filter);

char *read_infile (char *fname);
void tcpdump_install_filter (pcap_t * pcap, bpf_u_int32 net);


/* global pointer, the pcap info header */
static pcap_t *pcap;

/* Snaplen for the live capture*/
extern int snaplen;

/* Interaction with pcap */
static struct ether_header eth_header;
#define EH_SIZE sizeof(struct ether_header)
static char *ip_buf;		/* [IP_MAXPACKET] */
static void *callback_plast;

struct pcap_pkthdr *callback_phdr;

/* (Courtesy Jeffrey Semke, Pittsburgh Supercomputing Center) */
/* locate ip within FDDI according to RFC 1188 */
static int
find_ip_fddi (unsigned char *buf, int iplen)
{
  unsigned char *ptr, *ptr2;
  int i;
  u_char pattern[] = { 0xAA, 0x03, 0x00, 0x00, 0x00, 0x08, 0x00 };
#define FDDIPATTERNLEN 7

  ptr = ptr2 = buf;

  for (i = 0; i < FDDIPATTERNLEN; i++)
    {
      ptr2 = memchr (ptr, pattern[i], (iplen - (int) (ptr - buf)));
      if (!ptr2)
	return (-1);
      if (i && (ptr2 != ptr))
	{
	  ptr2 = ptr2 - i - 1;
	  i = -1;
	}
      ptr = ptr2 + 1;
    }
  return (ptr2 - buf + 1);

}

/* This function determine the offset for the IP packet in an Ethernet frame */
/* We handle two cases : straight Ethernet encapsulation or PPPoE encapsulation */
/* Written by Yann Samama (ysamama@nortelnetworks.com) on july 18th, 2003 */
int
find_ip_eth (unsigned char *buf)
{
  unsigned short ppp_proto_type;	/* the protocol type field of the PPP header */
  unsigned short eth_proto_type;	/* the protocol type field of the Ethernet header */
  unsigned short vlan_proto_type;	/* the protocol type field of the VLAN header */
  int offset = -1;		/* the calculated offset that this function will return */
#ifndef USE_MEMCPY
  uint16_t *ptype;              /* pointer at the location of the field in the buffer */ 
#endif

#ifdef USE_MEMCPY
  memcpy (&eth_proto_type, buf + 12, 2);
  eth_proto_type = ntohs (eth_proto_type);
#else
  ptype = (uint16_t *)(buf+12);
  eth_proto_type = ntohs (*ptype);
#endif

  switch (eth_proto_type)
    {
    case ETHERTYPE_IPV6:	/* it's pure IPv6 over ethernet */
      offset = 14;
      break;
    case ETHERTYPE_IP:		/* it's pure IPv4 over ethernet */
      offset = 14;
      break;
    case ETHERTYPE_PPPOE_SESSION:	/* it's a PPPoE session */
#ifdef USE_MEMCPY
      memcpy (&ppp_proto_type, buf + 20, 2);
      ppp_proto_type = ntohs (ppp_proto_type);
#else
      ptype = (uint16_t *)(buf+20);
      ppp_proto_type = ntohs (*ptype);
#endif
      if (ppp_proto_type == 0x0021)	/* it's IP over PPPoE */
	offset = PPPOE_SIZE;
      break;
    case ETHERTYPE_8021Q:
      offset = 18;
#ifdef USE_MEMCPY
      memcpy (&vlan_proto_type, buf + 16, 2);
      vlan_proto_type = ntohs (vlan_proto_type);
#else
      ptype = (uint16_t *)(buf+16);
      vlan_proto_type = ntohs (*ptype);
#endif
      if (vlan_proto_type == ETHERTYPE_MPLS)	/* it's MPLS over VLAN */
        {
	  offset += 4; /* Skip 4 bytes of MPLS label*/
	}
      break;
    case ETHERTYPE_MPLS: /* it's IP over MPLS over Eth - skip 4 bytes of MPLS label */
      offset = 18;
      break;

    default:			/* well, this is not an IP packet */
      offset = -1;
      break;
    }
  return offset;
}



/* This function determine the offset for the IP packet in a PPP or HDLC PPP frame */
/* Written by Yann Samama (ysamama@nortelnetworks.com) on june 19th, 2003 */
static int
find_ip_ppp (unsigned char *buf)
{
  unsigned char ppp_byte0;	/* the first byte of the PPP frame */
  unsigned short ppp_proto_type;	/* the protocol type field of the PPP header */
  int offset = -1;		/* the calculated offset that this function will return */
#ifndef USE_MEMCPY
  uint16_t *ptype;              /* pointer at the location of the field in the buffer */ 
#endif

#ifdef USE_MEMCPY
  memcpy (&ppp_byte0, buf, 1);
#else
  ppp_byte0 = buf[0];
#endif
  switch (ppp_byte0)
    {
    case 0xff:			/* It is HDLC PPP encapsulation (2 bytes for HDLC and 2 bytes for PPP) */
#ifdef USE_MEMCPY
      memcpy (&ppp_proto_type, buf + 2, 2);
      ppp_proto_type = ntohs (ppp_proto_type);
#else
      ptype = (uint16_t *)(buf+2);
      ppp_proto_type = ntohs (*ptype);
#endif
      if (ppp_proto_type == 0x21)	/* That means HDLC PPP is encapsulating IP */
	offset = 4;
      else			/* That means PPP is *NOT* encapsulating IP */
	offset = -1;
      break;

    case 0x0f:			/* It is raw CISCO HDLC encapsulation of IP */
      offset = 	4;
      break;

    case 0x21:			/* It is raw PPP encapsulation of IP with compressed (1 byte) protocol field */
      offset = 1;
      break;

    case 0x00:			/* It is raw PPP encapsulation */
#ifdef USE_MEMCPY
      memcpy (&ppp_proto_type, buf, 2);
      ppp_proto_type = ntohs (ppp_proto_type);
#else
      ptype = (uint16_t *)(buf);
      ppp_proto_type = ntohs (*ptype);
#endif
      if (ppp_proto_type == 0x21)	/* It is raw PPP encapsulation of IP with uncompressed (2 bytes) protocol field */
	offset = 2;
      else			/* That means PPP is *NOT* encapsulating IP */
	offset = -1;
      break;

    default:			/* There is certainly not an IP packet there ... */
      offset = -1;
      break;
    }
  return offset;
}


static int
callback (char *user, struct pcap_pkthdr *phdr, unsigned char *buf)
{
    int type;
    int iplen;
    static int offset = -1;
#ifndef USE_MEMCPY
    struct ether_header *ptr_eth_header;
#endif

    iplen = phdr->caplen;
    if (iplen > IP_MAXPACKET)
        iplen = IP_MAXPACKET;

    type = pcap_datalink (pcap);

    /* remember the stuff we always save */
    callback_phdr = phdr;
    pcap_current_hdr = *phdr;
    pcap_current_buf = buf;
    if (debug > 2)
       fprintf (fp_stderr, "tcpdump: read a type %d frame\n", type);

    /* kindof ugly, but about the only way to make them fit together :-( */
    switch (type)
    {
        case 100:
            /* for some reason, the windows version of tcpdump is using */
            /* this.  It looks just like ethernet to me */
        case PCAP_DLT_EN10MB:
            offset = find_ip_eth (buf);	/* Here we check if we are dealing with Straight Ethernet encapsulation or PPPoE */
            iplen -= offset;
#ifdef USE_MEMCPY
            memcpy (&eth_header, buf, EH_SIZE);	/* save ether header */
#else
	    ptr_eth_header = (struct ether_header *)buf;
	    eth_header.ether_dhost = ptr_eth_header->ether_dhost; /* save ether destination MAC */
	    eth_header.ether_shost = ptr_eth_header->ether_shost; /* save ether souce MAC */
	    eth_header.ether_type = ptr_eth_header->ether_type; /* save ether type */
#endif
            /* check if this frame is coming in */
            internal_shost = internal_dhost = FALSE;
            if(internal_eth (eth_header.ether_shost, &mac_filter))
               internal_shost = TRUE;
            if(internal_eth (eth_header.ether_dhost, &mac_filter))
               internal_dhost = TRUE;

	    /* now get rid of ethernet headers */
            switch (offset)
            {
                case -1:		/* Not an IP packet */
                    return (-1);
                case EH_SIZE:		/* straight Ethernet encapsulation */
#ifdef USE_MEMCPY
                    memcpy ((char *) ip_buf, buf + offset, iplen);
#else
		    ip_buf = (char *)(buf + offset);
#endif
                    callback_plast = ip_buf + iplen - 1;
                    break;
                case PPPOE_SIZE:	/* PPPoE encapsulation */
                //case MPLS8021Q_SIZE:		/* VLAN-MPLS encapsulation - same len*/
                    /* we use a fake ether type here */
                    eth_header.ether_type = htons (ETHERTYPE_IP);
#ifdef USE_MEMCPY
                    memcpy ((char *) ip_buf, buf + offset, iplen);
#else
		    ip_buf = (char *)(buf + offset);
#endif
                    callback_plast = ip_buf + iplen - 1;
                    break;
                case IEEE8021Q_SIZE:	/* VLAN encapsulation */
                //case MPLS_SIZE:			/* MPLS encapsulation - same len*/
                    /* we use a fake ether type here */
                    eth_header.ether_type = htons (ETHERTYPE_IP);
#ifdef USE_MEMCPY
                    memcpy ((char *) ip_buf, buf + offset, iplen);
#else
		    ip_buf = (char *)(buf + offset);
#endif
                    callback_plast = ip_buf + iplen - 1;
                    break;
                default:		/* should not be used, but we never know ... */
                    return (-1);
            }
            break;
        case PCAP_DLT_IEEE802:
            /* just pretend it's "normal" ethernet */
            offset = 14;		/* 22 bytes of IEEE cruft */
#ifdef USE_MEMCPY
            memcpy (&eth_header, buf, EH_SIZE);	/* save ether header */
#else
	    ptr_eth_header = (struct ether_header *)buf;
	    eth_header.ether_type = ptr_eth_header->ether_type; /* save ether type */
#endif
            iplen -= offset;
#ifdef USE_MEMCPY
            memcpy (ip_buf, buf + offset, iplen);
#else
	    ip_buf = (char *)(buf + offset);
#endif
            callback_plast = (char *) ip_buf + iplen - 1;
            break;
        case PCAP_DLT_SLIP:
#ifdef USE_MEMCPY
            memcpy (ip_buf, buf + 16, iplen);
#else
            ip_buf = (char *)(buf + 16);
#endif
            iplen -= 16;
            callback_plast = (char *) ip_buf + iplen - 1;
            break;
        case PCAP_DLT_PPP:
            /* deals with raw PPP and also with HDLC PPP frames */
            offset = find_ip_ppp (buf);
            if (offset < 0)		/* Not an IP packet */
                return (-1);
            iplen -= offset;
#ifdef USE_MEMCPY
            memcpy ((char *) ip_buf, buf + offset, iplen);
#else
	    ip_buf = (char *)(buf + offset);
#endif
            callback_plast = ip_buf + iplen - 1;
            break;
        case PCAP_DLT_FDDI:
            if (offset < 0)
                offset = find_ip_fddi (buf, iplen);
            if (offset < 0)
                return (-1);
            iplen -= offset;
#ifdef USE_MEMCPY
            memcpy ((char *) ip_buf, buf + offset, iplen);
#else
	    ip_buf = (char *)(buf + offset);
#endif
            callback_plast = ip_buf + iplen - 1;
            break;
        case PCAP_DLT_NULL:
            /* no phys header attached */
            offset = 4;
            iplen -= offset;
#ifdef USE_MEMCPY
            memcpy ((char *) ip_buf, buf + offset, iplen);
#else
	    ip_buf = (char *)(buf + offset);
#endif
            callback_plast = ip_buf + iplen - 1;
            /* we use a fake ether type here */
            eth_header.ether_type = htons (ETHERTYPE_IP);
            break;
        case PCAP_DLT_ATM_RFC1483:
            /* ATM RFC1483 - LLC/SNAP ecapsulated atm */
            iplen -= 8;
#ifdef USE_MEMCPY
            memcpy ((char *) ip_buf, buf + 8, iplen);
#else
	    ip_buf = (char *)(buf + 8);
#endif
            callback_plast = ip_buf + iplen - 1;
            break;
        case PCAP_DLT_RAW:
            /* raw IP */
            offset = 0;
            iplen -= offset;
#ifdef USE_MEMCPY
            memcpy ((char *) ip_buf, buf + offset, iplen);
#else
	    ip_buf = (char *)(buf + offset);
#endif
            callback_plast = ip_buf + iplen - 1;
            break;
        case PCAP_DLT_LINUX_SLL:
            /* linux cooked socket */
            offset = 16;
            iplen -= offset;
#ifdef USE_MEMCPY
            memcpy ((char *) ip_buf, buf + offset, iplen);
#else
	    ip_buf = (char *)(buf + offset);
#endif
            callback_plast = ip_buf + iplen - 1;
            break;
            // Patch sent by Brandon Eisenamann to passby 802.11, LLC/SNAP
            // and Prism2 headers to get to the IP packet.
        case PCAP_DLT_IEEE802_11:
            offset = 24 + 8;		// 802.11 header + LLC/SNAP header
            iplen -= offset;
#ifdef USE_MEMCPY
            memcpy ((char *) ip_buf, buf + offset, iplen);
#else
	    ip_buf = (char *)(buf + offset);
#endif
            callback_plast = ip_buf + iplen - 1;
            break;
        case PCAP_DLT_IEEE802_11_RADIO:
            offset = 64 + 24;		//WLAN header + 802.11 header
            iplen -= offset;
#ifdef USE_MEMCPY
            memcpy (&eth_header, buf, EH_SIZE);	// save ethernet header
            memcpy ((char *) ip_buf, buf + offset, iplen);
#else
	    ptr_eth_header = (struct ether_header *)buf;
	    eth_header.ether_type = ptr_eth_header->ether_type; /* save ether type */
	    ip_buf = (char *)(buf + offset);
#endif
            callback_plast = ip_buf + iplen - 1;
            break;
        case PCAP_DLT_PRISM2:
            offset = 144 + 24 + 8;	// PRISM2+IEEE 802.11+ LLC/SNAP headers
            iplen -= offset;
#ifdef USE_MEMCPY
            memcpy ((char *) ip_buf, buf + offset, iplen);
#else
	    ip_buf = (char *)(buf + offset);
#endif
            callback_plast = ip_buf + iplen - 1;
            break;
        case PCAP_DLT_C_HDLC:
            offset = 4;
            iplen -= offset;
#ifdef USE_MEMCPY
            memcpy ((char *) ip_buf, buf + offset, iplen);
#else
	    ip_buf = (char *)(buf + offset);
#endif
            callback_plast = (char *) ip_buf + iplen - 1;
            break;
        default:
            fprintf (fp_stderr, "Don't understand link-level format (%d)\n", type);

            exit (1);
    }

    return (0);
}


int
pread_tcpdump (struct timeval *ptime,
	       int *plen,
	       int *ptlen,
	       void **pphys, int *pphystype, struct ip **ppip, void **pplast)
{
  int ret;

  while (1)
    {
      if ((ret = pcap_dispatch (pcap, 1, (pcap_handler) callback, 0)) != 1)
	{
	  /* prob EOF */

	  if (ret == -1)
	    {
	      char *error;
	      error = pcap_geterr (pcap);

	      if (error && *error)
		fprintf (fp_stderr, "PCAP error: '%s'\n", pcap_geterr (pcap));
	      /* else, it's just EOF */
	      return (-1);
	    }

	  /* in live capture is just a packet filter by kernel */
	  if (live_flag)
	    continue;

	  /* from a file itshould be an EOF */
	  return (0);
	}

      /* at least one tcpdump implementation (AIX) seems to be */
      /* storing NANOseconds in the usecs field of the timestamp. */
      /* This confuses EVERYTHING.  Try to compensate. */
      {
	static Bool bogus_nanoseconds = FALSE;
	if ((pcap_current_hdr.ts.tv_usec >= US_PER_SEC) || (bogus_nanoseconds))
	  {
	    if (!bogus_nanoseconds)
	      {
		fprintf (fp_stderr,
			 "tcpdump: attempting to adapt to bogus nanosecond timestamps\n");
		bogus_nanoseconds = TRUE;
	      }
	    pcap_current_hdr.ts.tv_usec /= 1000;
	  }
      }

      /* fill in all of the return values */
      *pphys = &eth_header;	/* everything assumed to be ethernet */
      *pphystype = PHYS_ETHER;	/* everything assumed to be ethernet */
      *ppip = (struct ip *) ip_buf;
      *pplast = callback_plast;	/* last byte in IP packet */
      /* (copying time structure in 2 steps to avoid RedHat brain damage) */
      ptime->tv_usec = pcap_current_hdr.ts.tv_usec;
      ptime->tv_sec = pcap_current_hdr.ts.tv_sec;
      *plen = pcap_current_hdr.len;
      *ptlen = pcap_current_hdr.caplen;

      /* if it's not IP, then skip it */
      if ((ntohs (eth_header.ether_type) != ETHERTYPE_IP) &&
	  (ntohs (eth_header.ether_type) != ETHERTYPE_IPV6))
	{
	  if (debug > 2)
	    fprintf (fp_stderr, "pread_tcpdump: not an IP packet\n");
	  continue;
	}

      return (1);
    }
}


pread_f *
is_tcpdump (char *filename)
{
  char errbuf[100];
  char *physname = "<unknown>";
  int type;

#ifdef __WIN32
  if ((pcap = pcap_open_offline (filename, errbuf)) == NULL)
    {
#else
  if ((pcap = pcap_open_offline ("-", errbuf)) == NULL)
    {
#endif /* __WIN32 */
      if (debug > 2)
	fprintf (fp_stderr, "PCAP said: '%s'\n", errbuf);
      rewind (stdin);
      return (NULL);
    }

  tcpdump_install_filter (pcap, 0);

  if (debug)
    {
      fprintf (fp_stdout, "Using 'pcap' version of tcpdump\n");
      if (debug > 1)
	{
	  fprintf (fp_stdout, "\tversion_major: %d\n", pcap_major_version (pcap));
	  fprintf (fp_stdout, "\tversion_minor: %d\n", pcap_minor_version (pcap));
	  fprintf (fp_stdout, "\tsnaplen: %d\n", pcap_snapshot (pcap));
	  fprintf (fp_stdout, "\tlinktype: %d\n", pcap_datalink (pcap));
	  fprintf (fp_stdout, "\tswapped: %d\n", pcap_is_swapped (pcap));
	}
    }

  /* check the phys type (pretend everything is ethernet) */
  memset (&eth_header, 0, EH_SIZE);
  switch (type = pcap_datalink (pcap))
    {
    case 100:
    case PCAP_DLT_EN10MB:
      /* OK, we understand this one */
      physname = "Ethernet";
      break;
    case PCAP_DLT_IEEE802:
      /* just pretend it's normal ethernet */
      physname = "Ethernet";
      break;
    case PCAP_DLT_SLIP:
      eth_header.ether_type = htons (ETHERTYPE_IP);
      physname = "Slip";
      break;
    case PCAP_DLT_PPP:
      eth_header.ether_type = htons (ETHERTYPE_IP);
      physname = "PPP or HDLC PPP";
      break;
    case PCAP_DLT_FDDI:
      eth_header.ether_type = htons (ETHERTYPE_IP);
      physname = "FDDI";
      break;
    case PCAP_DLT_NULL:
      eth_header.ether_type = htons (ETHERTYPE_IP);
      physname = "NULL";
      break;
    case PCAP_DLT_ATM_RFC1483:
      eth_header.ether_type = htons (ETHERTYPE_IP);
      physname = "ATM, LLC/SNAP encapsulated";
      break;
    case PCAP_DLT_RAW:
      eth_header.ether_type = htons (ETHERTYPE_IP);
      physname = "RAW_IP";
      break;
    case PCAP_DLT_LINUX_SLL:
      /* linux cooked socket type */
      eth_header.ether_type = htons (ETHERTYPE_IP);
      physname = "Linux Cooked Socket";
      break;
    case PCAP_DLT_IEEE802_11:
      eth_header.ether_type = htons (ETHERTYPE_IP);
      physname = "IEEE802_11";
      break;
    case PCAP_DLT_IEEE802_11_RADIO:
      eth_header.ether_type = htons (ETHERTYPE_IP);
      physname = "IEEE802_11_RADIO";
      break;
    case PCAP_DLT_PRISM2:
      eth_header.ether_type = htons (ETHERTYPE_IP);
      physname = "PRISM2";
      break;
    case PCAP_DLT_C_HDLC:
      eth_header.ether_type = htons (ETHERTYPE_IP);
      physname = "Cisco HDLC";
      break;
    default:
      fprintf (fp_stderr, "tcptrace did not understand link format (%d)!\n",
	       type);
      fprintf (fp_stderr,
	       "\t If you can give us a capture file with this link format\n\
\t or even better, a patch to decipher this format, we shall add it in, \n\
\t in a future release.\n");
      rewind (stdin);
      return (NULL);
    }

  if (debug)
    fprintf (fp_stderr, "Tcpdump format, physical type is %d (%s)\n",
	     type, physname);

  /* set up some stuff */
  ip_buf = MallocZ (IP_MAXPACKET);


  return (pread_tcpdump);
}


void
tcpdump_install_filter (pcap_t * pcap, bpf_u_int32 net)
{

  struct bpf_program filter_comp;	/* The compiled filter expression */
  char *filter_string;

  if (filter_specified)
    {
      filter_string = read_infile (filter_filename);
      if (debug > 1)
	fprintf (fp_stdout, "Compiling filter '%s'\n", filter_string);

      if (pcap_compile (pcap, &filter_comp, filter_string, 1, net) < 0)
	{
	  fprintf (fp_stderr, "pcap_compile: %s\n", pcap_geterr (pcap));
	  exit (1);
	}

      if (pcap_setfilter (pcap, &filter_comp) < 0)
	{
	  fprintf (fp_stderr, "pcap_setfilter: %s\n", pcap_geterr (pcap));
	  exit (1);
	}
    }
}

pread_f *
init_live_tcpdump (char *filename)
{
  char errbuf[PCAP_ERRBUF_SIZE];

  if (dev == NULL)
    dev = pcap_lookupdev (errbuf);

  if (dev == NULL)
    {
      fprintf (fp_stderr, "%s\n ", errbuf);
      exit (1);
    }

  pcap = pcap_open_live (dev, snaplen, TRUE, 1000, errbuf);

  if (pcap == NULL)
    {
      fprintf (fp_stderr, "pcap_openlive: %s\n", errbuf);
      exit (1);
    }
  else if (*errbuf)
    {
      fprintf (fp_stderr, "pcap_openlive: %s\n", pcap_geterr (pcap));
    }


  /* put it in a blocking mode */
  if (pcap_setnonblock (pcap, 0, errbuf) < 0)
    {
      fprintf (fp_stderr, "pcap_setnonblock: %s\n", pcap_geterr (pcap));
      exit (1);
    }

  tcpdump_install_filter (pcap, 0);

  fprintf (fp_stdout, "Live capturing on: %s - snaplen = %d\n", dev, snaplen);


  memset (&eth_header, 0, EH_SIZE);
  /*
   Not the best solution, but force the payload type to be
   ETHERTYPE_IP also for pcap live capture, as done when reading
   from file.
  */
  eth_header.ether_type = htons (ETHERTYPE_IP);
  ip_buf = MallocZ (IP_MAXPACKET);
  return (pread_tcpdump);
}

/* support for writing a new pcap file */

void
PcapSavePacket (char *filename, struct ip *pip, void *plast)
{
  static MFILE *f_savefile = NULL;
  struct pcap_pkthdr phdr;
  int wlen;

  if (f_savefile == NULL)
    {
      struct pcap_file_header fhdr;

      /* try to open the file */
      if ((f_savefile = Mfopen (filename, "w")) == NULL)
	{
	  fprintf (fp_stderr, "%s: %s\n", filename, strerror(errno));
	  exit (-1);
	}

      /* make up the header info it wants */
      /* this comes from version 2.4, no pcap routine handy :-(  */
      fhdr.magic = TCPDUMP_MAGIC;
      fhdr.version_major = PCAP_VERSION_MAJOR;
      fhdr.version_minor = PCAP_VERSION_MINOR;

      fhdr.thiszone = 0;	/* don't have this info, just make it up */
      fhdr.snaplen = 1000000;	/* don't have this info, just make it up */
      fhdr.linktype = PCAP_DLT_EN10MB;	/* always Ethernet (10Mb) */
      fhdr.sigfigs = 0;

      /* write the header */
      Mfwrite ((char *) &fhdr, sizeof (fhdr), 1, f_savefile);

      if (debug)
	fprintf (fp_stderr, "Created pcap save file '%s'\n", filename);
    }

  /* create the packet header */
  /* (copying time structure in 2 steps to avoid RedHat brain damage) */
  phdr.ts.tv_sec = current_time.tv_sec;
  phdr.ts.tv_usec = current_time.tv_usec;
  phdr.caplen = (char *) plast - (char *) pip + 1;
  phdr.caplen += EH_SIZE;	/* add in the ether header */
  phdr.len = EH_SIZE + ntohs (PIP_LEN (pip));	/* probably this */

  /* write the packet header */
  Mfwrite (&phdr, sizeof (phdr), 1, f_savefile);

  /* write a (bogus) ethernet header */
  memset (&eth_header, 0, EH_SIZE);
  eth_header.ether_type = htons (ETHERTYPE_IP);
  Mfwrite (&eth_header, sizeof (eth_header), 1, f_savefile);

  /* write the IP/TCP parts */
  wlen = phdr.caplen - EH_SIZE;	/* remove the ether header */
  Mfwrite (pip, wlen, 1, f_savefile);
}


/* courtesely from tcpdump source... */
/* make a clean exit on interrupts */
void
tcpdump_cleanup (FILE * wheref)
{
  struct pcap_stat stat;

  fprintf (fp_stderr, "\nLive pcap_stats:");
  /* Can't print the summary if reading from a savefile */
  if (pcap != NULL && pcap_file (pcap) == NULL)
    {
      fflush (wheref);
      putc ('\n', wheref);
      if (pcap_stats (pcap, &stat) < 0)
	fprintf (wheref, "pcap_stats: %s\n", pcap_geterr (pcap));
      else
	{
	  fprintf (wheref, "%d packets received by filter\n", stat.ps_recv);
	  fprintf (wheref, "%d packets dropped by kernel\n", stat.ps_drop);
	}
    }
}

char *
read_infile (char *fname)
{
  int fd, cc;
  char *cp;
  struct stat buf;

  fd = open (fname, O_RDONLY);
  if (fd < 0)
    {
      fprintf (fp_stderr, "can't open %s\n", fname);
      exit (1);
    }

  if (fstat (fd, &buf) < 0)
    {
      fprintf (fp_stderr, "can't stat %s\n", fname);
      exit (1);
    }

  cp = malloc ((u_int) buf.st_size + 1);
  cc = read (fd, cp, (int) buf.st_size);
  if (cc < 0)
    {
      fprintf (fp_stderr, "read %s\n", fname);
      exit (1);
    }
  if (cc != buf.st_size)
    {
      fprintf (fp_stderr, "short read %s (%d != %d)\n", fname, cc,
	       (int) buf.st_size);
      exit (1);
    }
  cp[(int) buf.st_size] = '\0';

  return (cp);
}

#else /* GROK_TCPDUMP */

void
PcapSavePacket (char *filename, struct ip *pip, void *plast)
{
  fprintf (fp_stderr, "\
Sorry, packet writing only supported with the pcap library\n\
compiled into the program (See GROK_TCPDUMP)\n");
  exit (-2);
}

#endif /* GROK_TCPDUMP */
