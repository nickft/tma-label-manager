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
 * Author:	Marco Mellia, Andrea Carpani, Luca Muscariello, Dario Rossi
 * 		Telecomunication Networks Group
 * 		Politecnico di Torino
 * 		Torino, Italy
 *              http://www.tlc-networks.polito.it/index.html
 *		mellia@mail.tlc.polito.it, rossi@mail.tlc.polito.it
 *
 * Tstat is deeply based on TCPTRACE. The authors would like to thank
 * Shawn Ostermann for the development of TCPTRACE.
 *
*/

#include "pcapwrapper.h"

/* global pointer, the pcap info header */
static pcap_t *pcap;

/* Interaction with pcap */
static struct ether_header eth_header;
static struct pcap_pkthdr pcap_current_hdr;
static unsigned char *pcap_current_buf;

#define EH_SIZE sizeof(struct ether_header)
static char *ip_buf;		/* [IP_MAXPACKET] */
static void *callback_plast;

struct pcap_pkthdr *callback_phdr;


#define PCAP_DLT_EN10MB 1   
#define ETHERTYPE_8021Q 0x8100
#define IEEE8021Q_SIZE  18

/* This function determine the offset for the IP packet in an Ethernet frame */
static int
find_ip_in_ethframe (char *buf)
{
  unsigned short eth_proto_type;	/* the protocol type field of the Ethernet header */
  int offset = -1;		/* the calculated offset that this function will return */

  memcpy (&eth_proto_type, buf + 12, 2);
  eth_proto_type = ntohs (eth_proto_type);
  switch (eth_proto_type)
    {
    case ETHERTYPE_IP:		/* it's pure IPv4 over ethernet */
      offset = 14;
      break;
    case ETHERTYPE_8021Q: //VLAN
      offset = 18;
      break;
    default:			/* well, this is not an IP packet */
      offset = -1;
      break;
    }
  return offset;
}

/* function invoked by pcap library to handle a 
 * new packet captured (or readed for input trace)
 */
static int
read_pckt_callback (char *user, struct pcap_pkthdr *phdr, char *buf)
{
    int type;
    int iplen;
    static int offset = -1;

    iplen = phdr->caplen;
    if (iplen > IP_MAXPACKET)
        iplen = IP_MAXPACKET;

    type = pcap_datalink (pcap);

    /* remember the stuff we always save */
    callback_phdr = phdr;
    pcap_current_hdr = *phdr;
    pcap_current_buf = buf;

    /* kindof ugly, but about the only way to make them fit together :-( */
    switch (type)
    {
        case 100:
            /* for some reason, the windows version of tcpdump is using */
            /* this.  It looks just like ethernet to me */
        case PCAP_DLT_EN10MB:
            /* Here we check if we are dealing with Straight Ethernet encapsulation or PPPoE */
            offset = find_ip_in_ethframe (buf);	
            iplen -= offset;
            memcpy (&eth_header, buf, EH_SIZE);	/* save ether header */
            switch (offset)
            {
                /* Not an IP packet */
                case -1:
                    return (-1);

                /* straight Ethernet encapsulation */
                case EH_SIZE:
                    memcpy ((char *) ip_buf, buf + offset, iplen);
                    callback_plast = ip_buf + iplen - 1;
                    break;

                /* VLAN encapsulation */
                case IEEE8021Q_SIZE:
                  /* we use a fake ether type here */
                  eth_header.ether_type = htons (ETHERTYPE_IP);
                  memcpy ((char *) ip_buf, buf + offset, iplen);
                  callback_plast = ip_buf + iplen - 1;
                  break;

                /* should not be used, but we never know ... */
                default:		
                    return (-1);
            }
            break;
        default:
            fprintf (stderr, "Don't understand link-level format (%d)\n", type);
            exit (1);
    }

    /* everything fine */
    return 0;
}


/* internal function to read packet using pcap library */
int
read_pckt (struct timeval *ptime, 
               struct ip **ppip, 
               void **pplast, 
               int *ptlen)
{
    int ret;

    while (1)
    {
        /* registering a callback function so we can analize packet
         * readed using pcap library
         */
        if ((ret = pcap_dispatch (pcap, 1, (pcap_handler) read_pckt_callback, 0)) != 1)
        {
            /* prob EOF */
            if (ret == -1)
            {
                char *error;
                error = pcap_geterr (pcap);

                if (error && *error)
                    fprintf (stderr, "PCAP error: '%s'\n", pcap_geterr (pcap));
                /* else, it's just EOF */
                return (-1);
            }

            /* from a file itshould be an EOF */
            return (0);
        }

        /* if it's not IP, then skip it */
        if (ntohs (eth_header.ether_type) != ETHERTYPE_IP)
        {
            fprintf (stderr, "pread_tcpdump: not an IP packet (type=%d)\n", eth_header.ether_type);
            continue;
        }
        break;

    }

    /* fill in all of the return values */
    *ppip = (struct ip *) ip_buf;
    *pplast = callback_plast;	/* last byte in IP packet */
    /* (copying time structure in 2 steps to avoid RedHat brain damage) */
    ptime->tv_usec = callback_phdr->ts.tv_usec;
    ptime->tv_sec = callback_phdr->ts.tv_sec;
    *ptlen = callback_phdr->caplen;
    return 1;
}

/* init internal structures and return a pointer to function that
 * read packets using pcal library
 */
pcapwrapper_pfunc * pcapwrapper_init (char *trace_fname)
{
    char errbuf[100];
    char *physname = "<unknown>";
    int type;

    if ((pcap = pcap_open_offline (trace_fname, errbuf)) == NULL)
    {
        fprintf (stderr, "PCAP said: '%s'\n", errbuf);
        return (NULL);
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
        default:
            fprintf (stderr, "tcptrace did not understand link format (%d)!\n",
                    type);
            fprintf (stderr,
                    "\t If you can give us a capture file with this link format\n\
                    \t or even better, a patch to decipher this format, we shall add it in, \n\
                    \t in a future release.\n");
            rewind (stdin);
            return (NULL);
    }

    /* set up some stuff */
    ip_buf = calloc (65535, sizeof(char));

    return (read_pckt);
}
