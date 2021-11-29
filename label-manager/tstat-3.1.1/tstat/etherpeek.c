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


/****************************************
**  This is the Ether Peek reading stuff.
**  Author: Brian Wilson
**          Ohio University
**          Computer Science
**  Date:   Mon, July   ,1995
****************************************/


#include "tstat.h"


#ifdef GROK_ETHERPEEK

/* Defining SYS_STDIN which is fp for Windows and stdin for all other systems */
#ifdef __WIN32
static FILE *fp;
#define SYS_STDIN fp
#else
#define SYS_STDIN stdin
#endif /* __WIN32 */

/* NOTE:  This is for version 5 of the file.  Other file formats may not work
 correctly.*/

static struct EPFileHeader
{
  char version;			/* file version (must be 5, 6, or 7) */
  char status;			/* filler to fill to even boundary */
} file_header;

static struct EPFileHeader2
{
  tt_uint32 length;		/* length of file */
  tt_uint32 numPackets;		/* number of packets contained in the file */
  tt_uint32 timeDate;		/* time and date stamp of the file (MAC format) */
  tt_uint32 timeStart;		/* time of the first packet in the file */
  tt_uint32 timeStop;		/* time of the last packet in the file */
  tt_uint32 futureUse[7];	/*reserved for future use and irrelevent to us! */
} file_header2;



struct EPFilePacket_v5_6
{
  tt_uint16 packetlength;	/* total packet length */
  tt_uint16 slicelength;	/* sliced length of packet */
};

struct EPFilePacket2_v5_6
{
  u_char flags;			/* crc, frame, runt, ... */
  u_char status;		/* slice, trunc, ... */
};

struct EPFilePacket3_v5_6
{
  tt_uint32 timestamp;		/* timestamp in milliseconds */
  tt_uint16 destNum;		/* str corresponding to ether address */
  tt_uint16 srcNum;		/* dnum is entry in table */
  tt_uint16 protoNum;		/* table number for the protocol */
  char protoStr[8];		/* protocol identity string (NOT null terminated!) */
  tt_uint16 filterNum;		/* index to filter table */
};


/* what we need for version 7 */
typedef struct PeekPacket_v7
{
  tt_uint16 protospec;		/* ProtoSpec ID. */
  tt_uint16 packetlength;	/* Total length of packet. */
  tt_uint16 slicelength;	/* Sliced length of packet. */
  u_char flags;			/* CRC, frame, runt, ... */
  u_char status;		/* Slicing, ... */
  tt_uint32 timestamphi;	/* 64-bit timestamp in microseconds. */
  tt_uint32 timestamplo;
} PeekPacket_v7;

/* byte swapping */
/* Mac's are in network byte order.  If this machine is NOT, then */
/* we'll need to do conversion */


static u_long mactime;

#define Real_Size_FH 2
#define Real_Size_FH2 48
#define Real_Size_FP 4
#define Real_Size_FP2 2
#define Real_Size_FP3 20

#define Mac2unix 2082844800u	/* difference between Unix and Mac timestamp */

#define VERSION_7 7		/* Version 7 */
#define VERSION_6 6		/* Version 6 */
#define VERSION_5 5		/* Version 5 */
static char thisfile_ep_version;
#define EP_V5 (thisfile_ep_version == VERSION_5)
#define EP_V6 (thisfile_ep_version == VERSION_6)
#define EP_V7 (thisfile_ep_version == VERSION_7)



/* static buffers for reading */
static struct ether_header *pep;
static int *pip_buf;


/* currently only works for ETHERNET */
static int
pread_EP (struct timeval *ptime,
	  int *plen,
	  int *ptlen,
	  void **pphys, int *pphystype, struct ip **ppip, void **pplast)
{
  u_int packlen;
  u_int rlen;
  u_int len;

  /* read the EP packet header */
  while (1)
    {
      if (EP_V5 || EP_V6)
	{
	  struct EPFilePacket_v5_6 hdr;
	  struct EPFilePacket2_v5_6 hdr2;
	  struct EPFilePacket3_v5_6 hdr3;

	  if ((rlen =
	       fread (&hdr, 1, Real_Size_FP, SYS_STDIN)) != Real_Size_FP)
	    {
	      if (rlen != 0)
		fprintf (fp_stderr, "Bad EP header\n");
	      return (0);
	    }
	  hdr.packetlength = ntohs (hdr.packetlength);
	  hdr.slicelength = ntohs (hdr.slicelength);

	  if (debug > 1)
	    {
	      fprintf (fp_stdout, 
            "EP_read: next packet: original length: %d, saved length: %d\n",
		    hdr.packetlength, hdr.slicelength);
	    }


	  if ((rlen =
	       fread (&hdr2, 1, Real_Size_FP2, SYS_STDIN)) != Real_Size_FP2)
	    {
	      if (rlen != 0)
		fprintf (fp_stderr, "Bad EP header\n");
	      return (0);
	    }

	  if ((rlen =
	       fread (&hdr3, 1, Real_Size_FP3, SYS_STDIN)) != Real_Size_FP3)
	    {
	      if (rlen != 0)
		fprintf (fp_stderr, "Bad EP header\n");
	      return (0);
	    }

	  if (hdr.slicelength)
	    packlen = hdr.slicelength;
	  else
	    packlen = hdr.packetlength;

	  hdr3.timestamp = ntohl (hdr3.timestamp);

	  ptime->tv_sec = mactime + (hdr3.timestamp / 1000);	/*milliseconds div 1000 */
	  ptime->tv_usec = 1000 * (hdr3.timestamp % 1000);

	  *plen = hdr.packetlength;
	  /* hmmm... I guess 0 bytes means that they grabbed the whole */
	  /* packet.  Seems to work that way... sdo - Thu Feb 13, 1997 */
	  if (hdr.slicelength)
	    *ptlen = hdr.slicelength;
	  else
	    *ptlen = hdr.packetlength;
	}
      else
	{			/* version 7 */
	  struct PeekPacket_v7 hdrv7;

	  if ((rlen = fread (&hdrv7, sizeof (hdrv7), 1, SYS_STDIN)) != 1)
	    {
	      if (rlen != 0)
		fprintf (fp_stderr, "Bad EP V7 header (rlen is %d)\n", rlen);
	      return (0);
	    }

	  hdrv7.packetlength = ntohs (hdrv7.packetlength);
	  hdrv7.slicelength = ntohs (hdrv7.slicelength);

	  if (hdrv7.slicelength)
	    packlen = hdrv7.slicelength;
	  else
	    packlen = hdrv7.packetlength;

	  /* file save version 7 time is NOT an offset, it's a 64 bit counter in microseconds */
#ifdef HAVE_LONG_LONG
	  {			/* not everybody has LONG LONG now */
	    unsigned long long int usecs;

	    /* avoid ugly alignment problems */
	    usecs = ntohl (hdrv7.timestamphi);
	    usecs <<= 32;
	    usecs |= ntohl (hdrv7.timestamplo);

	    ptime->tv_sec = usecs / 1000000 - Mac2unix;
	    ptime->tv_usec = usecs % 1000000;
	  }
#else /* HAVE_LONG_LONG */
	  {
	    double usecs;

	    /* secs is hard because I don't want to depend on "long long" */
	    /* which isn't universal yet.  "float" probably isn't enough */
	    /* signigicant figures to make this work, so I'll do it in */
	    /* (slow) double precision :-(  */
	    usecs = (double) hdrv7.timestamphi * (65536.0 * 65536.0);
	    usecs += (double) hdrv7.timestamplo;
	    usecs -= (double) Mac2unix *1000000.0;
	    ptime->tv_sec = usecs / 1000000.0;

	    /* usecs is easier, the part we want is all in the lower word */
	    ptime->tv_usec = usecs - (double) ptime->tv_sec * 1000000.0;
	  }
#endif /* HAVE_LONG_LONG */


	  *plen = hdrv7.packetlength;
	  /* hmmm... I guess 0 bytes means that they grabbed the whole */
	  /* packet.  Seems to work that way... sdo - Thu Feb 13, 1997 */
	  if (hdrv7.slicelength)
	    *ptlen = hdrv7.slicelength;
	  else
	    *ptlen = hdrv7.packetlength;

	  if (debug > 1)
	    {
	      fprintf (fp_stdout, "File position: %ld\n", ftell (SYS_STDIN));
	      fprintf (fp_stdout, "pread_EP (v7) next packet:\n");
	      fprintf (fp_stdout, "  packetlength: %d\n", hdrv7.packetlength);
	      fprintf (fp_stdout, "  slicelength:  %d\n", hdrv7.slicelength);
	      fprintf (fp_stdout, "  packlen:      %d\n", packlen);
	      fprintf (fp_stdout, "  time:         %s\n", ts2ascii_date (ptime));
	    }
	}


      len = packlen;

      /* read the ethernet header */
      rlen = fread (pep, 1, sizeof (struct ether_header), SYS_STDIN);
      if (rlen != sizeof (struct ether_header))
	{
	  fprintf (fp_stderr, "Couldn't read ether header\n");
	  return (0);
	}


      /* read the rest of the packet */
      len -= sizeof (struct ether_header);
      if (len >= IP_MAXPACKET)
	{
	  /* sanity check */
	  fprintf (fp_stderr,
		   "pread_EP: invalid next packet, IP len is %d, return EOF\n",
		   len);
	  return (0);
	}
      if ((rlen = fread (pip_buf, 1, len, SYS_STDIN)) != len)
	{
	  if (rlen != 0)
	    if (debug)
	      fprintf (fp_stderr,
		       "Couldn't read %d more bytes, skipping last packet\n",
		       len);
	  return (0);
	}

      /* round to 2 bytes for V7 */
      if (EP_V7)
	{
	  if (len % 2 != 0)
	    {
	      /* can't SEEK, because this might be a pipe!! */
	      (void) fgetc (SYS_STDIN);
	    }
	}

      *ppip = (struct ip *) pip_buf;
      *pplast = (char *) pip_buf + len - 1;	/* last byte in the IP packet */
      *pphys = pep;
      *pphystype = PHYS_ETHER;

      /* if it's not IP, then skip it */
      if ((ntohs (pep->ether_type) != ETHERTYPE_IP) &&
	  (ntohs (pep->ether_type) != ETHERTYPE_IPV6))
	{
	  if (debug > 2)
	    fprintf (fp_stderr, "pread_EP: not an IP packet\n");
	  continue;
	}

      return (1);
    }
}



/* is the input file a Ether Peek format file?? */
pread_f *
is_EP (char *filename)
{
  int rlen;

#ifdef __WIN32
  if ((fp = fopen (filename, "r")) == NULL)
    {
      fprintf (fp_stderr, "%s: %s\n", filename, strerror(errno));
      exit (-1);
    }
#endif /* __WIN32 */

  /* read the EP file header */
  if ((rlen =
       fread (&file_header, 1, Real_Size_FH, SYS_STDIN)) != Real_Size_FH)
    {
      rewind (SYS_STDIN);
      return (NULL);
    }
  /*rewind(SYS_STDIN);  I might need this */
  if ((rlen =
       fread (&file_header2, 1, Real_Size_FH2, SYS_STDIN)) != Real_Size_FH2)
    {
      rewind (SYS_STDIN);
      return (NULL);
    }

  /* byte swapping */
  file_header2.length = ntohl (file_header2.length);
  file_header2.numPackets = ntohl (file_header2.numPackets);
  file_header2.timeDate = ntohl (file_header2.timeDate);
  file_header2.timeStart = ntohl (file_header2.timeStart);
  file_header2.timeStop = ntohl (file_header2.timeStop);

  mactime = file_header2.timeDate - Mac2unix;	/*get time plus offset to unix time */
    /********** File header info ********************************/
  if (debug > 1)
    {
      int i;

      fprintf (fp_stderr, "IS_EP says version number %d \n",
	       file_header.version);
      fprintf (fp_stderr, "IS_EP says status number %d\n", file_header.status);
      fprintf (fp_stderr, "IS_EP says length number %ld\n", file_header2.length);
      fprintf (fp_stderr, "IS_EP says num packets number %ld \n",
	       file_header2.numPackets);
      fprintf (fp_stderr, "IS_EP says time date in mac format %lu \n",
	       (tt_uint32) file_header2.timeDate);
      fprintf (fp_stderr, "IS_EP says time start  %lu \n",
	       file_header2.timeStart);
      fprintf (fp_stderr, "IS_EP says time stop %lu \n", file_header2.timeStop);
      fprintf (fp_stderr, "future is: ");
      for (i = 0; i < 7; i++)
	fprintf (fp_stderr, " %ld ", file_header2.futureUse[i]);
      fprintf (fp_stderr, "\n");
      fprintf (fp_stderr, "RLEN is %d \n", rlen);
    }


  /* check for EP file format */
  /* Note, there's no "magic number" here, so this is just a heuristic :-( */
  if ((file_header.version == VERSION_7 ||
       file_header.version == VERSION_6 ||
       file_header.version == VERSION_5) &&
      (file_header.status == 0) &&
      (memcmp (file_header2.futureUse, "\000\000\000\000\000\000\000", 7) ==
       0))
    {
      if (debug)
	fprintf (fp_stderr, "Valid Etherpeek format file (file version: %d)\n",
		 file_header.version);
      thisfile_ep_version = file_header.version;

    }
  else
    {
      if (debug)
	fprintf (fp_stderr,
		 "I don't think this is version 5, 6, or 7 Ether Peek File\n");

      return (NULL);
    }

  /* OK, it's mine.  Init some stuff */
  pep = MallocZ (sizeof (struct ether_header));
  pip_buf = MallocZ (IP_MAXPACKET);


  return (pread_EP);
}

#endif /* GROK_ETHERPEEK */
