/*
 * Kevin Lahey (kml@novell.com)
 * Novell, Inc.
 */

/* 
 * ns.c - ns specific file reading stuff
 */


#include "tstat.h"

#ifdef GROK_NS

/* Defining SYS_STDIN which is fp for Windows and stdin for all other systems */
#ifdef __WIN32
static FILE *fp;
#define SYS_STDIN fp
#else
#define SYS_STDIN stdin
#endif /* __WIN32 */

/* static buffers for reading */
static struct ether_header *pep;
static int *pip_buf;
static struct ip *ipb;
static struct tcphdr *tcpb;

/* for debugging */
static unsigned linenum;

/* return the next packet header */
/* currently only works for ETHERNET */
static int
pread_ns (struct timeval *ptime,
	  int *plen,
	  int *ptlen,
	  void **pphys, int *pphystype, struct ip **ppip, void **pplast)
{
  static int packlen = 0;
  double c, d, e;

  while (1)
    {
      /* read the packet info */

      char tt;
      double timestamp;
      int junk;
      char type[16];
      char flags[16];
      int iteration;
      int seq;
      int is_ack;
      int is_tcp;
      int rlen;
      char myline[128];
      char *isend;

      ++linenum;

      isend = fgets (myline, 128, SYS_STDIN);
      if (isend == NULL)
	{			// end of file
	  return (0);
	}
      /* correct NS output line would have 14 fields: */
      rlen = sscanf (myline, "%c %lg %d %d %s %d %s %d %d.%hu %d.%hu %d %hu",
		     &tt,
		     &timestamp,
		     &junk,
		     &junk,
		     type,
		     plen,
		     flags,
		     &iteration,
		     &ipb->ip_src.s_addr,
		     &tcpb->th_sport,
		     &ipb->ip_dst.s_addr, &tcpb->th_dport, &seq, &ipb->ip_id);

      /* if we can't match all 14 fields, we give up on the file */
      if (rlen != 14 && rlen != 18)
	{
	  fprintf (fp_stderr,
		   "Bad NS packet header in line %u only [%d] arguments can be matched expected 14 or 18 \n",
		   linenum, rlen);
	  return (0);
	}

      // find out who put in this line of code, because I'd love
      // to know what their reasoning was
      //tcpb->th_sport = tcpb->th_dport = iteration;

      is_tcp = strcmp (type, "tcp") == 0;
      is_ack = strcmp (type, "ack") == 0;

      /* if it's not a TCP data segment or ACK, discard and try again */
      if (!is_tcp && !is_ack)
	continue;

      if (packlen == 0)
	*plen = *plen + sizeof (struct ip) + sizeof (struct tcphdr);

      if (packlen == 0 && is_tcp)
	packlen = *plen - sizeof (struct ip) - sizeof (struct tcphdr);

      if (is_tcp)
	packlen = *plen - sizeof (struct ip) - sizeof (struct tcphdr);

      if (is_ack)		/* this is explicitly for SACK that creates packets > 40 Bytes */
	*plen = 40;

      ipb->ip_len = htons (*plen);

      if (is_tcp)
	{
	  tcpb->th_seq = htonl (packlen * seq);
	  tcpb->th_ack = 0;
	}
      else
	{
	  tcpb->th_seq = 0;
	  tcpb->th_ack = htonl (packlen * (seq + 1));
	}

      /* make up a reasonable IPv4 packet header */
#ifdef __VMS
      ipb->ip_vhl = 0x0405;	/* no options, normal length of 20 */
#else
      ipb->ip_hl = 5;		/* no options, normal length of 20 */
      ipb->ip_v = 4;		/* IPv4 */
#endif

      ipb->ip_tos = 0;
      ipb->ip_off = 0;
      ipb->ip_ttl = 64;		/* nice round number */
      ipb->ip_p = 6;		/* TCP */
      ipb->ip_sum = 0;		/* IP checksum, hope it doesn't get checked! */
      ipb->ip_id = htons (ipb->ip_id);

      /* is the transport "ECN-Capable"? */
      if (strchr (flags, 'N') != NULL)
	ipb->ip_tos |= IPTOS_ECT;

      /* was the "Experienced Congestion" bit set? */
      if (strchr (flags, 'E') != NULL)
	ipb->ip_tos |= IPTOS_CE;

      /* make up a reasonable TCP segment header */
#ifdef __VMS
      tcpb->th_xoff = 0x50;	/* no options, normal length of 20 */
#else
      tcpb->th_off = 5;		/* no options, normal length of 20 */
      tcpb->th_x2 = 0;
#endif
      tcpb->th_flags = TH_ACK;	/* sdo: what about first SYN?? */
      tcpb->th_sum = 0;
      tcpb->th_urp = 0;
      tcpb->th_win = htons (65535);

      /* x2 *was* reserved, now used for ECN bits */

      if (strchr (flags, 'C') != NULL)
#ifdef __VMS
	tcpb->th_xoff |= TH_ECN_ECHO;
#else
	tcpb->th_x2 |= TH_ECN_ECHO;
#endif
      if (strchr (flags, 'A') != NULL)
#ifdef __VMS
	tcpb->th_xoff |= TH_CWR;
#else
	tcpb->th_x2 |= TH_CWR;
#endif

      /* convert floating point timestamp to (tv_sec,tv_usec) */
      c = floor (timestamp);
      ptime->tv_sec = c;
      d = timestamp - (double) ptime->tv_sec;
      e = d * 1000000.0;
      ptime->tv_usec = e;

      *ptlen = *plen;

      *ppip = (struct ip *) pip_buf;
      *pplast = (char *) pip_buf + *plen;
      *pphys = pep;
      *pphystype = PHYS_ETHER;

/*
  fprintf(fp_stdout, "timestamp %g, type %s, plen %d, seq %d, id %d\n",
  timestamp, type, *plen, seq, ipb->ip_id);
*/
      return (1);
    }
}

int
pread_ns_fulltcp (struct timeval *ptime,
		  int *plen,
		  int *ptlen,
		  void **pphys,
		  int *pphystype, struct ip **ppip, void **pplast)
{
  double c, d, e;
  while (1)
    {
      /* read the packet info */

      char tt;
      double timestamp;
      int junk;
      unsigned short junkshort;
      char type[16];
      char flags[16];
      int iteration;
      int seqno;
      int ackno;
      int hdrlen;
      int is_ack;
      int is_tcp;
      int pflags;
      int rlen;
      char myline[128];
      char *isend;

      ++linenum;

      isend = fgets (myline, 128, SYS_STDIN);
      if (isend == NULL)
	{			// end of file
	  return 0;
	}
      /* correct NS output line would have 14 fields if show_tcphdr_ is 0: */
      /* For Full TCP this changes to 18 fields when show_tcp is 1 */
      rlen =
	sscanf (myline,
		"%c %lg %d %d %s %d %s %d %d.%hu %d.%hu %d %hu %d 0x%x %u %hu",
		&tt, &timestamp, &junk, &junk, type, plen, flags, &iteration,
		&ipb->ip_src.s_addr, &tcpb->th_sport, &ipb->ip_dst.s_addr,
		&tcpb->th_dport, &seqno, &ipb->ip_id, &ackno, &pflags,
		&hdrlen, &junkshort);

      /* if we can't match all 18 fields, we give up on the file */
      if (rlen != 18)
	{
	  fprintf (fp_stderr, "\"%s\"\n", myline);
	  fprintf (fp_stderr,
		   "Bad NS packet header in line %u only [%d] arguments can be matched expected 14 or 18 \n",
		   linenum, rlen);
	  fprintf (fp_stderr, "Is this a Full Tcp Header?\n");
	  return (0);
	}

      //tcpb->th_sport = tcpb->th_dport = iteration;
      is_tcp = strcmp (type, "tcp") == 0;
      is_ack = strcmp (type, "ack") == 0;

      /* if it's not a TCP data segment or ACK, discard and try again */
      if (!is_tcp && !is_ack)
	continue;

      /* we have biger header than 40 Bytes (SACK?) */
      if (hdrlen > sizeof (struct ip) + sizeof (struct tcphdr))
	{
	  *plen -= (hdrlen - (sizeof (struct ip) + sizeof (struct tcphdr)));
	}

      ipb->ip_len = htons (*plen);

      tcpb->th_seq = htonl (seqno);
      tcpb->th_ack = htonl (ackno);

      /* make up a reasonable IPv4 packet header */
      ipb->ip_hl = 5;		/* no options, normal length of 20 */
      ipb->ip_v = 4;		/* IPv4 */
      ipb->ip_tos = 0;
      ipb->ip_off = 0;
      ipb->ip_ttl = 64;		/* nice round number */
      ipb->ip_p = 6;		/* TCP */
      ipb->ip_sum = 0;		/* IP checksum, hope it doesn't get checked! */
      ipb->ip_id = ipb->ip_id;

      /* is the transport "ECN-Capable"? */
      if (strchr (flags, 'N') != NULL)
	ipb->ip_tos |= IPTOS_ECT;

      /* was the "Experienced Congestion" bit set? */
      if (strchr (flags, 'E') != NULL)
	ipb->ip_tos |= IPTOS_CE;

      /* make up a reasonable TCP segment header */
      tcpb->th_off = 5;		/* no options, normal length of 20 */
      tcpb->th_flags = pflags;	/* sdo: what about first SYN?? */
      tcpb->th_x2 = 0;
      tcpb->th_sum = 0;
      tcpb->th_urp = 0;
      tcpb->th_win = htons (65535);

      /* x2 *was* reserved, now used for ECN bits */

      if (strchr (flags, 'C') != NULL)
	tcpb->th_x2 |= TH_ECN_ECHO;
      if (strchr (flags, 'A') != NULL)
	tcpb->th_x2 |= TH_CWR;

      /* convert floating point timestamp to (tv_sec,tv_usec) */
      c = floor (timestamp);
      ptime->tv_sec = c;
      d = timestamp - (double) ptime->tv_sec;
      e = d * 1000000.0;
      ptime->tv_usec = e;

      *ptlen = *plen;

      *ppip = (struct ip *) pip_buf;
      *pplast = (char *) pip_buf + *plen;
      *pphys = pep;
      *pphystype = PHYS_ETHER;


      /* fprintf(fp_stdout, "timestamp %g, type %s, plen %d, seq %d, id %d, ack %d, 0x%x %d \n",
         timestamp, type, *plen, seqno, ipb->ip_id,ackno,pflags,hdrlen); */


      return (1);
    }

  return (0);
}


/*
 * is_ns()   is the input file in ns format??
 */
pread_f *
is_ns (char *filename)
{
  int rlen;
  char tt;
  int junk;
  double junkd;
  char junks[20];
  unsigned short junkshort;
  int hdrlen = 0;
  int pflags = 0;
  char myline[128];		// read into this line and then parse for values

#ifdef __WIN32
  if ((fp = fopen (filename, "r")) == NULL)
    {
      fprintf (fp_stderr, "%s: %s\n", filename, strerror(errno));
      exit (-1);
    }
#endif /* __WIN32 */

  fgets (myline, 128, SYS_STDIN);
  rlen = sscanf (myline,
		 "%c %lg %d %d %s %d %s %d %d.%hu %d.%hu %d %hu %d 0x%x %u %hu",
		 &tt, &junkd, &junk, &junk, (char *) &junks, &junk,
		 (char *) &junks, &junk, &junk, &junkshort, &junk,
		 &junkshort, &junk, &junkshort, &junk, &pflags, &hdrlen,
		 &junkshort);

  if ((rlen = getc (SYS_STDIN)) == EOF)
    {
      return (NULL);
    }
  else
    {
      if (ungetc (rlen, SYS_STDIN) == EOF)
	return NULL;
    }

  switch (tt)
    {
    case '+':
    case '-':
    case 'h':
    case 'r':
    case 'd':
      break;
    default:
      return (NULL);
    }

  /* OK, it's mine.  Init some stuff */
  pep = MallocZ (sizeof (struct ether_header));
  pip_buf = MallocZ (IP_MAXPACKET);

  ipb = (struct ip *) pip_buf;
  tcpb = (struct tcphdr *) (ipb + 1);

  /* Set up the stuff that shouldn't change */
  pep->ether_type = ETHERTYPE_IP;

  /* init line count (we might be called several times, must be done here) */
  linenum = 0;
  /* Lets check if it is FullTCP or not */
  if (hdrlen || pflags)
    {				/*it is FullTCP */
/*		fprintf(fp_stdout, "Full TCP \n"); */
      rewind (SYS_STDIN);
      return (pread_ns_fulltcp);
    }
  else
    {				/*Regular TCP (with or without tcpheaders activated */
      return (pread_ns);
    }
}
#endif /* GROK_NS */
