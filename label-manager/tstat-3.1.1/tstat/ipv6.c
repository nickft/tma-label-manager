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

#include "tstat.h"
extern Bool coming_in;
extern Bool net6_conf;
extern Bool internal_shost;
extern Bool internal_dhost;
extern eth_filter mac_filter;

#ifdef SUPPORT_IPV6
extern struct in6_addr *internal_net_listv6;
extern int *internal_net_maskv6;
extern int tot_internal_netsv6;
extern struct in6_addr *crypto_net_listv6;
extern int *crypto_net_maskv6;
extern int tot_crypto_netsv6;
extern struct in6_addr *cloud_net_listv6;
extern int *cloud_net_maskv6;
extern int tot_cloud_netsv6;
extern struct in6_addr *white_net_listv6;
extern int *white_net_maskv6;
extern int tot_white_netsv6;
#endif

/* the names of IPv6 extensions that we understand */
char *
ipv6_header_name (u_char nextheader)
{
  switch (nextheader)
    {
    case IPPROTO_DSTOPTS:
      return ("Destinations options");
    case IPPROTO_FRAGMENT:
      return ("Fragment header");
    case IPPROTO_HOPOPTS:
      return ("Hop by hop");
    case IPPROTO_NONE:
      return ("No next header");
    case IPPROTO_ROUTING:
      return ("Routing header");
    case IPPROTO_ICMPV6:
      return ("IPv6 ICMP");
    case IPPROTO_TCP:
      return ("TCP");
    case IPPROTO_UDP:
      return ("UDP");
    case IPPROTO_AH:
      return ("IPSec AH header");
    case IPPROTO_ESP:
      return ("IPSec ESP");
    case IPPROTO_MH:
      return ("Mobility IPv6");
    default:
      return ("<unknown>");
    }
}


/* given a next header type and a pointer to the header, return a pointer
   to the next extension header and type */
struct ipv6_ext *
ipv6_nextheader (void *pheader0, u_char * pnextheader)
{
#ifdef SUPPORT_IPV6
  struct ipv6_ext *pheader = pheader0;

  switch (*pnextheader)
    {
      /* nothing follows these... */
    case IPPROTO_TCP:
    case IPPROTO_NONE:
    case IPPROTO_ICMPV6:
    case IPPROTO_UDP:
    case IPPROTO_ESP:
      return (NULL);

      /* somebody follows these */
    case IPPROTO_HOPOPTS:
    case IPPROTO_ROUTING:
    case IPPROTO_DSTOPTS:
    case IPPROTO_MH:
      *pnextheader = pheader->ip6ext_nheader;
      return ((struct ipv6_ext *) ((char *) pheader + 8 + (pheader->ip6ext_len)*8));

    case IPPROTO_AH:
      /* Autentication Header lenght is measured in 32 bits units (minus 2 units) */
      *pnextheader = pheader->ip6ext_nheader;
      return ((struct ipv6_ext *) ((char *) pheader + 8 + (pheader->ip6ext_len)*4));
      
    case IPPROTO_FRAGMENT:
      /* Fragment extension is 8 bytes long */
      *pnextheader = pheader->ip6ext_nheader;
      return ((struct ipv6_ext *) ((char *) pheader + 8 ));
      
      /* I don't understand them.  Just save the type and return a NULL */
    default:
      *pnextheader = pheader->ip6ext_nheader;
      return (NULL);
    }
#else
  return (NULL);
#endif

}

#ifdef SUPPORT_IPV6
int match_ipv6_net(struct in6_addr adx, struct in6_addr *internal_list, int *mask_list, int list_size)
{
  static unsigned short int masks[] = { 0x80, 0xc0, 0xe0, 0xf0, 0xf8, 0xfc, 0xfe, 0xff };
  int i,full,partial,match;
//  char c[INET6_ADDRSTRLEN],d[INET6_ADDRSTRLEN];

  for (i = 0; i < list_size; i++)
    {
      if (mask_list[i]==0) 
	return 1;

//  inet_ntop(AF_INET6,&(adx),c,INET6_ADDRSTRLEN),
//  inet_ntop(AF_INET6,&(internal_net_listv6[i]),d,INET6_ADDRSTRLEN);
  
      full = mask_list[i]/8;
      partial = mask_list[i]%8;
      
      match = 0;
      if ( memcmp(&adx,&(internal_list[i]),full)!=0 )
       {
	 match = 0;
       }
      else if (partial!=0)
       {
	 if ( (adx.s6_addr[full] & masks[partial-1] ) == (internal_list[i].s6_addr[full] & masks[partial-1]) )
	   match = 1;
       }
      else
	match = 1;
      
      if (match == 1) 
         return 1;
    }

  return 0;
}

/* 
 * Check if the IP adx is included in the internal nets
 */

int
internal_ipv6 (struct in6_addr adx)
{
  return match_ipv6_net(adx,internal_net_listv6,internal_net_maskv6,tot_internal_netsv6);
}

int
cloud_ipv6 (struct in6_addr adx)
{
  return match_ipv6_net(adx,cloud_net_listv6,cloud_net_maskv6,tot_cloud_netsv6);
}

int
crypto_ipv6 (struct in6_addr adx)
{
  int crypto_res, white_res;
  
  if (tot_white_netsv6==0)    // No Whitelisted networks: just return Crypto
    return match_ipv6_net(adx,crypto_net_listv6,crypto_net_maskv6,tot_crypto_netsv6);
  else
   {
     crypto_res = match_ipv6_net(adx,crypto_net_listv6,crypto_net_maskv6,tot_crypto_netsv6);
     if (crypto_res == 0)
       return 0;
     else
      {
        white_res = match_ipv6_net(adx,white_net_listv6,white_net_maskv6,tot_white_netsv6);
        return white_res == 0 ? 1 : 0;
      }
   }
}

#endif

#ifdef SUPPORT_IPV6
void
IPv6_support (struct ip *pip, void *pplast, int ip_direction)
{
  struct ipv6 *ipv6;
  int internal_srcv6 = 0, internal_dstv6 = 0;
  char *next;
  unsigned int proto_type;

  proto_type = 0;

  ipv6 = (struct ipv6 *) pip;

  //next_header=ipv6->ip6_nheader;

  /* decide wheater this is internal or external */
  if (internal_wired)
    {
      internal_srcv6 = coming_in;
      internal_dstv6 = !coming_in;
    }
  else
   {
     if (mac_filter.tot_internal_eth >0)
      {
        /* going to use the Ethernet MAC here */
          internal_srcv6 = internal_shost;
          internal_dstv6 = internal_dhost;
      }
     else
      {
         /* stick with ip networks - or trust what you have been told */
         switch(ip_direction)                                                                         
          {
           case SRC_IN_DST_IN:
            internal_srcv6 = 1;
            internal_dstv6 = 1;
            break;
           case SRC_IN_DST_OUT:
            internal_srcv6 = 1;
            internal_dstv6 = 0;
            break;
           case SRC_OUT_DST_IN:
            internal_srcv6 = 0;
            internal_dstv6 = 1;
            break;
           case SRC_OUT_DST_OUT:
            internal_srcv6 = 0;
            internal_dstv6 = 0;
            break;
           case DEFAULT_NET:
           default:
              if (!net_conf)
               {
                 internal_srcv6 = 1;
                 internal_dstv6 = 1;
               }
             else
               {
                 internal_srcv6 = internal_ipv6 (ipv6->ip6_saddr);
                 internal_dstv6 = internal_ipv6 (ipv6->ip6_daddr);
               }
            break;
          }

      }
   }

  if (internal_srcv6 && !internal_dstv6)
    {
      add_histo (ip6_protocol_out, ipv6->ip6_nheader);
      add_histo (ip6_hop_limit_out, (float) ipv6->ip6_hlimit);
      add_histo (ip6_plen_out, (float) ntohs (ipv6->ip6_lngth));
    }
  else if (!internal_srcv6 && internal_dstv6)
    {
      add_histo (ip6_protocol_in, ipv6->ip6_nheader);
      add_histo (ip6_hop_limit_in, (float) ipv6->ip6_hlimit);
      add_histo (ip6_plen_in, (float) ntohs (ipv6->ip6_lngth));
    }
#ifndef LOG_UNKNOWN
  else if (internal_srcv6 && internal_dstv6)
#else
  else
#endif
    {
      add_histo (ip6_protocol_loc, ipv6->ip6_nheader);
      add_histo (ip6_hop_limit_loc, (float) ipv6->ip6_hlimit);
      add_histo (ip6_plen_loc, (float) ntohs (ipv6->ip6_lngth));

    }

  if (internal_srcv6 == 1)
    {
      internal_src = TRUE;
    }
  else
    {
      internal_src = FALSE;
    }

  if (internal_dstv6 == 1)
    {
      internal_dst = TRUE;
    }
  else
    {
      internal_dst = FALSE;
    }

  next = findheader_ipv6 (pplast, pip, &proto_type);

  if (proto_type == IPPROTO_ICMPV6)
    {
      ICMPv6_support (next, internal_srcv6, internal_dstv6);
    }

  //fprintf (fp_stdout, "IPv6 src addr: %s \n",
  //    inet_ntop(AF_INET6,
  //    (*ipv6).ip6_saddr.s6_addr,buffer_ipv6 ,INET6_ADDRSTRLEN));

  //fprintf (fp_stdout, "IPv6 dst addr: %s\n",
  //    inet_ntop(AF_INET6,
  //    (*ipv6).ip6_daddr.s6_addr,buffer_ipv6 ,INET6_ADDRSTRLEN));

  return;
}
#endif

char *
findheader_ipv6 (void *pplast, struct ip *pip, unsigned int *proto_type)
{
  struct ipv6_ext *pdef;
  struct ipv6 *ipv6;
  int next_header;
  char *next_header6;

  ipv6 = (struct ipv6 *) pip;

  next_header = ipv6->ip6_nheader;
  *proto_type = next_header;
  next_header6 = ((char *) pip) + 40;

  while ((void *) next_header6 < pplast)
    {
	//  fprintf (fp_stdout, "next header: %s (%d) \n",ipv6_header_name(next_header),next_header);
      switch (next_header)
	{
	case IPPROTO_TCP:
	  //fprintf (fp_stdout, "next header: %d \n",next_header);
	  return (next_header6);
	  break;
	case IPPROTO_UDP:
	  return (next_header6);
	  break;
	case IPPROTO_ICMPV6:
	  return (next_header6);
	  break;

	case IPPROTO_FRAGMENT:
	  {
	    struct ipv6_ext_frag *pfrag =
	      (struct ipv6_ext_frag *) next_header6;

	    if ((pfrag->ip6ext_fr_offset & 0xfc) != 0)
	      {
		if (debug > 1)
		  fprintf (fp_stdout, "findheader_ipv6: Skipping IPv6 non-initial fragment\n");
		return (NULL);
	      }

	    next_header = (int) pfrag->ip6ext_fr_nheader;
        next_header6 = (char *) (next_header6 + sizeof (struct ipv6_ext_frag));
        *proto_type = next_header;
	    break;
	  }
	case IPPROTO_HOPOPTS:
	case IPPROTO_ROUTING:
	case IPPROTO_DSTOPTS:
	case IPPROTO_MH:
	  pdef = (struct ipv6_ext *) next_header6;
	  next_header = pdef->ip6ext_nheader;
	  next_header6 = (char *) (next_header6 + 8 + pdef->ip6ext_len*8);
      *proto_type = next_header;
	  break;
	case IPPROTO_AH:
	  pdef = (struct ipv6_ext *) next_header6;
	  next_header = pdef->ip6ext_nheader;
      next_header6 = (char *) (next_header6 + 8 + pdef->ip6ext_len*4);
      *proto_type = next_header;
	  break;
	case IPPROTO_NONE:
	case IPPROTO_ESP:
	default:
	  return NULL;
	}
    }


  return NULL;

}


#ifdef SUPPORT_IPV6
void
ICMPv6_support (char *next, int internal_srcv6, int internal_dstv6)
{
  struct icmp6_hdr *picmpv6;

  picmpv6 = (struct icmp6_hdr *) next;

  if (internal_srcv6 && !internal_dstv6)
    {
      add_histo (icmpv6_type_out, picmpv6->icmp6_type);
    }
  else if (!internal_srcv6 && internal_dstv6)
    {
      add_histo (icmpv6_type_in, picmpv6->icmp6_type);
    }
#ifndef LOG_UNKNOWN
  else if (internal_srcv6 && internal_dstv6)
#else
  else
#endif
    {
      add_histo (icmpv6_type_loc, picmpv6->icmp6_type);
    }


  return;
}
#endif

/*
 * gettcp:  return a pointer to a tcp header.
 * Skips either ip or ipv6 headers
 */
static void *
findheader (u_int ipproto, struct ip *pip, void **pplast)
{
    void *theheader;
    unsigned int proto_type;

    if (PIP_ISV6 (pip))
    {
        theheader = findheader_ipv6 (*pplast, pip, &proto_type);
        if (proto_type != ipproto)
            return NULL;
        else
            return theheader;
    }
    else
        /* IPv4 is easy */
        if (PIP_ISV4 (pip))
        {
            /* make sure it's what we want */
            if (pip->ip_p != ipproto) {
                return NULL;
            }

            /* check the fragment field, if it's not the first fragment,
               it's useless (offset part of field must be 0 */
            if ((ntohs (pip->ip_off) & 0x1fff) != 0)
            {
                if (debug > 1)
                {
                    fprintf (fp_stdout, "gettcp: Skipping IPv4 non-initial fragment\n");
                }
                return NULL;
            }

            /* OK, it starts here */
            theheader = ((char *) pip + 4 * pip->ip_hl);

            /* adjust plast in accordance with ip_len (really short packets get garbage) */
            if (((unsigned long) pip + ntohs (pip->ip_len) - 1) <
                    (unsigned long) (*pplast))
            {
                *pplast = (void *) ((unsigned long) pip + ntohs (pip->ip_len));
            }

            return (theheader);
        }
        else
            return NULL;
}



/*
 * gettcp:  return a pointer to a tcp header.
 * Skips either ip or ipv6 headers
 */
struct tcphdr *
gettcp (struct ip *pip, void **pplast)
{
  struct tcphdr *ptcp;
  ptcp = (struct tcphdr *) findheader (IPPROTO_TCP, pip, pplast);
  return (ptcp);
}


/*
 * getudp:  return a pointer to a udp header.
 * Skips either ip or ipv6 headers
 */
struct udphdr *
getudp (struct ip *pip, void **pplast)
{
  struct udphdr *pudp;
  pudp = (struct udphdr *) findheader (IPPROTO_UDP, pip, pplast);
  return (pudp);
}



/* 
 * gethdrlength: returns the length of the header in the case of ipv4
 *               returns the length of all the headers in the case of ipv6
 */
int
gethdrlength (struct ip *pip, void *plast)
{
  int length, nextheader;
  char *pheader;
  struct ipv6 *pipv6;

  if (PIP_ISV6 (pip))
    {
      length = 40;

      pheader = (char *) pip;
      nextheader = *(pheader + 6);
      pheader += 40;

      pipv6 = (struct ipv6 *) pip;
      while (1)
	{
          if (   (nextheader == IPPROTO_TCP)
	      || (nextheader == IPPROTO_UDP)
	      || (nextheader == IPPROTO_ICMPV6)
	      || (nextheader == IPPROTO_NONE)
	      || (nextheader == IPPROTO_ESP))
	    return length;
	  else if (nextheader == IPPROTO_FRAGMENT)
	    {
	      nextheader = *pheader;
	      pheader += 8;
	      length += 8;
	    }
	  else if (nextheader == IPPROTO_AH)
	    {
	      nextheader = *pheader;
	      length += (*(pheader+1)+2)*4;
	      pheader += (*(pheader+1)+2)*4;
	    }
	  else if ((nextheader == IPPROTO_HOPOPTS)
	      || (nextheader == IPPROTO_ROUTING)
	      || (nextheader == IPPROTO_DSTOPTS)
	      || (nextheader == IPPROTO_MH))
	    {
	      nextheader = *pheader;
	      length += (*(pheader+1)+1)*8;
	      pheader += (*(pheader+1)+1)*8;
	    }
	  else
	    { /* Not a supported extension header */
	    break;
	    }
	  if (pheader > (char *) plast)
	    return -1;
	}
	return length;
    }
  else /* IPv4 */
    {
      return pip->ip_hl * 4;
    }
}

/*
 * getpayloadlength: returns the length of the packet without the header.
 */
int
getpayloadlength (struct ip *pip, void *plast)
{
#ifdef SUPPORT_IPV6
  struct ipv6 *pipv6;

  if (PIP_ISV6 (pip))
    {
      pipv6 = (struct ipv6 *) pip;	/* how about all headers */
    //  return ntohs (pipv6->ip6_lngth);
      return ntohs (pipv6->ip6_lngth) + 40 - gethdrlength(pip,plast);
    }
  else /* IPv4 */
#endif
  return ntohs (pip->ip_len) - (pip->ip_hl * 4);
}



/* 
 * ipcopyaddr: copy an IPv4 or IPv6 address  
 */
inline void
IP_COPYADDR (ipaddr * toaddr, ipaddr fromaddr)
{
#ifdef SUPPORT_IPV6
  if (ADDR_ISV6 (&fromaddr))
    {
      memcpy (toaddr->un.ip6.s6_addr, fromaddr.un.ip6.s6_addr, 16);
      toaddr->addr_vers = 6;
    }
  else
#endif
    {
      toaddr->un.ip4.s_addr = fromaddr.un.ip4.s_addr;
      toaddr->addr_vers = 4;
    }
}



/*
 * ipsameaddr: test for equality of two IPv4 or IPv6 addresses
 */
int
IP_SAMEADDR (ipaddr addr1, ipaddr addr2)
{
  int ret = 0;
#ifdef SUPPORT_IPV6
  if (ADDR_ISV6 (&addr1) && ADDR_ISV6 (&addr2))
    ret = (memcmp (addr1.un.ip6.s6_addr, addr2.un.ip6.s6_addr, 16) == 0);
  else
#endif
  if (ADDR_ISV4 (&addr2))
    ret = (addr1.un.ip4.s_addr == addr2.un.ip4.s_addr);
  return ret;
}



#ifndef HAVE_INET_PTON
int
inet_pton (int af, const char *src, void *dst)
{
  if (af == AF_INET)
    {
      /* use standard function */
      long answer = inet_addr (src);
      if (answer != -1)
	{
	  *((long *) dst) = answer;
	  return (1);
	}
    }
  else if (af == AF_INET6)
    {
      /* YUCC - lazy for now, not fully supported */
      int shorts[8];
      if (sscanf (src, "%x:%x:%x:%x:%x:%x:%x:%x",
		  &shorts[0], &shorts[1], &shorts[2], &shorts[3],
		  &shorts[4], &shorts[5], &shorts[6], &shorts[7]) == 8)
	{
	  int i;
	  for (i = 0; i < 8; ++i)
	    ((u_short *) dst)[i] = (u_short) shorts[i];
	  return (1);
	}
    }

  /* else, it failed */
  return (0);
}
#endif /* HAVE_INET_PTON */



/*
 * my_inet_ntop: makes a string address of the 16 byte ipv6 address
 * We use our own because various machines print them differently
 * and I wanted them to all be the same
 */
char *
my_inet_ntop (int af, const char *src, char *dst, size_t size)
{
  int i;
  u_short *src_shorts = (u_short *) src;
  char *ret = dst;
  Bool did_shorthand = FALSE;
  Bool doing_shorthand = FALSE;

  /* sanity check, this isn't general, but doesn't need to be */
  if (size != INET6_ADDRSTRLEN)
    {
      fprintf (fp_stderr, "my_inet_ntop: invalid size argument\n");
      exit (-1);
    }


  /* address is 128 bits == 16 bytes == 8 shorts */
  for (i = 0; i < 8; i++)
    {
      u_short twobytes = ntohs (src_shorts[i]);

      /* handle shorthand notation */
      if (twobytes == 0)
	{
	  if (doing_shorthand)
	    {
	      /* just eat it and continue (except last 2 bytes) */
	      if (i != 7)
		continue;
	    }
	  else if (!did_shorthand)
	    {
	      /* start shorthand */
	      doing_shorthand = TRUE;
	      continue;
	    }
	}

      /* terminate shorthand (on non-zero or last 2 bytes) */
      if (doing_shorthand)
	{
	  doing_shorthand = FALSE;
	  did_shorthand = TRUE;
	  sprintf (dst, ":");
	  dst += 1;
	}

      sprintf (dst, "%04x:", twobytes);
      dst += 5;
    }

  /* nuke the trailing ':' */
  *(dst - 1) = '\0';

  return (ret);
}



/* given an IPv4 IP address, return a pointer to a (static) ipaddr struct */
struct ipaddr *
IPV4ADDR2ADDR (struct in_addr *addr4)
{
  static struct ipaddr addr;

  addr.addr_vers = 4;
  addr.un.ip4.s_addr = addr4->s_addr;

  return (&addr);
}


/* given an IPv6 IP address, return a pointer to a (static) ipaddr struct */
struct ipaddr *
IPV6ADDR2ADDR (struct in6_addr *addr6)
{
#ifdef SUPPORT_IPV6
  static struct ipaddr addr;

  addr.addr_vers = 6;
  memcpy (&addr.un.ip6.s6_addr, &addr6->s6_addr, 16);

  return (&addr);
#else
  return (NULL);
#endif

}


/* given an internet address (IPv4 dotted decimal or IPv6 hex colon),
   return an "ipaddr" (allocated from heap) */
ipaddr *
str2ipaddr (char *str)
{
  ipaddr *pipaddr;

  /* allocate space */
  pipaddr = MallocZ (sizeof (ipaddr));

  /* N.B. - uses standard IPv6 facility inet_pton from RFC draft */
  if (strchr (str, '.') != NULL)
    {
      /* has dots, better be IPv4 */
      pipaddr->addr_vers = 4;
      if (inet_pton (AF_INET, str, &pipaddr->un.ip4.s_addr) != 1)
	{
	  if (debug)
	    fprintf (fp_stderr, "Address string '%s' unparsable as IPv4\n", str);
	  return (NULL);
	}
    }
#ifdef SUPPORT_IPV6
  else if (strchr (str, ':') != NULL)
    {
      /* has colons, better be IPv6 */
      pipaddr->addr_vers = 6;
      if (inet_pton (AF_INET6, str, &pipaddr->un.ip6.s6_addr) != 1)
	{
	  if (debug)
	    fprintf (fp_stderr, "Address string '%s' unparsable as IPv6\n", str);
	  return (NULL);
	}
    }
#endif
  else
    {
      if (debug)
	fprintf (fp_stderr, "Address string '%s' unparsable\n", str);
      return (NULL);
    }
  return (pipaddr);
}


/* compare two IP addresses */
/* result: */
/*    -2: different address types */
/*    -1: A < B */
/*     0: A = B */
/*     1: A > B */
int
IPcmp (ipaddr * pipA, ipaddr * pipB)
{
  int i;
  int len = (pipA->addr_vers == 4) ? 4 : 16;
  u_char *left = (unsigned char *) &pipA->un.ip4;
  u_char *right = (unsigned char *) &pipB->un.ip4;

  /* always returns -2 unless both same type */
  if (pipA->addr_vers != pipB->addr_vers)
    {
      if (debug > 1)
	{
	  fprintf (fp_stdout, "IPcmp %s", HostAddr (*pipA));
	  fprintf (fp_stdout, "%s fails, different addr types\n", HostAddr (*pipB));
	}
      return (-2);
    }


  for (i = 0; i < len; ++i)
    {
      if (left[i] < right[i])
	{
	  return (-1);
	}
      else if (left[i] > right[i])
	{
	  return (1);
	}
      /* else ==, keep going */
    }

  /* if we got here, they're the same */
  return (0);
}
