/*
 *
 * Copyright (c) 2001-2008
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
 * This code is derived from IPP2P, an  extension to iptables to identify P2P
 * traffic, written by Eicke Friedrich and Klaus Degner <ipp2p@ipp2p.org>
 * Original code available at http://ipp2p.org/
 *
 * Tstat is deeply based on TCPTRACE. The authors would like to thank
 * Shawn Ostermann for the development of TCPTRACE.
 *
*/

#include "tstat.h"
int ED2K_type;
int ED2K_subtype;

#define get_u8(X,O)  (*(tt_uint8 *)(X + O))
#define get_u16(X,O)  (*(tt_uint16 *)(X + O))
#define get_u32(X,O)  (*(tt_uint32 *)(X + O))

/*
MODULE_AUTHOR("Eicke Friedrich/Klaus Degner <ipp2p@ipp2p.org>");
MODULE_DESCRIPTION("An extension to iptables to identify P2P traffic.");
MODULE_LICENSE("GPL");
*/

/*Search for UDP eDonkey/eMule/Kad commands*/
int
udp_search_edk (unsigned char *haystack, const int packet_len, int payload_len)
{
  unsigned char *t = haystack;
  t += 8;

  switch (t[0])
    {
    case 0xe3:      /* eDonkey UDP messages*/
      {
	switch (t[1])
	  {
	    /* client -> server status request */
	  case 0x96:  /* packet_len = 8+2+4) */
	    if (packet_len == 14)
	      return ((IPP2P_EDK * 100) + 50);
	    break;
	    /* server -> client status request */
	  case 0x97:  /* packet_len = 8+2+ 12/16/24/28/32/40 ) */
	    if (packet_len == 42 || 
	        packet_len == 22 || 
	        packet_len == 26 || 
	        packet_len == 34 || 
	        packet_len == 38 || 
	        packet_len == 50)
	      return ((IPP2P_EDK * 100) + 51);
	    break;
	    /* server description request */
	    /* e3 2a ff f0 .. | size == 6 */
	  case 0xa2:
	    if ((packet_len == 14 && payload_len > 14)
		&& (get_u16 (t, 2) == htons (0xfff0)))
	      return ((IPP2P_EDK * 100) + 52);
	    break;
	    /* server description response */
	    /* e3 a3 ff f0 ..  | size > 40 && size < 200 */
	  case 0xa3: 
	    if ((packet_len >= 50 && payload_len > 14)
		&& (get_u16 (t, 2) == htons (0xfff0)))
	      return ((IPP2P_EDK * 100) + 53);
	    break;
	  case 0x9a:  /* packet_len = 8+2+n*16) */
	    if (((packet_len - 10) % 16) == 0)
	      return ((IPP2P_EDK * 100) + 54);
	    break;

	  case 0x9B:  /* packet_len = 8+2+k*(16+1+w*6) */
	              /* Try to match at least a few small sizes */
	    if (packet_len == 33 || 
	        packet_len == 39 || 
	        packet_len == 56 || 
	        packet_len == 68 || 
	        packet_len == 79 || 
	        packet_len == 97 )
	      return ((IPP2P_EDK * 100) + 56);
	    break;

	  case 0x92: /* search request - variable size */
	  case 0x98: /* search request - variable size */
	  case 0x99: /* search response - variable size */
	    // if (packet_len == 18)
	    return ((IPP2P_EDK * 100) + 55);
	    break;
	  }
	break;
      }

    case 0xe4:      /* KAD / KAD2 uncompressed messages */
    case 0xa4:      /* KADu (Kad AdunanzA on FastWeb) uncompressed messages */
      {
	switch (t[1])
	  {
	  case 0x00:   /* KAD BOOTSTRAP_REQ */ /* packet_len = 8+2+25 */
	    if (packet_len == 35)
	      return (((t[0]==0xa4?IPP2P_KADU:IPP2P_KAD) * 100) + 61);
	    break;
	  case 0x01:   /* KAD2 BOOTSTRAP_REQ*/  /* packet_len 10?? */
	    if (packet_len == 10)
	       return (((t[0]==0xa4?IPP2P_KADU:IPP2P_KAD) * 100) + 61);
            break;

	  case 0x08:   /* KAD BOOTSTRAP_RES - size=2+n*25 */
	    if (((packet_len - 12) % 25) == 0)
	      return (((t[0]==0xa4?IPP2P_KADU:IPP2P_KAD) * 100) + 75);
	    break;

	  case 0x09:   /* KAD2 BOOTSTRAP_RES */  /* packet_len 8+2+21+n*25 */
	    if (((packet_len - 31) % 25) == 0)
	      return (((t[0]==0xa4?IPP2P_KADU:IPP2P_KAD) * 100) + 75);
	    break;

	    /* e4 10 .. 00 | size == 35 ? */
	  case 0x10:   /* KAD HELLO_REQ */
	    if (packet_len == 35)
	      return (((t[0]==0xa4?IPP2P_KADU:IPP2P_KAD) * 100) + 62);
	    break;
	  case 0x11:   /* KAD2 HELLO_REQ */ /* packet_len 8+22?? */
	    if (packet_len == 30 || 
	        ( ( packet_len>30 && payload_len > 30) && 
		    t[21]!=0 && (t[22]>=0x01 && t[22]<0x0B)))
		    /*
		       Either there is no Tag (size==8+2+20) or
		       there are variable size tags, so t[21] (tag count)
		       is not zero and t[22] is a valid tag type (0x01-0x0B)
		    */
	     { 
	       return (((t[0]==0xa4?IPP2P_KADU:IPP2P_KAD) * 100) + 62);
	     }
//	    if (packet_len == 30)
//	      return (((t[0]==0xa4?IPP2P_KADU:IPP2P_KAD) * 100) + 62);
//	    break;

	    /* e4 18 .. 00 | size == 35 ? */
	  case 0x18:   /* KAD HELLO_RES */
	    if (packet_len == 35)
	      return (((t[0]==0xa4?IPP2P_KADU:IPP2P_KAD) * 100) + 63);
	    break;
	  case 0x19:   /* KAD2 HELLO_RES */  /* packet_len 8+22 + xxx */
	    if (packet_len == 30 || 
	        ( ( packet_len>30 && payload_len > 30) && 
		    t[21]!=0 && (t[22]>=0x01 && t[22]<0x0B)))
		    /*
		       Either there is no Tag (size==8+2+20) or
		       there are variable size tags, so t[21] (tag count)
		       is not zero and t[22] is a valid tag type (0x01-0x0B)
		    */
	     { 
	       return (((t[0]==0xa4?IPP2P_KADU:IPP2P_KAD) * 100) + 63);
	     }
	    break;

	    /* e4 20 .. | size == 43 */
	  case 0x20:   /* KAD REQ */
	    if ((packet_len == 43 && payload_len > 10) && (t[2] != 0x00))
             {
	      return (((t[0] == 0xa4 ? IPP2P_KADU : IPP2P_KAD) * 100) + 60);
	      }
	    break;
	  case 0x21:   /* KAD2 REQ *//* packet_len 8+2+33 */
	    if (packet_len == 43)
             {
	      return (((t[0]==0xa4?IPP2P_KADU:IPP2P_KAD) * 100) + 60);
	      }
	    break;
	  case 0x22:   /* KAD2 HELLO_RES_ACK *//* packet_len 8+2+ 16+tags */
	    if (packet_len >=27)
             {
	      return (((t[0]==0xa4?IPP2P_KADU:IPP2P_KAD) * 100) + 60);
	      }
	    break;

	    /* e4 28 .. | packet_len == 52,77,102,127... */
	  case 0x28:   /* KAD RES */
	    if (((packet_len - 52) % 25) == 0)
	      return (((t[0]==0xa4?IPP2P_KADU:IPP2P_KAD) * 100) + 67);
	    break;

	  case 0x29:   /* KAD2 RES */ /* the same than KAD format... */
	    if (((packet_len - 52) % 25) == 0)
	      return (((t[0]==0xa4?IPP2P_KADU:IPP2P_KAD) * 100) + 67);
	    break;

	  case 0x30:   /* KAD SEARCH_REQ */ /* packet_len=8+2 + 17+k*??*/
	    if (packet_len >= 27)
	      return (((t[0]==0xa4?IPP2P_KADU:IPP2P_KAD) * 100) + 74);
	    break;
	  case 0x32:   /* KAD SEARCH_NOTES_REQ */ /* packet_len=8+2 + 32 ??*/
	    if (packet_len == 42)
	      return (((t[0]==0xa4?IPP2P_KADU:IPP2P_KAD) * 100) + 74);
	    break;

	  case 0x33:   /* KAD2 SEARCH_KEY_REQ */
	  case 0x34:   /* KAD2 SEARCH_SOURCE_REQ */
	  case 0x35:   /* KAD2 SEARCH_NOTES_REQ */
	    return (((t[0]==0xa4?IPP2P_KADU:IPP2P_KAD) * 100) + 74);

	  case 0x38:   /* KAD SEARCH_RES */  /* packet_len=8+2 + 37+ xxx ??*/
	    if (packet_len >= 47)
	      return (((t[0]==0xa4?IPP2P_KADU:IPP2P_KAD) * 100) + 74);
	    break;
	  case 0x3A:   /* KAD SEARCH_NOTES_RES */  /* packet_len=8+2 + 37+ xxx ??*/
	    if (packet_len >= 47)
	      return (((t[0]==0xa4?IPP2P_KADU:IPP2P_KAD) * 100) + 74);
	    break;
	  case 0x3B:   /* KAD2 SEARCH_RES */
	    return (((t[0]==0xa4?IPP2P_KADU:IPP2P_KAD) * 100) + 74);

	  case 0x40:   /* KAD PUBLISH_REQ */ /* packet_len=8+2 + 37 + XXX ??*/
	    if (packet_len >= 47)
	      return (((t[0]==0xa4?IPP2P_KADU:IPP2P_KAD) * 100) + 69);
	    break;

	  case 0x42:   /* KAD PUBLISH_NOTES_REQ */ /* packet_len=8+2 + 37 + XXX ??*/
	    if (packet_len >= 47)
	      return (((t[0]==0xa4?IPP2P_KADU:IPP2P_KAD) * 100) + 74);
	    break;
	    
	  case 0x43:   /* KAD2 PUBLISH_KEY_REQ */
	  case 0x44:   /* KAD2 PUBLISH_SOURCE_REQ */
	  case 0x45:   /* KAD2 PUBLISH_NOTES_REQ */
	    return (((t[0]==0xa4?IPP2P_KADU:IPP2P_KAD) * 100) + 74);

	  case 0x48:   /* KAD PUBLISH_RES */ /* packet_len=8+2 + 16 [+1] */
	    if (packet_len == 26 || packet_len == 27)
	    return (((t[0]==0xa4?IPP2P_KADU:IPP2P_KAD) * 100) + 74);

	  case 0x4A:   /* KAD PUBLISH_NOTES_RES */ /* packet_len=8+2 + 16 [+1] */
	    if (packet_len == 26 || packet_len == 27)
	    return (((t[0]==0xa4?IPP2P_KADU:IPP2P_KAD) * 100) + 74); 

	  case 0x4B:   /* KAD2 PUBLISH_RES */ /* packet_len=8+2 + 16 +1 */
	    if (packet_len == 27)
	    return (((t[0]==0xa4?IPP2P_KADU:IPP2P_KAD) * 100) + 74);

	  case 0x4C:   /* KAD2 PUBLISH_RES_ACK */ /* packet_len=8+2 */
	    if (packet_len == 10)
	    return (((t[0]==0xa4?IPP2P_KADU:IPP2P_KAD) * 100) + 74);

	  case 0x50:  /* KAD FIREWALLED_REQ */ /* packet_len=8+2 + 2 */
	    if (packet_len == 12)
	      return (((t[0]==0xa4?IPP2P_KADU:IPP2P_KAD) * 100) + 68);
	    break;

	  case 0x51:  /* KAD FINDBUDDY_REQ */ /* packet_len=8+2 + 16+16+2 +1? */
	    if (packet_len == 44 || packet_len == 45)
	      return (((t[0]==0xa4?IPP2P_KADU:IPP2P_KAD) * 100) + 74);
	    break;

	  case 0x52:  /* KAD_CALLBACK_REQ */ /* packet_len=8+2 + 16+16+2 */
	    if (packet_len == 44)
	      return (((t[0]==0xa4?IPP2P_KADU:IPP2P_KAD) * 100) + 64);
	    break;
	    
	  case 0x53:  /* KAD_FIREWALLED2_REQ */ /* packet_len=8+2 + 2+16+1 */
	    if (packet_len == 29)
	      return (((t[0]==0xa4?IPP2P_KADU:IPP2P_KAD) * 100) + 64);
	    break;
	    
	  case 0x58:  /* KAD FIREWALLED_RES */ /* packet_len=8+2 + 4 */
	    if (packet_len == 14)
	      return (((t[0]==0xa4?IPP2P_KADU:IPP2P_KAD) * 100) + 65);
	    break;

	  case 0x59:  /* KAD FIREWALLED_ACK_RES */ /* packet_len=8+2 + 0 */
	    if (packet_len == 10)
	      return (((t[0]==0xa4?IPP2P_KADU:IPP2P_KAD) * 100) + 66);
	    break;

	  case 0x5A:  /* KAD FINDBUDDY_RES */ /* packet_len=8+2 + 16+16+2 */
	    if (packet_len == 44 || packet_len == 45)
	      return (((t[0]==0xa4?IPP2P_KADU:IPP2P_KAD) * 100) + 74);
	    break;
	    
	  case 0x60: /* KAD2 PING */  /* packet_len=8+2 + 0 */
	  case 0x61: /* KAD2 PONG */  /* packet_len=8+2 + 0 */
	    if (packet_len == 10)
	      return (((t[0]==0xa4?IPP2P_KADU:IPP2P_KAD) * 100) + 74);
	    break;

	  case 0x62:  /* KAD2 FIREWALLUDP */ /* packet_len=8+2 + 1 +2 */
	    if (packet_len == 13)
	      return (((t[0]==0xa4?IPP2P_KADU:IPP2P_KAD) * 100) + 74);
	    break;

	 default:
	   return 0;

	  }
	break;
      }
    case 0xc5:     /* Emule UDP extended messages */
      {
	switch (t[1])
	{
	 case 0x90: /* variable size*/
	 case 0x91: /* variable size*/
	 case 0x94: /* variable size*/
	   return ((IPP2P_EDK * 100) + 70); /* eMule extended UDP command*/
	 case 0xFE:
	   if (packet_len == 11)
	     {  
	      return ((IPP2P_EDK * 100) + 70); /* eMule extended UDP command*/
             }
	 case 0x92:
	 case 0x93:
	   if (packet_len == 10)
	     {  
	      return ((IPP2P_EDK * 100) + 70); /* eMule extended UDP command*/
             }
	   else
	      return 0;
	 case 0x95: /* DirectCallbackReq 8+2 + 2+16+1 */
	   if (packet_len == 29)
	     {  
	      return ((IPP2P_EDK * 100) + 70); /* eMule extended UDP command*/
             }
	 default:
	   return 0;
	}
        break;
      }
    case 0xe5:     /* KAD compressed messages */
    case 0xa5:     /* KADu (Kad AdunanzA on FastWeb) compressed messages */
      {                   
           if (payload_len> 12 && (t[2]==0x78 && (t[3]==0xda || t[3]==0x9c)))
	    {
	      /* zlib payload starts with 0x78da or 0x789c most of the times */
	      /* A more complex check would be that the 16-bits value
	         t[2]t[3] is a multiple of 31 due to the zlib checksum format
	     */
	    
	      return (((t[0]==0xa5?IPP2P_KADU:IPP2P_KAD) * 100) + 72); /* kad compressed command*/
	    }		  
	   else return 0;
      }

    }				/* end of switch (t[0]) */
  return 0;
}				/*udp_search_edk */


/*Search for UDP Gnutella commands*/
int
udp_search_gnu (unsigned char *haystack, const int packet_len, int payload_len)
{
  unsigned char *t = haystack;
  t += 8;

  if (memcmp (t, "GND", 3) == 0)
    return ((IPP2P_GNU * 100) + 51);
  if (memcmp (t, "GNUTELLA ", 9) == 0)
    return ((IPP2P_GNU * 100) + 52);
  return 0;
}				/*udp_search_gnu */


/*Search for UDP KaZaA commands*/
int
udp_search_kazaa (unsigned char *haystack, const int packet_len, int payload_len)
{
  unsigned char *t = haystack;

  if (packet_len == payload_len && t[packet_len - 1] == 0x00)
    {
      t += (packet_len - 6);
      if (memcmp (t, "KaZaA", 5) == 0)
	return (IPP2P_KAZAA * 100 + 50);
    }

  return 0;
}				/*udp_search_kazaa */

/*Search for UDP DirectConnect commands*/
int
_udp_search_directconnect (unsigned char *haystack, const int packet_len,
			  int payload_len)
{
  unsigned char *t = haystack;
  if ((packet_len == payload_len) && (*(t + 8) == 0x24)
      && (*(t + packet_len - 1) == 0x7c))
    {
      t += 8;
      if (memcmp (t, "SR ", 3) == 0)
	return ((IPP2P_DC * 100) + 60);
      if (memcmp (t, "Ping ", 5) == 0)
	return ((IPP2P_DC * 100) + 61);
    }
  return 0;
}				/*udp_search_directconnect */

/*Search for UDP DirectConnect commands*/
/* MMM - Original function completely wrong */
int
udp_search_directconnect (unsigned char *haystack, const int packet_len,
			  int payload_len)
{
  unsigned char *t = haystack;

  if (*(t + 8) != 0x24)
    return 0;  /* DirectConnect commands start with '$' */

  t += 9;

  if ((payload_len>11) && (memcmp (t, "SR ", 3) == 0) )
    return ((IPP2P_DC * 100) + 60);
  else if ((payload_len>13) && (memcmp (t, "Ping ", 5) == 0))
    return ((IPP2P_DC * 100) + 61);
  else 
    return 0;
}				/*udp_search_directconnect */


/*Search for UDP BitTorrent commands*/
int
udp_search_bit (unsigned char *haystack, const int packet_len, int payload_len)
{
  /* 
   * The default Mainstream BitTorrent DHT commands, starting with
   * "d1:" [a|r] "d2:id20:"
   */

  if (payload_len > 30 && get_u8 (haystack, 8) == 'd'
      && get_u8 (haystack, 9) == '1' && get_u8 (haystack, 10) == ':')
    {
      if (get_u8 (haystack, 11) == 'a' || get_u8 (haystack, 11) == 'r')
	{
	  if (memcmp (haystack + 12, "d2:id20:", 8) == 0)
          {
	    return (IPP2P_BIT * 100 + 57);
          }
	}
    }

  /* 
   * Less used, but common, Azureus/Vuze DHT commands
   * http://wiki.vuze.com/w/Distributed_hash_table
   */

  if (payload_len >= 20 && 
         ( haystack[16]==0x00 && haystack[17]==0x00 && haystack[18]==0x04 && ( haystack[8] & 0x80 )) )
   {
     switch (haystack[19])
      {
        case 0x00: /* Action 1024: REQUEST PING */
        case 0x02: /* Action 1026: REQUEST STORE */
        case 0x04: /* Action 1028: REQUEST FIND NODE */
        case 0x06: /* Action 1030: REQUEST FIND VALUE */
        case 0x0A: /* Action 1034: REQUEST STATS */
        case 0x0B: /* Action 1035: DATA */
        case 0x0C: /* Action 1036: REQUEST KEY BLOCK */
	      return (IPP2P_BIT * 100 + 98);
        default:
          break;
      }

   }
  else if (payload_len >= 20 && 
            ( haystack[8]==0x00 && haystack[9]==0x00 && haystack[10]==0x04 && ( haystack[16] & 0x80 )) )
   {
     switch (haystack[11])
      {
        case 0x01: /* Action 1025: REPLY PING */
        case 0x03: /* Action 1027: REPLY STORE */
        case 0x05: /* Action 1029: REPLY FIND NODE */
        case 0x07: /* Action 1031: REPLY FIND VALUE */
        case 0x08: /* Action 1032: REPLY ERROR */
        case 0x09: /* Action 1033: REPLY STATS */
        case 0x0D: /* Action 1037: REPLY KEY BLOCK */
          return (IPP2P_BIT * 100 + 99);
        default:
          break;
     }
   }

  /*
   * Original IPP2P rules, possibly from the xbt-tracker DHT
   * Apparenlty only the matching for 0x41727101980 works, the
   * others are too strict on the packet lenght.
   * Kept mostly for historical reasons. 
   */

  switch (packet_len)
    {
    case 24:
      /* ^ 00 00 04 17 27 10 19 80 */
      if ( payload_len>=16 &&
          (ntohl (get_u32 (haystack, 8)) == 0x00000417)
	      && (ntohl (get_u32 (haystack, 12)) == 0x27101980))
	    return (IPP2P_BIT * 100 + 50);
      break;
    case 44:
      if ( payload_len>=40 &&
          get_u32 (haystack, 16) == htonl (0x00000400)
          && get_u32 (haystack, 36) == htonl (0x00000104))
        return (IPP2P_BIT * 100 + 51);
       if ( payload_len>=20 &&
          get_u32 (haystack, 16) == htonl (0x00000400))
        return (IPP2P_BIT * 100 + 61);
      break;
    case 65:
      if ( payload_len>=40 &&
          get_u32 (haystack, 16) == htonl (0x00000404)
          && get_u32 (haystack, 36) == htonl (0x00000104))
        return (IPP2P_BIT * 100 + 52);
      if ( payload_len>=20 &&
          get_u32 (haystack, 16) == htonl (0x00000404))
        return (IPP2P_BIT * 100 + 62);
      break;
    case 67:
      if ( payload_len>=40 &&
          get_u32 (haystack, 16) == htonl (0x00000406)
          && get_u32 (haystack, 36) == htonl (0x00000104))
        return (IPP2P_BIT * 100 + 53);
      if ( payload_len>=20 &&
          get_u32 (haystack, 16) == htonl (0x00000406))
        return (IPP2P_BIT * 100 + 63);
      break;
    case 211:
      if ( payload_len>=12 &&
          get_u32 (haystack, 8) == htonl (0x00000405))
        return (IPP2P_BIT * 100 + 54);
      break;
    case 29:
      if ( payload_len>=12 &&
          (get_u32 (haystack, 8) == htonl (0x00000401)))
        return (IPP2P_BIT * 100 + 55);
      break;
    case 52:
      if ( payload_len>=16 &&
          get_u32 (haystack, 8) == htonl (0x00000827) &&
          get_u32 (haystack, 12) == htonl (0x37502950))
        return (IPP2P_BIT * 100 + 80);
      break;
    default:
      /* this packet does not have a constant size */
      if (packet_len >= 40 && get_u32 (haystack, 16) == htonl (0x00000402)
          && get_u32 (haystack, 36) == htonl (0x00000104))
        return (IPP2P_BIT * 100 + 56);
      break;
    }

#if 0
  /* bitlord rules */
  /* packetlen must be bigger than 40 */
  /* first 4 bytes are zero */
  if (packet_len > 40 && get_u32 (haystack, 8) == 0x00000000)
    {
      /* first rule: 00 00 00 00 01 00 00 xx xx xx xx 00 00 00 00 */
      if (get_u32 (haystack, 12) == 0x00000000 &&
	  get_u32 (haystack, 16) == 0x00010000 &&
	  get_u32 (haystack, 24) == 0x00000000)
	return (IPP2P_BIT * 100 + 71);

      /* 00 01 00 00 0d 00 00 xx xx xx xx 00 00 00 00 */
      if (get_u32 (haystack, 12) == 0x00000001 &&
	  get_u32 (haystack, 16) == 0x000d0000 &&
	  get_u32 (haystack, 24) == 0x00000000)
	return (IPP2P_BIT * 100 + 71);


    }
#endif

  return 0;
}				/*udp_search_bit */

int
udp_search_pplive (unsigned char *haystack, const int packet_len,
		   int payload_len)
{
    //byte1     (8) : 0xe9
    //byte2     (9) : 0x03
    //byte3     (10): 0x62 (not always)
    //byte4     (11): 0x01 (not always)
    //byte5     (12): 0x98
    //byte6     (13): 0xab
    //byte7     (14): 0x01
    //byte8     (15): 0x02
    //byte15    (22): 0x00 (not always)
    //byte16    (23): 0x00 (not always)
    //byte19    (26): 0x00 (not always)
    //byte20    (27): 0x00 (not always)
    
    int res = 0;
    if (get_u8(haystack, 8) != 0xe9 ||
        get_u8(haystack, 9) != 0x03 ||
        get_u8(haystack, 12) != 0x98 ||
        get_u8(haystack, 13) != 0xab ||
        get_u8(haystack, 14) != 0x01 ||
        get_u8(haystack, 15) != 0x02 
        //||get_u8(haystack, 10) != 0x62 || //remove from here to have 
        //get_u8(haystack, 11) != 0x01 || //a more general filter
        //get_u8(haystack, 22) != 0x00 ||
        //get_u8(haystack, 23) != 0x00 ||
        //get_u8(haystack, 26) != 0x00 ||
        //get_u8(haystack, 27) != 0x00)
        ) {
		// the match is based on 5 bytes
		// - the first three bytes of the payload
		// - other two consecutives bytes at ((((x1 & 0x0f) % 8) // 2) * 2 + 5)
		//
		//                          xa xb   xa xb   xa  xb    xa  xb
		//   [x1 : (x2:x3) (x4:x5) (x6:x7) (x8:x9) (x10:x11) (x12:x13)]
		//                          ^       ^       ^         ^
		//    x1 & 0x0f = 0,1,8,9___|       |       |         |
		//    x1 & 0x0f = 2,3,10,11_________|       |         |
		//    x1 & 0x0f = 4,5,12,13_________________|         |
		//    x1 & 0x0f = 6,7,14,15___________________________|
		//
		// the target is the comparison between (x2:x3) and the other group of bytes (xa:xb)
		// - xa == x2
		// - x3 % 2 == 0 --> xb == x3+1
		// - x3 % 2 != 0 --> xb == x3-1
		// - xb == x3
		// - x1 != 0, x2 != 0, x3 != 0 (just to encrease the strength!)
		unsigned int ind = ((get_u8(haystack, 8) & 0x0F) % 8 / 2)*2 + 5;
		unsigned int val1 = get_u8(haystack, 10);
		unsigned int val2 = get_u8(haystack, 8 + ind + 1);
		if (get_u8(haystack, 8) != 0 &&
		    get_u8(haystack, 9) != 0 &&
		    get_u8(haystack, 10) != 0) {
			if (get_u8(haystack,9) == get_u8(haystack, 8 + ind)) {
				if ((val1 % 2 == 0 && val2 == val1 + 1) || val2 == val1 - 1 || val1 == val2) {
					res = IPP2P_PPLIVE * 100 + 0;
				}
			}
		}
	}
    else  {
        res = IPP2P_PPLIVE * 100 + 0;
    }
 
    return res;
}

int
udp_search_sopcast (unsigned char *haystack, 
                    const int packet_len,
		            int payload_len)
{
    unsigned int byte1, byte9, byte10; 
    //unsigned int byte21, byte22;

    //byte1     (8):        0x00
    //byte3     (10):       0x01
    //byte9-10  (16-17):    (0x06, 0x01), (0x01, 0x01), (0x01, 0xFF), (0x03, 0xFF)
    //byte11-12 (18-19):    specific check using payload length
    //byte21-22 (28-29):    (optional!!!) specific check usign payload length
    byte1 = get_u8(haystack, 8);
    if (byte1 == 0x00) {
        //check specific values
        byte9 = get_u8(haystack, 16);
        byte10 = get_u8(haystack, 17);
        if (get_u8(haystack, 10) != 0x01 ||
            (!(byte9 == 0x06 && byte10 == 0x01) &&
             !(byte9 == 0x01 && byte10 == 0x01) &&
             !(byte9 == 0x01 && byte10 == 0xFF) &&
             !(byte9 == 0x03 && byte10 == 0xFF)))
            return 0;

        //check payload length using byte11-12 
        if ((get_u8(haystack, 18) * 256 + get_u8(haystack, 19) + 16) != packet_len)
            return 0;

        //byte21-22: different check based on byte9 value
        /* this can be optional???
        byte21 = get_u8(haystack, 28);
        byte22 = get_u8(haystack, 29);
        if ((byte9 == 0x06 && (byte21 * 256 + byte22 + 28) != packet_len) ||
            (byte9 == 0x01 && byte21 != 0 && byte22 != 0))
            return 0;
        */
    }
    //byte1     (8):        0xFF
    //byte2     (9):        0xFF
    //byte3     (10):       0x01
    //byte11    (18):       0x00
    //byte12    (19):       specific check using payload length
    else if (byte1 == 0xFF) {
        //check specific values
        if (get_u8(haystack, 9) != 0xFF ||
            get_u8(haystack, 10) != 0x01 ||
            get_u8(haystack, 18) != 0x00)
            return 0;
        //check payload length
        if (get_u8(haystack, 19) + 16 != packet_len)
            return 0;
    }
    else 
        return 0;

	return (IPP2P_SOPCAST * 100 + 0);
}

int
udp_search_tvants (unsigned char *haystack, 
                   const int packet_len,
		           int payload_len)
{
    //unsigned int byte9, byte5, byte6;
    //byte1     (8)     : 0x04
    //byte2     (9)     : 0x00
    //byte3     (10)    : 0x07, 0x05
    //byte4     (11)    : 0x00
    //byte5-6   (12-13) : (optional) specific check using payload length
    //byte7     (14)    : 0x00
    //byte8     (15)    : 0x00
    //byte9     (16)    : 0x53, 0x44
    //byte10    (17)    : 0x53
    //byte11    (18)    : 0x00
    //byte12    (19)    : 0x11, 0x12, 0x13
    //byte13    (20)    : 0x00

    //check constant values
    if (get_u8(haystack, 8) != 0x04 ||
        get_u8(haystack, 9) != 0x00 ||
        (get_u8(haystack, 10) != 0x07 && get_u8(haystack, 10) != 0x05) ||
        get_u8(haystack, 11) != 0x00 ||
        get_u8(haystack, 14) != 0x00 ||
        get_u8(haystack, 15) != 0x00 ||
        (get_u8(haystack, 16) != 0x53 && 
         get_u8(haystack, 16) != 0x44) ||
        get_u8(haystack, 17) != 0x53 ||
        get_u8(haystack, 18) != 0x00 ||
        (get_u8(haystack, 19) != 0x11 && 
         get_u8(haystack, 19) != 0x12 && 
         get_u8(haystack, 19) != 0x13) ||
        get_u8(haystack, 20) != 0x00)
        return 0;
 
    //check payload values
    /* optional
    byte5 = get_u8(haystack, 12);
    byte6 = get_u8(haystack, 13);
    byte9 = get_u8(haystack, 16);

    if (byte9 == 0x53 && 
        byte6 * 256 + byte5 + 8 != packet_len)
        return 0;
    else if (byte9 == 0x44)
    {
        if ((packet_len - 8) % byte5 != 0 || byte6 != 0)
         return 0;
    }
    */

    return (IPP2P_TVANTS * 100 + 0);
}

int
udp_search_dns (unsigned char *haystack, 
                   const int packet_len,
		           int payload_len)
{
  unsigned char *t = haystack;
  t += 8;

  // Following the example of L7 Filter, we match QUESTION (either 1 or 2) at (offset 4-5)
  // and the fact that the queries start with 0x01-0x3F followed by [a-z0-9] (offset 12-13)
  // This should be enough if we have at least 22 bytes in the payload.
  // If we have more bytes, we look for Type (0x0001-0x0010 or 0x001c) 
  // and Class (0x01,0x03,0x04,0xff), that are located after the Name termination 0x00
  // If you really want to be paranoid, you can check that characters in Name are in the 
  // legitimate charset.
  // This rule does not match the refused responses for Dynamic Update, because Zones (i.e. 
  // Question) is 0. The corresponding queries are matched.
  // It also doesn't match a few esoteric queries.

  if (!(t[4]==0 && (t[5]==0x01 || t[5]==0x02)))
    return 0;
    
  if (t[12]<0x01 || t[12]>0x3F)
    return 0;

  if (!((t[13]>=0x61 && t[13]<=0x7a) || (t[13]>=0x41 && t[13]<=0x5a) || (t[13]>=0x30 && t[13]<=0x39)))
    return 0;

  if (payload_len>22)
   {
     int idx = 14;
     while (idx < payload_len-8)
      {
        if (t[idx]==0) 
	  break;
	idx++;
      }

     if (idx < payload_len-12)
      {
        if ( t[idx+1]==0 &&
	    ( ( t[idx+2]>=0x01 && t[idx+2]<=0x10) || t[idx+2]==0x1c ||
	        t[idx+2]==0x26 || /* A6 IPv6 with indirection */ 
	      ( t[idx+2]==0xff || t[idx+2]==0xfd || t[idx+2]==0xfc )  /* QTYPEs */
	    ) &&
	     t[idx+3]==0 &&
	     ( t[idx+4]==0x01 || t[idx+4]==0x03 || t[idx+4]==0x04 || t[idx+4]==0xFF)
	   )
          return (IPP2P_DNS *100 + 0);
	else
	  return 0;
      }
     else
      return (IPP2P_DNS *100 + 0);
   }

 return (IPP2P_DNS *100 + 0);

}

int
udp_search_ppstream (unsigned char *haystack, const int packet_len,
		   int payload_len)
{
  unsigned char *t = haystack;
  unsigned int len;
  t += 8;

  if (t[2]==0x43)
   {
     len = get_u16(haystack,8);
     if (len==packet_len-8 || len==packet_len-12 || len==packet_len-14)
       return (IPP2P_PPSTREAM *100 + 0);
   }
  return 0;
}

int
udp_search_teredo (unsigned char *haystack, const int packet_len,
		   int payload_len)
{
  unsigned char *t = haystack;
  t += 8;

  if (t[0]==0x60 && t[1]==0x00 && t[2]==0x00 && t[3]==0x00 && 
      t[8]==0x20 && t[9]==0x01 && t[10]==0x00 && t[11]==0x00 )
   {
     /* IPv6 Teredo Tunneling */
     /* We might get a look inside to distinguish content, but on the 
        outside it will stay a single UDP flow... */
     switch (t[6])
      {
        case 0x06: /* TCP */
          return (IPP2P_TEREDO *100 + 1);
	  break;
        case 0x11: /* UDP */
          return (IPP2P_TEREDO *100 + 2);
	  break;
        default:   /* IPv6 fragments, IPv6 no-next-header and others */
          return (IPP2P_TEREDO *100 + 0);
	  break;
      }
   }
  else
   return 0;
}

int
udp_search_dtls (unsigned char *haystack, const int packet_len,
		   int payload_len)
{
  unsigned char *t = haystack;
  t += 8;

  if (  t[0]==0x16 && // Client Handshake
        t[1]==0xFE && // 255-1 (TLS 1.x)
      ( t[2]<=0xFF && t[2]>=0xFB ) && // 255-x (TLS 1.x)
      ( t[11]>=0x00 && t[11]<=0x39 ) )
  {
    if  ( t[13] == 0x01 )  // Client Hello
     {
       return (IPP2P_DTLS * 100 + 1 );
     }
    else if ( t[13] == 0x02 )  // Server Hello
     {
       return (IPP2P_DTLS * 100 + 2 );
     }
    else
      return (IPP2P_DTLS * 100 + 0 );
  } 
  else
   return 0;
}

int
udp_search_quic (unsigned char *haystack, const int packet_len,
		   int payload_len)
{
  unsigned char *t = haystack;
  t += 8;

  if (  t[0]==0x0d && // Client 1st packet with 8 byte ID and version indication
        t[9]==0x51 && // 'Q' (as of Qxxx QUIC version)
        t[13]==0x01 ) // 1st packet
  {
    /*
    A better test would be like uTP, matching the 8 bytes ID in both directions,
    with 0d+ID+'Q'+01 followed by 0c+ID+'01' 
    */
       return (IPP2P_QUIC * 100 + 1 );
  }
  else if (  t[0]==0x0c && // Server 1st packet with 8 byte ID 
        t[9]==0x01 ) // 1st packet
  {
    /*
    A better test would be like uTP, matching the 8 bytes ID in both directions,
    with 0d+ID+'Q'+01 followed by 0c+ID+'01' 
    */
       return (IPP2P_QUIC * 100 + 2 );
  }
  else
   return 0;
}

int
udp_search_sip (unsigned char *haystack, const int packet_len,
		   int payload_len)
{
  unsigned char *t = haystack;
  t += 8;

/*
INVITE 	Indicates a client is being invited to participate in a call session. 	RFC 3261
ACK 	Confirms that the client has received a final response to an INVITE request. 	RFC 3261
BYE 	Terminates a call and can be sent by either the caller or the callee. 	RFC 3261
CANCEL 	Cancels any pending request. 	RFC 3261
OPTIONS 	Queries the capabilities of servers. 	RFC 3261
REGISTER 	Registers the address listed in the To header field with a SIP server. 	RFC 3261
PRACK 	Provisional acknowledgement. 	RFC 3262
SUBSCRIBE 	Subscribes for an Event of Notification from the Notifier. 	RFC 3265
NOTIFY 	Notify the subscriber of a new Event. 	RFC 3265
PUBLISH 	Publishes an event to the Server. 	RFC 3903
INFO 	Sends mid-session information that does not modify the session state. 	RFC 6086
REFER 	Asks recipient to issue SIP request (call transfer.) 	RFC 3515
MESSAGE 	Transports instant messages using SIP. 	RFC 3428
UPDATE 	Modifies the state of a session without changing the state of the dialog. 	RFC 3311
*/

  if (memcmp (t, "SIP/2.0", 7) == 0)
    return ((IPP2P_SIP * 100) + 1);
  else if (memcmp (t, "REGISTER sip:", 13) == 0)
    return ((IPP2P_SIP * 100) + 2);
  else if (memcmp (t, "ACK sip:", 8) == 0)
    return ((IPP2P_SIP * 100) + 3);
  else if (memcmp (t, "INVITE sip:", 11) == 0)
    return ((IPP2P_SIP * 100) + 4);
  else if (memcmp (t, "PRACK sip:", 10) == 0)
    return ((IPP2P_SIP * 100) + 5);
  else if (memcmp (t, "BYE sip:", 8) == 0)
    return ((IPP2P_SIP * 100) + 6);
  else if (memcmp (t, "OPTIONS sip:", 12) == 0)
    return ((IPP2P_SIP * 100) + 7);
  else if (memcmp (t, "CANCEL sip:", 11) == 0)
    return ((IPP2P_SIP * 100) + 8);
  else if (memcmp (t, "UPDATE sip:", 11) == 0)
    return ((IPP2P_SIP * 100) + 9);
  else if (memcmp (t, "SUBSCRIBE sip:", 14) == 0)
    return ((IPP2P_SIP * 100) + 10);
  else if (memcmp (t, "NOTIFY sip:", 11) == 0)
    return ((IPP2P_SIP * 100) + 11);
  else if (memcmp (t, "PUBLISH sip:", 12) == 0)
    return ((IPP2P_SIP * 100) + 12);
  else if (memcmp (t, "INFO sip:", 9) == 0)
    return ((IPP2P_SIP * 100) + 13);
  else if (memcmp (t, "REFER sip:", 10) == 0)
    return ((IPP2P_SIP * 100) + 14);
  else if (memcmp (t, "MESSAGE sip:", 12) == 0)
    return ((IPP2P_SIP * 100) + 15);
  else
   return 0;
}


/*Search for Ares commands*/
//#define IPP2P_DEBUG_ARES
int
search_ares (const unsigned char *payload, const int plen, int payload_len)
//int search_ares (unsigned char *haystack, int packet_len, int head_len)
{
//      const unsigned char *t = haystack + head_len;

  /* all ares packets start with  */
  if (payload[1] == 0 && (plen - payload[0]) == 3)
    {
      switch (payload[2])
	{
	case 0x5a:
	  /* ares connect */
	  if (plen == 6 && payload[5] == 0x05)
	    return ((IPP2P_ARES * 100) + 1);
	  break;
	case 0x09:
	  /* ares search, min 3 chars --> 14 bytes
	   * lets define a search can be up to 30 chars --> max 34 bytes
	   */
	  if (plen >= 14 && plen <= 34)
	    return ((IPP2P_ARES * 100) + 1);
	  break;
#ifdef IPP2P_DEBUG_ARES
	default:
	  printk (KERN_DEBUG "Unknown Ares command %x recognized, len: %u \n",
		  (unsigned int) payload[2], plen);
#endif /* IPP2P_DEBUG_ARES */
	}
    }

#if 0
  /* found connect packet: 03 00 5a 04 03 05 */
  /* new version ares 1.8: 03 00 5a xx xx 05 */
  if ((plen) == 6 && payload_len == plen)
    {				/* possible connect command */
      if ((payload[0] == 0x03) && (payload[1] == 0x00) && (payload[2] == 0x5a)
	  && (payload[5] == 0x05))
	return ((IPP2P_ARES * 100) + 1);
    }
  if ((plen) == 60 && payload_len == plen)
    {				/* possible download command */
      if ((payload[59] == 0x0a) && (payload[58] == 0x0a))
	{
	  if (memcmp (t, "PUSH SHA1:", 10) == 0)	/* found download command */
	    return ((IPP2P_ARES * 100) + 2);
	}
    }
#endif

  return 0;
}				/*search_ares */

/*Search for SoulSeek commands*/
int
search_soul (const unsigned char *payload, const int plen, int payload_len)
{
//#define IPP2P_DEBUG_SOUL
  /* match: xx xx xx xx | xx = sizeof(payload) - 4 */
  if (get_u32 (payload, 0) == (plen - 4))
    {
      const tt_uint32 m = get_u32 (payload, 4);
      /* match 00 yy yy 00, yy can be everything */
      if (get_u8 (payload, 4) == 0x00 && get_u8 (payload, 7) == 0x00)
	{
#ifdef IPP2P_DEBUG_SOUL
	  printk (KERN_DEBUG "0: Soulseek command 0x%x recognized\n",
		  get_u32 (payload, 4));
#endif /* IPP2P_DEBUG_SOUL */
	  return ((IPP2P_SOUL * 100) + 1);
	}

      /* next match: 01 yy 00 00 | yy can be everything */
      if (get_u8 (payload, 4) == 0x01 && get_u16 (payload, 6) == 0x0000)
	{
#ifdef IPP2P_DEBUG_SOUL
	  printk (KERN_DEBUG "1: Soulseek command 0x%x recognized\n",
		  get_u16 (payload, 4));
#endif /* IPP2P_DEBUG_SOUL */
	  return ((IPP2P_SOUL * 100) + 2);
	}

      /* other soulseek commandos are: 1-5,7,9,13-18,22,23,26,28,35-37,40-46,50,51,60,62-69,91,92,1001 */
      /* try to do this in an intelligent way */
      /* get all small commandos */
      switch (m)
	{
	case 7:
	case 9:
	case 22:
	case 23:
	case 26:
	case 28:
	case 50:
	case 51:
	case 60:
	case 91:
	case 92:
	case 1001:
#ifdef IPP2P_DEBUG_SOUL
	  printk (KERN_DEBUG "2: Soulseek command 0x%x recognized\n",
		  get_u16 (payload, 4));
#endif /* IPP2P_DEBUG_SOUL */
	  return ((IPP2P_SOUL * 100) + 3);
	}

      if (m > 0 && m < 6)
	{
#ifdef IPP2P_DEBUG_SOUL
	  printk (KERN_DEBUG "3: Soulseek command 0x%x recognized\n",
		  get_u16 (payload, 4));
#endif /* IPP2P_DEBUG_SOUL */
	  return ((IPP2P_SOUL * 100) + 4);
	}
      if (m > 12 && m < 19)
	{
#ifdef IPP2P_DEBUG_SOUL
	  printk (KERN_DEBUG "4: Soulseek command 0x%x recognized\n",
		  get_u16 (payload, 4));
#endif /* IPP2P_DEBUG_SOUL */
	  return ((IPP2P_SOUL * 100) + 5);
	}

      if (m > 34 && m < 38)
	{
#ifdef IPP2P_DEBUG_SOUL
	  printk (KERN_DEBUG "5: Soulseek command 0x%x recognized\n",
		  get_u16 (payload, 4));
#endif /* IPP2P_DEBUG_SOUL */
	  return ((IPP2P_SOUL * 100) + 6);
	}

      if (m > 39 && m < 47)
	{
#ifdef IPP2P_DEBUG_SOUL
	  printk (KERN_DEBUG "6: Soulseek command 0x%x recognized\n",
		  get_u16 (payload, 4));
#endif /* IPP2P_DEBUG_SOUL */
	  return ((IPP2P_SOUL * 100) + 7);
	}

      if (m > 61 && m < 70)
	{
#ifdef IPP2P_DEBUG_SOUL
	  printk (KERN_DEBUG "7: Soulseek command 0x%x recognized\n",
		  get_u16 (payload, 4));
#endif /* IPP2P_DEBUG_SOUL */
	  return ((IPP2P_SOUL * 100) + 8);
	}

#ifdef IPP2P_DEBUG_SOUL
      printk (KERN_DEBUG
	      "unknown SOULSEEK command: 0x%x, first 16 bit: 0x%x, first 8 bit: 0x%x ,soulseek ???\n",
	      get_u32 (payload, 4), get_u16 (payload, 4) >> 16,
	      get_u8 (payload, 4) >> 24);
#endif /* IPP2P_DEBUG_SOUL */
    }

  /* match 14 00 00 00 01 yy 00 00 00 STRING(YY) 01 00 00 00 00 46|50 00 00 00 00 */
  /* without size at the beginning !!! */
  if (get_u32 (payload, 0) == 0x14 && get_u8 (payload, 4) == 0x01)
    {
      tt_uint32 y = get_u32 (payload, 5);
      /* we need 19 chars + string */
      if ((plen == payload_len) && (y + 19) <= (plen))
	{
	  const unsigned char *w = payload + 9 + y;
	  if (get_u32 (w, 0) == 0x01
	      && (get_u16 (w, 4) == 0x4600 || get_u16 (w, 4) == 0x5000)
	      && get_u32 (w, 6) == 0x00);
#ifdef IPP2P_DEBUG_SOUL
	  printk (KERN_DEBUG "Soulssek special client command recognized\n");
#endif /* IPP2P_DEBUG_SOUL */
	  return ((IPP2P_SOUL * 100) + 9);
	}
    }
  return 0;
}


/*Search for WinMX commands*/
int
search_winmx (const unsigned char *payload, const int plen, int payload_len)
{
//#define IPP2P_DEBUG_WINMX
  if (((plen) == 4 && payload_len == plen)
      && (memcmp (payload, "SEND", 4) == 0))
    return ((IPP2P_WINMX * 100) + 1);
  if (((plen) == 3 && payload_len == plen)
      && (memcmp (payload, "GET", 3) == 0))
    return ((IPP2P_WINMX * 100) + 2);
  //if (packet_len < (head_len + 10)) return 0;
  if (plen < 10 || payload_len != plen)
    return 0;

  if ((memcmp (payload, "SEND", 4) == 0) || (memcmp (payload, "GET", 3) == 0))
    {
      tt_uint16 c = 4;
      tt_uint8 count = 0;
      while (c + 2 < plen)
	{
	  if (payload[c] == 0x20 && payload[c + 1] == 0x22)
	    {
	      c++;
	      count++;
	      if (count >= 2)
		return ((IPP2P_WINMX * 100) + 3);
	    }
	  c++;
	}
    }

  if (plen == 149 && payload[0] == '8')
    {
#ifdef IPP2P_DEBUG_WINMX
      printk (KERN_INFO "maybe WinMX\n");
#endif
      if (get_u32 (payload, 17) == 0 && get_u32 (payload, 21) == 0
	  && get_u32 (payload, 25) == 0 &&
//          get_u32(payload,33) == htonl(0x71182b1a) && get_u32(payload,37) == htonl(0x05050000) &&
//          get_u32(payload,133) == htonl(0x31097edf) && get_u32(payload,145) == htonl(0xdcb8f792))
	  get_u16 (payload, 39) == 0
	  && get_u16 (payload, 135) == htons (0x7edf)
	  && get_u16 (payload, 147) == htons (0xf792))

	{
#ifdef IPP2P_DEBUG_WINMX
	  printk (KERN_INFO "got WinMX\n");
#endif
	  return ((IPP2P_WINMX * 100) + 4);
	}
    }
  return 0;
}				/*search_winmx */


/*Search for appleJuice commands*/
int
search_apple (const unsigned char *payload, const int plen, int payload_len)
{
  if ((payload_len > 7) && (plen > 7) && (payload[6] == 0x0d)
      && (payload[7] == 0x0a) && (memcmp (payload, "ajprot", 6) == 0))
    return (IPP2P_APPLE * 100);

  return 0;
}


/*Search for BitTorrent commands*/
int
search_bittorrent (const unsigned char *payload, const int plen,
		   int payload_len)
{
  if (plen > 20 && payload_len > 6)
    {
      /* test for match 0x13+"BitTorrent protocol" */
      if (payload[0] == 0x13)
	{
	  if (memcmp
	      (payload + 1, "BitTorrent protocol",
	       ((payload_len - 1) < 19 ? payload_len - 1 : 19)) == 0)
	    return (IPP2P_BIT * 100);
	}

      /* get tracker commandos, all starts with GET /
       * then it can follow: scrape| announce
       * and then ?hash_info=
       */

      if (memcmp (payload, "GET /", 5) == 0)
        { 
	  if (payload[5]==0x61 || payload[5]==0x73) /* either 'a' or 's' */ 
	   {
	     /* message scrape */
	     if (memcmp
	     	 (payload + 5, "scrape?info_hash=",
	     	  ((payload_len - 5) < 17 ? payload_len - 5 : 17)) == 0)
	       return (IPP2P_BIT * 100 + 1);
	     /* message announce */
	     if (memcmp
	     	 (payload + 5, "announce?info_hash=",
	     	  ((payload_len - 5) < 19 ? payload_len - 5 : 19)) == 0)
	       return (IPP2P_BIT * 100 + 2);
	     /* Private torrent messages */
	     if (memcmp
	     	 (payload + 5, "announce.php?info_hash=",
	     	  ((payload_len - 5) < 23 ? payload_len - 5 : 23)) == 0)
	       return (IPP2P_BIT * 100 + 3);
	     if (memcmp
	     	 (payload + 5, "announce.php?passkey=",
	     	  ((payload_len - 5) < 21 ? payload_len - 5 : 21)) == 0)
	       return (IPP2P_BIT * 100 + 4);
	     if (memcmp
	     	 (payload + 5, "announce.php?pid=",
	     	  ((payload_len - 5) < 17 ? payload_len - 5 : 17)) == 0)
	       return (IPP2P_BIT * 100 + 5);
	   }
         else if ( payload_len>45 &&(payload[38]==0x61 || payload[38]==0x73))
	   {
	     /* message scrape */
	     if (memcmp
	     	 (payload + 38, "scrape?info_hash=",
	     	  ((payload_len - 38) < 17 ? payload_len - 38 : 17)) == 0)
	       return (IPP2P_BIT * 100 + 1);
	     /* message announce */
	     if (memcmp
	     	 (payload + 38, "announce?info_hash=",
	     	  ((payload_len - 38) < 19 ? payload_len - 38 : 19)) == 0)
	       return (IPP2P_BIT * 100 + 2);
	     /* Private torrent messages */
	     if (memcmp
	     	 (payload + 38, "announce.php?info_hash=",
	     	  ((payload_len - 38) < 23 ? payload_len - 38 : 23)) == 0)
	       return (IPP2P_BIT * 100 + 3);
	     if (memcmp
	     	 (payload + 38, "announce.php?passkey=",
	     	  ((payload_len - 38) < 21 ? payload_len - 38 : 21)) == 0)
	       return (IPP2P_BIT * 100 + 4);
	     if (memcmp
	     	 (payload + 38, "announce.php?pid=",
	     	  ((payload_len - 38) < 17 ? payload_len - 38 : 17)) == 0)
	       return (IPP2P_BIT * 100 + 5);
	   }
	}
    }
  else
    {
      /* bitcomet encryptes the first packet, so we have to detect another 
       * one later in the flow */
      /* first try failed, too many missdetections */
      //if ( size == 5 && get_u32(t,0) == htonl(1) && t[4] < 3) return (IPP2P_BIT * 100 + 3);

      /* second try: block request packets */
      if (plen == 17 && payload_len == plen
	  && get_u32 (payload, 0) == htonl (0x0d) && payload[4] == 0x06
	  && get_u32 (payload, 13) == htonl (0x4000))
	return (IPP2P_BIT * 100 + 3);
    }

  return 0;
}



/*check for Kazaa get command*/
int
search_kazaa (const unsigned char *payload, const int plen, int payload_len)
{
  if ((payload_len == plen) && (payload[plen - 2] == 0x0d)
      && (payload[plen - 1] == 0x0a)
      && memcmp (payload, "GET /.hash=", 11) == 0)
    return (IPP2P_DATA_KAZAA * 100);

  return 0;
}


/*check for gnutella get command*/
int
search_gnu (const unsigned char *payload, const int plen, int payload_len)
{
  if ((payload_len == plen) && (payload[plen - 2] == 0x0d)
      && (payload[plen - 1] == 0x0a))
    {
      if (memcmp (payload, "GET /get/", 9) == 0)
	return ((IPP2P_DATA_GNU * 100) + 1);
      if (memcmp (payload, "GET /uri-res/", 13) == 0)
	return ((IPP2P_DATA_GNU * 100) + 2);
    }
  return 0;
}


/*check for gnutella get commands and other typical data*/
int
search_all_gnu (const unsigned char *payload, const int plen, int payload_len)
{

  if ((payload_len == plen) && (payload[plen - 2] == 0x0d)
      && (payload[plen - 1] == 0x0a))
    {

      if (memcmp (payload, "GNUTELLA CONNECT/", 17) == 0)
	return ((IPP2P_GNU * 100) + 1);
      if (memcmp (payload, "GNUTELLA/", 9) == 0)
	return ((IPP2P_GNU * 100) + 2);


      if ((memcmp (payload, "GET /get/", 9) == 0)
	  || (memcmp (payload, "GET /uri-res/", 13) == 0))
	{
	  tt_uint16 c = 8;
	  while (c + 13 < plen )
	    {
	      if (payload[c] == 0x0a && payload[c + 1] == 0x0d
		  && ((memcmp (&payload[c + 2], "X-Gnutella-", 11) == 0)
		      || (memcmp (&payload[c + 2], "X-Queue:", 8) == 0)))
		return ((IPP2P_GNU * 100) + 3);
	      c++;
	    }
	}
    }
  return 0;
}


/*check for KaZaA download commands and other typical data*/
int
search_all_kazaa (const unsigned char *payload, const int plen,
		  int payload_len)
{
  if ((payload_len == plen) && (payload[plen - 2] == 0x0d)
      && (payload[plen - 1] == 0x0a))
    {

      if (memcmp (payload, "GIVE ", 5) == 0)
	return ((IPP2P_KAZAA * 100) + 1);

      if (memcmp (payload, "GET /", 5) == 0)
	{
	  tt_uint16 c = 8;
	  while (c + 26 < plen )
	    {
	      if (payload[c] == 0x0a && payload[c + 1] == 0x0d
		  &&
		  ((memcmp (&payload[c + 2], "X-Kazaa-Username: ", 18) == 0)
		   ||
		   (memcmp (&payload[c + 2], "User-Agent: PeerEnabler/", 24)
		    == 0)))
		return ((IPP2P_KAZAA * 100) + 2);
	      c++;
	    }
	}
    }
  return 0;
}

/*fast check for edonkey file segment transfer command*/
int
search_edk (const unsigned char *payload, const int plen, int payload_len)
{
  if (payload[0] != 0xe3)
    return 0;
  else
    {
      if (payload[5] == 0x47)
	return (IPP2P_DATA_EDK * 100);
      else
	return 0;
    }
}



/*intensive but slower search for some edonkey packets including size-check*/
int
search_all_edk (const unsigned char *payload, const int plen, int payload_len)
{
  if (payload[0] != 0xe3 && payload[0] != 0xc5 && payload[0]!=0xd4)
    return 0;
  else
    {
      const tt_uint16 cmd = get_u16 (payload, 1);
      ED2K_type = payload[0];
      ED2K_subtype = payload[5];
      if (cmd == (plen - 5))   /* This check works only if the message
                                  is transmitted in a single segment  */
	{
	  switch (payload[5])
	    {
	    case 0x01:
	      return ((IPP2P_EDK * 100) + 1);	/*Client: hello or Server:hello */
	    case 0x4c:
	      return ((IPP2P_EDK * 100) + 9);	/*Client: Hello-Answer */
	    case 0x40:
	      if (payload[0] == 0xc5 || payload[0]==0xd4)
	        {
		  return ((IPP2P_EDK * 100) + 3);	/*Data: Compressed Part - return unused code*/
                }
	      else
	         return ((IPP2P_EDK * 100) + payload[5] % 100);
	    case 0x46:
	      if (payload[0] == 0xe3)
	         return ((IPP2P_EDK * 100) + 4);	/*Data: Sending Part - return unused code*/
	      else
	         return ((IPP2P_EDK * 100) + payload[5] % 100);
	    default:
	      return ((IPP2P_EDK * 100) + payload[5] % 100);
	    }
	}
      else if (payload[3] == 0 && payload[4] == 0)
        {
	  /* Previous check failed: perhaps a message larger than one segment
	     Message size usually 10kbyte, in any case smaller than 64K,
	     so byte 3 and byte 4 are 0
	     We also verify that we match the possible message types 
	     for emule/edonkey (opcodes.h for emule 0.48a)
	  */
	  
	 switch(payload[0])
	  {
	    case 0xe3:
	     switch (payload[5])
	      {
        	case  0x01:
        	case  0x05:
        	case  0x14:
        	case  0x15:
        	case  0x16:
        	case  0x18:
        	case  0x19:
        	case  0x1A:
        	case  0x1C:
        	case  0x1D:
        	case  0x1E:
        	case  0x1F:
        	case  0x21:
		case  0x23:
        	case  0x32:
        	case  0x33:
        	case  0x34:
        	case  0x35:
        	case  0x36:
        	case  0x38:
        	case  0x39:
        	case  0x3A:
        	case  0x3B:
        	case  0x3C:
        	case  0x3D:
        	case  0x40:
        	case  0x41:
        	case  0x42:
        	case  0x43:
		case  0x44:
        	case  0x47:
        	case  0x48:
        	case  0x49:
        	case  0x4A:
        	case  0x4B:
        	case  0x4C:
        	case  0x4D:
        	case  0x4E:
        	case  0x4F:
        	case  0x50:
        	case  0x51:
        	case  0x52:
        	case  0x53:
        	case  0x54:
        	case  0x55:
        	case  0x56:
        	case  0x57:
        	case  0x58:
        	case  0x59:
        	case  0x5B:
        	case  0x5C:
        	case  0x5D:
        	case  0x5E:
        	case  0x5F:
        	case  0x60:
        	case  0x61:
	          return ((IPP2P_EDK * 100) +  payload[5] % 100);
        	case  0x46:
	          return ((IPP2P_EDK * 100) + 4);
		default:
		  return 0;
	      }
	      break;
	    case 0xd4:
	     switch (payload[5])
	      {
        	case  0x15:
	          return ((IPP2P_EDK * 100) +  payload[5] % 100);
	      }
	    case 0xc5:
	     switch (payload[5])
	      {
        	case  0x01:
        	case  0x02:
        	case  0x60:
        	case  0x81:
        	case  0x82:
        	case  0x83:
        	case  0x84:
        	case  0x85:
        	case  0x86:
        	case  0x87:
        	case  0x90:
        	case  0x91:
        	case  0x92:
        	case  0x93:
        	case  0x94:
        	case  0x95:
        	case  0x96:
        	case  0x97:
        	case  0x98:
        	case  0x99:
        	case  0x9A:
        	case  0x9B:
        	case  0x9C:
        	case  0x9D:
        	case  0x9E:
        	case  0x9F:
        	case  0xA0:
        	case  0xA1:
        	case  0xA2:
        	case  0xA3:
        	case  0xA4:
	          return ((IPP2P_EDK * 100) +  payload[5] % 100);
        	case  0x40:
	          return ((IPP2P_EDK * 100) + 3);
		default:
		  return 0;
	      }
	      break;
            default:
	     return 0;	    
	  }
	  
	}
      else
       return 0;
    }
}


/*fast check for Direct Connect send command*/
int
search_dc (const unsigned char *payload, const int plen, int payload_len)
{

  if (payload[0] != 0x24)
    return 0;
  else
    {
      if (memcmp (&payload[1], "Send|", 5) == 0)
	return (IPP2P_DATA_DC * 100);
      else
	return 0;
    }

}


/*intensive but slower check for all direct connect packets*/
int
_search_all_dc (const unsigned char *payload, const int plen, int payload_len)
{
  if ((payload_len == plen) && payload[0] == 0x24
      && payload[plen - 1] == 0x7c)
    {
      const unsigned char *t = &payload[1];
      /* Client-Hub-Protocol */
      if (memcmp (t, "Lock ", 5) == 0)
	return ((IPP2P_DC * 100) + 1);
      /* Client-Client-Protocol, some are already recognized by client-hub (like lock) */
      if (memcmp (t, "MyNick ", 7) == 0)
	return ((IPP2P_DC * 100) + 38);
    }
  return 0;
}

/*intensive but slower check for all direct connect packets*/
/* - MMM - Modified to support looser matches over partial packets */
int
search_all_dc (const unsigned char *payload, const int plen, int payload_len)
{
  /* All commands start with '$' */
  if (payload[0] != 0x24)
    return 0;

  /* All commands end with '|' - If we have a complete packet, we check that */
 
  if ((payload_len == plen) && payload[plen - 1] != 0x7c)
    return 0;

  if (payload_len <= plen)
    {
      const unsigned char *t = &payload[1];
      /* Client-Hub-Protocol */
      if ( payload_len>=6 && memcmp (t, "Lock ", 5) == 0)
	 return ((IPP2P_DC * 100) + 1);
      /* Client-Client-Protocol, some are already recognized by client-hub (like lock) */
      if ( payload_len>=8 && memcmp (t, "MyNick ", 7) == 0)
	return ((IPP2P_DC * 100) + 38);
      /* Client-Client-Protocol, Upload command */
      if ( payload_len>=6 && memcmp (t, "Send|", 5) == 0)
	return (IPP2P_DC * 100);
    }
  return 0;
}

/*check for mute*/
int
search_mute (const unsigned char *payload, const int plen, int payload_len)
{
  if ((payload_len > 11)
      && (plen == 209 || plen == 345 || plen == 473 || plen == 609
	  || plen == 1121))
    {
      //printk(KERN_DEBUG "size hit: %u",size);
      if (memcmp (payload, "PublicKey: ", 11) == 0)
	{
	  return ((IPP2P_MUTE * 100) + 0);

/*			if (memcmp(t+size-14,"\x0aEndPublicKey\x0a",14) == 0)
			{
				printk(KERN_DEBUG "end pubic key hit: %u",size);
				
			}*/
	}
    }
  return 0;
}


/* check for xdcc */
int
search_xdcc (const unsigned char *payload, const int plen, int payload_len)
{
  /* search in small packets only */
  if ((payload_len == plen) && plen > 20 && plen < 200
      && payload[plen - 1] == 0x0a && payload[plen - 2] == 0x0d
      && memcmp (payload, "PRIVMSG ", 8) == 0)
    {

      tt_uint16 x = 10;

      /* is seems to be a irc private massage, chedck for xdcc command */
      while (x + 13 < plen)
	{
	  if (payload[x] == ':')
	    {
	      if (memcmp (&payload[x + 1], "xdcc send #", 11) == 0)
		return ((IPP2P_XDCC * 100) + 0);
	    }
	  x++;
	}
    }
  return 0;
}

/* search for waste */
int
search_waste (const unsigned char *payload, const int plen, int payload_len)
{
  if (plen >= 8 && payload_len >= 8 && memcmp (payload, "GET.sha1:", 9) == 0)
    return ((IPP2P_WASTE * 100) + 0);

  return 0;
}

#ifdef P2P_OLDPROTO
/* Full P2P matching, even if it includes obsolete protocols */

struct tcpmatch matchlist[] = {
  {IPP2P_EDK, SHORT_HAND_IPP2P, 20, &search_all_edk},
//    {IPP2P_DATA_KAZAA,SHORT_HAND_DATA,200, &search_kazaa},
//    {IPP2P_DATA_EDK,SHORT_HAND_DATA,60, &search_edk},
//    {IPP2P_DATA_DC,SHORT_HAND_DATA,26, &search_dc},
  {IPP2P_DC, SHORT_HAND_IPP2P, 5, search_all_dc},
//    {IPP2P_DATA_GNU,SHORT_HAND_DATA,40, &search_gnu},
  {IPP2P_GNU, SHORT_HAND_IPP2P, 5, &search_all_gnu},
  {IPP2P_KAZAA, SHORT_HAND_IPP2P, 5, &search_all_kazaa},
  {IPP2P_BIT, SHORT_HAND_IPP2P, 20, &search_bittorrent},
  {IPP2P_APPLE, SHORT_HAND_IPP2P, 5, &search_apple},
  {IPP2P_SOUL, SHORT_HAND_IPP2P, 5, &search_soul},
  {IPP2P_WINMX, SHORT_HAND_IPP2P, 2, &search_winmx},
  {IPP2P_ARES, SHORT_HAND_IPP2P, 5, &search_ares},
  {IPP2P_MUTE, SHORT_HAND_NONE, 200, &search_mute},
  {IPP2P_WASTE, SHORT_HAND_NONE, 5, &search_waste},
  {IPP2P_XDCC, SHORT_HAND_NONE, 5, &search_xdcc},
  {0, 0, 0, NULL}
};

struct udpmatch udp_list[] = {
  {IPP2P_DNS, SHORT_HAND_IPP2P, 22, &udp_search_dns},
  {IPP2P_KAZAA, SHORT_HAND_IPP2P, 14, &udp_search_kazaa},
  {IPP2P_BIT, SHORT_HAND_IPP2P, 23, &udp_search_bit},
  {IPP2P_GNU, SHORT_HAND_IPP2P, 11, &udp_search_gnu},
  {IPP2P_EDK, SHORT_HAND_IPP2P, 9, &udp_search_edk},
  {IPP2P_SIP, SHORT_HAND_IPP2P, 22, &udp_search_sip},
  {IPP2P_DC, SHORT_HAND_IPP2P, 12, &udp_search_directconnect},
  {IPP2P_PPLIVE, SHORT_HAND_IPP2P, 22, &udp_search_pplive},
  {IPP2P_SOPCAST, SHORT_HAND_IPP2P, 22, &udp_search_sopcast},
  {IPP2P_TVANTS, SHORT_HAND_IPP2P, 22, &udp_search_tvants},
  {IPP2P_PPSTREAM, SHORT_HAND_IPP2P, 12, &udp_search_ppstream},
  {IPP2P_TEREDO, SHORT_HAND_IPP2P, 21, &udp_search_teredo},
  {IPP2P_DTLS, SHORT_HAND_IPP2P, 25, &udp_search_dtls},
//  {IPP2P_QUIC, SHORT_HAND_IPP2P, 30, &udp_search_quic}, // Disabled, since there is new code for it
  {0, 0, 0, NULL}
};

#else
/* Only include current protocols (BitTorrent and eMule/ED2K/KAD) */

struct tcpmatch matchlist[] = {
  {IPP2P_EDK, SHORT_HAND_IPP2P, 20, &search_all_edk},
  {IPP2P_BIT, SHORT_HAND_IPP2P, 20, &search_bittorrent},
  {0, 0, 0, NULL}
};

struct udpmatch udp_list[] = {
  {IPP2P_DNS, SHORT_HAND_IPP2P, 22, &udp_search_dns},
  {IPP2P_BIT, SHORT_HAND_IPP2P, 23, &udp_search_bit},
  {IPP2P_EDK, SHORT_HAND_IPP2P, 9, &udp_search_edk},
  {IPP2P_SIP, SHORT_HAND_IPP2P, 22, &udp_search_sip},
  {IPP2P_PPLIVE, SHORT_HAND_IPP2P, 22, &udp_search_pplive},
  {IPP2P_SOPCAST, SHORT_HAND_IPP2P, 22, &udp_search_sopcast},
  {IPP2P_TVANTS, SHORT_HAND_IPP2P, 22, &udp_search_tvants},
  {IPP2P_PPSTREAM, SHORT_HAND_IPP2P, 12, &udp_search_ppstream},
  {IPP2P_TEREDO, SHORT_HAND_IPP2P, 21, &udp_search_teredo},
  {IPP2P_DTLS, SHORT_HAND_IPP2P, 25, &udp_search_dtls},
//  {IPP2P_QUIC, SHORT_HAND_IPP2P, 30, &udp_search_quic}, // Disabled, since there is new code for it
  {0, 0, 0, NULL}
};

#endif