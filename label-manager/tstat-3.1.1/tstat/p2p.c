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
#include "tcpL7.h"

#define P2P_DEBUG_LEVEL 1
#define P2P_DEBUG (debug>=P2P_DEBUG_LEVEL)
extern int debug;
extern FILE *fp_udp_logc;
extern int ED2K_type;
extern int ED2K_subtype;

int UDP_p2p_to_L7type (ucb *thisflow);
int UDP_p2p_to_logtype(ucb *thisflow);

int ED2K_is_C2C(int type, int subtype)
{
  // fprintf(fp_stdout, "%02x %02x\n",type,subtype);
  switch (type)
   {
   case 0xe3:
     switch (subtype)
      {
        case  0x01:
        case  0x46:
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
	   return 1;
        default:
	   return 0;	
      }
      break;
   case 0xd4:
   case 0xc5:
     switch (subtype)
      {
        case  0x01:
        case  0x02:
        case  0x40:
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
        case  0xA5:
        case  0xA6:
        case  0xA7:
        case  0xA8:
	   return 1;
        default:
	   return 0;
      }	
      break;
   default:
      return 0;
    }
}

int ED2K_is_C2S(int type, int subtype)
{
  // fprintf(fp_stdout, "%02x %02x\n",type,subtype);
  switch (type)
   {
   case 0xe3:
     switch (subtype)
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
	case  0x23:
	case  0x44:
	   return 1;
        default:
	   return 0;	
      }
      break;
   case 0xd4:
     switch (subtype)
      {
        case  0x15:
	   return 1;
        default:
	   return 0;	
      }
   default:
      return 0;
    }
}


int ED2K_is_data(int type, int subtype)
{
  if ( (type == 0xE3 && subtype == 0x46) ||
       (type == 0xD4 && subtype == 0x40) ||
       (type == 0xC5 && subtype == 0x40))
   {
    // fprintf (fp_stdout, "++Data found %02x-%02x\n",type,subtype); 
    return 1;
   }
  else
    return 0;
}

int ED2K_is_msg(int type, int subtype)
{
  switch (type)
   {
   case 0xe3:
     switch (subtype)
      {
        case  0x4E:
//  fprintf (fp_stdout, "++Message found %02x-%02x\n",type,subtype); 
	   return 1;
        default:
	   return 0;	
      }
      break;
   default:
      return 0;
    }
}



void
p2p_init ()
{
  /* nothing to do so far */
}

void *
getp2p (struct udphdr *pudp, int tproto, void *pdir, void *plast)
{
  /* just pass the complete packet and let the p2p_flow_stat decide */

  return (void *) pudp;
}

void
p2p_flow_stat (struct ip *pip, void *pproto, int tproto, void *pdir,
	       int dir, void *hdr, void *plast)
{
  int return_code;
  tcp_pair *ptp;
  ucb *udir;

  if (tproto == PROTOCOL_UDP)
    {

      udir = (ucb *) pdir;

#ifndef P2P_DETAILS
      if (udir->type!=UDP_UNKNOWN && udir->type!=P2P_UTP)
        return;
#endif

      if ((udir->type==UDP_UNKNOWN || udir->type==P2P_UTP ) && 
          udir->packets > MAX_UNKNOWN_PACKETS)
	return;

      return_code =
	p2p_udp_match (pip, pproto, tproto, pdir, dir, hdr, plast);

      if (return_code != 0)
	{
#ifdef P2P_DETAILS
	  udir->is_p2p = 1;
	  (udir->p2p).total_pkt++;
#endif

	  switch (return_code / 100)
	   {
	     case IPP2P_EDK:
              udir->type = P2P_EDK;
	      break;
	     case IPP2P_KAD:
              udir->type = P2P_KAD;
	      break;
	     case IPP2P_KADU:
              udir->type = P2P_KADU;
	      break;
	     case IPP2P_GNU:
              udir->type = P2P_GNU;
	      break;
	     case IPP2P_BIT:
               if (udir->type==P2P_UTP)
                  udir->type = P2P_UTPBT;
	       else
                  udir->type = P2P_BT;
	      break;
	     case IPP2P_DC:
              udir->type = P2P_DC;
	      break;
	     case IPP2P_KAZAA:
              udir->type = P2P_KAZAA;
	      break;
	    case IPP2P_PPLIVE:
	      if (udir->pup->addr_pair.a_port != 53 && 
              udir->pup->addr_pair.b_port != 53 &&
              //NETBIOS
              udir->pup->addr_pair.a_port != 137 &&
              udir->pup->addr_pair.b_port != 137) 
	          udir->type = P2P_PPLIVE;
	      break;
	    case IPP2P_SOPCAST:
	      udir->type = P2P_SOPCAST;
	      break;  
	    case IPP2P_TVANTS:
	      udir->type = P2P_TVANTS;
	      break;  
	    case IPP2P_DNS:
	      udir->type = DNS;
	      break;  
	    case IPP2P_PPSTREAM:
	      udir->type = P2P_PPSTREAM;
	      break;  
	    case IPP2P_TEREDO:
	      udir->type = TEREDO;
	      break;  
	    case IPP2P_SIP:
	      udir->type = UDP_SIP;
	      break;  
	    case IPP2P_DTLS:
	      udir->type = UDP_DTLS;
	      break;  
	    case IPP2P_QUIC:
	      udir->type = UDP_QUIC;
	      break;  
	   }

#ifdef P2P_DETAILS
	  switch (return_code / 100)
	   {
	     case IPP2P_EDK:
	      (udir->p2p).pkt_type_num[0]++;
	      break;
	     case IPP2P_KAD:
	      (udir->p2p).pkt_type_num[1]++;
	      break;
	     case IPP2P_KADU:
	      (udir->p2p).pkt_type_num[2]++;
	      break;
	     case IPP2P_GNU:
	      (udir->p2p).pkt_type_num[3]++;
	      break;
	     case IPP2P_BIT:
	      (udir->p2p).pkt_type_num[4]++;
	      break;
	     case IPP2P_DC:
	      (udir->p2p).pkt_type_num[5]++;
	      break;
	     case IPP2P_KAZAA:
	      (udir->p2p).pkt_type_num[6]++;
	      break;
	     case IPP2P_PPLIVE:
	      (udir->p2p).pkt_type_num[7]++;
	      break;
	     case IPP2P_SOPCAST:
	      (udir->p2p).pkt_type_num[8]++;
	      break;
	     case IPP2P_TVANTS:
	      (udir->p2p).pkt_type_num[9]++;
	      break;
	     default:
              /* No use counting DNS messages */
	      break;
	   }
#endif
	}
     
    }
  else
    {

      tcphdr *ptcp;
      ptcp = (tcphdr *) hdr;

      ptp = ((tcb *) pdir)->ptp;
      if (ptp != NULL && ptp->p2p_state != IGNORE_FURTHER_PACKETS && 
             ptp->ignore_dpi!=TRUE )
	{
	  return_code =
	    p2p_tcp_match (pip, pproto, tproto, pdir, dir, hdr, plast);
	  if (return_code != 0)
	    {
              /* this flow is a P2P flow, so the L7 FLOW must be set */
              
	      ptp->con_type |= P2P_PROTOCOL;
	      ptp->con_type &= ~OBF_PROTOCOL;
	      ptp->con_type &= ~MSE_PROTOCOL;
              
              if (ptp->p2p_type != 0
		  && (ptp->p2p_type / 100) != (return_code / 100))
		{
		  if (P2P_DEBUG)
		    fprintf(fp_stdout,"Warning: multiple P2P type matching: Old %d - New %d\n",
		    ptp->p2p_type, return_code);
		}
	      else if (ptp->p2p_type != 0 && ptp->p2p_type != return_code)
		{
		        ptp->p2p_type = return_code; /* return the last code */
 		  //    fprintf(fp_stdout, 
          //        "Warning: multiple P2P commands matching: Old %d - New %d\n",
          //        ptp->p2p_type,return_code);
		}
	      else
		ptp->p2p_type = return_code;
               
              
/*               if ( (return_code / 100 == IPP2P_EDK) && ED2K_subtype!=0x01)
	       {
	         if (ED2K_is_C2S(ED2K_type,ED2K_subtype))
		  {
	             ptp->p2p_c2s_count++;
		  }
		 else
		  {
	             ptp->p2p_c2c_count++;
		  }
	         if (ED2K_is_data(ED2K_type,ED2K_subtype))
		  {
	             ptp->p2p_data_count++;
		  }
		 else
		  {
	             ptp->p2p_sig_count++;
		  }
	       }
 */
              if (return_code / 100 == IPP2P_EDK)
	       {
	         if (ED2K_is_data(ED2K_type,ED2K_subtype))
		  {
	             ptp->p2p_data_count++;
		  }
		 else
		  {
	             ptp->p2p_sig_count++;
		  }
                 if (ED2K_subtype!=0x01)
		  { 
	            if (ED2K_is_C2S(ED2K_type,ED2K_subtype))
		     {
	               ptp->p2p_c2s_count++;
		     }
		    else
		    {
	              ptp->p2p_c2c_count++;
		    }
	          }
	         if (ED2K_is_msg(ED2K_type,ED2K_subtype))
		  {
	             ptp->p2p_msg_count++;
		  }
                }

              ED2K_type = 0;
	      ED2K_subtype = 0;
	    }

	  if ((ptp->p2p_type/100 != IPP2P_EDK) && ptp->packets > MAX_PACKETS_CON)
	    ptp->p2p_state = IGNORE_FURTHER_PACKETS;
//	  if (ptp->packets > MAX_PACKETS_CON)
//	    ptp->p2p_state = IGNORE_FURTHER_PACKETS;
	}
    }


}

int
p2p_tcp_match (struct ip *pip, void *pproto, int tproto, void *pdir,
	       int dir, void *hdr, void *plast)
{
  extern struct tcpmatch matchlist[];
  int payload_len;
  tcphdr *ptcp;
  unsigned char *haystack;
  int data_len;
  int p2p_result;
  int i;


  ptcp = (tcphdr *) hdr;
  i = 0;

  payload_len =
    getpayloadlength (pip, plast) - ((tcphdr *) pproto)->th_off * 4;

  haystack = (unsigned char *) ptcp + ptcp->th_off * 4;
  data_len = (unsigned char *) plast - (unsigned char *) haystack + 1;

  if (data_len <= 0 || payload_len == 0)
    return 0;


  p2p_result = 0;
  while (matchlist[i].command)
    {
      if (payload_len > matchlist[i].packet_len)
	{
	  p2p_result =
	    matchlist[i].function_name (haystack, payload_len, data_len);
	  if (p2p_result)
	    {
	     /*
               if (info->debug) printk("IPP2P.debug:TCP-match: %i from: %u.%u.%u.%u:%i to: %u.%u.%u.%u:%i Length: %i\n", 
                                  p2p_result, NIPQUAD(ip->saddr),ntohs(tcph->source), NIPQUAD(ip->daddr),ntohs(tcph->dest),hlen);
             */
	      return p2p_result;
	    }
	}
      i++;
    }
  return p2p_result;
}

int
p2p_udp_match (struct ip *pip, void *pproto, int tproto, void *pdir,
	       int dir, void *hdr, void *plast)
{
  extern struct udpmatch udp_list[];
  int payload_len;
  udphdr *pudp;
  unsigned char *haystack;
  int p2p_result;
  int data_len;
  int i;


  pudp = (udphdr *) hdr;
  payload_len = ntohs (((struct udphdr *) pproto)->uh_ulen);
  /* This is the UDP complete length, included the header size */

  i = 0;

  haystack = (unsigned char *) pudp;
  data_len = (unsigned char *) plast - (unsigned char *) haystack + 1;

  p2p_result = 0;
  while (udp_list[i].command)
    {
      if (payload_len > udp_list[i].packet_len)
	{
	  p2p_result = udp_list[i].function_name (haystack,
						  payload_len, data_len);
	  if (p2p_result)
	    {
              /*
              if (info->debug) printk("IPP2P.debug:UDP-match: %i from: %u.%u.%u.%u:%i to: %u.%u.%u.%u:%i Length: %i\n", 
                 p2p_result, NIPQUAD(ip->saddr),ntohs(udph->source), NIPQUAD(ip->daddr),ntohs(udph->dest),hlen);
              */
	      return p2p_result;
	    }
	}
      i++;
    }
  return p2p_result;
}


/* this will be called by the plugin */
void
make_p2p_conn_stats (void * flow, int tproto)
{
  ucb *thisUdir,*thisC2S,*thisS2C;
  udp_pair *pup;
  udp_pair * thisflow = (udp_pair *)flow;
  
  if (tproto == PROTOCOL_TCP)
    return;

  thisC2S = &(thisflow->c2s);
  thisS2C = &(thisflow->s2c);

  /* log only P2P or unknown traffic. avoid RTP and SKYPE that are managed
  by their plugin */
  
  if ( ( thisC2S->type < RTP || thisC2S->type >= SKYPE_SIG ) &&
       ( thisS2C->type < RTP || thisS2C->type >= SKYPE_SIG ) )
  {
     int L7type = UDP_p2p_to_L7type(thisC2S);
      
      switch (in_out_loc(thisflow->internal_src, thisflow->internal_dst,C2S))
      {
      case OUT_FLOW:
            add_histo (L7_UDP_num_out, L7type);
	    if (thisflow->cloud_dst)
	      {
                add_histo (L7_UDP_num_c_out, L7type);
	      }
	    else
	      {
                add_histo (L7_UDP_num_nc_out, L7type);
	      }
            break;
      case IN_FLOW:
            add_histo (L7_UDP_num_in, L7type);
	    if (thisflow->cloud_src)
	      {
                add_histo (L7_UDP_num_c_in, L7type);
	      }
	    else
	      {
                add_histo (L7_UDP_num_nc_in, L7type);
	      }
            break;
      case LOC_FLOW:
            add_histo (L7_UDP_num_loc, L7type);
            break;
      }
     
      L7type = UDP_p2p_to_L7type(thisS2C);
      
      if (thisS2C->packets!=0)
       {
	 switch (in_out_loc(thisflow->internal_src, thisflow->internal_dst,S2C))
     	  {
     	   case OUT_FLOW:
     	       add_histo (L7_UDP_num_out, L7type);
	       if (thisflow->cloud_src)
	         {
                   add_histo (L7_UDP_num_c_out, L7type);
	         }
	       else
	         {
                   add_histo (L7_UDP_num_nc_out, L7type);
	         }
     	       break;
     	   case IN_FLOW:
     	       add_histo (L7_UDP_num_in, L7type);
	       if (thisflow->cloud_dst)
	         {
                   add_histo (L7_UDP_num_c_in, L7type);
	         }
	       else
	         {
                   add_histo (L7_UDP_num_nc_in, L7type);
	         }
     	       break;
     	   case LOC_FLOW:
     	       add_histo (L7_UDP_num_loc, L7type);
     	       break;
     	  }
       }
   }
#ifndef LOG_ALL_UDP
   else
       return;
#endif

  if (!LOG_IS_ENABLED(LOG_UDP_COMPLETE) || fp_udp_logc == NULL)
    return;

  thisUdir = thisC2S;
  pup = thisUdir->pup;

  //     #   Field Meaning
  //    --------------------------------------
  //     1   Source Address
  //     2   Source Port

  if (pup->crypto_src==FALSE)
     wfprintf (fp_udp_logc, "%s %s",
	       HostName (pup->addr_pair.a_address),
	       ServiceName (pup->addr_pair.a_port));
  else 
     wfprintf (fp_udp_logc, "%s %s",
	       HostNameEncrypted (pup->addr_pair.a_address),
	       ServiceName (pup->addr_pair.a_port));
	       
  //     3   Flow Start Time
  //     4   Flow Elapsed Time [s]
  //     5   Flow Size [Bytes]
  wfprintf (fp_udp_logc,
	   " %f %.6f %llu",
	   time2double ((thisUdir->first_pkt_time))/1000., 
//         elapsed (first_packet,thisUdir->first_pkt_time)/1000,
	   elapsed (thisUdir->first_pkt_time, thisUdir->last_pkt_time) /
	   1000.0 / 1000.0, thisUdir->data_bytes);

  //     6   No. of Total flow packets
  wfprintf (fp_udp_logc, " %lld", thisUdir->packets);

  // 7 internal address
  // 8 udp_type

  wfprintf (fp_udp_logc, " %d %d %d",
	   thisflow->internal_src, thisflow->crypto_src, UDP_p2p_to_logtype(thisUdir));

#ifdef P2P_DETAILS
  wfprintf (fp_udp_logc, " %d %d %d %d %d %d %d %d %d %d",
  //  9
  //  10 Emule-EDK
  //  11 Emule-KAD
  //  12 Emule-KADU
  //  13 Gnutella
  //  14 Bittorrent
  //  15 DirectConnect
  //  16 Kazaa
  //  17 PPLive
  //  18 SopCast
  //  19 TVAnts
           thisUdir->p2p.total_pkt,
	   thisUdir->p2p.pkt_type_num[0],
	   thisUdir->p2p.pkt_type_num[1],
	   thisUdir->p2p.pkt_type_num[2],
	   thisUdir->p2p.pkt_type_num[3],
	   thisUdir->p2p.pkt_type_num[4],
	   thisUdir->p2p.pkt_type_num[5],
	   thisUdir->p2p.pkt_type_num[6],
	   thisUdir->p2p.pkt_type_num[7],
	   thisUdir->p2p.pkt_type_num[8],
	   thisUdir->p2p.pkt_type_num[9]);
#endif

  thisUdir = thisS2C;
  pup = thisUdir->pup;

  //     #   Field Meaning
  //    --------------------------------------
  //     9   Source Address
  //     10   Source Port

  if (pup->crypto_dst==FALSE)
     wfprintf (fp_udp_logc, " %s %s",
	       HostName (pup->addr_pair.b_address),
	       ServiceName (pup->addr_pair.b_port));
  else
     wfprintf (fp_udp_logc, " %s %s",
	       HostNameEncrypted (pup->addr_pair.b_address),
	       ServiceName (pup->addr_pair.b_port));

  //     11   Flow Start Time
  //     12   Flow Elapsed Time [s]
  //     13   Flow Size [Bytes]
  wfprintf (fp_udp_logc,
	   " %f %.6f %llu",
	   time2double ((thisUdir->first_pkt_time))/1000., 
//         elapsed (first_packet,thisUdir->first_pkt_time)/1000,
	   elapsed (thisUdir->first_pkt_time, thisUdir->last_pkt_time) /
	   1000.0 / 1000.0, thisUdir->data_bytes);

  //     14   No. of Total flow packets
  wfprintf (fp_udp_logc, " %lld", thisUdir->packets);

  // 15 internal address
  // 16 udp_type

  wfprintf (fp_udp_logc, " %d %d %d",
	   thisflow->internal_dst, thisflow->crypto_dst, UDP_p2p_to_logtype(thisUdir));

#ifdef P2P_DETAILS
  wfprintf (fp_udp_logc, " %d %d %d %d %d %d",
  //  9
  //  10 Emule-EDK
  //  11 Emule-KAD
  //  12 Emule-KADU
  //  13 Gnutella
  //  14 Bittorrent
  //  15 DirectConnect
  //  16 Kazaa
  //  17 PPLive
  //  18 SopCast
  //  19 TVAnts
           logline, thisUdir->p2p.total_pkt,
	   thisUdir->p2p.pkt_type_num[0],
	   thisUdir->p2p.pkt_type_num[1],
	   thisUdir->p2p.pkt_type_num[2],
	   thisUdir->p2p.pkt_type_num[3],
	   thisUdir->p2p.pkt_type_num[4],
	   thisUdir->p2p.pkt_type_num[5],
	   thisUdir->p2p.pkt_type_num[6],
	   thisUdir->p2p.pkt_type_num[7],
	   thisUdir->p2p.pkt_type_num[8],
	   thisUdir->p2p.pkt_type_num[9]);
#endif

#ifdef DNS_CACHE_PROCESSOR
  wfprintf (fp_udp_logc, " %s",thisflow->dns_name!=NULL?thisflow->dns_name:"-");
#endif

  // wfprintf (fp_udp_logc, " %d %d",thisC2S->is_QUIC,thisS2C->is_QUIC);
  
  wfprintf (fp_udp_logc, "\n");

  return;
}

int UDP_p2p_to_logtype(ucb *thisflow)
{
   switch(thisflow->type)
   {
    case UDP_UNKNOWN:
    case FIRST_RTP:
    case FIRST_RTCP:
      switch(thisflow->pup->kad_state)
        {
          case OUDP_RES52_K25:
          case OUDP_RES68_K25:
          case OUDP_SIZE_IN_46_57:
          case OUDP_SIZEX_22:
          case OUDP_SIZEX_52:
	    if (thisflow->pup->addr_pair.a_port != 123 &&
	        thisflow->pup->addr_pair.b_port != 123)
	        return P2P_OKAD;
	    else
	        return thisflow->type;
          default:
	    return thisflow->type;
	}
    case SKYPE_E2E:
      if (thisflow->skype!=NULL && 
          thisflow->skype->skype_type==L7_FLOW_SKYPE_E2E)
         return SKYPE_E2E;
      else
	 return UDP_UNKNOWN;

    case SKYPE_OUT:
      if (thisflow->skype!=NULL && 
          thisflow->skype->skype_type==L7_FLOW_SKYPE_E2O)
         return SKYPE_OUT;
      else
	 return UDP_UNKNOWN;
    default:
      return thisflow->type;
   }
}

int UDP_p2p_to_L7type (ucb *thisflow)
{
   switch(thisflow->type)
   {
    case RTP:
      return L7_FLOW_RTP;

    case RTCP:
      return L7_FLOW_RTCP;

    case SKYPE_E2E:
      if (thisflow->skype!=NULL && 
          thisflow->skype->skype_type==L7_FLOW_SKYPE_E2E)
         return L7_FLOW_SKYPE_E2E;
      else
	 return L7_FLOW_UNKNOWN;

    case SKYPE_OUT:
      if (thisflow->skype!=NULL && 
          thisflow->skype->skype_type==L7_FLOW_SKYPE_E2O)
         return L7_FLOW_SKYPE_E2O;
      else
	 return L7_FLOW_UNKNOWN;

    case SKYPE_SIG:
      return L7_FLOW_SKYPE_SIG;

      
    case P2P_EDK:
      return L7_FLOW_EDK;
      
    case P2P_KAD:
      return L7_FLOW_KAD;
      
    case P2P_KADU:
      return L7_FLOW_KADU;
      
    case P2P_DC:
      return L7_FLOW_DC;
      
    case P2P_GNU:
      return L7_FLOW_GNU;
      
    case P2P_KAZAA:
      return L7_FLOW_KAZAA;
      
    case P2P_BT:
      return L7_FLOW_BIT;

    case P2P_UTP:
    case P2P_UTPBT:
      return L7_FLOW_UTP;
      
    case P2P_PPLIVE:
      return L7_FLOW_PPLIVE;
      
    case P2P_SOPCAST:
      return L7_FLOW_SOPCAST; 
    
    case P2P_TVANTS:
      return L7_FLOW_TVANTS; 

    case DNS:
      return L7_FLOW_DNS;

    case UDP_VOD:
      return L7_FLOW_VOD;

    case P2P_PPSTREAM:
      return L7_FLOW_PPSTREAM;
      
    case TEREDO:
      return L7_FLOW_TEREDO;

    case UDP_SIP:
      return L7_FLOW_SIP;

    case UDP_DTLS:
      return L7_FLOW_DTLS;

    case UDP_QUIC:
      return L7_FLOW_QUIC;

    case UDP_UNKNOWN:
    case FIRST_RTP:
    case FIRST_RTCP:
      switch(thisflow->pup->kad_state)
        {
          case OUDP_RES52_K25:
          case OUDP_RES68_K25:
          case OUDP_SIZE_IN_46_57:
          case OUDP_SIZEX_22:
          case OUDP_SIZEX_52:
	    if (thisflow->pup->addr_pair.a_port != 123 &&
	        thisflow->pup->addr_pair.b_port != 123)
	        return L7_FLOW_OBF_KAD;
	    else
	        return L7_FLOW_UNKNOWN;
          default:
	    return L7_FLOW_UNKNOWN;
	}
    default:
      return L7_FLOW_UNKNOWN;
   }
}



int TCP_p2p_to_L7type (tcp_pair *thisflow)
{
    switch(thisflow->p2p_type / 100)
    {
    case IPP2P_EDK:
    case IPP2P_DATA_EDK:
      return L7_FLOW_EDK;

    case IPP2P_KAZAA:
    case IPP2P_DATA_KAZAA:
      return L7_FLOW_KAZAA;

    case IPP2P_DATA_DC:
    case IPP2P_DC:
      return L7_FLOW_DC;

    case IPP2P_DATA_GNU:
    case IPP2P_GNU:
      return L7_FLOW_GNU;

    case IPP2P_BIT:
      return L7_FLOW_BIT;

    case IPP2P_APPLE:
      return L7_FLOW_APPLE;

    case IPP2P_SOUL:
      return L7_FLOW_SOUL;

    case IPP2P_WINMX:
      return L7_FLOW_WINMX;

    case IPP2P_ARES:
      return L7_FLOW_ARES;

    case IPP2P_MUTE:
      return L7_FLOW_MUTE;

    case IPP2P_WASTE:
      return L7_FLOW_WASTE;

    case IPP2P_XDCC:
      return L7_FLOW_XDCC;
    }
  return L7_FLOW_UNKNOWN;
}

