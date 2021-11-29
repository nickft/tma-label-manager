/*
 *
 * Copyright (c) 2001
 *      Politecnico di Torino.  All rights reserved.
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
 * v1.2.0 memcpy optimization
*/

#ifdef DNS_CACHE_PROCESSOR

#include "tstat.h"

#include "dns_cache.h"

#define MAX_RECURSION 25
#define MAX_DNS_ENTRIES 30  /* max number of entries to be cached */

extern FILE *fp_stderr;

#define get_u8(X,O)   (*(tt_uint8  *)(X + O))
#define get_u16(X,O)  (*(tt_uint16 *)(X + O))
#define get_u32(X,O)  (*(tt_uint32 *)(X + O))

struct dnshdr{
  u_int16_t id;
  unsigned rd :1;
  unsigned tc :1;
  unsigned aa :1;
  unsigned opcode :4;
  unsigned qr :1;
  unsigned rcode :4;
  unsigned z :3;
  unsigned ra :1;
  u_int16_t qdcount;
  u_int16_t ancount;
  u_int16_t nscount;
  u_int16_t arcount;
};

void dns_response_processing(struct ip *pip, void* dnsdata, void* plast, void* pup);

void dns_cache_init()
{
  /* init the cache */
  cacheInitialize(GLOBALS.DNS_Cache_Size);
#ifdef SUPPORT_IPV6
  cacheInitialize_ipv6(GLOBALS.DNS_Cache_Size_IPv6);
#endif
}

void *check_dns_response(struct udphdr *pudp, int tproto, void *pdir, void *plast)
{
 /* check for dns response */
 if (tproto == PROTOCOL_UDP)
  {
    /* at least it's UDP protocol */
    if (ntohs(pudp->uh_sport)==53 || ntohs(pudp->uh_dport)==53)
     {
       /* A good candidate to be DNS response */
       struct dnshdr* dns_hdr = (struct dnshdr*)((unsigned char *)pudp+sizeof(struct udphdr));
       if (dns_hdr->qr==1 && (dns_hdr->ancount>0 && ntohs(dns_hdr->ancount)<=MAX_DNS_ENTRIES))
        {
 	  /* A valid DNS response */
 	  /* Return a pointer to the DNS payload data */
 	  return (void *)(dns_hdr);
        }else if(dns_hdr->qr==0 && dns_hdr->opcode==0 && dns_hdr->rcode==0){
        	/* A DNS query, save the time in which the request has been made */
        }
     }
  }
 /* do not process */
 return (void *)NULL;
}

void dns_process_response(struct ip *pip, void *pproto, int tproto, void *pdir,
                        int dir, void *udp_payload, void *plast)
{
  /* insert the dns response into the cache */
  dns_response_processing(pip, udp_payload, plast, pdir);
}

void dns_cache_status(void *thisdir, int tproto){
	/* return the status of the cache */
}

unsigned char read_str(unsigned char *payload, unsigned int offset, unsigned char *str_offset,
                       unsigned char *data, unsigned int maxsize, int depth)
{
  if (depth>MAX_RECURSION)
     return 0;

  /* Read a String from DNS message */
  if (offset>=maxsize)
     return 0;
    
  if (payload[offset]==0x00)
   {
     data[*str_offset -1] = 0x00;
     return 0x01;
   }
  else if ((payload[offset]&0xc0)==0xc0)
   {
     unsigned int pointer;

     pointer = ntohs(get_u16(payload,offset)) & 0x3fff;

     read_str(payload, pointer, str_offset, data, maxsize,depth+1);
     return 2;
   }
  else
   {
     unsigned char tot_read = 1;
     unsigned char len = payload[offset];
     unsigned char n;

     for(n=0; n<len; n++)
      {
	tot_read++;
	data[*str_offset] = payload[++offset];
	//Added because of buggy qname dati.uon.it,5433
	if(data[*str_offset]==0x2C)
	 {
	   data[*str_offset] = 0x00;
	 }
	str_offset[0] = str_offset[0]+1;
      }
     offset++;
     data[*str_offset] = 0x2e;
     str_offset[0] = str_offset[0]+1;
     u_char next_offset = read_str(payload, offset, str_offset, data, maxsize, depth+1);
     if (next_offset==0)
      {
	return 0;
      }
     return tot_read + next_offset;
   }
}

void dns_response_processing(
		struct ip *pip,
		void* dnsdata,
		void* plast,
		void* thisdir)
{
  void *dns_payload = dnsdata;
  struct dnshdr* dns_hdr = (struct dnshdr*)dnsdata;
  unsigned int payload_size = (unsigned char*)plast - (unsigned char*)dnsdata + 1;
  unsigned int  offset = sizeof(struct dnshdr);
  u_char qquery[255];
  u_char rquery[255];
  int valid = 1;
  int n_questions;

  if (debug >0)
     fprintf(fp_stderr, "DNS: processing response\n");
  for(n_questions = 0; n_questions< ntohs(dns_hdr->qdcount); n_questions++)
   {
     ////////////////////////////////////////////////////////////////////////////
     /*  Parse NAME FIELD
     *  
     *//////////////////////////////////////////////////////////////////////////
     unsigned char str_len = 0;
     unsigned char str_added_offset = 
                   read_str((unsigned char*)dnsdata, offset, &str_len, qquery,payload_size,0);

     if(str_added_offset == 0)
      {
        // Malformed dns response
        if (debug >0)
  	       fprintf(fp_stderr, "DNS: malformed dns response\n");
  	return;
      }
     offset += str_added_offset;

     unsigned int qtype;
     unsigned int qclass;

     qtype = ntohs(get_u16(dnsdata,offset));
     qclass = ntohs(get_u16(dnsdata,offset+2));

     if ( (qtype!=0x0001 && qtype!=0x001c && qtype!=0x00ff) || qclass!=0x0001)
      {
        // Question is not an PTR A question querying an IP address, then discard packet
        if (debug >0)
  	       fprintf(fp_stderr, "DNS: not a PTR A - discarding\n");
  	valid = 0;
      }
     offset+=4;
   }
   
  if (valid==1)
   {
     unsigned int n_answers;
     _Bool a_records = FALSE;
     _Bool aaaa_records = FALSE;
     unsigned long int servers[MAX_DNS_ENTRIES];
     struct in6_addr servers_ipv6[MAX_DNS_ENTRIES];
     int n_servers = 0;
     int n_servers_ipv6 = 0;
     unsigned int client_ip = 0;
     struct in6_addr client_ipv6;

     for (n_answers = 0; n_answers<ntohs(dns_hdr->ancount) && n_servers < MAX_DNS_ENTRIES ;n_answers++)
      {
  	unsigned char str_len = 0;
  	unsigned char str_added_offset = 
	              read_str(dnsdata, offset, &str_len, rquery, payload_size,0);
  	if(str_added_offset == 0)
	 {
  	   // Malformed dns query
           if (debug >0)
  	          fprintf(fp_stderr, "DNS: malformed dns response\n");
  	   continue;
  	 }
  	offset += str_added_offset;

  	unsigned int type;
	type = ntohs(get_u16(dns_payload,offset));
  	offset +=2;

  	unsigned int class_;
	class_ = ntohs(get_u16(dns_payload,offset));
  	offset +=2 + 4;

  	unsigned int rdlen;
	rdlen = ntohs(get_u16(dns_payload,offset));
  	offset +=2;

  	if ( type==0x0001 && class_==0x0001 )
	 {
  	   // A Record
  	   unsigned long int host_addr;
  	   a_records = TRUE;
  	   u_char i;
	   if (PIP_ISV4(pip))
  	      client_ip = ntohl(pip->ip_dst.s_addr);
	   else
	      memcpy(&client_ipv6,&(PIP_V6(pip)->ip6_daddr),sizeof(struct in6_addr));
  	   for (i=0;i<rdlen/4 && n_servers < MAX_DNS_ENTRIES;i++)
	    {
	      host_addr = ntohl(get_u32(dns_payload,offset));
  	      if (debug >0)
	       {
	         char address_mem[INET6_ADDRSTRLEN];
		 if (PIP_ISV4(pip))
	           inet_ntop(AF_INET,&(pip->ip_dst.s_addr),address_mem,sizeof(address_mem));
		 else
	           inet_ntop(AF_INET6,&client_ipv6,address_mem,sizeof(address_mem));
		 
  	   	     fprintf(fp_stderr, "DNS entry: %lu.%lu.%lu.%lu %s %s\n",
		             (host_addr & 0xff000000)>>24,
  	   	   	     (host_addr & 0x00ff0000)>>16,
  	   	   	     (host_addr & 0x0000ff00)>>8,
  	   	   	     (host_addr & 0x000000ff),
  	   	   	     qquery,address_mem);
	       }
  	      servers[n_servers] = host_addr;
  	      n_servers++;
  	      offset+=4;
  	    }
  	 }
	else if (type==0x000f)
	 {
  	   //MX Record
  	   offset += rdlen;
  	 }
  	else if (type==0x001c && class_==0x0001 )
	 {
	   // AAAA record
	   // We parse these entries even if SUPPORT_IPV6 is false
  	   aaaa_records = TRUE;
  	   u_char i;
	   struct in6_addr entry_ipv6;
	   
	   if (PIP_ISV4(pip))
  	      client_ip = ntohl(pip->ip_dst.s_addr);
	   else
	      memcpy(&client_ipv6,&(PIP_V6(pip)->ip6_daddr),sizeof(struct in6_addr));
	   for (i=0;i<rdlen/16;i++)
	    {
	      /* Read the IPv6 address in a in6_addr struct */
              entry_ipv6.s6_addr32[0] = get_u32(dns_payload,offset);
              entry_ipv6.s6_addr32[1] = get_u32(dns_payload,offset+4);
              entry_ipv6.s6_addr32[2] = get_u32(dns_payload,offset+8);
              entry_ipv6.s6_addr32[3] = get_u32(dns_payload,offset+12);
  	      if (debug >0)
	       {
	         char address_mem[INET6_ADDRSTRLEN];
	         inet_ntop(AF_INET6,&entry_ipv6,address_mem,sizeof(address_mem));
	         fprintf(fp_stderr, "DNS AAAA entry: %s",address_mem);
		 if (PIP_ISV4(pip))
	           inet_ntop(AF_INET,&(pip->ip_dst.s_addr),address_mem,sizeof(address_mem));
		 else
	           inet_ntop(AF_INET6,&client_ipv6,address_mem,sizeof(address_mem));
	         fprintf(fp_stderr, " for %s",address_mem);
                 fprintf(fp_stderr," about %s\n",qquery);
	       }

	      memcpy(&(servers_ipv6[n_servers_ipv6]),&entry_ipv6,sizeof(struct in6_addr));
	      n_servers_ipv6++;
	      offset+=16;
	    }
	 }
	else
	 {
  	   offset += rdlen;
  	 }
      }

     /* Send the answer to the cache if there is something to send */
     if (a_records && PIP_ISV4(pip))
      {
        int rval;
        rval = insert(
			qquery,
			client_ip,
			servers,
			n_servers*sizeof(servers[0]),
			pip->ip_src,
			((struct ucb*)thisdir)->pup->c2s.last_pkt_time,
			((struct ucb*)thisdir)->pup->s2c.last_pkt_time);

	if (rval > 0)
	 {
	   // fprintf(fp_stderr,"\nDNS cache (size=%d) full at %s\n",rval,Timestamp());
	 }
      }
#ifdef SUPPORT_IPV6
     else if (aaaa_records && PIP_ISV6(pip))
      {
        // We store only IPv6 entries contained in IPv6 DNS queries
        int rval;
	struct my_in6_addr my_client_ipv6;
	memcpy(&my_client_ipv6,&client_ipv6,sizeof(struct my_in6_addr));
        rval = insert_ipv6(
			qquery,
			my_client_ipv6,
			(struct my_in6_addr*)servers_ipv6,
			n_servers_ipv6*sizeof(servers_ipv6[0]),
			PIP_V6(pip)->ip6_saddr,
			((struct ucb*)thisdir)->pup->c2s.last_pkt_time,
			((struct ucb*)thisdir)->pup->s2c.last_pkt_time);

	if (rval > 0)
	 {
	   fprintf(fp_stderr,"\nDNS IPv6 cache (size=%d) full at %s\n",rval,Timestamp());
	 }
      }
#endif
   }
}

/* Return the hostname of server_ip when it was contacted by client_ip. If not return NULL */
unsigned char* reverse_lookup(unsigned long int client_ip, unsigned long int server_ip)
{
  return get(client_ip, server_ip);
}

struct DNS_data* get_dns_entry(
		unsigned long int client_ip,
		unsigned long int server_ip)
{
	struct DNS_data* dns_data;
	dns_data = getEntry(client_ip, server_ip);
	if(dns_data!=NULL){
		return dns_data;
	}else{
		return NULL;
	}
}

#ifdef SUPPORT_IPV6
unsigned char* reverse_lookup_ipv6(struct in6_addr *client_ip, struct in6_addr *server_ip)
{
  struct my_in6_addr my_client_ip,my_server_ip;
  memcpy(&my_client_ip,client_ip,sizeof(struct my_in6_addr));
  memcpy(&my_server_ip,server_ip,sizeof(struct my_in6_addr));
  return get_ipv6(my_client_ip,my_server_ip);
}

struct DNS_data_IPv6* get_dns_entry_ipv6(
		struct in6_addr *client_ip,
		struct in6_addr *server_ip)
{
	struct DNS_data_IPv6* dns_data;
	struct my_in6_addr my_client_ip,my_server_ip;
        memcpy(&my_client_ip,client_ip,sizeof(struct my_in6_addr));
        memcpy(&my_server_ip,server_ip,sizeof(struct my_in6_addr));
	dns_data = getEntry_ipv6(my_client_ip, my_server_ip);
	if(dns_data!=NULL){
		return dns_data;
	}else{
		return NULL;
	}
}
#endif
/*
unsigned long int dns_server(unsigned long int client_ip, unsigned long int server_ip)
{
  return get_dns_server(client_ip, server_ip);
}
*/
#endif
