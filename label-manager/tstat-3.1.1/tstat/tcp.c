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
#include "videoL7.h"
#include <regex.h>

/* DNS cache piece */
#include "dns_cache.h"
long int tcp_cleaned = 0;
long int udp_cleaned = 0;

/* provided globals  */
extern FILE *fp_logc;
extern FILE *fp_lognc;
extern FILE *fp_rtp_logc;
extern FILE *fp_video_logc;
extern FILE *fp_streaming_logc;

extern Bool is_stdin;
extern Bool printticks;
extern unsigned long int fcount;
extern unsigned long int f_TCP_count;
/* TOPIX */
extern unsigned long int f_RTP_tunneled_TCP_count;
extern struct L4_bitrates L4_bitrate;
/* end TOPIX */
extern int log_version;
extern int log_level;
extern int video_level;

extern long int tcp_packet_count;
extern Bool strict_privacy;

#ifdef DNS_CACHE_PROCESSOR
extern Bool dns_enabled;
#endif

Bool thread_stats_flag = FALSE;	/* parameter used to make not possible that two
				   istances of the same thread can run at the same time */

/* garbage offloading vars */
int tcp_index = 0;
int udp_index = 0;

/* tcp database stats */
long not_id_p;
int search_count = 0;

int num_tcp_pairs = 0;		/* how many pairs we've allocated */
tcp_pair **ttp = NULL;		/* array of pointers to allocated pairs */
struct tp_list_elem *tp_list_start = NULL;	/* starting point of the linked list */
struct tp_list_elem *tp_list_curr = NULL;	/* current insert point of the linked list */
u_long tcp_trace_count_outgoing = 0;
u_long tcp_trace_count_incoming = 0;
u_long tcp_trace_count_local = 0;


/* local routine definitions */
static tcp_pair **NewTTP_2 (struct ip *, struct tcphdr *);
static ptp_snap **FindTTP (struct ip *, struct tcphdr *, int *);
static void free_tp (tcp_pair * ptp_save);
static int ConnReset (tcp_pair *);
static int ConnComplete (tcp_pair *);
/*
static u_int SynCount (tcp_pair * ptp);
*/
/*
static u_int FinCount (tcp_pair * ptp);
*/
void update_conn_log_mm_v1 (tcp_pair *tcp_save, tcb *pab, tcb *pba);
void update_conn_log_mm_v2 (tcp_pair *tcp_save, tcb *pab, tcb *pba);

#if defined(VIDEO_DETAILS) || defined(STREAMING_CLASSIFIER) 
Bool is_video(tcp_pair *ptp_save);
void update_video_log (tcp_pair *tcp_save, tcb *pab, tcb *pba);
#endif

#if defined(VIDEO_DETAILS) || defined(STREAMING_CLASSIFIER) 
Bool is_streaming(tcp_pair *ptp_save);
void update_streaming_log(tcp_pair *tcp_save, tcb *pab, tcb *pba);
#endif

/* Patterns for SSL_youtube*/
regex_t yt_re[4];

void init_ssl_youtube_patterns();
Bool is_ssl_youtube(tcp_pair *ptp_save);

#ifdef CHECK_TCP_DUP
Bool
dup_tcp_check (struct ip *pip, struct tcphdr *ptcp, tcb * thisdir)
{
//  static int tot;
  double delta_t = elapsed (thisdir->last_time, current_time);
  
  if (!PIP_ISV4(pip)) return FALSE;
  
  if (thisdir->last_ip_id == pip->ip_id &&
      thisdir->last_checksum == ntohs(ptcp->th_sum) && 
      delta_t < GLOBALS.Min_Delta_T_TCP_Dup_Pkt && thisdir->last_len == pip->ip_len)
    {
 //      fprintf (fp_stdout, "dup tcp %d , id = %u ",tot++, pip->ip_id);
 //      fprintf (fp_stdout, "TTL: %d ID: %d Checksum: %d Delta_t: %g\n", 
 //           pip->ip_ttl,pip->ip_id,ntohs(ptcp->th_sum),delta_t);
      thisdir->last_ip_id = pip->ip_id;
      thisdir->last_len = pip->ip_len;
      thisdir->last_checksum = ntohs(ptcp->th_sum);
      return TRUE;
    }
 //   fprintf (fp_stdout, "NOT dup tcp %d\n",tot);
  thisdir->last_ip_id = pip->ip_id;
  thisdir->last_len = pip->ip_len;
  thisdir->last_checksum = ntohs(ptcp->th_sum);
  return FALSE;
}
#endif


void
tcp_header_stat (struct tcphdr *ptcp, struct ip *pip, void *plast)
{
  int ip_len = gethdrlength (pip, plast) + getpayloadlength (pip, plast);
  
  /* perform TCP packet analysis */
  if ((!ACK_SET (ptcp) && SYN_SET (ptcp)))
    {
      if (internal_src && !internal_dst)
	{
	  add_histo (tcp_port_synsrc_out, (float) ntohs (ptcp->th_sport));
	  add_histo (tcp_port_syndst_out, (float) ntohs (ptcp->th_dport));
	}
      else if (!internal_src && internal_dst)
	{
	  add_histo (tcp_port_synsrc_in, (float) ntohs (ptcp->th_sport));
	  add_histo (tcp_port_syndst_in, (float) ntohs (ptcp->th_dport));
	}
#ifndef LOG_UNKNOWN
      else if (internal_src && internal_dst)
#else
      else
#endif
	{
	  add_histo (tcp_port_synsrc_loc, (float) ntohs (ptcp->th_sport));
	  add_histo (tcp_port_syndst_loc, (float) ntohs (ptcp->th_dport));
	}
    }

  if (internal_src && !internal_dst)
    {
      L4_bitrate.out[TCP_TYPE] += ip_len;
      add_histo (tcp_port_src_out, (float) ntohs (ptcp->th_sport));
      add_histo (tcp_port_dst_out, (float) ntohs (ptcp->th_dport));
      if (cloud_dst)
       {
         L4_bitrate.c_out[TCP_TYPE] += ip_len;
       }
      else
       {
         L4_bitrate.nc_out[TCP_TYPE] += ip_len;
       }
    }
  else if (!internal_src && internal_dst)
    {
      L4_bitrate.in[TCP_TYPE] += ip_len;
      add_histo (tcp_port_src_in, (float) ntohs (ptcp->th_sport));
      add_histo (tcp_port_dst_in, (float) ntohs (ptcp->th_dport));
      if (cloud_src)
       {
         L4_bitrate.c_in[TCP_TYPE] += ip_len;
       }
      else
       {
         L4_bitrate.nc_in[TCP_TYPE] += ip_len;
       }
    }
#ifndef LOG_UNKNOWN
  else if (internal_src && internal_dst)
#else
  else
#endif
    {
      L4_bitrate.loc[TCP_TYPE] += ip_len;
      add_histo (tcp_port_src_loc, (float) ntohs (ptcp->th_sport));
      add_histo (tcp_port_dst_loc, (float) ntohs (ptcp->th_dport));
    }

  return;
}

/*
u_int
SynCount (tcp_pair * ptp)
{
  tcb *pab = &ptp->c2s;
  tcb *pba = &ptp->s2c;

  return (((pab->syn_count >= 1) ? 1 : 0) + ((pba->syn_count >= 1) ? 1 : 0));
}
*/

/*
u_int
FinCount (tcp_pair * ptp)
{
  tcb *pab = &ptp->c2s;
  tcb *pba = &ptp->s2c;

  return (((pab->fin_count >= 1) ? 1 : 0) + ((pba->fin_count >= 1) ? 1 : 0));
}
*/


/* copy the IP addresses and port numbers into an addrblock structure	*/
/* in addition to copying the address, we also create a HASH value	*/
/* which is based on BOTH IP addresses and port numbers.  It allows	*/
/* faster comparisons most of the time					*/
void
CopyAddr (tcp_pair_addrblock * ptpa,
	  struct ip *pip, portnum port1, portnum port2)
{
  ptpa->a_port = port1;
  ptpa->b_port = port2;

  if (PIP_ISV4 (pip))
    {				/* V4 */
      IP_COPYADDR (&ptpa->a_address, *IPV4ADDR2ADDR (&pip->ip_src));
      IP_COPYADDR (&ptpa->b_address, *IPV4ADDR2ADDR (&pip->ip_dst));
      /* fill in the hashed address */
      ptpa->hash = ptpa->a_address.un.ip4.s_addr
	+ ptpa->b_address.un.ip4.s_addr + ptpa->a_port + ptpa->b_port;
    }
#ifdef SUPPORT_IPV6
  else
    {				/* V6 */
      int i;
      struct ipv6 *pip6 = (struct ipv6 *) pip;
      IP_COPYADDR (&ptpa->a_address, *IPV6ADDR2ADDR (&pip6->ip6_saddr));
      IP_COPYADDR (&ptpa->b_address, *IPV6ADDR2ADDR (&pip6->ip6_daddr));
      /* fill in the hashed address */
      ptpa->hash = ptpa->a_port + ptpa->b_port;
      for (i = 0; i < 16; ++i)
	{
	  ptpa->hash += ptpa->a_address.un.ip6.s6_addr[i];
	  ptpa->hash += ptpa->b_address.un.ip6.s6_addr[i];
	}
    }
#endif
}



int
WhichDir (tcp_pair_addrblock * ptpa1, tcp_pair_addrblock * ptpa2)
{

#ifdef BROKEN_COMPILER
  /* sorry for the ugly nested 'if', but a 4-way conjunction broke my */
  /* Optimizer (under 'gcc version cygnus-2.0.2')                     */

  /* same as first packet */
  if (IP_SAMEADDR (ptpa1->a_address, ptpa2->a_address))
    if (IP_SAMEADDR (ptpa1->b_address, ptpa2->b_address))
      if ((ptpa1->a_port == ptpa2->a_port))
	if ((ptpa1->b_port == ptpa2->b_port))
	  return (C2S);

  /* reverse of first packet */
  if (IP_SAMEADDR (ptpa1->a_address, ptpa2->b_address))
    if (IP_SAMEADDR (ptpa1->b_address, ptpa2->a_address))
      if ((ptpa1->a_port == ptpa2->b_port))
	if ((ptpa1->b_port == ptpa2->a_port))
	  return (S2C);
#else /* BROKEN_COMPILER */
  /* same as first packet */
  if (IP_SAMEADDR (ptpa1->a_address, ptpa2->a_address) &&
      IP_SAMEADDR (ptpa1->b_address, ptpa2->b_address) &&
      (ptpa1->a_port == ptpa2->a_port) && (ptpa1->b_port == ptpa2->b_port))
    return (C2S);

  /* reverse of first packet */
  if (IP_SAMEADDR (ptpa1->a_address, ptpa2->b_address) &&
      IP_SAMEADDR (ptpa1->b_address, ptpa2->a_address) &&
      (ptpa1->a_port == ptpa2->b_port) && (ptpa1->b_port == ptpa2->a_port))
    return (S2C);
#endif /* BROKEN_COMPILER */

  /* different connection */
  return (0);
}

int
SameConn (tcp_pair_addrblock * ptpa1, tcp_pair_addrblock * ptpa2, int *pdir)
{
  /* if the hash values are different, they can't be the same */
  if (ptpa1->hash != ptpa2->hash)
    return (0);

  /* OK, they hash the same, are they REALLY the same function */
  *pdir = WhichDir (ptpa1, ptpa2);
  return (*pdir != 0);
}

int
ConnComplete (tcp_pair * ptp)
{
  return (ptp->c2s.closed && ptp->s2c.closed);
}


int
ConnReset (tcp_pair * ptp)
{
  return (ptp->c2s.reset_count + ptp->s2c.reset_count != 0);
}


extern Bool warn_MAX_;
static tcp_pair **
NewTTP_2 (struct ip *pip, struct tcphdr *ptcp)
{
  tcp_pair *ptp;
  int old_new_tcp_pairs = num_tcp_pairs;
  int steps = 0;

  /* look for the next eventually available free block */
  num_tcp_pairs++;
  num_tcp_pairs = num_tcp_pairs % GLOBALS.Max_TCP_Pairs;
  /* make a new one, if possible */
  while ((num_tcp_pairs != old_new_tcp_pairs) && (ttp[num_tcp_pairs] != NULL)
	 && (steps < GLOBALS.List_Search_Dept))
    {
      steps++;
      /* look for the next one */
//         fprintf (fp_stdout, "%d %d\n", num_tcp_pairs, old_new_tcp_pairs);
      num_tcp_pairs++;
      num_tcp_pairs = num_tcp_pairs % GLOBALS.Max_TCP_Pairs;
    }
  if (ttp[num_tcp_pairs] != NULL)
    {
      if (warn_MAX_)
	{
	  fprintf (fp_stderr, "\n" 
	    "ooopsss: number of simultaneous connection opened is greater then the maximum supported number!\n"
	    "you have to rebuild the source with a larger LIST_SEARCH_DEPT defined!\n"
	    "or possibly with a larger MAX_TCP_PAIRS defined!\n");
	}
      warn_MAX_ = FALSE;
      return (NULL);
    }

  /* create a new TCP pair record and remember where you put it */
  ptp = ttp[num_tcp_pairs] = tp_alloc ();

  /* grab the address from this packet */
  CopyAddr (&ptp->addr_pair,
	    pip, ntohs (ptcp->th_sport), ntohs (ptcp->th_dport));

  ptp->c2s.time.tv_sec = -1;
  ptp->s2c.time.tv_sec = -1;
  /* a.c */
  ptp->s2c.closed = FALSE;
  ptp->c2s.closed = FALSE;

  ptp->c2s.ptp = ptp;
  ptp->s2c.ptp = ptp;

  ptp->c2s.min_jitter = MAXFLOAT;
  ptp->s2c.min_jitter = MAXFLOAT;

  ptp->internal_src = internal_src;
  ptp->internal_dst = internal_dst;

  ptp->cloud_src = cloud_src;
  ptp->cloud_dst = cloud_dst;

  if (crypto_src)
   {
#ifdef SUPPORT_IPV6
     if (ADDR_ISV6(&(ptp->addr_pair.a_address)))
       store_crypto_ipv6(&(ptp->addr_pair.a_address.un.ip6));
     else
#endif
       store_crypto_ip(&(ptp->addr_pair.a_address.un.ip4));
   }

  if (crypto_dst)
   {
#ifdef SUPPORT_IPV6
     if (ADDR_ISV6(&(ptp->addr_pair.b_address)))
       store_crypto_ipv6(&(ptp->addr_pair.b_address.un.ip6));
     else
#endif
       store_crypto_ip(&(ptp->addr_pair.b_address.un.ip4));
   }

  ptp->crypto_src = crypto_src;
  ptp->crypto_dst = crypto_dst;
  
  /* Initialize the state */
  ptp->con_type = 0;
  ptp->state = UNKNOWN_TYPE;
  ptp->p2p_type = 0;
  ptp->p2p_state = UNKNOWN_TYPE;
  ptp->ignore_dpi = FALSE;

  /* Assume all packets must be dumped */
  ptp->stop_dumping_tcp = FALSE;
/* DNS cache piece */
  /* Do reverse Lookup */
#ifdef DNS_CACHE_PROCESSOR
 if (dns_enabled)
  {
#ifdef SUPPORT_IPV6
    if (PIP_ISV6(pip))
     { 
    struct DNS_data_IPv6* dns_data =  get_dns_entry_ipv6(&(PIP_V6(pip)->ip6_saddr), &(PIP_V6(pip)->ip6_daddr));
    if(dns_data!=NULL){
	 ptp->dns_name = dns_data->hostname;
	 ptp->dns_server.addr_vers = 6;
	 memcpy((&ptp->dns_server.un.ip6),&(dns_data->dns_server),sizeof(struct in6_addr));
	 ptp->request_time = dns_data->request_time;
	 ptp->response_time = dns_data->response_time;
     }
    if(debug >1)
     {
       fprintf (fp_stdout, "got DNS reverse %s %s ", ptp->dns_name, HostName (ptp->addr_pair.a_address));
       fprintf (fp_stdout, "from DNS server %s\n", HostName(ptp->dns_server));
     }
     }
    else
#endif
     {
    struct DNS_data* dns_data =  get_dns_entry(ntohl(pip->ip_src.s_addr), ntohl(pip->ip_dst.s_addr));
    if(dns_data!=NULL){
	 ptp->dns_name = dns_data->hostname;
	 ptp->dns_server.addr_vers = 4;
	 memcpy((&ptp->dns_server.un.ip4),&(dns_data->dns_server),sizeof(struct in_addr));
	 ptp->request_time = dns_data->request_time;
	 ptp->response_time = dns_data->response_time;
     }
    if(debug >1)
     {
       fprintf (fp_stdout, "got DNS reverse %s %s ", ptp->dns_name, HostName (ptp->addr_pair.a_address));
       fprintf (fp_stdout, "from DNS server %s\n", HostName(ptp->dns_server));
     }
     }
/* check if we are interested into dumping this flow packets accoring to the DNS name */
  ptp->stop_dumping_tcp = !check_DNSname(ptp->dns_name);
  }
 else
  ptp->dns_name = NULL;
#else
  ptp->dns_name = NULL;
  /*
  ptp->dns_server = NULL;
  ptp->request_time = NULL;
  ptp->response_time = NULL;
  */
#endif

#ifdef VIDEO_DETAILS
  memset(&ptp->http_meta,0,sizeof(struct flv_metadata));
#endif

  ptp->http_request_count  = 0;
  ptp->http_response_count = 0;

  ptp->ssl_client_subject = NULL;
  ptp->ssl_server_subject = NULL;

  ptp->ssl_client_npnalpn = TLS_EMPTY;
  ptp->ssl_server_npnalpn = TLS_EMPTY;

  ptp->ssl_client_data_seen = FALSE;
  ptp->ssl_server_data_seen = FALSE;

  ptp->ssl_client_data_byte = 0;
  ptp->ssl_server_data_byte = 0;
  
  ptp->tls_service = TLS_OTHER;
  
  return (&ttp[num_tcp_pairs]);
}

static ptp_snap *
NewPTPH_2 (void)
{
  return (ptph_alloc ());
}



/* connection records are stored in a hash table.  Buckets are linked	*/
/* lists sorted by most recent access.					*/

// ptp_snap *ptp_hashtable[HASH_TABLE_SIZE] = { NULL };
ptp_snap **ptp_hashtable;

static ptp_snap **
FindTTP (struct ip *pip, struct tcphdr *ptcp, int *pdir)
{

  ptp_snap **pptph_head = NULL;
  ptp_snap *ptph;
  ptp_snap *ptph_last;
  static tcp_pair **temp_ttp;

  tcp_pair_addrblock tp_in;
  int dir;
  hash hval;

  int prof_curr_clk;
  struct timeval prof_tm;
  double prof_curr_tm;
  struct tms prof_curr_tms;
  double cpu_sys,cpu_usr;

  /* grab the address from this packet */
  CopyAddr (&tp_in, pip, ntohs (ptcp->th_sport), ntohs (ptcp->th_dport));

  /* grab the hash value (already computed by CopyAddr) */
  hval = tp_in.hash % GLOBALS.Hash_Table_Size;

  ptph_last = NULL;
  pptph_head = &ptp_hashtable[hval];


  for (ptph = *pptph_head; ptph; ptph = ptph->next)
    {
      ++search_count;

      if (SameConn (&tp_in, &ptph->addr_pair, &dir))
	{
	  /* OK, this looks good, suck it into memory */
	  tcp_pair *ptp = ptph->ptp;
	  tcb *thisdir;
	  tcb *otherdir;


	  /* figure out which direction this packet is going */
	  if (dir == C2S)
	    {
	      thisdir = &ptp->c2s;
	      otherdir = &ptp->s2c;
	    }
	  else
	    {
	      thisdir = &ptp->s2c;
	      otherdir = &ptp->c2s;
	    }

	  /* move to head of access list (unless already there) */
	  if (ptph != *pptph_head)
	    {
	      ptph_last->next = ptph->next;	/* unlink */
	      ptph->next = *pptph_head;	/* move to head */
	      *pptph_head = ptph;
	    }
	  *pdir = dir;
	  return (pptph_head);
	}
      ptph_last = ptph;
    }

  /* Didn't find it, make a new one, if possible */

  if (!(SYN_SET (ptcp) && !ACK_SET (ptcp)))
    {
      /* the new connection must begin with a SYN */
      if (debug > 1)
	{
	  fprintf (fp_stdout, 
        "** trash TCP packet: it does not belong to any known flows\n");
	}
      not_id_p++;
      add_histo (profile_trash, 0);

      return (NULL);
    }

  if (debug > 1)
    {
      fprintf (fp_stdout, "tracing a new TCP flow\n");
    }

    if (profile_cpu -> flag == HISTO_ON) {
        prof_curr_clk = (int)clock();
        gettimeofday(&prof_tm, NULL);
        prof_curr_tm = time2double(prof_tm)/1e6;
        times(&prof_curr_tms);
        
        
        if (prof_curr_tm - prof_last_tm > PROFILE_IDLE) {
            /* system cpu */
            cpu_sys = 1.0 * (prof_curr_tms.tms_stime - prof_last_tms.tms_stime) / prof_cps /
                  (prof_curr_tm - prof_last_tm) * 100;
            AVE_new_step(prof_tm, &ave_win_sys_cpu, cpu_sys);
            // system + user cpu 
            //cpu = 1.0 * (prof_curr_clk - prof_last_clk) / CLOCKS_PER_SEC / 
            //      (prof_curr_tm - prof_last_tm) * 100;
            //AVE_new_step(prof_tm, &ave_win_usrsys_cpu, cpu);
            cpu_usr = 1.0 * (prof_curr_tms.tms_utime - prof_last_tms.tms_utime) / prof_cps /
                  (prof_curr_tm - prof_last_tm) * 100;
            AVE_new_step(prof_tm, &ave_win_usr_cpu, cpu_usr);
        
            prof_last_tm = prof_curr_tm;
            prof_last_clk = prof_curr_clk; 
            prof_last_tms = prof_curr_tms;
            max_cpu = (max_cpu < (cpu_usr+cpu_sys)) ? cpu_usr+cpu_sys : max_cpu;
            //printf("cpu:%.2f max:%.2f\n", cpu, max_cpu);
        }
    }
    
    

  // we fire it at DOUBLE rate, but actually clean only those > TCP_IDLE_TIME
  if (elapsed (last_cleaned, current_time) > GLOBALS.GC_Fire_Time)
    {
      int i;
      for (i=0; i< elapsed (last_cleaned, current_time) / GLOBALS.GC_Fire_Time; i++ )
        trace_done_periodic ();
      last_cleaned = current_time;
    }


  add_histo (L4_flow_number, L4_FLOW_TCP);
  fcount++;
  f_TCP_count++;

  temp_ttp = NewTTP_2 (pip, ptcp);
  if (temp_ttp == NULL)		/* not enough memory to store the new flow */
    {
      /* the new connection must begin with a SYN */
      if (debug > 0)
	{
	  fprintf (fp_stdout, 
        "** out of memory when creating flows - considering a not_id_p\n");
	}
      not_id_p++;
      add_histo (profile_trash, 0);

    /* profile number of missed TCP session */
    if (profile_flows->flag == HISTO_ON)
        AVE_arrival(current_time, &missed_flows_win_TCP);

      return (NULL);
    }
  if (profile_flows->flag == HISTO_ON)
    AVE_arrival(current_time, &active_flows_win_TCP);
  tot_conn_TCP++;
  ptph = NewPTPH_2 ();
  ptph->ttp_ptr = temp_ttp;
  ptph->ptp = *(ptph->ttp_ptr);
  ptph->ptp->id_number = f_TCP_count;

  ptph->addr_pair = ptph->ptp->addr_pair;

  /* put at the head of the access list */
  ptph->next = *pptph_head;
  *pptph_head = ptph;

  *pdir = C2S;


  /* return the new ptph */
  return (pptph_head);
}

int
tcp_flow_stat (struct ip * pip, struct tcphdr * ptcp, void *plast, int *dir)
{
  struct tcp_options *ptcpo;
  tcp_pair *ptp_save;
  ptp_snap **ptph_ptr;
  ptp_snap *ptph_save;
  ptp_snap *ptph_tmp;
  int tcp_length;
  int tcp_data_length;
  u_long start;
  u_long end;
  tcb *thisdir;
  tcb *otherdir;
  tcp_pair tp_in;
  Bool retrans;
  Bool ecn_ce = FALSE;
  Bool ecn_echo = FALSE;
  Bool cwr = FALSE;
  int retrans_num_bytes;
  Bool out_order;		/* out of order */
  u_short th_sport;		/* source port */
  u_short th_dport;		/* destination port */
  tcp_seq th_seq;		/* sequence number */
  tcp_seq th_ack;		/* acknowledgement number */
  u_short th_win;		/* window */
  u_long eff_win;		/* window after scaling */
  short ip_len;			/* total length */
  enum t_ack ack_type = NORMAL;	/* how should we draw the ACK */
   /*TOPIX*/ double delta_t = 0;
  /*end TOPIX */

  /* make sure we have enough of the packet */
  if ((unsigned long) ptcp + sizeof (struct tcphdr) - 1 >
      (unsigned long) plast)
    {
      if (warn_printtrunc)
	fprintf (fp_stderr,
		 "TCP packet %lu truncated too short (%ld) to trace, ignored\n",
		 pnum,
		 (unsigned long) ptcp + sizeof (struct tcphdr) -
		 (unsigned long) plast);
      ++ctrunc;
      return (FLOW_STAT_SHORT);
    }


  /* convert interesting fields to local byte order */
  th_seq = ntohl (ptcp->th_seq);
  th_ack = ntohl (ptcp->th_ack);
  th_sport = ntohs (ptcp->th_sport);
  th_dport = ntohs (ptcp->th_dport);
  th_win = ntohs (ptcp->th_win);
  ip_len = gethdrlength (pip, plast) + getpayloadlength (pip, plast);


  /* make sure this is one of the connections we want */
  ptph_ptr = FindTTP (pip, ptcp, dir);

  /* if the connection is not to be analyzed return a NULL */
  if (ptph_ptr == NULL)
    {
      return (FLOW_STAT_NULL);
    }

  ptph_save = (*ptph_ptr);
  ptp_save = ptph_save->ptp;


  if (ptp_save == NULL)
    {
      return (FLOW_STAT_NULL);
    }

  if (internal_src && !internal_dst)
    {
      ++tcp_trace_count_outgoing;
    }
  else if (!internal_src && internal_dst)
    {
      ++tcp_trace_count_incoming;
    }
#ifndef LOG_UNKNOWN
  else if (internal_src && internal_dst)
#else
  else
#endif
    {
      ++tcp_trace_count_local;
    }


  /* do time stats */
  if (ZERO_TIME (&ptp_save->first_time))
    {
      ptp_save->first_time = current_time;
    }
  ptp_save->last_time = current_time;



  /* bug fix:  it's legal to have the same end points reused.  The */
  /* program uses a heuristic of looking at the elapsed time from */
  /* the last packet on the previous instance and the number of FINs */
  /* in the last instance.  If we don't increment the fin_count */
  /* before bailing out in "ignore_pair" below, this heuristic breaks */

  /* figure out which direction this packet is going */
  if (*dir == C2S)
    {
      thisdir = &ptp_save->c2s;
      otherdir = &ptp_save->s2c;
    }
  else
    {
      thisdir = &ptp_save->s2c;
      otherdir = &ptp_save->c2s;
    }

#ifdef CHECK_TCP_DUP
  /* check if this is a dupe udp */
  if (dup_tcp_check (pip, ptcp,thisdir)) {
    return(FLOW_STAT_DUP);
  }
#endif

  /* calculate data length */
  tcp_length = getpayloadlength (pip, plast);
  tcp_data_length = tcp_length - (4 * ptcp->th_off);

  /* meta connection stats */
  if (SYN_SET (ptcp))
    ++thisdir->syn_count;
  if (RESET_SET (ptcp))
    ++thisdir->reset_count;
  if (FIN_SET (ptcp))
    {
      ++thisdir->fin_count;
      thisdir->fin_seqno = th_seq + tcp_data_length;
    }
  /* sanity check - stop tracking this flow if we got a SYN */
  /* from the client, no SYN+ACK from the server */
  /* and this is a data packet from the client */
  /* indeed, if no SYN+ACK has been seen, then this must be an */
  /* half flow... force a false RST message to close this flow */

  if ((*dir == C2S) && (!SYN_SET (ptcp)) && (otherdir->syn_count == 0) && tcp_data_length != 0 )
    {
       ptp_save->ignore_dpi = TRUE;
    }

#ifndef LOG_HALFDUPLEX
  if ((*dir == C2S) && (!SYN_SET (ptcp)) && (otherdir->syn_count == 0) && tcp_data_length != 0 )
    {
      //fprintf (fp_stdout, "  Closing a half duplex flow\n");
      if (profile_flows->flag == HISTO_ON)
        AVE_departure(current_time, &active_flows_win_TCP);
      tot_conn_TCP--;
      make_conn_stats (ptp_save,
		       (ptp_save->s2c.syn_count > 0
			&& ptp_save->c2s.syn_count > 0));

      /* free up memory for this flow */

      free_tp (ptp_save);

      /* free up the first element of the list pointer by the hash */
      ptph_tmp = ptph_save;
      *(ptph_save->ttp_ptr) = NULL;
      *ptph_ptr = ptph_save->next;
      ptph_release (ptph_tmp);

      return (FLOW_STAT_OK);
    }
#endif

  if ((ACK_SET (ptcp)) &&
      (otherdir->fin_count >= 1) && (th_ack >= (otherdir->fin_seqno + 1)))
    {
      // This is the ACK to the FIN
      otherdir->closed = TRUE;
    }

  if (ACK_SET (ptcp) && otherdir->cwnd_flag)
    {
      add_histo (tcp_cwnd, (otherdir->seq - thisdir->ack));

      /* we already counted this flight-size, then do not 
       * consider it anymore until some new data will be received on the
       * backward direction.
       */
      otherdir->cwnd_flag = 0;
    }

  /* compute the "effective window", which is the advertised window */
  /* with scaling */
  if (ACK_SET (ptcp) || SYN_SET (ptcp))
    {
      eff_win = (u_long) th_win;

      /* N.B., the window_scale stored for the connection DURING 3way */
      /* handshaking is the REQUESTED scale.  It's only valid if both */
      /* sides request scaling.  AFTER we've seen both SYNs, that field */
      /* is reset (above) to contain zero.  Note that if we */
      /* DIDN'T see the SYNs, the windows will be off. */
      if (thisdir->f1323_ws && otherdir->f1323_ws)
	eff_win <<= thisdir->window_scale;
    }
  else
    {
      eff_win = 0;
    }


  /* idle-time stats */
  if (!ZERO_TIME (&thisdir->last_time))
    {
      u_llong itime = elapsed (thisdir->last_time, current_time);
      delta_t = (double) itime;
    }
  thisdir->last_time = current_time;

  /* congestion window 
   * This is a new data segment which enable the cwnd evaluation
   */
  if ((tcp_data_length != 0) || SYN_SET (ptcp) || FIN_SET (ptcp)
      || RESET_SET (ptcp))
    {
      thisdir->cwnd_flag = 1;
    }

  /* calc. data range */
  start = th_seq;
  end = start + tcp_data_length;

  /* record sequence limits */
  if (SYN_SET (ptcp))
    {
      /* error checking - better not change! */
      if ((thisdir->syn_count > 1) && (thisdir->syn != start))
	{
	  /* it changed, that shouldn't happen! */
	  if (warn_printbad_syn_fin_seq)
	    fprintf (fp_stderr,
		     "rexmitted SYN had diff. seqnum! (was %lu, now %lu, etime: %d sec)\n",
		     thisdir->syn, start,
		     (int) (elapsed (ptp_save->first_time, current_time) / 1000000));
	  thisdir->bad_behavior = TRUE;
	}
      thisdir->syn = start;
      otherdir->ack = start;
      /* bug fix for Rob Austein <sra@epilogue.com> */
    }
  if (FIN_SET (ptcp))
    {
      /* bug fix, if there's data here too, we need to bump up the FIN */
      /* (psc data file shows example) */
      u_long fin = start + tcp_data_length;
      /* error checking - better not change! */
      if ((thisdir->fin_count > 1) && (thisdir->fin != fin))
	{
	  /* it changed, that shouldn't happen! */
	  if (warn_printbad_syn_fin_seq)
	    fprintf (fp_stderr,
		     "rexmitted FIN had diff. seqnum! (was %lu, now %lu, etime: %d sec)\n",
		     thisdir->fin, fin,
		     (int) (elapsed (ptp_save->first_time, current_time) /
			    1000000));
	  thisdir->bad_behavior = TRUE;
	}
      thisdir->fin = fin;
    }

  /* "ONLY" bug fix - Wed Feb 24, 1999 */
  /* the tcp-splicing heuristic needs "windowend", which was only being */
  /* calculated BELOW the "only" point below.  Move that part of the */
  /* calculation up here! */

  if (ACK_SET (ptcp))
    {
      thisdir->windowend = th_ack + eff_win;
    }
  /* end bugfix */

  /* grab the address from this packet */
  CopyAddr (&tp_in.addr_pair, pip, th_sport, th_dport);


  /* check the options */
  ptcpo = ParseOptions (ptcp, plast);
  if (ptcpo->mss != -1)
    thisdir->mss = ptcpo->mss;
  if (ptcpo->ws != -1)
    {
      thisdir->window_scale = ptcpo->ws;
      thisdir->f1323_ws = TRUE;
    }
  if (ptcpo->tsval != -1)
    {
      thisdir->f1323_ts = TRUE;
    }
  /* NOW, unless BOTH sides asked for window scaling in their SYN     */
  /* segments, we aren't using window scaling */
  if (!SYN_SET (ptcp) && ((!thisdir->f1323_ws) || (!otherdir->f1323_ws)))
    {
      thisdir->window_scale = otherdir->window_scale = 0;
    }

  /* check sacks */
  if (ptcpo->sack_req)
    {
      thisdir->fsack_req = 1;
    }
  if (ptcpo->sack_count > 0)
    {
      ++thisdir->sacks_sent;
    }

  /* check mptcp */
  if (ptcpo->mptcp_req)
    {
      thisdir->mptcp_req = 1;
    }


  if (*dir == C2S)
    ptp_save->c2s.ip_bytes += ip_len;
  else
    ptp_save->s2c.ip_bytes += ip_len;

  /* do data stats */
  if (tcp_data_length > 0)
    {
      thisdir->data_pkts += 1;
      if (PUSH_SET (ptcp))
	thisdir->data_pkts_push += 1;
      thisdir->data_bytes += tcp_data_length;
      if (tcp_data_length > thisdir->max_seg_size)
	thisdir->max_seg_size = tcp_data_length;
      if ((thisdir->min_seg_size == 0) ||
	  (tcp_data_length < thisdir->min_seg_size))
	thisdir->min_seg_size = tcp_data_length;
      /* record first and last times for data (Mallman) */
      if (ZERO_TIME (&thisdir->first_data_time))
	thisdir->first_data_time = current_time;
      thisdir->last_data_time = current_time;

#ifdef PACKET_STATS
      thisdir->data_pkts_sum2 += tcp_data_length*tcp_data_length; 
      
      { double current_intertime;
      if (thisdir->seg_count==0)
       {
         thisdir->last_seg_time=time2double(current_time);
       }
      else
       {
         current_intertime = 
	      time2double(current_time) - thisdir->last_seg_time;
         thisdir->last_seg_time=time2double(current_time);
	 thisdir->seg_intertime_sum += current_intertime;
	 thisdir->seg_intertime_sum2 += current_intertime*current_intertime;
       }

      if (thisdir->seg_count<MAX_COUNT_SEGMENTS)
       {
         thisdir->seg_size[thisdir->seg_count] = tcp_data_length;
	 if (thisdir->seg_count>0)
	  {
	    thisdir->seg_intertime[thisdir->seg_count-1] = current_intertime;
	  }
       }

	 thisdir->seg_count++;
      }
#endif
#ifdef VIDEO_DETAILS
      if (ZERO_TIME (&thisdir->rate_last_sample))
       {
	 thisdir->rate_last_sample = current_time;
	 thisdir->rate_left_edge = time2double(current_time);
	 thisdir->rate_right_edge = thisdir->rate_left_edge+GLOBALS.Rate_Sampling;
	 thisdir->rate_min=MAXFLOAT;
	 thisdir->rate_max=0.0;
	 thisdir->rate_bytes=0;
	 thisdir->rate_empty_streak=0;
       }

      if ( time2double(current_time) < thisdir->rate_right_edge)
       {
	 thisdir->rate_bytes += tcp_data_length;
       }
      else
       {
         double sample;
	 int streak=0;

	 sample = thisdir->rate_bytes *1e6 / GLOBALS.Rate_Sampling;

	 if (thisdir->rate_min>sample) 
	   thisdir->rate_min = sample;
	 if (thisdir->rate_max<sample) 
	   thisdir->rate_max = sample;
	   
	 thisdir->rate_sum += sample;
	 thisdir->rate_sum2 += sample*sample;
 	 if (thisdir->rate_samples<10)
	  {
	    thisdir->rate_begin_bytes[thisdir->rate_samples] = thisdir->rate_bytes;
	  }

	 thisdir->rate_samples++;
         if (thisdir->rate_bytes==0)
	   {
	     thisdir->rate_empty_samples++;
	     streak++;
	   }

	 thisdir->rate_left_edge +=  GLOBALS.Rate_Sampling;
	 thisdir->rate_right_edge +=  GLOBALS.Rate_Sampling;

         while (time2double(current_time) >= thisdir->rate_right_edge)
	  {
 	    thisdir->rate_left_edge +=  GLOBALS.Rate_Sampling;
	    thisdir->rate_right_edge +=  GLOBALS.Rate_Sampling;
 	    if (thisdir->rate_samples<10)
	     {
	      thisdir->rate_begin_bytes[thisdir->rate_samples] = 0;
	     }
	    thisdir->rate_samples++;
	    thisdir->rate_empty_samples++;
	    streak++;
	  }
	 
	 if (streak > thisdir->rate_empty_streak)
	  thisdir->rate_empty_streak = streak;

	 thisdir->rate_last_sample = current_time;
	 thisdir->rate_bytes = tcp_data_length;
       }
#endif

    }

  /*TTL stats */
  if (PIP_ISV4(pip))
  {
    if ((thisdir->ttl_min == 0) || (thisdir->ttl_min > (int) pip->ip_ttl))
      thisdir->ttl_min = (int) pip->ip_ttl;
    if (thisdir->ttl_max < (int) pip->ip_ttl)
      thisdir->ttl_max = (int) pip->ip_ttl;

     /*TOPIX*/ thisdir->ttl_tot += (u_llong) pip->ip_ttl;
     /*TOPIX*/
    }
  else
  {
    if ((thisdir->ttl_min == 0) || (thisdir->ttl_min > (int) PIP_V6(pip)->ip6_hlimit))
      thisdir->ttl_min = (int) PIP_V6(pip)->ip6_hlimit;
    if (thisdir->ttl_max < (int) PIP_V6(pip)->ip6_hlimit)
      thisdir->ttl_max = (int) PIP_V6(pip)->ip6_hlimit;

     /*TOPIX*/ thisdir->ttl_tot += (u_llong) PIP_V6(pip)->ip6_hlimit;
     /*TOPIX*/
  }
    /* total packets stats */
    ++ptp_save->packets;
  ++thisdir->packets;

  if(end > thisdir->max_seq)
    thisdir->max_seq = end;


  /* Kevin Lahey's ECN code */
  /* only works for IPv4 */
  if (PIP_ISV4 (pip))
    {
      ecn_ce = IP_ECT (pip) && IP_CE (pip);
    }
  cwr = CWR_SET (ptcp);
  ecn_echo = ECN_ECHO_SET (ptcp);

  /* do rexmit stats */
  retrans = FALSE;
  out_order = FALSE;
  retrans_num_bytes = 0;
  if (SYN_SET (ptcp) || FIN_SET (ptcp) || tcp_data_length > 0)
    {
      int len = tcp_data_length;
      int retrans;
      if (SYN_SET (ptcp))
	++len;
      if (FIN_SET (ptcp))
	++len;

      retrans = retrans_num_bytes =
	rexmit (thisdir, start, len, &out_order, pip->ip_id);

      /* count anything NOT retransmitted as "unique" */
      /* exclude SYN and FIN */
      if (SYN_SET (ptcp))
	{
	  /* don't count the SYN as data */
	  --len;
	  /* if the SYN was rexmitted, then don't count it */
	  if (thisdir->syn_count > 1)
	    --retrans;
	}
      if (FIN_SET (ptcp))
	{
	  /* don't count the FIN as data */
	  --len;
	  /* if the FIN was rexmitted, then don't count it */
	  if (thisdir->fin_count > 1  && retrans > 0)
	    --retrans;
	}
      if (retrans < len)
	thisdir->unique_bytes += (len - retrans);

    }
  if (out_order)
    thisdir->out_order_pkts++;

   /*TOPIX*/
    /* delta_t evaluation if packets are data packets */
    if (tcp_data_length > 0)
    {
      double jitter;
      /* delta_t in milliseconds */
      delta_t = delta_t / 1000.0;
      thisdir->sum_delta_t += delta_t;
      thisdir->n_delta_t++;
      jitter = delta_t - thisdir->sum_delta_t / thisdir->n_delta_t;
      if (jitter < 0)
	jitter = -jitter;
      thisdir->sum_jitter += jitter;
      if (thisdir->max_jitter < jitter)
	thisdir->max_jitter = jitter;
      if (thisdir->min_jitter > jitter)
	thisdir->min_jitter = jitter;

    }
  /*end TOPIX */


  /* do rtt stats */
  if (ACK_SET (ptcp))
    {
      ack_type = ack_in (otherdir, th_ack, tcp_data_length);
    }

  /* stats for rexmitted data */
  if (retrans_num_bytes > 0)
    {
      retrans = TRUE;
      thisdir->rexmit_pkts += 1;
      thisdir->rexmit_bytes += retrans_num_bytes;
    }
  else
    {
      thisdir->seq = end;
    }

  /* check for RESET */
  if (RESET_SET (ptcp))
    {

      if (ACK_SET (ptcp))
	++thisdir->ack_pkts;

      /* make upper layer protocol analysis and update the classified bitrate */
      /* Probably harmless because the RESET should not have payload, but 
         this is the only way to call the dump plugin */

      proto_analyzer (pip, ptcp, PROTOCOL_TCP, thisdir, *dir, plast);

      if (thisdir != NULL && thisdir->ptp != NULL)
       {
	    make_tcpL7_rate_stats(thisdir->ptp, ip_len);
        make_videoL7_rate_stats(thisdir->ptp, ip_len);
       }
      /* */
      
      if (ConnReset (ptp_save))
	{
	  //fprintf (fp_stdout, "  (new reset)\n");
      if (profile_flows->flag == HISTO_ON)
        AVE_departure(current_time, &active_flows_win_TCP);
	  tot_conn_TCP--;
	  make_conn_stats (ptp_save,
			   (ptp_save->s2c.syn_count > 0
			    && ptp_save->c2s.syn_count > 0));

	  /* free up memory for this flow */

	  free_tp (ptp_save);

	  /* free up the first element of the list pointer by the hash */
	  ptph_tmp = ptph_save;
	  *(ptph_save->ttp_ptr) = NULL;
	  *ptph_ptr = ptph_save->next;
	  ptph_release (ptph_tmp);
	}

      return (FLOW_STAT_OK);
    }


  /* do window stats (include first SYN too!) */
  if (ACK_SET (ptcp) || SYN_SET (ptcp))
    {
      thisdir->win_curr = eff_win;
      if (eff_win > thisdir->win_max)
	thisdir->win_max = eff_win;
      if ((eff_win > 0) &&
	  ((thisdir->win_min == 0) || (eff_win < thisdir->win_min)))
	thisdir->win_min = eff_win;
      thisdir->win_tot += eff_win;
    }

  if (ACK_SET (ptcp))
    {
      seqnum ack = th_ack;
      u_long winend;

      winend = ack + eff_win;

      if (eff_win == 0)
	++thisdir->win_zero_ct;

      ++thisdir->ack_pkts;
      if ((tcp_data_length == 0) &&
	  !SYN_SET (ptcp) && !FIN_SET (ptcp) && !RESET_SET (ptcp))
	{
	  ++thisdir->pureack_pkts;
	}

      thisdir->time = current_time;
      thisdir->ack = ack;

    }

  /* do stats for initial window (first slow start) */
  /* (if there's data in this and we've NEVER seen */
  /*  an ACK coming back from the other side) */
  /* this is for Mark Allman for slow start testing -- Mon Mar 10, 1997 */
  if (!otherdir->data_acked && ACK_SET (ptcp)
      && ((otherdir->syn + 1) != th_ack))
    {
      otherdir->data_acked = TRUE;
    }
  if ((tcp_data_length > 0) && (!thisdir->data_acked))
    {
      if (!retrans)
	{
	  /* don't count it if it was retransmitted */
	  thisdir->initialwin_bytes += tcp_data_length;
	  thisdir->initialwin_segs += 1;
	}
    }

  if (SYN_SET (ptcp) && !ACK_SET (ptcp))
    {
      thisdir->highest_seqno = thisdir->max_seq;
    }

  if (ACK_SET(ptcp) && !SYN_SET(ptcp))
    {
       if (ZERO_TIME(&(thisdir->ack_start_time)))
        {
	  thisdir->ack_start_time = current_time;
	}    
    }

  /* check if this segment is carrying the first data */
  if (thisdir->payload_start_time.tv_sec == 0 &&
      thisdir->payload_start_time.tv_usec == 0 && tcp_data_length != 0)
    {
      thisdir->payload_start_time = current_time;
    }

  /* check if this segment is carrying new or retransmitted data */
  if (tcp_data_length != 0)
    {
      thisdir->payload_end_time = current_time;
    }

  /* do stats for congestion window (estimated) */
  /* estimate the congestion window as the number of outstanding */
  /* un-acked bytes */
  if (!SYN_SET (ptcp) && !out_order && !retrans)
    {
      u_int32_t cwin = end - otherdir->ack;

      if ((int32_t) cwin > 0 && cwin > thisdir->cwin_max) {
	thisdir->cwin_max = cwin;
        }
      if ((int32_t) cwin > 0 && ((thisdir->cwin_min == 0) || (cwin < thisdir->cwin_min)))
	thisdir->cwin_min = cwin;
    }

  /* Count TCP messages and track message sizes.
     We split messages on PSH segments 
  */
  if (ACK_SET(ptcp))
   {
     if ( (PUSH_SET(ptcp)||FIN_SET(ptcp)) && 
           thisdir->msg_last_seq < thisdir->seq) 
      {
        u_int curr_msg_size = thisdir->msg_last_seq==0 ? 
	                           thisdir->seq - thisdir->syn - 1 :
	                           thisdir->seq - thisdir->msg_last_seq;
	if (thisdir->msg_count<MAX_COUNT_MESSAGES)
          thisdir->msg_size[thisdir->msg_count]= curr_msg_size;
        if (curr_msg_size>0) thisdir->msg_count++;
        thisdir->msg_last_seq = thisdir->seq;
     }

   }

  /* make upper layer protocol analysis and update the classified bitrate */

  proto_analyzer (pip, ptcp, PROTOCOL_TCP, thisdir, *dir, plast);

  if (thisdir != NULL && thisdir->ptp != NULL)
   {
     make_tcpL7_rate_stats(thisdir->ptp, ip_len);
     make_videoL7_rate_stats(thisdir->ptp, ip_len);
   }
  

  /* Check if the connection is completed */

  if (ConnComplete (ptp_save))
    {
      //fprintf (fp_stdout, "  (new complete)\n");
      if (profile_flows->flag == HISTO_ON)
        AVE_departure(current_time, &active_flows_win_TCP);
      tot_conn_TCP--;
      make_conn_stats (ptp_save, TRUE);

      /* free up memory for this flow */

      free_tp (ptp_save);

      /* free up the first element of the list pointedby the hash */
      ptph_tmp = ptph_save;
      *(ptph_save->ttp_ptr) = NULL;

      /* ptph_ptr is the head, pointed by the hash */
      /* recall the this element is the first, as it has been moved by the
         FindTTP() */
      *ptph_ptr = ptph_save->next;
      ptph_release (ptph_tmp);
    }
  return (FLOW_STAT_OK);
}

void
print_ttp ()
{
  int p;

  for (p = 0; p < GLOBALS.Max_TCP_Pairs; p++)
    {
      fprintf (fp_stdout, "[%2d]", p);
      if (ttp[p] != NULL)
	fprintf (fp_stdout, "->[ptp]\n");
      else
	fprintf (fp_stdout, "->[NULL]\n");
    }
}

void
trace_done (void)
{
  tcp_pair *ptp;
  int ix;


  for (ix = 0; ix < GLOBALS.Max_TCP_Pairs; ++ix)
    {
      ptp = ttp[ix];

      if ((ptp == NULL))
	continue;

#ifdef WIPE_TCP_SINGLETONS
      if (( (
             (
	      (ptp->c2s.syn_count>0 && ptp->s2c.syn_count==0)
              ||
	      (ptp->c2s.syn_count==0 && ptp->s2c.syn_count>0)
	     ) 
	     &&
	     (
	      ptp->packets == (ptp->c2s.syn_count+ptp->s2c.syn_count)
	     )
	    )
            && 
	    (elapsed (ptp->last_time, current_time) > GLOBALS.TCP_Singleton_Time)
	  )
	  ||
          (elapsed (ptp->last_time, current_time) > GLOBALS.TCP_Idle_Time))
#else
      if ((elapsed (ptp->last_time, current_time) > GLOBALS.TCP_Idle_Time))
#endif
	{
	  
	  make_conn_stats (ptp, (ptp->s2c.syn_count > 0)
			   && (ptp->c2s.syn_count > 0));

	  tot_conn_TCP--;

	  ttp[ix] = NULL;

	}

    }


  for (ix = 0; ix < GLOBALS.Max_TCP_Pairs; ++ix)
    {
      ptp = ttp[ix];
      if (ptp == NULL)		// already analyzed
	continue;

      // do not consider this flow for the stats
      make_conn_stats (ptp, FALSE);
      tot_conn_TCP--;
    }
}

long int counter = 0;

void
trace_done_periodic ()
{
  tcp_pair *ptp;
  udp_pair *pup;
  int ix, dir, j;
  //unsigned int cleaned = 0;
  unsigned long init_tot_conn = tot_conn_TCP;
  extern ptp_snap **ptp_hashtable;

  hash hval;
  ptp_snap *ptph_tmp, *ptph, *ptph_prev;
  ptp_snap **pptph_head = NULL;

 /* complete the "idle time" calculations using NOW */
  if (printticks && debug > 1)
    fprintf (fp_stdout, "\nStart cleaning TCP flows\n");
  for (ix = tcp_index; ix < GLOBALS.Max_TCP_Pairs; ix += GLOBALS.GC_Split_Ratio )
    {
      ptp = ttp[ix];

      if ((ptp == NULL))
	continue;

      /* If no packets have been received in the last IDLE_TIME period,
         close the flow */
#ifdef WIPE_TCP_SINGLETONS
      if (( (
             (
	      (ptp->c2s.syn_count>0 && ptp->s2c.syn_count==0)
              ||
	      (ptp->c2s.syn_count==0 && ptp->s2c.syn_count>0)
	     ) 
	     &&
	     (
	      ptp->packets == (ptp->c2s.syn_count+ptp->s2c.syn_count)
	     )
	    )
            && 
	    (elapsed (ptp->last_time, current_time) > GLOBALS.TCP_Singleton_Time)
	  )
	  ||
          (elapsed (ptp->last_time, current_time) > GLOBALS.TCP_Idle_Time))
#else
      if ((elapsed (ptp->last_time, current_time) > GLOBALS.TCP_Idle_Time))
#endif
	{
	  /* must be cleaned */
	  //tcp_cleaned++;

	  make_conn_stats (ptp, (ptp->s2c.syn_count > 0)
			   && (ptp->c2s.syn_count > 0));

      if (profile_flows->flag == HISTO_ON)
        AVE_departure(current_time, &active_flows_win_TCP);
	  tot_conn_TCP--;

	  /* free up hash element->.. */
	  hval = ptp->addr_pair.hash % GLOBALS.Hash_Table_Size;

	  pptph_head = &ptp_hashtable[hval];
	  j = 0;
	  ptph_prev = *pptph_head;
	  for (ptph = *pptph_head; ptph; ptph = ptph->next)
	    {
	      j++;
	      if (SameConn (&ptp->addr_pair, &ptph->addr_pair, &dir))
		{
		  ptph_tmp = ptph;
		  if (j == 1)
		    {
		      /* it is the top of the list */
		      ptp_hashtable[hval] = ptph->next;
		    }
		  else
		    {
		      /* it is in the middle of the list */
		      ptph_prev->next = ptph->next;
		    }
		  ptph_release (ptph_tmp);
		  break;
		}
	      ptph_prev = ptph;
	    }

	  /* ... and free up the TP. */
	  free_tp (ptp);
	  ttp[ix] = NULL;
	}

    }

  /* Increasing starting index for the next function call */
  tcp_index = (tcp_index + 1) % GLOBALS.GC_Split_Ratio ;

  if (printticks && debug > 1)
    fprintf (fp_stdout,
	     "\rCleaned %d/(%ld) TCP flows\n", tcp_cleaned, init_tot_conn);

  if (do_udp == FALSE)
    return;
 /************ Start cleaning UDP flows *******************/


  if (printticks && debug > 1)
    fprintf (fp_stdout, "Start cleaning UDP flows\n");

  //cleaned = 0;
  init_tot_conn = tot_conn_UDP;
  for (ix = udp_index; ix < GLOBALS.Max_UDP_Pairs; ix += GLOBALS.GC_Split_Ratio )
    {
      pup = utp[ix];

      if ((pup == NULL))
	continue;

      /* If no packets have been received in the last UDP_IDLE_TIME period,
         close the flow */
#ifdef WIPE_UDP_SINGLETONS
      if (( (pup->packets == 1) && 
	    (elapsed (pup->last_time, current_time) > GLOBALS.UDP_Singleton_Time)
	  )
	  ||
          (elapsed (pup->last_time, current_time) > GLOBALS.UDP_Idle_Time))
	{
	   close_udp_flow (pup, ix, dir);
           udp_cleaned++;
	}
#else
      if ((elapsed (pup->last_time, current_time) > GLOBALS.UDP_Idle_Time))
	{
	   close_udp_flow (pup, ix, dir);
           udp_cleaned++;
	}
#endif

    }

  /* Increasing starting index for the next function call */
  udp_index = (udp_index + 1) % GLOBALS.GC_Split_Ratio ;

	//if (counter++%500 == 0)printf("Cleaned %d flows\n", cleaned);

  if (printticks && debug > 1)
    fprintf (fp_stdout,
	     "\rCleaned %d/(%ld) UDP flows\n", udp_cleaned, init_tot_conn);
}

void
trace_init (void)
{
  static Bool initted = FALSE;
  extern ptp_snap **ptp_hashtable;

  if (initted)
    return;

  initted = TRUE;

  /* initialize the hash table */

  ptp_hashtable = (ptp_snap **) MallocZ (GLOBALS.Hash_Table_Size * sizeof (ptp_snap *));

  /* create an array to hold any pairs that we might create */
  ttp = (tcp_pair **) MallocZ (GLOBALS.Max_TCP_Pairs * sizeof (tcp_pair *));

  init_ssl_youtube_patterns();

  Minit ();
}


/* get a long (4 byte) option (to avoid address alignment problems) */
static u_long
get_long_opt (void *ptr)
{
  u_long l;
  memcpy (&l, ptr, sizeof (u_long));
  return (l);
}


/* get a short (2 byte) option (to avoid address alignment problems) */
static u_short
get_short_opt (void *ptr)
{
  u_short s;
  memcpy (&s, ptr, sizeof (u_short));
  return (s);
}


struct tcp_options *
ParseOptions (struct tcphdr *ptcp, void *plast)
{
  static struct tcp_options tcpo;
  struct sack_block *psack;
  u_char *pdata;
  u_char *popt;
  u_char *plen;

  popt = (u_char *) ptcp + sizeof (struct tcphdr);
  pdata = (u_char *) ptcp + ptcp->th_off * 4;
  /* init the options structure */
  memset (&tcpo, 0, sizeof (tcpo));
  tcpo.mss = tcpo.ws = tcpo.tsval = tcpo.tsecr = -1;
  tcpo.sack_req = 0;
  tcpo.sack_count = -1;
  tcpo.echo_req = tcpo.echo_repl = -1;
  tcpo.cc = tcpo.ccnew = tcpo.ccecho = -1;

  /* a quick sanity check, the unused (MBZ) bits must BZ! */
  if (warn_printbadmbz)
    {
      if (ptcp->th_x2 != 0)
	{
	  fprintf (fp_stderr,
		   "TCP packet %lu: 4 reserved bits are not zero (0x%01x)\n",
		   pnum, ptcp->th_x2);
	}
      if ((ptcp->th_flags & 0xc0) != 0)
	{
	  fprintf (fp_stderr,
		   "TCP packet %lu: upper flag bits are not zero (0x%02x)\n",
		   pnum, ptcp->th_flags);
	}
    }
  else
    {
      static int warned = 0;
      if (!warned && ((ptcp->th_x2 != 0) || ((ptcp->th_flags & 0xc0) != 0)))
	{
	  warned = 1;
	  fprintf (fp_stderr, "\
TCP packet %lu: reserved bits are not all zero.  \n\
\tFurther warnings disabled, use '-w' for more info\n", pnum);
	}
    }

  /* looks good, now check each option in turn */
  while (popt < pdata)
    {
      plen = popt + 1;
      /* check for truncation error */
      if ((unsigned long) popt > (unsigned long) plast)
	{
	  if (warn_printtrunc)
	    fprintf (fp_stderr, "\
ParseOptions: packet %lu too short (%lu) to parse remaining options\n", pnum, (unsigned long) popt - (unsigned long) plast + 1);
	  ++ctrunc;
	  break;
	}

#define CHECK_O_LEN(opt) \
	if (*plen == 0) { \
	    if (warn_printtrunc) fprintf (fp_stderr, "\
ParseOptions: packet %lu %s option has length 0, skipping other options\n", \
                                           pnum,opt); \
	    popt = pdata; break;} \
	if ((unsigned long)popt + *plen - 1 > (unsigned long)(plast)) { \
	    if (warn_printtrunc) \
		fprintf (fp_stderr, "\
ParseOptions: packet %lu %s option truncated, skipping other options\n", \
              pnum,opt); \
	    ++ctrunc; \
	    popt = pdata; break;} \


      switch (*popt)
	{
	case TCPOPT_EOL:
	  ++popt;
	  break;
	case TCPOPT_NOP:
	  ++popt;
	  break;
	case TCPOPT_MAXSEG:
	  CHECK_O_LEN ("TCPOPT_MAXSEG");
	  tcpo.mss = ntohs (get_short_opt (popt + 2));
	  popt += *plen;
	  break;
	case TCPOPT_WS:
	  CHECK_O_LEN ("TCPOPT_WS");
	  tcpo.ws = *((u_char *) (popt + 2));
	  popt += *plen;
	  break;
	case TCPOPT_TS:
	  CHECK_O_LEN ("TCPOPT_TS");
	  tcpo.tsval = ntohl (get_long_opt (popt + 2));
	  tcpo.tsecr = ntohl (get_long_opt (popt + 6));
	  popt += *plen;
	  break;
	case TCPOPT_ECHO:
	  CHECK_O_LEN ("TCPOPT_ECHO");
	  tcpo.echo_req = ntohl (get_long_opt (popt + 2));
	  popt += *plen;
	  break;
	case TCPOPT_ECHOREPLY:
	  CHECK_O_LEN ("TCPOPT_ECHOREPLY");
	  tcpo.echo_repl = ntohl (get_long_opt (popt + 2));
	  popt += *plen;
	  break;
	case TCPOPT_CC:
	  CHECK_O_LEN ("TCPOPT_CC");
	  tcpo.cc = ntohl (get_long_opt (popt + 2));
	  popt += *plen;
	  break;
	case TCPOPT_CCNEW:
	  CHECK_O_LEN ("TCPOPT_CCNEW");
	  tcpo.ccnew = ntohl (get_long_opt (popt + 2));
	  popt += *plen;
	  break;
	case TCPOPT_CCECHO:
	  CHECK_O_LEN ("TCPOPT_CCECHO");
	  tcpo.ccecho = ntohl (get_long_opt (popt + 2));
	  popt += *plen;
	  break;
	case TCPOPT_SACK_PERM:
	  CHECK_O_LEN ("TCPOPT_SACK_PERM");
	  tcpo.sack_req = 1;
	  popt += *plen;
	  break;
	case TCPOPT_SACK:
	  /* see which bytes are acked */
	  CHECK_O_LEN ("TCPOPT_SACK");
	  tcpo.sack_count = 0;
	  psack = (sack_block *) (popt + 2);	/* past the kind and length */
	  popt += *plen;
	  while ((unsigned long) psack < (unsigned long) popt)
	    {
	      struct sack_block *psack_local =
		&tcpo.sacks[(unsigned) tcpo.sack_count];
	      /* warning, possible alignment problem here, so we'll
	         use memcpy() and hope for the best */
	      /* better use -fno-builtin to avoid gcc alignment error
	         in GCC 2.7.2 */
	      memcpy (psack_local, psack, sizeof (sack_block));

	      /* convert to local byte order (Jamshid Mahdavi) */
	      psack_local->sack_left = ntohl (psack_local->sack_left);
	      psack_local->sack_right = ntohl (psack_local->sack_right);

	      ++psack;
	      if ((unsigned long) psack > ((unsigned long) plast + 1))
		{
		  /* this SACK block isn't all here */
		  if (warn_printtrunc)
		    fprintf (fp_stderr, "packet %lu: SACK block truncated\n",
			     pnum);
		  ++ctrunc;
		  break;
		}
	      ++tcpo.sack_count;
	      if (tcpo.sack_count > MAX_SACKS)
		{
		  /* this isn't supposed to be able to happen */
		  fprintf (fp_stderr,
			   "Warning, internal error, too many sacks!!\n");
		  tcpo.sack_count = MAX_SACKS;
		}
	    }
	  break;
	case TCPOPT_MPTCP:
	  CHECK_O_LEN ("TCPOPT_MPTCP");
	  tcpo.mptcp_req = 1;
	  popt += *plen;
	  break;

	default:
	  if (debug)
	    fprintf (fp_stderr,
		     "Warning, ignoring unknown TCP option 0x%x\n", *popt);
	  CHECK_O_LEN ("TCPOPT_UNKNOWN");

	  /* record it anyway... */
	  if (tcpo.unknown_count < MAX_UNKNOWN)
	    {
	      int ix = tcpo.unknown_count;	/* make lint happy */
	      tcpo.unknowns[ix].unkn_opt = *popt;
	      tcpo.unknowns[ix].unkn_len = *plen;
	    }
	  ++tcpo.unknown_count;

	  popt += *plen;
	  break;
	}
    }

  return (&tcpo);
}


/* given a tcp_pair and a packet, tell me which tcb it is */
struct tcb *
ptp2ptcb (tcp_pair * ptp, struct ip *pip, struct tcphdr *ptcp)
{
  int dir = 0;
  tcp_pair tp_in;

  /* grab the address from this packet */
  CopyAddr (&tp_in.addr_pair, pip,
	    ntohs (ptcp->th_sport), ntohs (ptcp->th_dport));

  /* check the direction */
  if (!SameConn (&tp_in.addr_pair, &ptp->addr_pair, &dir))
    return (NULL);		/* not found, internal error */

  if (dir == C2S)
    return (&ptp->c2s);
  else
    return (&ptp->s2c);
}


/*------------------------------------------------------------------------
 *  cksum  -  Return 16-bit ones complement of 16-bit ones complement sum 
 *------------------------------------------------------------------------
 */
static u_short
cksum (void *pvoid,		/* any alignment is legal */
       int nbytes)
{
  u_char *pchar = pvoid;
  u_long sum = 0;

  while (nbytes >= 2)
    {
      /* can't assume pointer alignment :-( */
      sum += (pchar[0] << 8);
      sum += pchar[1];

      pchar += 2;
      nbytes -= 2;
    }

  /* special check for odd length */
  if (nbytes == 1)
    {
      sum += (pchar[0] << 8);
      /* lower byte is assumed to be 0 */
    }

  sum = (sum >> 16) + (sum & 0xffff);	/* add in carry   */
  sum += (sum >> 16);		/* maybe one more */

  return (sum);
}

/* compute IP checksum */
static u_short
ip_cksum (struct ip *pip, void *plast)
{
  u_short sum;

#ifdef SUPPORT_IPV6
  if (PIP_ISV6 (pip))
    return (0);			/* IPv6 has no header checksum */
#endif
  if (!PIP_ISV4 (pip))
    return (1);			/* I have no idea! */


  /* quick sanity check, if the packet is truncated, pretend it's valid */
  if (plast < (void *) ((char *) pip + pip->ip_hl * 4 - 1))
    {
      return (0);
    }

  /* ... else IPv4 */
  sum = cksum (pip, pip->ip_hl * 4);
  return (sum);
}


/* is the IP checksum valid? */
Bool
ip_cksum_valid (struct ip * pip, void *plast)
{
  u_short sum;

  sum = ip_cksum (pip, plast);

  return ((sum == 0) || (sum == 0xffff));
}


/* compute the TCP checksum */
static u_short
tcp_cksum (struct ip *pip, struct tcphdr *ptcp, void *plast)
{
  u_long sum = 0;
  unsigned tcp_length;

  /* verify version */
  if (!PIP_ISV4 (pip) && !PIP_ISV6 (pip))
    {
      fprintf (fp_stderr, "Internal error, tcp_cksum: neither IPv4 nor IPv6\n");
      exit (-1);
    }


  /* TCP checksum includes: */
  /* - IP source */
  /* - IP dest */
  /* - IP type */
  /* - TCP header length + TCP data length */
  /* - TCP header and data */

  if (PIP_ISV4 (pip))
    {
      /* quick sanity check, if the packet is fragmented,
         pretend it's valid */
      if ((ntohs (pip->ip_off) << 2) != 0)
	{
	  /* both the offset AND the MF bit must be 0 */
	  /* (but we shifted off the DF bit */
	  return (0);
	}

      /* 2 4-byte numbers, next to each other */
      sum += cksum (&pip->ip_src, 4 * 2);

      /* type */
      sum += (u_short) pip->ip_p;

      /* length (TCP header length + TCP data length) */
      tcp_length = ntohs (pip->ip_len) - (4 * pip->ip_hl);
      sum += (u_short) htons (tcp_length);
    }
#ifdef SUPPORT_IPV6
  else
    {				/* if (PIP_ISV6(pip)) */

      static Bool warned = FALSE;

      /* wow, this gets ugly with pseudo headers, sounds like a good
         job for another day :-(  */

      if (!warned)
	{
	  fprintf (fp_stderr, "\nWarning: IPv6 TCP checksums not verified\n\n");
	  warned = TRUE;
	}
      return (0);		/* pretend it's valid */
    }
#endif

  /* quick sanity check, if the packet is truncated, pretend it's valid */
  if (plast < (void *) ((char *) ptcp + tcp_length - 1))
    {
      return (0);
    }


  /* checksum the TCP header and data */
  sum += cksum (ptcp, tcp_length);

  /* roll down into a 16-bit number */
  sum = (sum >> 16) + (sum & 0xffff);
  sum += (sum >> 16);

  return (u_short) (~sum & 0xffff);
}



/* compute the UDP checksum */
static u_short
udp_cksum (struct ip *pip, struct udphdr *pudp, void *plast)
{
  u_long sum = 0;
  unsigned udp_length;

  /* WARNING -- this routine has not been extensively tested */

  /* verify version */
  if (!PIP_ISV4 (pip) && !PIP_ISV6 (pip))
    {
      fprintf (fp_stderr, "Internal error, udp_cksum: neither IPv4 nor IPv6\n");
      exit (-1);
    }


  /* UDP checksum includes: */
  /* - IP source */
  /* - IP dest */
  /* - IP type */
  /* - UDP length field */
  /* - UDP header and data */

  if (PIP_ISV4 (pip))
    {
      /* 2 4-byte numbers, next to each other */
      sum += cksum (&pip->ip_src, 4 * 2);

      /* type */
      sum += (u_short) pip->ip_p;

      /* UDP length */
      udp_length = ntohs (pudp->uh_ulen);
      sum += pudp->uh_ulen;
    }
#ifdef SUPPORT_IPV6
  else
    {				/* if (PIP_ISV6(pip)) */

      static Bool warned = FALSE;

      /* wow, this gets ugly with pseudo headers, sounds like a good
         job for another day :-(  */

      if (!warned)
	{
	  fprintf (fp_stderr, "\nWarning: IPv6 UDP checksums not verified\n\n");
	  warned = TRUE;
	}
      return (0);		/* pretend it's valid */
    }
#endif

  /* quick sanity check, if the packet is truncated, pretend it's valid */
  if (plast < (void *) ((char *) pudp + udp_length - 1))
    {
      return (0);
    }


  /* checksum the UDP header and data */
  sum += cksum (pudp, udp_length);

  /* roll down into a 16-bit number */
  sum = (sum >> 16) + (sum & 0xffff);
  sum += (sum >> 16);

  return (u_short) (~sum & 0xffff);
}


/* is the TCP checksum valid? */
Bool
tcp_cksum_valid (struct ip * pip, struct tcphdr * ptcp, void *plast)
{
  return (tcp_cksum (pip, ptcp, plast) == 0);
}


/* is the UDP checksum valid? */
Bool
udp_cksum_valid (struct ip * pip, struct udphdr * pudp, void *plast)
{
  if (ntohs (pudp->uh_sum) == 0)
    {
      /* checksum not used */
      return (1);		/* valid */
    }

  return (udp_cksum (pip, pudp, plast) == 0);
}

/*
** Functions to print selected groups of TCP measurements
*/

void print_tcp_stats_core(FILE *fp, tcp_pair *ptp_save, tcb *pab, tcb *pba)
{
  double etime;

  /* connection time and throughput */
  /* from microseconds to ms */
  etime = elapsed (ptp_save->first_time, ptp_save->last_time);
  etime = etime / 1000;

  /* Core Tstat TCP measurements */
  if (ptp_save->crypto_src==FALSE)
   {
     wfprintf (fp, "%s", HostName (ptp_save->addr_pair.a_address));
   }   
  else
   {
     wfprintf (fp, "%s", HostNameEncrypted (ptp_save->addr_pair.a_address));
   }
  wfprintf (fp, 
    	   " %s %lu %u %lu %lu %lu %lu %lu %u %u %u %d %d",
    	   ServiceName (ptp_save->addr_pair.a_port),
    	   pab->packets,
    	   pab->reset_count,
    	   pab->ack_pkts,
    	   pab->pureack_pkts,
    	   pab->unique_bytes,
    	   pab->data_pkts,
    	   pab->data_bytes,
    	   pab->rexmit_pkts,
    	   pab->rexmit_bytes,
    	   pab->out_order_pkts,
    	   pab->syn_count,
    	   pab->fin_count);
  if (ptp_save->crypto_dst==FALSE)
   {
     wfprintf (fp, " %s", HostName (ptp_save->addr_pair.b_address));
   }   
  else
   {
     wfprintf (fp, " %s", HostNameEncrypted (ptp_save->addr_pair.b_address));
   }
  wfprintf (fp,
    	   " %s %lu %u %lu %lu %lu %lu %lu %u %u %u %d %d",
    	   ServiceName (ptp_save->addr_pair.b_port),
    	   pba->packets,
    	   pba->reset_count,
    	   pba->ack_pkts,
    	   pba->pureack_pkts,
    	   pba->unique_bytes,
    	   pba->data_pkts,
    	   pba->data_bytes,
    	   pba->rexmit_pkts,
    	   pba->rexmit_bytes,
    	   pba->out_order_pkts,
    	   pba->syn_count,
    	   pba->fin_count);

  /* first pkt time */
  wfprintf (fp, " %f",time2double(ptp_save->first_time) / 1000.0);
  /* last pkt time */
  wfprintf (fp, " %f",time2double(ptp_save->last_time) / 1000.0);

  /* elapsed time */
  wfprintf (fp, " %f", etime);

  /* first DATA pkt time */
  wfprintf (fp, " %f",
	       elapsed (ptp_save->first_time,
			pab->payload_start_time) / 1000.0);
  wfprintf (fp, " %f",
	       elapsed (ptp_save->first_time,
			pba->payload_start_time) / 1000.0);

  /* last DATA pkt time */
  wfprintf (fp, " %f",
	       elapsed (ptp_save->first_time,
			pab->payload_end_time) / 1000.0);
  wfprintf (fp, " %f",
	       elapsed (ptp_save->first_time,
			pba->payload_end_time) / 1000.0);
  /* first ACK pkt time */
  wfprintf (fp, " %f",
	       elapsed (ptp_save->first_time,
			pab->ack_start_time) / 1000.0);
  wfprintf (fp, " %f",
	       elapsed (ptp_save->first_time,
			pba->ack_start_time) / 1000.0);

  /* printing boolean flag if source is considered internal or not */
  wfprintf (fp, " %d", ptp_save->internal_src);
  /* printing boolean flag if destination is considered internal or not */
  wfprintf (fp, " %d", ptp_save->internal_dst);

  /* printing boolean flag if source is considered internal or not */
  wfprintf (fp, " %d", ptp_save->crypto_src);
  /* printing boolean flag if destination is considered internal or not */
  wfprintf (fp, " %d", ptp_save->crypto_dst);

  /* TOPIX: added 97th column: connection type */
  wfprintf (fp, " %d", ptp_save->con_type);

  /* P2P: added 98-99th column: p2p protocol / p2p message type /  */
  wfprintf (fp, " %d", ptp_save->p2p_type / 100);

  /* Web2.0: added 105th column: HTTP content type */
  /* 
     Using http_data+1 so that valid values are > 0, i.e. GET is 1,
     POST is 2, etc.
  */
  wfprintf (fp, " %d", ptp_save->con_type & HTTP_PROTOCOL ?
  		       ptp_save->http_data + 1 : 0 );

/* End of the Core TCP set */
}

void print_tcp_stats_e2e(FILE *fp, tcp_pair *ptp_save, tcb *pab, tcb *pba)
{
  /* End to End flow measures (RTT and TTL) */

 wfprintf (fp, " %f %f %f %f %u %u %u",
   	  (Average (ptp_save->c2s.rtt_sum, ptp_save->c2s.rtt_count) /
   	   1000.0),
   	  (ptp_save->c2s.rtt_min / 1000.0),
 	  (ptp_save->c2s.rtt_max / 1000.0),
   	  (Stdev (ptp_save->c2s.rtt_sum, ptp_save->c2s.rtt_sum2,
   		 ptp_save->c2s.rtt_count) / 1000.0),
   	   ptp_save->c2s.rtt_count,
 	   ptp_save->c2s.ttl_min,
 	   ptp_save->c2s.ttl_max);

 wfprintf (fp, " %f %f %f %f %u %u %u",
   	  (Average (ptp_save->s2c.rtt_sum, ptp_save->s2c.rtt_count) /
   	   1000.0),
   	  (ptp_save->s2c.rtt_min / 1000.0),
 	  (ptp_save->s2c.rtt_max / 1000.0),
   	  (Stdev (ptp_save->s2c.rtt_sum, ptp_save->s2c.rtt_sum2,
   		 ptp_save->s2c.rtt_count) / 1000.0),
   	   ptp_save->s2c.rtt_count,
 	   ptp_save->s2c.ttl_min,
 	   ptp_save->s2c.ttl_max);
}

void print_tcp_stats_p2p(FILE *fp, tcp_pair *ptp_save, tcb *pab, tcb *pba)
{
  /* P2P: added 98-99th column: p2p protocol / p2p message type /  */
  wfprintf (fp, " %d", ptp_save->p2p_type % 100);

  /* P2P: added 100-103th column: p2p data mesg. / p2p signalling msg.   */
  /*	  currently only for ED2K-TCP - MMM 7/3/08*/
  wfprintf (fp, " %d %d %d %d", ptp_save->p2p_data_count,
    	   ptp_save->p2p_sig_count,ptp_save->p2p_c2s_count,ptp_save->p2p_c2c_count);

  /* P2P: added 104th column: p2p chat mesg. count */
  /*	  currently only for ED2K-TCP - MMM 5/6/08*/
  wfprintf (fp, " %d", ptp_save->p2p_msg_count);
}

void print_tcp_stats_options(FILE *fp, tcp_pair *ptp_save, tcb *pab, tcb *pba)
{
  wfprintf (fp, 
    	   " %d %d %d %d %d %d %u %u %u %u %d %lu %lu %u",
    	   pab->f1323_ws,
    	   pab->f1323_ts,
    	   pab->window_scale,
    	   pab->fsack_req,
    	   pab->sacks_sent,
    	   pab->mss,
    	   pab->max_seg_size,
    	   pab->min_seg_size,
    	   pab->win_max,
    	   pab->win_min,
    	   pab->win_zero_ct,
    	   pab->cwin_max,
    	   pab->cwin_min,
    	   pab->initialwin_bytes);

  wfprintf (fp, " %u %u %u %u %u %u %u %u",
    	   ptp_save->c2s.rtx_RTO,
    	   ptp_save->c2s.rtx_FR,
    	   ptp_save->c2s.reordering,
    	   ptp_save->c2s.net_dup,
    	   ptp_save->c2s.unknown,
    	   ptp_save->c2s.flow_control,
    	   ptp_save->c2s.unnecessary_rtx_RTO,
    	   ptp_save->c2s.unnecessary_rtx_FR);
  /* Bad behaviour */
  wfprintf (fp, " %d", ptp_save->c2s.bad_behavior);

  wfprintf (fp,
    	   " %d %d %d %d %d %d %u %u %u %u %d %lu %lu %u",
    	   pba->f1323_ws,
    	   pba->f1323_ts,
    	   pba->window_scale,
    	   pba->fsack_req,
    	   pba->sacks_sent,
    	   pba->mss,
    	   pba->max_seg_size,
    	   pba->min_seg_size,
    	   pba->win_max,
    	   pba->win_min,
    	   pba->win_zero_ct,
    	   pba->cwin_max, pba->cwin_min, pba->initialwin_bytes);

  wfprintf (fp, " %u %u %u %u %u %u %u %u",
    	   ptp_save->s2c.rtx_RTO,
    	   ptp_save->s2c.rtx_FR,
    	   ptp_save->s2c.reordering,
    	   ptp_save->s2c.net_dup,
    	   ptp_save->s2c.unknown,
    	   ptp_save->s2c.flow_control,
    	   ptp_save->s2c.unnecessary_rtx_RTO,
    	   ptp_save->s2c.unnecessary_rtx_FR);
  /* Bad behaviour */
  wfprintf (fp, " %d", ptp_save->s2c.bad_behavior);
}

void print_tcp_stats_advanced(FILE *fp, tcp_pair *ptp_save, tcb *pab, tcb *pba,
                              u_long pab_expected, u_long pba_expected)
{
  /* write to log file */
  /* printing boolean flag if this is considered internal or not */
  // wfprintf (fp, " %d", ptp_save->cloud_src);
  // wfprintf (fp, " %d", ptp_save->cloud_dst);

#ifdef LOST_PACKET_STAT
/* Expected unique bytes (from sequence numbers) used to detect missing packets */
  wfprintf (fp, " %u %u", pab_expected, pba_expected);
#endif

#ifdef PACKET_STATS
  {
    int i;

     /* PSH-delimited Message sizes */
    wfprintf (fp, " %d",ptp_save->c2s.msg_count);
    for (i=0;i<MAX_COUNT_MESSAGES;i++) {
    	wfprintf (fp, " %d",ptp_save->c2s.msg_size[i]);
     }

    wfprintf (fp, " %d",ptp_save->s2c.msg_count);
    for (i=0;i<MAX_COUNT_MESSAGES;i++) {
    	wfprintf (fp, " %d",ptp_save->s2c.msg_size[i]);
     }

     /* Segment sizes */
    wfprintf (fp, " %d",ptp_save->c2s.seg_count);
    for (i=0;i<MAX_COUNT_SEGMENTS;i++) {
    	wfprintf (fp, " %d",ptp_save->c2s.seg_size[i]);
     }

    wfprintf (fp, " %d",ptp_save->s2c.seg_count);
    for (i=0;i<MAX_COUNT_SEGMENTS;i++) {
    	wfprintf (fp, " %d",ptp_save->s2c.seg_size[i]);
     }

     /* Segment intertimes */
    for (i=0;i<MAX_COUNT_SEGMENTS-1;i++) {
    	wfprintf (fp, " %f",ptp_save->c2s.seg_intertime[i]/1000.);
     }

    for (i=0;i<MAX_COUNT_SEGMENTS-1;i++) {
    	wfprintf (fp, " %f",ptp_save->s2c.seg_intertime[i]/1000.);
     }

#define MEAN(SUM,ENNE) (((ENNE)>0)?((SUM)*1.0/(ENNE)):0.0)
#define VAR(ME,SQ,ENNE) (((ENNE)>1)?((SQ)-(ENNE)*(ME)*(ME))/((ENNE)-1):0.0)

    /* Averages */
     {
       double mval,varval;
       mval = MEAN(ptp_save->c2s.data_bytes,ptp_save->c2s.data_pkts);
       varval = VAR(mval,ptp_save->c2s.data_pkts_sum2,ptp_save->c2s.data_pkts);
       wfprintf (fp, " %d %f %f",ptp_save->c2s.data_pkts,mval,sqrt(varval));

       mval = MEAN(ptp_save->s2c.data_bytes,ptp_save->s2c.data_pkts);
       varval = VAR(mval,ptp_save->s2c.data_pkts_sum2,ptp_save->s2c.data_pkts);
       wfprintf (fp, " %d %f %f",ptp_save->s2c.data_pkts,mval,sqrt(varval));

       mval = MEAN(ptp_save->c2s.seg_intertime_sum,ptp_save->c2s.seg_count-1);
       varval = VAR(mval,ptp_save->c2s.seg_intertime_sum2,ptp_save->c2s.seg_count-1);
       wfprintf (fp, " %d",(ptp_save->c2s.seg_count>1)?ptp_save->c2s.seg_count:0);
       wfprintf (fp, " %f %f",mval/1e3,sqrt(varval)/1e3);

       mval = MEAN(ptp_save->s2c.seg_intertime_sum,ptp_save->s2c.seg_count-1);
       varval = VAR(mval,ptp_save->s2c.seg_intertime_sum2,ptp_save->s2c.seg_count-1);
       wfprintf (fp, " %d",(ptp_save->s2c.seg_count>1)?ptp_save->s2c.seg_count:0);
       wfprintf (fp, " %f %f",mval/1e3,sqrt(varval)/1e3);

     }

    /* PSH */
    wfprintf (fp, " %d %d",ptp_save->c2s.data_pkts_push,
     			   ptp_save->s2c.data_pkts_push);
  }
#endif

#ifdef ENABLE_LOG_MPTCP
  /* MPTCP usage */
  wfprintf (fp," %d %d",ptp_save->c2s.mptcp_req, ptp_save->s2c.mptcp_req);
#endif

}

void print_tcp_stats_layer7(FILE *fp, tcp_pair *ptp_save, tcb *pab, tcb *pba)
{

  /* Number of (potential) HTTP Requests and Responses  */
  wfprintf(fp, " %d %d", ptp_save->http_request_count, 
                         ptp_save->http_response_count);

  /* First HTTP response code, if HTTP */
  wfprintf(fp, " %s", (ptp_save->con_type & HTTP_PROTOCOL) ?
                            ptp_save->http_response : "---" );

  /* Number of PSH-separated messages */
  wfprintf(fp," %d %d",ptp_save->c2s.msg_count,ptp_save->s2c.msg_count);

  /* TLS SNI required by the client, if any */
  wfprintf(fp," %s",ptp_save->ssl_client_subject!=NULL?ptp_save->ssl_client_subject:"-");

  /* TLS Server Certificate Name SCN, if any */   
  wfprintf(fp," %s",ptp_save->ssl_server_subject!=NULL?ptp_save->ssl_server_subject:"-");

  /* TLS NPN / ALPN bitmask recording the usage of SPDY and HTTP2 */
  wfprintf(fp," %d %d",ptp_save->ssl_client_npnalpn, ptp_save->ssl_server_npnalpn);

  /* Record if the TLS Client Hello carries an old Session ID */
  wfprintf(fp," %d",ptp_save->ssl_sessionid_reuse);

/* Record time of the end of the SSL handshake */
  
  wfprintf(fp," %f",(ptp_save->con_type & SSL_PROTOCOL?
                     elapsed (ptp_save->first_time,
			      ptp_save->ssl_client_before_data_time) / 1000.0 : 0.0));
  wfprintf(fp," %f",(ptp_save->con_type & SSL_PROTOCOL?
                     elapsed (ptp_save->first_time,
			      ptp_save->ssl_server_before_data_time) / 1000.0 : 0.0));

/* Record time and data before first Application Data in TLS connections */

  wfprintf(fp," %f",(ptp_save->ssl_client_data_seen?
                     elapsed (ptp_save->first_time,
			      ptp_save->ssl_client_data_time) / 1000.0 : 0.0));
  wfprintf(fp," %f",(ptp_save->ssl_server_data_seen?
                     elapsed (ptp_save->first_time,
			      ptp_save->ssl_server_data_time) / 1000.0 : 0.0));


  wfprintf(fp," %lu",(ptp_save->ssl_client_data_seen?
                     (ptp_save->ssl_client_data_byte) : 0L));
  wfprintf(fp," %lu",(ptp_save->ssl_server_data_seen?
                     (ptp_save->ssl_server_data_byte) : 0L));

  #ifdef SNOOP_DROPBOX
  wfprintf(fp," %s",(ptp_save->con_type & HTTP_PROTOCOL) && 
                    (ptp_save->http_data==HTTP_DROPBOX) ? (strict_privacy ? "XXX" : ptp_save->http_ytid) :"-");
#endif
#ifdef DNS_CACHE_PROCESSOR
  if (ptp_save->dns_name!=NULL)
   {
     wfprintf(fp, " %s",ptp_save->dns_name);
     /* DNS server */     
     wfprintf(fp, " %s",HostName(ptp_save->dns_server));
     /* Absolute Request time */
     wfprintf(fp, " %f", time2double(ptp_save->request_time) / 1000.);
      /* Absolute Response time */
     wfprintf(fp, " %f", time2double(ptp_save->response_time) / 1000.);
   }
  else
   {
     wfprintf(fp, " - - 0.0 0.0");
   }
#endif

 /*  Uncomment if we need to trace which TLS connections are popular and not classified */
//  wfprintf(fp," %d",(ptp_save->tls_service); 

}

void print_video_stats_core(FILE *fp, tcp_pair *ptp_save, tcb *pab, tcb *pba)
{
  char id_string[20];

  /* Streaming : 75th column : Classification based on Content Type */

  wfprintf(fp, " %d", ptp_save->streaming.video_content_type);

  /* Streaming : 76th column : Classification based on Payload signature */
  wfprintf(fp, " %d", ptp_save->streaming.video_payload_type);

  /* Video ID16/46 */

  if ((ptp_save->con_type & HTTP_PROTOCOL) && 
     	     ( ptp_save->http_data==HTTP_YOUTUBE_VIDEO ||
     	       ptp_save->http_data==HTTP_YOUTUBE_VIDEO204 ||
     	       ptp_save->http_data==HTTP_YOUTUBE_204 ))
   {
     if (strlen(ptp_save->http_ytid)==11)
      {
	/* Some YouTube HLS flows use the ID11 in the request */
	id11to16(id_string, ptp_save->http_ytid);
	wfprintf(fp, " %s", (strict_privacy ? "XXX" : id_string));
      }
     else
      {
        /* This is both good for ID16 and ID46 */
        wfprintf(fp, " %s", (strict_privacy ? "XXX" : ptp_save->http_ytid));
      }
   }
  else if ((ptp_save->con_type & HTTP_PROTOCOL) && 
     	     ( ptp_save->http_data==HTTP_YOUTUBE_SITE ||
     	       ptp_save->http_data==HTTP_YOUTUBE_SITE_DIRECT ||
     	       ptp_save->http_data==HTTP_YOUTUBE_SITE_EMBED ))
   {
     id11to16(id_string,ptp_save->http_ytid);
     wfprintf (fp, " %s", (strict_privacy ? "XXX" : id_string));
   }
  else			 
   {
     wfprintf (fp, " --");
   }

   /* YouTube Format */

  if ((ptp_save->con_type & HTTP_PROTOCOL) && 
             ( ptp_save->http_data==HTTP_YOUTUBE_VIDEO ||
               ptp_save->http_data==HTTP_YOUTUBE_VIDEO204 ||
               ptp_save->http_data==HTTP_YOUTUBE_204  )
	 )
   {
     wfprintf (fp, " %s", ptp_save->http_ytitag);
   }
  else
   {
     wfprintf (fp, " --");
   }

}

void print_video_stats_info(FILE *fp, tcp_pair *ptp_save, tcb *pab, tcb *pba)
{
  /* Streaming : 77th column : Video Duration*/
  wfprintf(fp, " %f", ptp_save->streaming.metadata.duration);

  /* Streaming : 78th column : Overall Video Bitrate*/
  wfprintf(fp, " %f", ptp_save->streaming.metadata.videodatarate);

  /* Streaming : 79th column : Video Width*/
  wfprintf(fp, " %d", ptp_save->streaming.metadata.width);

  /* Streaming : 80th column : Video Height*/
  wfprintf(fp, " %d", ptp_save->streaming.metadata.height);

}

void print_video_stats_youtube(FILE *fp, tcp_pair *ptp_save, tcb *pab, tcb *pba)
{
  char id_string[20];

  /* ID11 */
  if ((ptp_save->con_type & HTTP_PROTOCOL) && 
     	     ( ptp_save->http_data==HTTP_YOUTUBE_VIDEO ||
     	       ptp_save->http_data==HTTP_YOUTUBE_VIDEO204 ||
     	       ptp_save->http_data==HTTP_YOUTUBE_204 ))
   {
     if (strlen(ptp_save->http_ytid)==11)
      {
	/* Some YouTube HLS flows use the ID11 in the request */
	wfprintf(fp, " %s", (strict_privacy ? "XXX" : ptp_save->http_ytid));
      }
     else
      {
        /* This is both good for ID16 and ID46 */
        id16to11(id_string, ptp_save->http_ytid);
        wfprintf(fp, " %s", (strict_privacy ? "XXX" : id_string));
      }
   }
  else if ((ptp_save->con_type & HTTP_PROTOCOL) && 
     	       ( ptp_save->http_data==HTTP_YOUTUBE_SITE ||
     		 ptp_save->http_data==HTTP_YOUTUBE_SITE_DIRECT ||
     		 ptp_save->http_data==HTTP_YOUTUBE_SITE_EMBED ))
   {
     wfprintf (fp, " %s", (strict_privacy ? "XXX" : ptp_save->http_ytid));
   }
  else			 
   {
     wfprintf (fp, " --");
   }

  /* Other YouTube info */

  if ((ptp_save->con_type & HTTP_PROTOCOL) && 
             ( ptp_save->http_data==HTTP_YOUTUBE_VIDEO ||
               ptp_save->http_data==HTTP_YOUTUBE_VIDEO204 ||
               ptp_save->http_data==HTTP_YOUTUBE_204  ))
   {
     wfprintf (fp, " %d %d %d %d %d", 
				 ptp_save->http_ytseek,
				 ptp_save->http_ytredir_mode,
				 ptp_save->http_ytredir_count,
				 ptp_save->http_ytmobile,
				 ptp_save->http_ytstream );
   }
  else
   {
     wfprintf (fp, " 0 0 0 0 0");
   }

}

void print_video_stats_advanced(FILE *fp, tcp_pair *ptp_save, tcb *pab, tcb *pba)
{
  int i;

  /* Rate c2s */
  if (ptp_save->c2s.rate_samples > 1)
   {
     wfprintf (fp, " %d %d %d %.3f %.3f %.3f %.3f",
  		    ptp_save->c2s.rate_samples, 				   
  		    ptp_save->c2s.rate_empty_samples,				   
    		    ptp_save->c2s.rate_empty_streak,
  		    8e-3*ptp_save->c2s.rate_sum/ptp_save->c2s.rate_samples,	   
  		    8e-3*sqrt((ptp_save->c2s.rate_sum2 - 
  			       ptp_save->c2s.rate_sum*ptp_save->c2s.rate_sum/ptp_save->c2s.rate_samples)/
  			       (ptp_save->c2s.rate_samples-1)),
  		    8e-3*ptp_save->c2s.rate_min,
  		    8e-3*ptp_save->c2s.rate_max);
   }
  else
   {
     wfprintf (fp, " 0 0 0 0.000 0.000 0.000 0.000");
   }

  /* Rate s2c */
  if (ptp_save->s2c.rate_samples > 1 )
   {
     wfprintf (fp, " %d %d %d %.3f %.3f %.3f %.3f",
  		    ptp_save->s2c.rate_samples, 				   
  		    ptp_save->s2c.rate_empty_samples,
    		    ptp_save->s2c.rate_empty_streak,
  		    8e-3*ptp_save->s2c.rate_sum/ptp_save->s2c.rate_samples,	   
  		    8e-3*sqrt((ptp_save->s2c.rate_sum2 - 
  			       ptp_save->s2c.rate_sum*ptp_save->s2c.rate_sum/ptp_save->s2c.rate_samples)/
  			       (ptp_save->s2c.rate_samples-1)),
  		    8e-3*ptp_save->s2c.rate_min,
  		    8e-3*ptp_save->s2c.rate_max);
   }
  else
   {
     wfprintf (fp, " 0 0 0 0.000 0.000 0.000 0.000");
   }

  /* write to log file */

  for (i=0;i<10;i++)
   {
     wfprintf (fp, " %d",ptp_save->c2s.rate_begin_bytes[i]);
   }

  for (i=0;i<10;i++)
   {
     wfprintf (fp, " %d",ptp_save->s2c.rate_begin_bytes[i]);
   }

  wfprintf (fp, " %d",ptp_save->s2c.msg_count);
  for (i=0;i<MAX_COUNT_MESSAGES;i++)
   {
     wfprintf (fp, " %d",ptp_save->s2c.msg_size[i]);
   }

}


void
make_conn_stats (tcp_pair * ptp_save, Bool complete)
{
  tcb *outgoing, *incoming;
  Bool local;
  double etime;
  FILE *fp;
  tcb *pab, *pba;
  u_long pab_expected, pba_expected;

   /* Statistichs about CHAT flows */
   tcp_cleaned ++;

  /* Statistichs about CHAT flows */
#ifdef MSN_CLASSIFIER
  print_msn_conn_stats(ptp_save);
#endif
#ifdef YMSG_CLASSIFIER
  print_ymsg_conn_stats(ptp_save);
#endif
#ifdef XMPP_CLASSIFIER
  print_jabber_conn_stats(ptp_save);
#endif

#ifdef VIDEO_DETAILS
 if (!ZERO_TIME (&(ptp_save->c2s.rate_last_sample)))
  {
    double sample;
    double delta;
    int streak=0;

    delta = time2double(current_time)-ptp_save->c2s.rate_left_edge;
    if (delta < GLOBALS.Rate_Sampling )
       sample = ptp_save->c2s.rate_bytes * 1e6 / delta;
    else
       sample = ptp_save->c2s.rate_bytes * 1e6 / GLOBALS.Rate_Sampling;

    if (ptp_save->c2s.rate_min>sample) 
      ptp_save->c2s.rate_min = sample;
    if (ptp_save->c2s.rate_max<sample) 
      ptp_save->c2s.rate_max = sample;
      
    ptp_save->c2s.rate_sum += sample;
    ptp_save->c2s.rate_sum2 += sample*sample;
    if (ptp_save->c2s.rate_samples<10)
     {
       ptp_save->c2s.rate_begin_bytes[ptp_save->c2s.rate_samples] = ptp_save->c2s.rate_bytes;
     }
    ptp_save->c2s.rate_samples++;
    if (ptp_save->c2s.rate_bytes==0)
     {
       ptp_save->c2s.rate_empty_samples++;
       streak++;
     }

    ptp_save->c2s.rate_left_edge +=  GLOBALS.Rate_Sampling;
    ptp_save->c2s.rate_right_edge +=  GLOBALS.Rate_Sampling;

    while (time2double(current_time) >= ptp_save->c2s.rate_right_edge)
     {
       ptp_save->c2s.rate_left_edge +=  GLOBALS.Rate_Sampling;
       ptp_save->c2s.rate_right_edge +=  GLOBALS.Rate_Sampling;
       if (ptp_save->c2s.rate_samples<10)
        {
          ptp_save->c2s.rate_begin_bytes[ptp_save->c2s.rate_samples] = 0;
        }
       ptp_save->c2s.rate_samples++;
       ptp_save->c2s.rate_empty_samples++;
       streak++;
     }
     
    if (streak > ptp_save->c2s.rate_empty_streak)
      ptp_save->c2s.rate_empty_streak = streak;
  }
 if (!ZERO_TIME (&(ptp_save->s2c.rate_last_sample)))
  {
    double sample;
    double delta;
    int streak=0;

    delta = time2double(current_time)-ptp_save->s2c.rate_left_edge;
    if (delta < GLOBALS.Rate_Sampling )
       sample = ptp_save->s2c.rate_bytes * 1e6 / delta;
    else
       sample = ptp_save->s2c.rate_bytes * 1e6 / GLOBALS.Rate_Sampling;

    if (ptp_save->s2c.rate_min>sample) 
      ptp_save->s2c.rate_min = sample;
    if (ptp_save->s2c.rate_max<sample) 
      ptp_save->s2c.rate_max = sample;
      
    ptp_save->s2c.rate_sum += sample;
    ptp_save->s2c.rate_sum2 += sample*sample;
    if (ptp_save->s2c.rate_samples<10)
     {
       ptp_save->s2c.rate_begin_bytes[ptp_save->s2c.rate_samples] = ptp_save->s2c.rate_bytes;
     }
    ptp_save->s2c.rate_samples++;
    if (ptp_save->s2c.rate_bytes==0)
     {
       ptp_save->s2c.rate_empty_samples++;
       streak++;
     }

    ptp_save->s2c.rate_left_edge +=  GLOBALS.Rate_Sampling;
    ptp_save->s2c.rate_right_edge +=  GLOBALS.Rate_Sampling;

    while (time2double(current_time) >= ptp_save->s2c.rate_right_edge)
     {
       ptp_save->s2c.rate_left_edge +=  GLOBALS.Rate_Sampling;
       ptp_save->s2c.rate_right_edge +=  GLOBALS.Rate_Sampling;
       if (ptp_save->s2c.rate_samples<10)
        {
          ptp_save->s2c.rate_begin_bytes[ptp_save->s2c.rate_samples] = 0;
        }
       ptp_save->s2c.rate_samples++;
       ptp_save->s2c.rate_empty_samples++;
       streak++;
     }

    if (streak > ptp_save->c2s.rate_empty_streak)
      ptp_save->c2s.rate_empty_streak = streak;
  }
#endif

  /* Statistics from the plugins */

  /* TCP proto stats should be done only for complete flows 
     This affects only the histograms of L7 TCP flows */
  if (complete)
     make_proto_stat (ptp_save, PROTOCOL_TCP);


  /* TOPIX: connection type statistics */
  if (ptp_save->con_type & RTP_PROTOCOL)
    f_RTP_tunneled_TCP_count++;
  /* end TOPIX */

  pab = &(ptp_save->c2s);
  pba = &(ptp_save->s2c);

  if (ptp_save->internal_src && !ptp_save->internal_dst)
    {
      outgoing = &(ptp_save->c2s);	// c2s out
      incoming = &(ptp_save->s2c);	// s2c in
      local = FALSE;
    }
  else if (ptp_save->internal_dst && !ptp_save->internal_src)
    {
      outgoing = &(ptp_save->s2c);	// s2c out
      incoming = &(ptp_save->c2s);	// c2s in
      local = FALSE;
    }
  else if (ptp_save->internal_src && ptp_save->internal_dst)
    {
      local = TRUE;
      outgoing = &(ptp_save->s2c);	// s2s loc
      incoming = &(ptp_save->c2s);	// c2s loc
    }
  else
    {
      if (warn_IN_OUT)
	{
	  fprintf (fp_stderr, 
        "\nWARN: This flow is neither incoming nor outgoing: src - %s;",
	     HostName (ptp_save->addr_pair.a_address));
	  fprintf (fp_stderr, " dst - %s!\n", HostName (ptp_save->addr_pair.b_address));
	  warn_IN_OUT = FALSE;
	}
#ifndef LOG_UNKNOWN
      return;
#else
/* fool the internal and external definition... */
      outgoing = &(ptp_save->s2c);
      incoming = &(ptp_save->c2s);
      // local = FALSE;
      local = TRUE;
#endif
    }


/* Code for sequence_number checking to detect missing packets */ 
   if (pab->max_seq!=pab->syn)
    {
      if ( (pab->fin_count > 0) &&  pab->max_seq > pab->fin_seqno ) 
         pab_expected = pab->max_seq - pab->syn - 2;
      else 
	 pab_expected = pab->max_seq - pab->syn - 1;
    }
   else
    {
      pab_expected = 0;
    }
   
   if (pba->max_seq!=pba->syn)
    {
      if ( (pba->fin_count > 0) &&  pba->max_seq > pba->fin_seqno ) 
	 pba_expected = pba->max_seq - pba->syn - 2;
      else 
	 pba_expected = pba->max_seq - pba->syn - 1;
    }
   else
    {
      pba_expected = 0;
    }

  if (complete)
    {
      /* sack
       *  [1] A<->B  both agree
       *  [2] A ->B  a set
       *  [3] A<- B  b set
       *  [4] not set
       */

      if (ptp_save->c2s.fsack_req && ptp_save->s2c.fsack_req)
	{
	  add_histo (tcp_opts_SACK, 1);
	}
      else if (ptp_save->c2s.fsack_req)
	{
	  add_histo (tcp_opts_SACK, 2);
	}
      else if (ptp_save->s2c.fsack_req)
	{
	  add_histo (tcp_opts_SACK, 3);
	}
      else
	{
	  add_histo (tcp_opts_SACK, 4);
	}

      /* winscale
       *  [1] A<->B  both agree
       *  [2] A ->B  a set
       *  [3] A<- B  b set
       *  [4] not set
       */

      if (ptp_save->c2s.f1323_ws && ptp_save->s2c.f1323_ws)
	{
	  add_histo (tcp_opts_WS, 1);
	}
      else if (ptp_save->c2s.f1323_ws)
	{
	  add_histo (tcp_opts_WS, 2);
	}
      else if (ptp_save->s2c.f1323_ws)
	{
	  add_histo (tcp_opts_WS, 3);
	}
      else
	{
	  add_histo (tcp_opts_WS, 4);
	}


      /* timestamp
       *  [1] A<->B  both agree
       *  [2] A ->B  a set
       *  [3] A<- B  b set
       *  [4] not set
       */

      if (ptp_save->c2s.f1323_ts && ptp_save->s2c.f1323_ts)
	{
	  add_histo (tcp_opts_TS, 1);
	}
      else if (ptp_save->c2s.f1323_ts)
	{
	  add_histo (tcp_opts_TS, 2);
	}
      else if (ptp_save->s2c.f1323_ts)
	{
	  add_histo (tcp_opts_TS, 3);
	}
      else
	{
	  add_histo (tcp_opts_TS, 4);
	}

      /* MultiPath TCP - mptcp
       *  [1] A<->B  both agree
       *  [2] A ->B  a set
       *  [3] A<- B  b set
       *  [4] not set
       */

      if (ptp_save->c2s.mptcp_req && ptp_save->s2c.mptcp_req)
	{
	  add_histo (tcp_opts_MPTCP, 1);
	}
      else if (ptp_save->c2s.mptcp_req)
	{
	  add_histo (tcp_opts_MPTCP, 2);
	}
      else if (ptp_save->s2c.mptcp_req)
	{
	  add_histo (tcp_opts_MPTCP, 3);
	}
      else
	{
	  add_histo (tcp_opts_MPTCP, 4);
	}

      /* MSS
       */

      add_histo (tcp_mss_a, ptp_save->c2s.mss);
      add_histo (tcp_mss_b, ptp_save->s2c.mss);

      if ((ptp_save->c2s.mss == 0) || (ptp_save->s2c.mss == 0))
	{
	  add_histo (tcp_mss_used, 536);
	}
      else if (ptp_save->c2s.mss < ptp_save->s2c.mss)
	{
	  add_histo (tcp_mss_used, ptp_save->c2s.mss);
	}
      else
	{
	  add_histo (tcp_mss_used, ptp_save->s2c.mss);
	}

/* flow lenght */
      if (!local)
	{
	  add_histo (tcp_cl_b_s_out, outgoing->data_bytes);
	  add_histo (tcp_cl_b_s_in, incoming->data_bytes);
	  add_histo (tcp_cl_b_l_out, outgoing->data_bytes);
	  add_histo (tcp_cl_b_l_in, incoming->data_bytes);

	  add_histo (tcp_cl_p_out, outgoing->packets);
	  add_histo (tcp_cl_p_in, incoming->packets);
	}
      else
	{
	  add_histo (tcp_cl_b_s_loc, outgoing->data_bytes);
	  add_histo (tcp_cl_b_s_loc, incoming->data_bytes);
	  add_histo (tcp_cl_b_l_loc, outgoing->data_bytes);
	  add_histo (tcp_cl_b_l_loc, incoming->data_bytes);

	  add_histo (tcp_cl_p_loc, outgoing->packets);
	  add_histo (tcp_cl_p_loc, incoming->packets);
	}

      add_histo (tcp_cl_b_s_c2s, ptp_save->c2s.data_bytes);
      add_histo (tcp_cl_b_s_s2c, ptp_save->s2c.data_bytes);
      add_histo (tcp_cl_b_l_c2s, ptp_save->c2s.data_bytes);
      add_histo (tcp_cl_b_l_s2c, ptp_save->s2c.data_bytes);

      add_histo (tcp_cl_p_c2s, ptp_save->c2s.packets);
      add_histo (tcp_cl_p_s2c, ptp_save->s2c.packets);
      /* receiver window */
      add_histo (tcp_win_min, ptp_save->c2s.win_min);
      add_histo (tcp_win_min, ptp_save->s2c.win_min);


      if (ptp_save->c2s.packets)
	{
	  add_histo (tcp_win_avg,
		     (ptp_save->c2s.win_tot / ptp_save->c2s.packets));
	}
      if (ptp_save->s2c.packets)
	{
	  add_histo (tcp_win_avg,
		     (ptp_save->s2c.win_tot / ptp_save->s2c.packets));
	}

      add_histo (tcp_win_max, ptp_save->c2s.win_max);
      add_histo (tcp_win_max, ptp_save->s2c.win_max);

      /* RTT */

      if ((incoming->rtt_count >= 1) && (outgoing->rtt_count >= 1))
	{
	  if (!local)
	    {
	      add_histo (tcp_rtt_avg_out,
			 (Average (outgoing->rtt_sum, outgoing->rtt_count) /
			  1000.0));
	      add_histo (tcp_rtt_avg_in,
			 (Average (incoming->rtt_sum, incoming->rtt_count) /
			  1000.0));
	      if (ptp_save->cloud_src || ptp_save->cloud_dst)
	       {
	         add_histo (tcp_rtt_c_avg_out,
	        	 (Average (outgoing->rtt_sum, outgoing->rtt_count) /
	        	  1000.0));
	         add_histo (tcp_rtt_c_avg_in,
	        	 (Average (incoming->rtt_sum, incoming->rtt_count) /
	        	  1000.0));
	       }
	      else
	       {
	         add_histo (tcp_rtt_nc_avg_out,
	        	 (Average (outgoing->rtt_sum, outgoing->rtt_count) /
	        	  1000.0));
	         add_histo (tcp_rtt_nc_avg_in,
	        	 (Average (incoming->rtt_sum, incoming->rtt_count) /
	        	  1000.0));
	       }

	      /* min */
	      add_histo (tcp_rtt_min_out, (outgoing->rtt_min / 1000.0));
	      add_histo (tcp_rtt_min_in, (incoming->rtt_min / 1000.0));

	      /* max */
	      add_histo (tcp_rtt_max_out, (outgoing->rtt_max / 1000.0));
	      add_histo (tcp_rtt_max_in, (incoming->rtt_max / 1000.0));

	      /* stdev */
	      add_histo (tcp_rtt_stdev_out,
			 (Stdev (outgoing->rtt_sum, outgoing->rtt_sum2,
				 outgoing->rtt_count) / 1000.0));
	      add_histo (tcp_rtt_stdev_in,
			 (Stdev (incoming->rtt_sum, incoming->rtt_sum2,
				 incoming->rtt_count) / 1000.0));

	      /* valid samples */
	      add_histo (tcp_rtt_cnt_out, outgoing->rtt_count);
	      add_histo (tcp_rtt_cnt_in, incoming->rtt_count);
	    }
	  else 
	    {
	      add_histo (tcp_rtt_avg_loc,
			 (Average (outgoing->rtt_sum, outgoing->rtt_count) /
			  1000.0));
	      add_histo (tcp_rtt_avg_loc,
			 (Average (incoming->rtt_sum, incoming->rtt_count) /
			  1000.0));

	      /* min */
	      add_histo (tcp_rtt_min_loc, (outgoing->rtt_min / 1000.0));
	      add_histo (tcp_rtt_min_loc, (incoming->rtt_min / 1000.0));

	      /* max */
	      add_histo (tcp_rtt_max_loc, (outgoing->rtt_max / 1000.0));
	      add_histo (tcp_rtt_max_loc, (incoming->rtt_max / 1000.0));

	      /* stdev */
	      add_histo (tcp_rtt_stdev_loc,
			 (Stdev (outgoing->rtt_sum, outgoing->rtt_sum2,
				 outgoing->rtt_count) / 1000.0));
	      add_histo (tcp_rtt_stdev_loc,
			 (Stdev (incoming->rtt_sum, incoming->rtt_sum2,
				 incoming->rtt_count) / 1000.0));

	      /* valid samples */
	      add_histo (tcp_rtt_cnt_loc, outgoing->rtt_count);
	      add_histo (tcp_rtt_cnt_loc, incoming->rtt_count);
	    }


	  /* avg */
	  add_histo (tcp_rtt_avg_c2s,
		     (Average (ptp_save->c2s.rtt_sum, ptp_save->c2s.rtt_count)
		      / 1000.0));
	  add_histo (tcp_rtt_avg_s2c,
		     (Average (ptp_save->s2c.rtt_sum, ptp_save->s2c.rtt_count)
		      / 1000.0));

	  /* min */
	  add_histo (tcp_rtt_min_c2s, (ptp_save->c2s.rtt_min / 1000.0));
	  add_histo (tcp_rtt_min_s2c, (ptp_save->s2c.rtt_min / 1000.0));

	  /* max */
	  add_histo (tcp_rtt_max_c2s, (ptp_save->c2s.rtt_max / 1000.0));
	  add_histo (tcp_rtt_max_s2c, (ptp_save->s2c.rtt_max / 1000.0));

	  /* stdev */
	  add_histo (tcp_rtt_stdev_c2s,
		     (Stdev (ptp_save->c2s.rtt_sum, ptp_save->c2s.rtt_sum2,
			     ptp_save->c2s.rtt_count) / 1000.0));
	  add_histo (tcp_rtt_stdev_s2c,
		     (Stdev (ptp_save->s2c.rtt_sum, ptp_save->s2c.rtt_sum2,
			     ptp_save->s2c.rtt_count) / 1000.0));

	  /* valid samples */
	  add_histo (tcp_rtt_cnt_c2s, ptp_save->c2s.rtt_count);
	  add_histo (tcp_rtt_cnt_s2c, ptp_save->s2c.rtt_count);
	}

      /* Statistichs about duplicates and rtxs */

      if (!local)
	{
	  add_histo (tcp_rtx_RTO_out, outgoing->rtx_RTO);
	  add_histo (tcp_rtx_RTO_in, incoming->rtx_RTO);

	  add_histo (tcp_rtx_FR_out, outgoing->rtx_FR);
	  add_histo (tcp_rtx_FR_in, incoming->rtx_FR);

	  add_histo (tcp_reordering_out, outgoing->reordering);
	  add_histo (tcp_reordering_in, incoming->reordering);

	  add_histo (tcp_net_dup_out, outgoing->net_dup);
	  add_histo (tcp_net_dup_in, incoming->net_dup);

	  add_histo (tcp_unknown_out, outgoing->unknown);
	  add_histo (tcp_unknown_in, incoming->unknown);

	  add_histo (tcp_flow_ctrl_out, outgoing->flow_control);
	  add_histo (tcp_flow_ctrl_in, incoming->flow_control);

	  add_histo (tcp_unnrtx_RTO_out, outgoing->unnecessary_rtx_RTO);
	  add_histo (tcp_unnrtx_RTO_in, incoming->unnecessary_rtx_RTO);

	  add_histo (tcp_unnrtx_FR_out, outgoing->unnecessary_rtx_FR);
	  add_histo (tcp_unnrtx_FR_in, incoming->unnecessary_rtx_FR);
	}
      else
	{
	  add_histo (tcp_rtx_RTO_loc, outgoing->rtx_RTO);
	  add_histo (tcp_rtx_RTO_loc, incoming->rtx_RTO);

	  add_histo (tcp_rtx_FR_loc, outgoing->rtx_FR);
	  add_histo (tcp_rtx_FR_loc, incoming->rtx_FR);

	  add_histo (tcp_reordering_loc, outgoing->reordering);
	  add_histo (tcp_reordering_loc, incoming->reordering);

	  add_histo (tcp_net_dup_loc, outgoing->net_dup);
	  add_histo (tcp_net_dup_loc, incoming->net_dup);

	  add_histo (tcp_unknown_loc, outgoing->unknown);
	  add_histo (tcp_unknown_loc, incoming->unknown);

	  add_histo (tcp_flow_ctrl_loc, outgoing->flow_control);
	  add_histo (tcp_flow_ctrl_loc, incoming->flow_control);

	  add_histo (tcp_unnrtx_RTO_loc, outgoing->unnecessary_rtx_RTO);
	  add_histo (tcp_unnrtx_RTO_loc, incoming->unnecessary_rtx_RTO);

	  add_histo (tcp_unnrtx_FR_loc, outgoing->unnecessary_rtx_FR);
	  add_histo (tcp_unnrtx_FR_loc, incoming->unnecessary_rtx_FR);
	}


      add_histo (tcp_rtx_RTO_c2s, ptp_save->c2s.rtx_RTO);
      add_histo (tcp_rtx_RTO_s2c, ptp_save->s2c.rtx_RTO);

      add_histo (tcp_rtx_FR_c2s, ptp_save->c2s.rtx_FR);
      add_histo (tcp_rtx_FR_s2c, ptp_save->s2c.rtx_FR);

      add_histo (tcp_reordering_c2s, ptp_save->c2s.reordering);
      add_histo (tcp_reordering_s2c, ptp_save->s2c.reordering);

      add_histo (tcp_net_dup_c2s, ptp_save->c2s.net_dup);
      add_histo (tcp_net_dup_s2c, ptp_save->s2c.net_dup);

      add_histo (tcp_unknown_c2s, ptp_save->c2s.unknown);
      add_histo (tcp_unknown_s2c, ptp_save->s2c.unknown);

      add_histo (tcp_flow_ctrl_c2s, ptp_save->c2s.flow_control);
      add_histo (tcp_flow_ctrl_s2c, ptp_save->s2c.flow_control);

      add_histo (tcp_unnrtx_RTO_c2s, ptp_save->c2s.unnecessary_rtx_RTO);
      add_histo (tcp_unnrtx_RTO_s2c, ptp_save->s2c.unnecessary_rtx_RTO);

      add_histo (tcp_unnrtx_FR_c2s, ptp_save->c2s.unnecessary_rtx_FR);
      add_histo (tcp_unnrtx_FR_s2c, ptp_save->s2c.unnecessary_rtx_FR);
    }



  /* connection time and throughput */
  /* from microseconds to ms */
  etime = elapsed (ptp_save->first_time, ptp_save->last_time);
  etime = etime / 1000;

  if (complete)
    {
      double transfer_time, thru;
      
      add_histo (tcp_tot_time, etime);

      transfer_time = elapsed (ptp_save->first_time, pab->payload_end_time);
      
      if (transfer_time > 0.0)
       {
         thru = ((double) ptp_save->c2s.unique_bytes / transfer_time * 8000.0);
        /* throughput in kbps */

	 add_histo (tcp_thru_c2s, thru);
         /* Large flow stats */
	 if ( ptp_save->c2s.unique_bytes >= 1000000)
	  {
	    add_histo (tcp_thru_lf_c2s, thru);
	    if (ptp_save->cloud_src || ptp_save->cloud_dst)
	     {
	       add_histo (tcp_thru_lf_c_c2s, thru);
	     }
	    else
	     {
	       add_histo (tcp_thru_lf_nc_c2s, thru);
	     }
	  }
       }

      transfer_time = elapsed (ptp_save->first_time, pba->payload_end_time);

      if (transfer_time > 0.0)
       {

         thru = ((double) ptp_save->s2c.unique_bytes / transfer_time * 8000.0);

	 add_histo (tcp_thru_s2c, thru);
         /* Large flow stats */
	 if ( ptp_save->s2c.unique_bytes >= 1000000)
	  {
	    add_histo (tcp_thru_lf_s2c, thru);
	    if (ptp_save->cloud_src || ptp_save->cloud_dst)
	     {
	       add_histo (tcp_thru_lf_c_s2c, thru);
	     }
	    else
	     {
	       add_histo (tcp_thru_lf_nc_s2c, thru);
	     }
	  }
       }
    }

  if (complete)
   {
     u_long missing_bytes = 0;

    /*
      Counting the amount of bytes missing in the measured TCP flow, due to packets 
      not seen by the probe and/or tstat.

      pab_expected is the expected size of the TCP flow, computed above using
      the sequence numbers in the SYN and FIN packets.
      Due to multiple impredictable issues (packet reordering, flow reuse, buggy TCP 
      implementation), its value might be HUGELY off, so we need a heuristic to 
      exclude those situations from our measure.

      We suppose that the computed expected bytes are 'meaningful' if:
       - either no data packets (only SYN, FIN and ACK) are seen but the missing volume is
         small (1 MB);
       - or some data packets were seen, and the missing volume is smaller than 10 times 
         the maximum volume representable by the seen data packets (i.e. I miss less than
	 the 90% of the data)
    */ 

    if (pab_expected > pab->unique_bytes)
      {
      // printf("C -> S: %d %lu %lu %lu %lu\n",pab->bad_behavior,pab_expected-pab->unique_bytes,pab_expected,pab->unique_bytes,pab->data_pkts);
        if (!((pab->data_pkts == 0 && pab_expected > 1e6) ||
              (pab->data_pkts > 0 && pab_expected > 1500*10*pab->data_pkts))
    	   )
    	 missing_bytes += pab_expected - pab->unique_bytes;
      }
    if (pba_expected > pba->unique_bytes)
      {
     //  printf("S -> C: %d %lu %lu %lu %lu\n",pba->bad_behavior,pba_expected-pba->unique_bytes,pba_expected,pba->unique_bytes,pba->data_pkts);
        if (!((pba->data_pkts == 0 && pba_expected > 1e6) ||
              (pba->data_pkts > 0 && pba_expected > 1500*10*pba->data_pkts))
    	   )
    	 missing_bytes += pba_expected - pba->unique_bytes;
      }

    tcpdata_received_total += ((double)pab->unique_bytes+(double)pba->unique_bytes)/1e6;
    tcpdata_missed_total += (double)missing_bytes/1e6;	
     
   //     printf("%lu %lu %lu - %lu %lu %lu\n",pab->unique_bytes,pab_expected,pab_expected - pab->unique_bytes,
   //                                pba->unique_bytes,pba_expected,pba_expected - pba->unique_bytes);
     
   }
   
  /* check if this flow has been abruptly interrupted by the user       */
  /* according to the heuristic defined in                              */
  /* D. Rossi, C. Casetti, M. Mellia                                    */
  /*      User Patience and the Web: a hands-on investigation           */
  /*      IEEE Globecom 2003                                            */
  /*      San Francisco, CA, USA, December 1-5, 2003                    */
  {
    Bool eligible = !(pba->fin_count > 0 || pba->reset_count > 0)
      && pba->unique_bytes > 0 && pab->reset_count > 0;
    double RTT = Average (ptp_save->c2s.rtt_sum, ptp_save->c2s.rtt_count) +
      Average (ptp_save->s2c.rtt_sum, ptp_save->s2c.rtt_count);
    Bool Interrupted = eligible &&
      (elapsed (ptp_save->last_time, pba->payload_end_time) < RTT);
    add_histo (tcp_interrupted, Interrupted);
  }

  /*---------------------------------------------------------*/
  /* dump stream properties                                  */
  /* topix                                                   */

  if (ptp_save->con_type & (RTP_PROTOCOL | ICY_PROTOCOL))
    {

      if (!ptp_save->internal_src && ptp_save->internal_dst)
	{
	  add_histo (mm_type_out, ptp_save->con_type);
	  if (ptp_save->con_type & RTP_PROTOCOL)
	    {
	      add_histo (mm_rtp_pt_out, ptp_save->rtp_pt);
	    }
	  add_histo (mm_cl_b_out, pba->unique_bytes);
	  //if(pba->unique_bytes <= SHORT_MM_CL_B)
	  add_histo (mm_cl_b_s_out, pba->unique_bytes);
	  if (pba->packets >= BITRATE_MIN_PKTS)
	    {
	      add_histo (mm_avg_bitrate_out,
			 (pba->unique_bytes >> 7) / (etime / 1000.0));
	    }
	  add_histo (mm_cl_p_out, pba->packets);
	  //if(pba->packets <= SHORT_MM_CL_P)
	  add_histo (mm_cl_p_s_out, pba->packets);
	  add_histo (mm_avg_ipg_out,
		     (pba->sum_delta_t / (pba->n_delta_t - 1)) * 10.);
	  add_histo (mm_avg_jitter_out,
		     (pba->sum_jitter / (pba->n_delta_t - 1)) * 10.);
	  add_histo (mm_n_oos_out, pba->out_order_pkts);
	  add_histo (mm_p_oos_out,
		     ((float) pba->out_order_pkts /
		      (float) pba->packets) * 1000);
	  add_histo (mm_tot_time_out, etime / 1000);
	  //if (etime <= SHORT_MM_TOT_TIME)
	  add_histo (mm_tot_time_s_out, etime);
	  add_histo (mm_p_dup_out, (pba->rexmit_pkts * 1000) / pba->packets);
	}
      else if (ptp_save->internal_src && !ptp_save->internal_dst)
	{
	  add_histo (mm_type_in, ptp_save->con_type);
	  if (ptp_save->con_type & RTP_PROTOCOL)
	    {
	      add_histo (mm_rtp_pt_in, ptp_save->rtp_pt);
	    }
	  add_histo (mm_cl_b_in, pba->unique_bytes);
	  //if(pba->unique_bytes <= SHORT_MM_CL_B)
	  add_histo (mm_cl_b_s_in, pba->unique_bytes);
	  if (pba->packets >= BITRATE_MIN_PKTS)
	    {
	      add_histo (mm_avg_bitrate_in,
			 (pba->unique_bytes >> 7) / (etime / 1000.0));
	    }
	  add_histo (mm_cl_p_in, pba->packets);
	  //if(pba->packets <= SHORT_MM_CL_P)
	  add_histo (mm_cl_p_s_in, pba->packets);
	  add_histo (mm_avg_ipg_in,
		     (pba->sum_delta_t / (pba->n_delta_t - 1)) * 10.);
	  add_histo (mm_avg_jitter_in,
		     (pba->sum_jitter / (pba->n_delta_t - 1)) * 10.);
	  add_histo (mm_n_oos_in, pba->out_order_pkts);
	  add_histo (mm_p_oos_in,
		     ((float) pba->out_order_pkts /
		      (float) pba->packets) * 1000);
	  add_histo (mm_tot_time_in, etime / 1000);
	  //if (etime <= SHORT_MM_TOT_TIME)
	  add_histo (mm_tot_time_s_in, etime);
	  add_histo (mm_p_dup_in, (pba->rexmit_pkts * 1000) / pba->packets);
	}
      else if (ptp_save->internal_src && ptp_save->internal_dst)
	{
	  add_histo (mm_type_loc, ptp_save->con_type);
	  if (ptp_save->con_type & RTP_PROTOCOL)
	    {
	      add_histo (mm_rtp_pt_loc, ptp_save->rtp_pt);
	    }
	  add_histo (mm_cl_b_loc, pba->unique_bytes);
	  //if(pba->unique_bytes <= SHORT_MM_CL_B)
	  add_histo (mm_cl_b_s_loc, pba->unique_bytes);
	  if (pba->packets >= BITRATE_MIN_PKTS)
	    {
	      add_histo (mm_avg_bitrate_loc,
			 (pba->unique_bytes >> 7) / (etime / 1000.0));
	    }
	  add_histo (mm_cl_p_loc, pba->packets);
	  //if(pba->packets <= SHORT_MM_CL_P)
	  add_histo (mm_cl_p_s_loc, pba->packets);
	  add_histo (mm_avg_ipg_loc,
		     (pba->sum_delta_t / (pba->n_delta_t - 1)) * 10.);
	  add_histo (mm_avg_jitter_loc,
		     (pba->sum_jitter / (pba->n_delta_t - 1)) * 10.);
	  add_histo (mm_n_oos_loc, pba->out_order_pkts);
	  add_histo (mm_p_oos_loc,
		     ((float) pba->out_order_pkts /
		      (float) pba->packets) * 1000);
	  add_histo (mm_tot_time_loc, etime / 1000);
	  //if (etime <= SHORT_MM_TOT_TIME)
	  add_histo (mm_tot_time_s_loc, etime);
	  add_histo (mm_p_dup_loc, (pba->rexmit_pkts * 1000) / pba->packets);
	}
      else
	{
	  if (warn_IN_OUT)
	    {
	      fprintf (fp_stderr, 
            "\nWARN: This stream is neither incoming nor outgoing: src - %s;",
		    HostName (ptp_save->addr_pair.a_address));
	      fprintf (fp_stderr, " dst - %s!\n",
		      HostName (ptp_save->addr_pair.b_address));
	      warn_IN_OUT = FALSE;
	    }
#ifdef LOG_UNKNOWN
/* fool the internal and external definition... */
	  add_histo (mm_type_loc, ptp_save->con_type);
	  if (ptp_save->con_type & RTP_PROTOCOL)
	    {
	      add_histo (mm_rtp_pt_loc, ptp_save->rtp_pt);
	    }
	  add_histo (mm_cl_b_loc, pba->unique_bytes);
	  //if(pba->unique_bytes <= SHORT_MM_CL_B)
	  add_histo (mm_cl_b_s_loc, pba->unique_bytes);
	  if (pba->packets >= BITRATE_MIN_PKTS)
	    {
	      add_histo (mm_avg_bitrate_loc,
			 (pba->unique_bytes >> 7) / (etime / 1000.0));
	    }
	  add_histo (mm_cl_p_loc, pba->packets);
	  //if(pba->packets <= SHORT_MM_CL_P)
	  add_histo (mm_cl_p_s_loc, pba->packets);
	  add_histo (mm_avg_ipg_loc,
		     (pba->sum_delta_t / (pba->n_delta_t - 1)) * 10.);
	  add_histo (mm_avg_jitter_loc,
		     (pba->sum_jitter / (pba->n_delta_t - 1)) * 10.);
	  add_histo (mm_n_oos_loc, pba->out_order_pkts);
	  add_histo (mm_p_oos_loc,
		     ((float) pba->out_order_pkts /
		      (float) pba->packets) * 1000);
	  add_histo (mm_tot_time_loc, etime / 1000);
	  //if (etime <= SHORT_MM_TOT_TIME)
	  add_histo (mm_tot_time_s_loc, etime);
	  add_histo (mm_p_dup_loc, (pba->rexmit_pkts * 1000) / pba->packets);
#endif
	}
    }
  /* end topix */

  /*---------------------------------------------------------*/
  /* RRDtools                                                */
    if (complete) {
        fp = LOG_IS_ENABLED(LOG_TCP_COMPLETE) ? fp_logc : NULL;
    } else {
        fp = LOG_IS_ENABLED(LOG_TCP_NOCOMPLETE) ? fp_lognc : NULL;
    }
  if (fp != NULL)
   {
     /* Core Tstat TCP measurements */
     print_tcp_stats_core(fp, ptp_save, pab, pba);

     /* End to End flow measures (RTT and TTL) */
     if ((log_level & TCP_LOG_END_TO_END) && (complete))
       print_tcp_stats_e2e(fp, ptp_save, pab, pba);

     /* P2P specific information */
     if ((log_level & TCP_LOG_P2P) && (complete))
       print_tcp_stats_p2p(fp, ptp_save, pab, pba);

     /* TCP protocol specific information */
     if ((log_level & TCP_LOG_OPTIONS) && (complete))
       print_tcp_stats_options(fp, ptp_save, pab, pba);

     /* TCP Layer7 specific information */
     if ((log_level & TCP_LOG_LAYER7) && (complete))
       print_tcp_stats_layer7(fp, ptp_save, pab, pba);

     /* TCP flow advanced measurements */
     if ((log_level & TCP_LOG_ADVANCED) && (complete))
       print_tcp_stats_advanced(fp, ptp_save, pab, pba, pab_expected, pba_expected);

     wfprintf (fp, "\n");
   }
   
#if defined(VIDEO_DETAILS) || defined(STREAMING_CLASSIFIER)
/*
 We might substitute the call to is_ssl_youtube() to the check of tls_service.
 Currently (15/12/15) they are not the same, since tls_service==TLS_YOUTUBE includes also
 ytimg.com, that is excluded in is_ssl_youtube(). -MMM-
*/
  if (fp_video_logc && LOG_IS_ENABLED(LOG_VIDEO_COMPLETE) 
                    && ( is_video(ptp_save) || is_streaming(ptp_save) || is_ssl_youtube(ptp_save) ) 
                    && complete )
   {
     update_video_log(ptp_save,pab,pba);
   }
#endif
   
   if(!fp_rtp_logc || (((ptp_save->con_type & RTP_PROTOCOL) == 0)
      && ((ptp_save->con_type & ICY_PROTOCOL) == 0)))
      return;
   if(log_version == 1)
      update_conn_log_mm_v1(ptp_save,pab,pba);
   else
      update_conn_log_mm_v2(ptp_save,pab,pba);
}

Bool is_video(tcp_pair *ptp_save)
{
  if (ptp_save->con_type & RTMP_PROTOCOL)
    return TRUE;
    
  if (!(ptp_save->con_type & HTTP_PROTOCOL))
    return FALSE;

  switch (ptp_save->http_data)
   {
     case HTTP_YOUTUBE_VIDEO:
     case HTTP_YOUTUBE_VIDEO204:
     case HTTP_YOUTUBE_204:
     case HTTP_YOUTUBE_SITE:
     case HTTP_YOUTUBE_SITE_DIRECT:
     case HTTP_YOUTUBE_SITE_EMBED:
     case HTTP_VIDEO_CONTENT:
     case HTTP_VIMEO:
     case HTTP_NETFLIX:
     case HTTP_FLASHVIDEO:
       return TRUE;
     default:
       return FALSE;
   }
}

void init_ssl_youtube_patterns()
{
  regcomp(&yt_re[0],"\\.youtube\\.com$",REG_NOSUB);
  regcomp(&yt_re[1],"\\.youtube-nocookie\\.com$",REG_NOSUB);
  regcomp(&yt_re[2],"\\googlevideo\\.com$",REG_NOSUB);
  regcomp(&yt_re[3],"\\gvt1\\.com$",REG_NOSUB);
}

Bool is_ssl_youtube(tcp_pair *ptp_save)
{

  if (!(ptp_save->con_type & SSL_PROTOCOL))
    return FALSE;

  if (ptp_save->ssl_client_subject!=NULL)
   {
     if  ( regexec(&yt_re[0],ptp_save->ssl_client_subject,0,NULL,0)==0 ||
           regexec(&yt_re[1],ptp_save->ssl_client_subject,0,NULL,0)==0 ||
           regexec(&yt_re[2],ptp_save->ssl_client_subject,0,NULL,0)==0 ||
           regexec(&yt_re[3],ptp_save->ssl_client_subject,0,NULL,0)==0 )
       return TRUE;
     else
       return FALSE;
   }
  else
    return FALSE;
}

#if defined(VIDEO_DETAILS) || defined(STREAMING_CLASSIFIER) 
void update_video_log(tcp_pair *ptp_save, tcb *pab, tcb *pba)
{
  if (fp_video_logc != NULL)
   {
    /* Core Tstat TCP measurements */
    print_tcp_stats_core(fp_video_logc, ptp_save, pab, pba);

    /* End to End flow measures (RTT and TTL) */
    if ( video_level & VIDEO_LOG_END_TO_END )
      print_tcp_stats_e2e(fp_video_logc, ptp_save, pab, pba);

    /* Core video information */
    print_video_stats_core(fp_video_logc, ptp_save, pab, pba);

    /* Video additional information */
    if ( video_level & VIDEO_LOG_VIDEOINFO )
      print_video_stats_info(fp_video_logc, ptp_save, pab, pba);

    /* Video YouTube information */
    if ( video_level & VIDEO_LOG_YOUTUBE )
      print_video_stats_youtube(fp_video_logc, ptp_save, pab, pba);

    /* Video advanced rate measurements */
    if ( video_level & VIDEO_LOG_ADVANCED )
      print_video_stats_advanced(fp_video_logc, ptp_save, pab, pba);

    /* TCP protocol specific information */
    if ( video_level & VIDEO_LOG_OPTIONS )
      print_tcp_stats_options(fp_video_logc, ptp_save, pab, pba);

    /* TCP Layer7 specific information */
    if ( video_level & VIDEO_LOG_LAYER7 )
      print_tcp_stats_layer7(fp_video_logc, ptp_save, pab, pba);

    wfprintf (fp_video_logc, "\n");

   }
}
#endif

Bool is_streaming(tcp_pair *ptp_save) {
	if (!(ptp_save->con_type & HTTP_PROTOCOL))
		return FALSE;

	if (ptp_save->streaming.video_content_type != VIDEO_NOT_DEFINED
			|| ptp_save->streaming.video_payload_type != VIDEO_NOT_DEFINED) {
		return TRUE;
	} else
		return FALSE;
}

void
update_conn_log_mm_v1(tcp_pair *ptp_save, tcb *pab, tcb *pba)
{
  double etime;

  etime = elapsed (ptp_save->first_time, ptp_save->last_time);

/* A --> B */
  if (ptp_save->crypto_src==FALSE)
     wfprintf (fp_rtp_logc, "%d %d %s %s",
	   PROTOCOL_TCP,
	   ptp_save->con_type,
	   HostName (ptp_save->addr_pair.a_address),
	   ServiceName (ptp_save->addr_pair.a_port));
  else
     wfprintf (fp_rtp_logc, "%d %d %s %s",
	   PROTOCOL_TCP,
	   ptp_save->con_type,
	   HostNameEncrypted (ptp_save->addr_pair.a_address),
	   ServiceName (ptp_save->addr_pair.a_port));

  if (ptp_save->crypto_dst==FALSE)
     wfprintf (fp_rtp_logc, " %s",
           HostName (ptp_save->addr_pair.b_address));
  else
     wfprintf (fp_rtp_logc, " %s",
           HostNameEncrypted (ptp_save->addr_pair.b_address));
	   
  wfprintf (fp_rtp_logc, " %s %lu %g %g %g %g %d %d %g %u %u %f %f %lu %g %g %g %u %u %g %g %g %g %u %g %g",
	   ServiceName (ptp_save->addr_pair.b_port), 
	   pab->packets,
	   (pab->sum_delta_t / (pab->n_delta_t - 1)),
	   (pab->sum_jitter / (pab->n_delta_t - 1)),
	   pab->max_jitter,
	   pab->min_jitter,
	   ptp_save->internal_src,
	   ptp_save->internal_dst,
	   (double) pab->ttl_tot / (double) pab->packets,
	   pab->ttl_max,
	   pab->ttl_min,
	   (double) ptp_save->first_time.tv_sec + (double) ptp_save->first_time.tv_usec / 1000000.0,
	   etime / 1000.0,	/* [s] */
	   pab->unique_bytes,
	   ((double) (pab->unique_bytes) / (etime / 1000.0)) * 8,
	   elapsed (ptp_save->first_time,
		    pab->u_protocols.f_http) / 1000.0,
	   elapsed (ptp_save->first_time,
		    pab->u_protocols.f_rtsp) / 1000.0,
	   pab->out_order_pkts,
	   pab->rexmit_pkts,
	   elapsed (ptp_save->first_time,
		    pab->u_protocols.f_rtp) / 1000.0,
	   (Average (pab->rtt_sum, pab->rtt_count) / 1000.0),
	   pab->rtt_max / 1000.0,
	   pab->rtt_min / 1000.0,
	   pab->rtt_count,
	   pab->rttvar / 1000.0,
	   elapsed (ptp_save->first_time,
		    pab->u_protocols.f_icy) / 1000.0);

/* B --> A */
  if (ptp_save->crypto_dst==FALSE)
     wfprintf (fp_rtp_logc, " %d %d %s %s",
	   PROTOCOL_TCP,
	   ptp_save->con_type,
	   HostName (ptp_save->addr_pair.b_address),
	   ServiceName (ptp_save->addr_pair.b_port));
  else
     wfprintf (fp_rtp_logc, " %d %d %s %s",
	   PROTOCOL_TCP,
	   ptp_save->con_type,
	   HostNameEncrypted (ptp_save->addr_pair.b_address),
	   ServiceName (ptp_save->addr_pair.b_port));

  if (ptp_save->crypto_src==FALSE)
     wfprintf (fp_rtp_logc, " %s",
           HostName (ptp_save->addr_pair.a_address));
  else
     wfprintf (fp_rtp_logc, " %s",
           HostNameEncrypted (ptp_save->addr_pair.a_address));
	   
  wfprintf (fp_rtp_logc, " %s %lu %g %g %g %g %d %d %g %u %u %f %f %lu %g %g %g %u %u %g %g %g %g %u %g %g",
	   ServiceName (ptp_save->addr_pair.a_port), 
	   pba->packets,
	   (pba->sum_delta_t / (pba->n_delta_t - 1)),
	   (pba->sum_jitter / (pba->n_delta_t - 1)),
	   pba->max_jitter,
	   pba->min_jitter,
	   ptp_save->internal_src,
	   ptp_save->internal_dst,
	   (double) pba->ttl_tot / (double) pba->packets,
	   pba->ttl_max,
	   pba->ttl_min,
	   (double) ptp_save->first_time.tv_sec + (double) ptp_save->first_time.tv_usec / 1000000.0,
	   etime / 1000.0,	/* [s] */
	   pba->unique_bytes,
	   ((double) (pba->unique_bytes) / (etime / 1000.0)) * 8,
	   elapsed (ptp_save->first_time,
		    pba->u_protocols.f_http) / 1000.0,
	   elapsed (ptp_save->first_time,
		    pba->u_protocols.f_rtsp) / 1000.0,
	   pba->out_order_pkts,
	   pba->rexmit_pkts,
	   elapsed (ptp_save->first_time,
		    pba->u_protocols.f_rtp) / 1000.0,
	   (Average (pba->rtt_sum, pba->rtt_count) / 1000.0),
	   pba->rtt_max / 1000.0,
	   pba->rtt_min / 1000.0,
	   pba->rtt_count,
	   pba->rttvar / 1000.0,
	   elapsed (ptp_save->first_time,
		    pba->u_protocols.f_icy) / 1000.0);

  wfprintf (fp_rtp_logc, "\n");
}

void
update_conn_log_mm_v2(tcp_pair *ptp_save, tcb *pab, tcb *pba)
{
  double etime;

  etime = elapsed (ptp_save->first_time, ptp_save->last_time);

/* A --> B */
  wfprintf (fp_rtp_logc, "%d %d",
	   PROTOCOL_TCP,
	   ptp_save->con_type);

  if (ptp_save->crypto_src==FALSE)
     wfprintf (fp_rtp_logc, " %s", HostName (ptp_save->addr_pair.a_address));
  else
     wfprintf (fp_rtp_logc, " %s", HostNameEncrypted (ptp_save->addr_pair.a_address));

  wfprintf (fp_rtp_logc, " %s %d %lu %g %g %g %g %g %u %u %f %f %lu %g 0 0 %u %u 0 0 0 0 0 0 0 %g %g %g %u 0 %g %g %g %g",
	   ServiceName (ptp_save->addr_pair.a_port),
	   ptp_save->internal_src,
	   pab->packets,
	   (pab->sum_delta_t / (pab->n_delta_t - 1)),
	   (pab->sum_jitter / (pab->n_delta_t - 1)),
	   pab->max_jitter,
	   pab->min_jitter,
	   (double) pab->ttl_tot / (double) pab->packets,
	   pab->ttl_max,
	   pab->ttl_min,
	   (double) ptp_save->first_time.tv_sec + (double) ptp_save->first_time.tv_usec / 1000000.0,
	   etime / 1000.0,	/* [s] */
	   pab->unique_bytes,
	   ((double) (pab->unique_bytes) / (etime / 1000.0)) * 8,
	   pab->out_order_pkts,
	   pab->rexmit_pkts,
	   (Average (pab->rtt_sum, pab->rtt_count) / 1000.0),
	   pab->rtt_max / 1000.0,
	   pab->rtt_min / 1000.0,
	   pab->rtt_count,
	   elapsed (ptp_save->first_time,
		    pab->u_protocols.f_http) / 1000.0,
	   elapsed (ptp_save->first_time,
		    pab->u_protocols.f_rtsp) / 1000.0,
	   elapsed (ptp_save->first_time,
		    pab->u_protocols.f_rtp) / 1000.0,
	   elapsed (ptp_save->first_time,
		    pab->u_protocols.f_icy) / 1000.0);

/* B --> A */
  if (ptp_save->crypto_dst==FALSE)
     wfprintf (fp_rtp_logc, " %d %s",
	   ptp_save->con_type,
	   HostName (ptp_save->addr_pair.b_address));
  else
     wfprintf (fp_rtp_logc, " %d %s",
	   ptp_save->con_type,
	   HostNameEncrypted (ptp_save->addr_pair.b_address));

  wfprintf (fp_rtp_logc, " %s %d %lu %g %g %g %g %g %u %u %f %f %lu %g 0 0 %u %u 0 0 0 0 0 0 0 %g %g %g %u 0 %g %g %g %g",
	   ServiceName (ptp_save->addr_pair.b_port),
	   ptp_save->internal_dst,
	   pba->packets,
	   (pba->sum_delta_t / (pba->n_delta_t - 1)),
	   (pba->sum_jitter / (pba->n_delta_t - 1)),
	   pba->max_jitter,
	   pba->min_jitter,
	   (double) pba->ttl_tot / (double) pba->packets,
	   pba->ttl_max,
	   pba->ttl_min,
	   (double) ptp_save->first_time.tv_sec + (double) ptp_save->first_time.tv_usec / 1000000.0,
	   etime / 1000.0,	/* [s] */
	   pba->unique_bytes,
	   ((double) (pba->unique_bytes) / (etime / 1000.0)) * 8,
	   pba->out_order_pkts,
	   pba->rexmit_pkts,
	   (Average (pba->rtt_sum, pba->rtt_count) / 1000.0),
	   pba->rtt_max / 1000.0,
	   pba->rtt_min / 1000.0,
	   pba->rtt_count,
	   elapsed (ptp_save->first_time,
		    pba->u_protocols.f_http) / 1000.0,
	   elapsed (ptp_save->first_time,
		    pba->u_protocols.f_rtsp) / 1000.0,
	   elapsed (ptp_save->first_time,
		    pba->u_protocols.f_rtp) / 1000.0,
	   elapsed (ptp_save->first_time,
		    pba->u_protocols.f_icy) / 1000.0);
  
  wfprintf (fp_rtp_logc, "\n");
}

void
free_tp (tcp_pair * ptp_save)
{
  int i;
  /* free up memory for the flow stats */

  /* for each quad then for each segment in each quad... */
  for (i = 0; i < 4; i++)
    {
      if (ptp_save->c2s.ss->pquad[i] != NULL)
	{
	  freequad (&(ptp_save->c2s.ss->pquad[i]));
	}
    }

  for (i = 0; i < 4; i++)
    {
      if (ptp_save->s2c.ss->pquad[i] != NULL)
	{
	  freequad (&(ptp_save->s2c.ss->pquad[i]));
	}
    }

  /* finally free up the ptp */

  tp_release (ptp_save);
  ptp_save = NULL;

}


void
freequad (quadrant ** ppquad)
{
  segment *pseg;
  segment *pseg_next;

  pseg = (*ppquad)->seglist_head;
  while (pseg && pseg->next)
    {
      pseg_next = pseg->next;
      segment_release (pseg);
      pseg = pseg_next;
    }
  if (pseg)
    segment_release (pseg);

  (*ppquad)->no_of_segments = 0;
  quadrant_release (*ppquad);
  *ppquad = NULL;
}
