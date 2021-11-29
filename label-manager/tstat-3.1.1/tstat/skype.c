/*
 *
 * Copyright (c) 2006
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

/* define SKYPE_DEBUG if you want to see all identified pkts */
//#define SKYPE_DEBUG

FILE *fp_skype_mode;
extern FILE *fp_skype_logc;
extern FILE *fp_bayes_logc;
extern Bool bayes_engine;
extern struct L4_bitrates L4_bitrate;
extern struct L7_bitrates L7_bitrate;
extern struct L7_bitrates L7_udp_bitrate;


static Bool is_skype_pkt (struct ip * pip, struct udphdr * pudp, 
                          void *pdir, struct skype_hdr * pskype, void *plast);


void skype_conn_stats_UDP (void *);
void skype_conn_stats_TCP (void *);

void
skype_init ()
{
  /* nothing to do so far */
}


/******** function used to convert bayes configuration FEATURE string into 
	  a numerical valueto speedup the code execution	**********/

int
skype_feat2code (char *str)
{

#define SKYPE_FEAT_PKTSIZE 0
  if (!strcmp (str, "PKTSIZE"))
    return SKYPE_FEAT_PKTSIZE;

#define SKYPE_FEAT_MAXDELPKTSIZE 1
  if (!strcmp (str, "MAXDELPKTSIZE"))
    return SKYPE_FEAT_MAXDELPKTSIZE;

#define SKYPE_FEAT_AVGIPG 2
  if (!strcmp (str, "AVGIPG"))
    return SKYPE_FEAT_AVGIPG;

#define SKYPE_FEAT_PKTRATE 3
  if (!strcmp (str, "PKTRATE"))
    return SKYPE_FEAT_PKTRATE;

#define SKYPE_FEAT_BITRATE 4
  if (!strcmp (str, "BITRATE"))
    return SKYPE_FEAT_BITRATE;

#define SKYPE_FEAT_AVGPKT 5
  if (!strcmp (str, "AVGPKT"))
    return SKYPE_FEAT_AVGPKT;

#define SKYPE_FEAT_UNKNOWN -1
  return SKYPE_FEAT_UNKNOWN;
}






/******** function used to find the skype packet starting point **********/


void
update_randomness (random_stat * random, void *hdr, skype_hdr * pskype,
		   void *plast, int tproto, int payload_len)
{
  int i, j;
  int random_bits;
  int valid_blocks;
  u_int32_t *ppayload = NULL;

/* 
we use the chi square test, forming nibbles of N_RANDOM_BIT bits
and checkg the uniformity of the distribution.
for each random bits, update the frequency */

  if (tproto == PROTOCOL_UDP)
    {
      udphdr *pudp;
      pudp = (udphdr *) hdr;

      ppayload = ((u_int32_t *) pudp) + 2 /* 32bit*2 for udp header */ ;
    }
  else if (tproto == PROTOCOL_TCP)
    {
      tcphdr *ptcp;
      ptcp = (tcphdr *) hdr;

      ppayload = ((u_int32_t *) ptcp) + (u_int32_t) (ptcp->th_off);
    }
  valid_blocks = (payload_len > ((int) plast - (int) ppayload + 1)
		  ? ((int) plast - (int) ppayload + 1)
		  : payload_len) * 8 / N_RANDOM_BIT;

  i = 0;
  do
    {
      for (j = 0; j < (sizeof (u_int32_t) * 8 / N_RANDOM_BIT) && (i < N_BLOCK); j++)	/* number of shift in the word */
	{
	  if (i <= valid_blocks)
	    {
	      random_bits = (*ppayload >> N_RANDOM_BIT * j) & RND_MASK;
	    }
	  else			/* real data, no padding */
	    {
	      random_bits = 0;
	    }
	  random->rnd_bit_histo[random_bits][i]++;
	  i++;
	}
      ppayload++;		/* go to the next word */
    }
  while (i < N_BLOCK);
  random->rnd_n_samples++;	/* Number of valid packets */
}


void
update_delta_t (deltaT_stat * stat)
{
  if (stat->last_time.tv_usec == 0 && stat->last_time.tv_usec == 0)
    stat->last_time = current_time;
  else
    {
      stat->sum += elapsed (stat->last_time, current_time) / 1000;
      stat->n++;
      stat->last_time = current_time;
    }
}

double
get_average_delta_t (deltaT_stat * stat)
{
  if (stat->n)
    return (stat->sum / stat->n);
  else
    return -1.0;
}


struct skype_hdr *
getSkype (void *pproto, int tproto, void *pdir, void *plast)
{

  void *theheader;

  if (tproto == PROTOCOL_UDP) {
      theheader = ((char *) pproto + 8);
      if ((u_long) theheader + (sizeof (struct skype_hdr)) - 1 > (u_long) plast)
        {
          /* part of the header is missing */
          return (NULL);
        }
  }
  else {
      theheader = (char *)pproto + 4 * ((tcphdr *) pproto)->th_off;
  }
  return (struct skype_hdr *) theheader;
}

void
print_skype (struct ip *pip, void *pproto, void *plast)
{
  unsigned char *theheader = ((unsigned char *) pproto + 8);
  int i;

  fprintf (fp_stdout, "%s\t", inet_ntoa (pip->ip_src));
  fprintf (fp_stdout, "%s\t", inet_ntoa (pip->ip_dst));
  fprintf (fp_stdout, "%3d ", (ntohs ((pip)->ip_len) - 28));
  for (i = 0; i < 11; i++, theheader++)
    {
      /* we have headers of this packet */
      if (theheader <= (unsigned char *) plast)
	fprintf (fp_stdout, "%2X ", *theheader);
      else
	fprintf (fp_stdout, "xx ");
    }

  theheader = ((unsigned char *) pproto + 8);
  for (i = 0; i < 11; i++, theheader++)
    {
      /* we have headers of this packet */
      if (theheader <= (unsigned char *) plast)
	fprintf (fp_stdout, "%3d ", *theheader);
      else
	fprintf (fp_stdout, "xxx ");
    }
  fprintf (fp_stdout, "\n");
}



void
skype_flow_stat (struct ip *pip, void *pproto, int tproto, void *pdir,
		 int dir, void *hdr, void *plast)
{
  skype_hdr *pskype = (struct skype_hdr *) hdr;
  int type;
  int payload_len;
  tcphdr *ptcp;
  ptcp = (tcphdr *) hdr;
  ucb *thisdir, *otherdir;

  thisdir = (ucb *)pdir;
  otherdir = (dir == C2S) ? &(thisdir->pup->s2c) : &(thisdir->pup->c2s);

  type = (tproto == PROTOCOL_UDP) ?
      is_skype_pkt (pip, pproto, pdir, pskype, plast) : NOT_SKYPE;


  if (tproto == PROTOCOL_UDP)
  {
      payload_len = ntohs (((struct udphdr *) pproto)->uh_ulen) - 8;
      ((ucb *) pdir)->skype->pkt_type_num[type]++;
      update_delta_t (&((ucb *) pdir)->skype->stat[type]);
      if (payload_len >= N_BLOCK*N_RANDOM_BIT/8)	/* skip pure ack and signalling */
         update_randomness (&((ucb *) pdir)->skype->random, pproto, pskype, plast,
              tproto, payload_len);
#ifdef SKYPE_EARLY_CLASSIF
      // try to identify skype comunication after few packets
      if (elapsed(thisdir->first_pkt_time, current_time) > SKYPE_EARLY_CLASSIF_WINDOW &&
          thisdir->packets > 200 &&
          !thisdir->skype->early_classification)
          {
              thisdir->skype->early_classification = TRUE;
              otherdir->skype->early_classification = TRUE;
              skype_conn_stats_UDP (((ucb *) pdir)->pup);
          }
#endif
    }
  else
    {				/* tproto == PROTOCOL_TCP */


      payload_len =
	getpayloadlength (pip, plast) - ((tcphdr *) pproto)->th_off * 4;

      if (payload_len >= N_BLOCK*N_RANDOM_BIT/8)	/* skip pure ack and signalling */
	update_randomness (&((tcb *) pdir)->skype->random, pproto, pskype,
			   plast, tproto, payload_len);

    }

//===================================================================================
//  bayes classification
#define SKYPE_WINDOW_SIZE 30

  if (bayes_engine)
    {
      struct bayes_classifier *bc_pktsize = (tproto == PROTOCOL_UDP) ?
	((ucb *) pdir)->bc_pktsize : ((tcb *) pdir)->bc_pktsize;

      struct bayes_classifier *bc_avgipg = (tproto == PROTOCOL_UDP) ?
	((ucb *) pdir)->bc_avgipg : ((tcb *) pdir)->bc_avgipg;

      struct skype_stat *sk = (tproto == PROTOCOL_UDP) ?
	((ucb *) pdir)->skype : ((tcb *) pdir)->skype;

      int pktsize, avgipg;
      Bool full_window = FALSE;

      // 
      // non windowed 
      // 
      // 
      // or windowed ?                                                                                
      // 


      switch (tproto)
	{
	case PROTOCOL_UDP:
	  pktsize = UDP_PAYLOAD_LEN (pip,plast);
      if (!sk->first_pkt_done) {
          sk->win.start = current_time;
      }
      break;

	case PROTOCOL_TCP:
	  pktsize =
	    getpayloadlength (pip, plast) - (4 * ((tcphdr *) pproto)->th_off);
	  /* avoid to consider TCP ACK */
	  if (pktsize == 0)
	    return;
	  if (!sk->first_pkt_done)
	    {
	      sk->win.start = current_time;
	    }
	  break;
	default:
	  fprintf (fp_stderr, "skype_flow_stat: fatal - you should never stop here!!\n");
      fprintf (fp_stderr, "%s\n", strerror(errno));
	  exit (1);
	}

      // update the number of pure video packets
      // CHECK DARIO
      if (((pktsize >= 400 && pktsize <= 490)
	   || (pktsize >= 800 && pktsize <= 980)) && tproto == PROTOCOL_UDP)
	{
	  sk->video_pkts++;
	  full_window = FALSE;
	}
      else
	{
	  sk->audiovideo_pkts++;
	  full_window = !(sk->audiovideo_pkts % SKYPE_WINDOW_SIZE);
	}

      // update window size      
      sk->win.bytes += pktsize;
      sk->win.pktsize_max =
	sk->win.pktsize_max > pktsize ? sk->win.pktsize_max : pktsize;
      sk->win.pktsize_min =
	sk->win.pktsize_min < pktsize ? sk->win.pktsize_min : pktsize;

      if (full_window && sk->first_pkt_done)
	{
	  avgipg =
	    (int) (elapsed (sk->win.start, current_time) / 1000.0 /
		   SKYPE_WINDOW_SIZE);

	  // reset the window
	  sk->win.pktsize_max = -1;
	  sk->win.pktsize_min = 65535;
	  sk->win.start = current_time;
	  sk->win.bytes = 0;

	  bayes_sample (bc_avgipg, avgipg);
	}

      // rougly filter video packets for UDP protocol only
      if ((pktsize < 400 && tproto == PROTOCOL_UDP) || tproto == PROTOCOL_TCP)
	bayes_sample (bc_pktsize, pktsize);

      sk->first_pkt_done = TRUE;
    }

// bayes END
//===================================================================================



#ifdef SKYPE_DEBUG
  switch (type)
    {
    case SKYPE_NAK:
      fprintf (fp_stdout, "%4llu NAK\t", ((ucb *) pdir)->packets);
      print_skype (pip, pproto, plast);
      break;

    case SKYPE_FUN2:
      fprintf (fp_stdout, "%4llu FUN2\t", ((ucb *) pdir)->packets);
      print_skype (pip, pproto, plast);
      break;

    case SKYPE_FUN3:
      fprintf (fp_stdout, "%4llu FUN3\t", ((ucb *) pdir)->packets);
      print_skype (pip, pproto, plast);
      break;

    case SKYPE_E2E_DATA:
      fprintf (fp_stdout, "%4llu E2E_DATA\t", ((ucb *) pdir)->packets);
      print_skype (pip, pproto, plast);
      break;

    case SKYPE_OUT_DATA:
      fprintf (fp_stdout, "%4llu OUT_DATA\t", ((ucb *) pdir)->packets);
      print_skype (pip, pproto, plast);

      break;

    case NOT_SKYPE:
      fprintf (fp_stdout, "%4llu UNKNOWN\t", ((ucb *) pdir)->packets);
      print_skype (pip, pproto, plast);
    default:
      ;

    }
#endif
}


int
is_skypeOUT_pkt (struct ip *pip, struct udphdr *pudp, void *pdir,
		 struct skype_hdr *pskype, void *plast)
{

  /* the length was 29bytes */
  /* this might be an OUT DATA PKT */
  /* should see one every 20ms */

  void *theheader = ((char *) pudp + 8);	/* skip udp header */
  ucb *thisdir = (ucb *) pdir;

  if ((thisdir->skype->OUT_data_block == 0) &&
      ((u_long) theheader + (sizeof (struct skype_OUT)) - 1 <=
       (u_long) plast))
    {
      /* we have all the identifier block, copy it for future use */
      thisdir->skype->OUT_data_block = ((struct skype_OUT *) theheader)->block;
      return NOT_SKYPE;
    }

  if (thisdir->skype->OUT_data_block == ((struct skype_OUT *)
					theheader)->block)
    {
      return SKYPE_OUT_DATA;
    }
  else
    {
      /* we have a new the identifier block, copy it for future use */
      thisdir->skype->OUT_data_block = ((struct skype_OUT *) theheader)->block;
      return NOT_SKYPE;
    }



  return NOT_SKYPE;
}



static Bool is_skype_pkt (struct ip * pip, struct udphdr * pudp, void *pdir,
	                      struct skype_hdr * pskype, void *plast)
{


  if (is_skypeOUT_pkt (pip, pudp, pdir, pskype, plast) == SKYPE_OUT_DATA)
    return SKYPE_OUT_DATA;



  if (((pskype->func & 0x8f) == 0x07) &&	/* is function 7  */
      (UDP_PAYLOAD_LEN (pip,plast) == 11))	/* the length was 11bytes */
    {
      /* this is a NAK, used as quick STUN like hack to find my real IP
         in case a NAT is going to be traversed */

      return SKYPE_NAK;
    }

  if ((pskype->func & 0x8f) == 0x02)	/* is function 2  */
    {
      /* this is a FUN2 msg. It is sent several time, with different length
         is usually the first packet, whose len is 28 */

      return SKYPE_FUN2;
    }

  if ((pskype->func & 0x8f) == 0x03)	/* is function 3  */
    {
      /* this is a FUN3 msg. It is sent several time, usually after receiving
         a NAK packet */

      return SKYPE_FUN3;
    }


  if ((pskype->func & 0x8f) == 0x0d)	/* is function 13  */
    {
      if (UDP_PAYLOAD_LEN (pip,plast) > 4)
	{
	  /* this might be a voice sample */
	  /* should see one every DeltaT ms */
	  return SKYPE_E2E_DATA;
	}
      else
	{
	  /* this might be a data keep alive */
	  return SKYPE_FUN3;
	}

    }

  return NOT_SKYPE;
}



/******** function to update the skype stats *********/

/* this will be called by the plugin */
void
make_skype_conn_stats (void *thisflow, int tproto)
{
  /* Statistichs about SKYPE flows */

  switch (tproto)
    {
       case PROTOCOL_UDP:
         skype_conn_stats_UDP (thisflow);
        break;
       case PROTOCOL_TCP:
         skype_conn_stats_TCP (thisflow);
        break;
       default:
        fprintf (fp_stderr, "skype_conn_stats: fatal - you should never stop here!!\n");
        fprintf (fp_stderr, "%s\n", strerror(errno));
        exit (1);
    }
}

void
skype_conn_stats_UDP (void *thisdir)
{
  struct skype_stat *pskype;
  int i,j;
  int tot_skype = 0;
  struct ucb *thisUdir;
  int directions[2],dir;
  Bool isSkype;
  
  directions[0]=C2S;
  directions[1]=S2C;
  
  isSkype = FALSE;
  
  for (j=0;j<2;j++)
   {
     dir = directions[j];

     if (dir == C2S)
 	  {
	   thisUdir = &(((udp_pair *) thisdir)->c2s);
 	   pskype = thisUdir->skype;
 	  }
       else
	 {
	   thisUdir = &(((udp_pair *) thisdir)->s2c);
	   pskype = thisUdir->skype;
	 }

  /* first check if there is at least a skype pkt */

  tot_skype = 0;
  for (i = 1; i < TOTAL_SKYPE_KNOWN_TYPE; i++)
    tot_skype += pskype->pkt_type_num[i];

  // Skip only very short flows
  //  if ( tot_skype  < MIN_SKYPE_PKTS)

   if (thisUdir->packets>= MIN_SKYPE_PKTS)
    {
      switch (thisUdir->type)
      {
  	  case RTP:
  	  case RTCP:
  	  case P2P_DC:
  	  case P2P_GNU:
  	  case P2P_KAZAA:
  	  case P2P_BT:
  	  case P2P_PPLIVE:
  	  case P2P_SOPCAST:
  	  case P2P_TVANTS:
  	  case P2P_EDK:  /* Skype could be matched by generic Emule/Kad rules */
//  	  case P2P_KAD:
  	  case P2P_KADU:
  	  case P2P_OKAD:
	  case P2P_PPSTREAM:
          case TEREDO:
      case UDP_SIP:
  	      break;

  	  case SKYPE_E2E:
  	  case SKYPE_OUT:
  	  case SKYPE_SIG:
  	      if (!thisUdir->skype->early_classification) {
  		  fprintf (fp_stdout, "skype.c: No idea how I get there !\n");
  		  exit (1);
  	      }
  	      break;

  	  case FIRST_RTP:
  	  case FIRST_RTCP:
  	  case UDP_UNKNOWN:
  	  default: 
  	      if ((pskype->pkt_type_num[SKYPE_E2E_DATA] > MIN_SKYPE_E2E_NUM) &&
  		      ((double) pskype->pkt_type_num[SKYPE_E2E_DATA] * 100.0 /
  		       (double) thisUdir->packets > MIN_SKYPE_E2E_PERC))
  	      {
  		  thisUdir->type = SKYPE_E2E;
  		  isSkype = TRUE;
  	      }
  	      else if ((pskype->pkt_type_num[SKYPE_OUT_DATA] > MIN_SKYPE_OUT_NUM)
  		      && ((double) pskype->pkt_type_num[SKYPE_OUT_DATA] * 100.0 /
  			  (double) thisUdir->packets > MIN_SKYPE_OUT_PERC))
  	      {
  		  thisUdir->type = SKYPE_OUT;
  		  isSkype = TRUE;
  		  /*	if (dir == S2C) {
  			if (strcmp(ServiceName(pup->addr_pair.a_port),"12340")==0)  {

  			thisUdir->type = SKYPE_OUT;
  			}
  			}
  			else 
  			if (strcmp(ServiceName(pup->addr_pair.b_port),"12340")==0)  {

  			thisUdir->type = SKYPE_OUT;
  			} */
  	      }
  	      else if (thisUdir->packets
  		      && (tot_skype * 100 / thisUdir->packets > MIN_SKYPE_PERC))
  	      {
  		  thisUdir->type = SKYPE_SIG;
  		  isSkype = TRUE;
  	      }
  	      else
  	      {
  		  if (thisUdir->type==FIRST_RTP || thisUdir->type==FIRST_RTCP)
  		  {
  		      thisUdir->type = UDP_UNKNOWN;
  		  }
  	      }

  	      break;
      } /* switch*/
    }
   } /* for */

   if (isSkype)
     print_skype_conn_stats_UDP (thisUdir,dir);    /* thisUdir */
}

void
skype_conn_stats_TCP (void *thisdir)
{
  struct skype_stat *pskype;
  int i,j;
  int tot_skype = 0;
  struct tcb *thisTdir;
  int directions[2],dir;
  Bool isSkype;
  
  directions[0]=C2S;
  directions[1]=S2C;
  
  isSkype = FALSE;
  
  for (j=0;j<2;j++)
   {
     dir = directions[j];

      if (dir == C2S)
	{
	  thisTdir = &(((tcp_pair *) thisdir)->c2s);
	  pskype = thisTdir->skype;
	}
      else
	{
	  thisTdir = &(((tcp_pair *) thisdir)->s2c);
	  pskype = thisTdir->skype;
	}

  /* first check if there is at least a skype pkt */

  tot_skype = 0;
  for (i = 1; i < TOTAL_SKYPE_KNOWN_TYPE; i++)
    tot_skype += pskype->pkt_type_num[i];

  // Skip only very short flows
  //  if ( tot_skype  < MIN_SKYPE_PKTS)

  if ((thisTdir->skype)->random.rnd_n_samples >= MIN_SKYPE_PKTS_TCP)
    isSkype = TRUE;
   }

   if (isSkype)
     print_skype_conn_stats_TCP (thisTdir, dir);       /* thisTdir */
}

void
print_skype_conn_stats_UDP (void *thisdir, int olddir)
{
  int i, j, dir; 
  int C2S_CSFT = -1;
  int S2C_CSFT = -1;
  int C2S_is_Skype = 0;
  int S2C_is_Skype = 0;
  struct ucb *thisUdir;
  struct skype_stat *pskype;
  struct sudp_pair *pup;
  double chi_square[N_BLOCK];
  double expected_num;
  Bool video_present;
  double c2s_minCHI_E2O_HDR, c2s_maxCHI_E2E_HDR,
         c2s_minCHI_E2E_HDR, c2s_maxCHI_PAY;
  double s2c_minCHI_E2O_HDR, s2c_maxCHI_E2E_HDR,
         s2c_minCHI_E2E_HDR, s2c_maxCHI_PAY;
  Bool b_pktsize_c2s, b_avgipg_c2s, b_pktsize_s2c, b_avgipg_s2c;

  thisUdir = (ucb *) thisdir;
  pup = thisUdir->pup;
  pskype = thisUdir->skype;
  
  if (bayes_engine)
    {
      if (pup->s2c.bc_pktsize->mean_max_belief == 0)
	{
	  pup->s2c.bc_pktsize->mean_max_belief = MIN_TH_VALID_PERC;
	  pup->s2c.bc_pktsize->argmax = -1;
	}
      if (pup->c2s.bc_pktsize->mean_max_belief == 0)
	{
	  pup->c2s.bc_pktsize->mean_max_belief = MIN_TH_VALID_PERC;
	  pup->c2s.bc_pktsize->argmax = -1;
	}

      if (pup->s2c.bc_avgipg->mean_max_belief == 0)
	{
	  pup->s2c.bc_avgipg->mean_max_belief = MIN_TH_VALID_PERC;
	  pup->s2c.bc_avgipg->argmax = -1;
	}
      if (pup->c2s.bc_avgipg->mean_max_belief == 0)
	{
	  pup->c2s.bc_avgipg->mean_max_belief = MIN_TH_VALID_PERC;
	  pup->c2s.bc_avgipg->argmax = -1;
	}
    }

  // was video present? yes if video only pkts are larger than 10%

  dir = C2S;
  thisUdir = &(pup->c2s);
  pskype = thisUdir->skype;

  b_pktsize_c2s = 0;
  b_avgipg_c2s = 0;
  
  if (bayes_engine)
    {

      b_pktsize_c2s = (pup->c2s.bc_pktsize->mean_max_belief >=
		   pup->c2s.bc_pktsize->settings->avg_threshold);
      b_avgipg_c2s = (pup->c2s.bc_avgipg->mean_max_belief >=
		  pup->c2s.bc_avgipg->settings->avg_threshold);
    }

  /* evaluate the chi_square as
     (x_i - E_i)^2
     sum -----------
     E_i
   */

  /* start with the skype hdr of e2e messages */
  expected_num = (double) thisUdir->packets * E2E_EXPECTED_PROB;

  for (j = 0; j < N_BLOCK; j++)
    {
      chi_square[j] = 0.0;
      for (i = 0; i < N_RANDOM_BIT_VALUES; i++)
	{
	  chi_square[j] +=
	    (pskype->random.rnd_bit_histo[i][j] - expected_num) *
	    (pskype->random.rnd_bit_histo[i][j] - expected_num);
	}
      chi_square[j] /= expected_num;
    }
  c2s_maxCHI_E2E_HDR = chi_square[0];
  for (i = 1; i < N_BLOCK / 2; i++)
    {
      if (i == 4 || i == 5)	/* 5 e 6 CHI deterministico */
	i = 6;			/* salta non calcola il max */
      if (c2s_maxCHI_E2E_HDR < chi_square[i])
	c2s_maxCHI_E2E_HDR = chi_square[i];
    }
  c2s_minCHI_E2E_HDR = chi_square[4];	/* 5 e 6 CHI deterministico */
  if (c2s_minCHI_E2E_HDR > chi_square[5])	/* calcola il min tra i due */
    c2s_minCHI_E2E_HDR = chi_square[5];

  c2s_maxCHI_PAY = chi_square[8];
  for (i = 9; i < N_BLOCK; i++)
    if (c2s_maxCHI_PAY < chi_square[i])
      c2s_maxCHI_PAY = chi_square[i];

  c2s_minCHI_E2O_HDR = chi_square[0];
  for (i = 1; i < N_BLOCK / 2; i++)
    if (c2s_minCHI_E2O_HDR > chi_square[i])
      c2s_minCHI_E2O_HDR = chi_square[i];

  if (c2s_minCHI_E2O_HDR >= 150 && c2s_maxCHI_PAY < 150)
    C2S_CSFT = L7_FLOW_SKYPE_E2O;	/* SKYPE E2O */
  else
    {
      if (c2s_maxCHI_E2E_HDR < 150 && chi_square[4] >= 150
	  && chi_square[5] >= 100 && c2s_maxCHI_PAY < 150)
	C2S_CSFT = L7_FLOW_SKYPE_E2E;	/* SKYPE E2E */
      else
	C2S_CSFT = NOT_SKYPE;
    }

  if ((thisUdir->type == SKYPE_E2E || thisUdir->type == SKYPE_OUT) &&
      b_avgipg_c2s && b_pktsize_c2s && C2S_CSFT != NOT_SKYPE)
    C2S_is_Skype = 1;
 

/* add this flow to the skype one */
  if (b_avgipg_c2s && b_pktsize_c2s && C2S_CSFT != NOT_SKYPE)
    {
      pskype->skype_type = C2S_CSFT;
      switch ((in_out_loc (pup->internal_src, pup->internal_dst, dir)))
	{
	case OUT_FLOW:
	  switch (C2S_CSFT)
	    {
	    case L7_FLOW_SKYPE_E2E:
	      add_histo (L7_UDP_num_out, L7_FLOW_SKYPE_E2E);
	      L7_udp_bitrate.out[L7_FLOW_SKYPE_E2E] += thisUdir->data_bytes;
	      if ( (dir==C2S && pup->cloud_src) || (dir==S2C && pup->cloud_dst))
	        {
	          add_histo (L7_UDP_num_c_out, L7_FLOW_SKYPE_E2E);
	          L7_udp_bitrate.c_out[L7_FLOW_SKYPE_E2E] += thisUdir->data_bytes;
	        }
	      else
	        {
	          add_histo (L7_UDP_num_nc_out, L7_FLOW_SKYPE_E2E);
	          L7_udp_bitrate.nc_out[L7_FLOW_SKYPE_E2E] += thisUdir->data_bytes;
	        }
	      break;
	    case L7_FLOW_SKYPE_E2O:
	      add_histo (L7_UDP_num_out, L7_FLOW_SKYPE_E2O);
	      L7_udp_bitrate.out[L7_FLOW_SKYPE_E2O] += thisUdir->data_bytes;
	      if ( (dir==C2S && pup->cloud_src) || (dir==S2C && pup->cloud_dst))
	        {
	          add_histo (L7_UDP_num_c_out, L7_FLOW_SKYPE_E2O);
	          L7_udp_bitrate.c_out[L7_FLOW_SKYPE_E2O] += thisUdir->data_bytes;
	        }
	      else
	        {
	          add_histo (L7_UDP_num_nc_out, L7_FLOW_SKYPE_E2O);
	          L7_udp_bitrate.nc_out[L7_FLOW_SKYPE_E2O] += thisUdir->data_bytes;
	        }
	      break;
	    }
	  break;

	case IN_FLOW:
	  switch (C2S_CSFT)
	    {
	    case L7_FLOW_SKYPE_E2E:
	      add_histo (L7_UDP_num_in, L7_FLOW_SKYPE_E2E);
	      L7_udp_bitrate.in[L7_FLOW_SKYPE_E2E] += thisUdir->data_bytes;
	      if ( (dir==C2S && pup->cloud_src) || (dir==S2C && pup->cloud_dst))
	        {
	          add_histo (L7_UDP_num_c_in, L7_FLOW_SKYPE_E2E);
	          L7_udp_bitrate.c_in[L7_FLOW_SKYPE_E2E] += thisUdir->data_bytes;
	        }
	      else
	        {
	          add_histo (L7_UDP_num_nc_in, L7_FLOW_SKYPE_E2E);
	          L7_udp_bitrate.nc_in[L7_FLOW_SKYPE_E2E] += thisUdir->data_bytes;
	        }
	      break;
	    case L7_FLOW_SKYPE_E2O:
	      add_histo (L7_UDP_num_in, L7_FLOW_SKYPE_E2O);
	      L7_udp_bitrate.in[L7_FLOW_SKYPE_E2O] += thisUdir->data_bytes;
	      if ( (dir==C2S && pup->cloud_src) || (dir==S2C && pup->cloud_dst))
	        {
	          add_histo (L7_UDP_num_c_in, L7_FLOW_SKYPE_E2O);
	          L7_udp_bitrate.c_in[L7_FLOW_SKYPE_E2O] += thisUdir->data_bytes;
	        }
	      else
	        {
	          add_histo (L7_UDP_num_nc_in, L7_FLOW_SKYPE_E2O);
	          L7_udp_bitrate.nc_in[L7_FLOW_SKYPE_E2O] += thisUdir->data_bytes;
	        }
	      break;
	    }
	  break;
	case LOC_FLOW:
	  switch (C2S_CSFT)
	    {
	    case L7_FLOW_SKYPE_E2E:
	      add_histo (L7_UDP_num_loc, L7_FLOW_SKYPE_E2E);
	      L7_udp_bitrate.loc[L7_FLOW_SKYPE_E2E] += thisUdir->data_bytes;
	      break;
	    case L7_FLOW_SKYPE_E2O:
	      add_histo (L7_UDP_num_loc, L7_FLOW_SKYPE_E2O);
	      L7_udp_bitrate.loc[L7_FLOW_SKYPE_E2O] += thisUdir->data_bytes;
	      break;
	    }
	  break;
	}
    }

/*S2C*/

  dir = S2C;
  thisUdir = &(pup->s2c);
  pskype = thisUdir->skype;

  b_pktsize_s2c = 0;
  b_avgipg_s2c = 0;

  if (bayes_engine)
    {
      b_pktsize_s2c = (pup->s2c.bc_pktsize->mean_max_belief >=
		   pup->s2c.bc_pktsize->settings->avg_threshold);
      b_avgipg_s2c = (pup->s2c.bc_avgipg->mean_max_belief >=
		  pup->s2c.bc_avgipg->settings->avg_threshold);
    }

  /* evaluate the chi_square as
     (x_i - E_i)^2
     sum -----------
     E_i
   */

  /* start with the skype hdr of e2e messages */
  expected_num = (double) thisUdir->packets * E2E_EXPECTED_PROB;

  for (j = 0; j < N_BLOCK; j++)
    {
      chi_square[j] = 0.0;
      for (i = 0; i < N_RANDOM_BIT_VALUES; i++)
	{
	  chi_square[j] +=
	    (pskype->random.rnd_bit_histo[i][j] - expected_num) *
	    (pskype->random.rnd_bit_histo[i][j] - expected_num);
	}
      chi_square[j] /= expected_num;
    }
  s2c_maxCHI_E2E_HDR = chi_square[0];
  for (i = 1; i < N_BLOCK / 2; i++)
    {
      if (i == 4 || i == 5)	/* 5 e 6 CHI deterministico */
	i = 6;			/* salta non calcola il max */
      if (s2c_maxCHI_E2E_HDR < chi_square[i])
	s2c_maxCHI_E2E_HDR = chi_square[i];
    }
  s2c_minCHI_E2E_HDR = chi_square[4];	/* 5 e 6 CHI deterministico */
  if (s2c_minCHI_E2E_HDR > chi_square[5])	/* calcola il min tra i due */
    s2c_minCHI_E2E_HDR = chi_square[5];

  s2c_maxCHI_PAY = chi_square[8];
  for (i = 9; i < N_BLOCK; i++)
    if (s2c_maxCHI_PAY < chi_square[i])
      s2c_maxCHI_PAY = chi_square[i];

  s2c_minCHI_E2O_HDR = chi_square[0];
  for (i = 1; i < N_BLOCK / 2; i++)
    if (s2c_minCHI_E2O_HDR > chi_square[i])
      s2c_minCHI_E2O_HDR = chi_square[i];

  if (s2c_minCHI_E2O_HDR >= 150 && s2c_maxCHI_PAY < 150)
    S2C_CSFT = L7_FLOW_SKYPE_E2O;	/* SKYPE E2O */
  else
    {
      if (s2c_maxCHI_E2E_HDR < 150 && chi_square[4] >= 150
	  && chi_square[5] >= 100 && s2c_maxCHI_PAY < 150)
	S2C_CSFT = L7_FLOW_SKYPE_E2E;	/* SKYPE E2E */
      else
	S2C_CSFT = NOT_SKYPE;
    }

  if ((thisUdir->type == SKYPE_E2E || thisUdir->type == SKYPE_OUT) &&
      b_avgipg_s2c && b_pktsize_s2c && S2C_CSFT != NOT_SKYPE)
    S2C_is_Skype = 1;

/* add this flow to the skype one */
  if (b_avgipg_s2c && b_pktsize_s2c && S2C_CSFT != NOT_SKYPE)
    {
      pskype->skype_type = S2C_CSFT;
      switch ((in_out_loc (pup->internal_src, pup->internal_dst, dir)))
	{
	case OUT_FLOW:
	  switch (S2C_CSFT)
	    {
	    case L7_FLOW_SKYPE_E2E:
	      add_histo (L7_UDP_num_out, L7_FLOW_SKYPE_E2E);
	      L7_udp_bitrate.out[L7_FLOW_SKYPE_E2E] += thisUdir->data_bytes;
	      if ( (dir==C2S && pup->cloud_src) || (dir==S2C && pup->cloud_dst))
	        {
	          add_histo (L7_UDP_num_c_out, L7_FLOW_SKYPE_E2E);
	          L7_udp_bitrate.c_out[L7_FLOW_SKYPE_E2E] += thisUdir->data_bytes;
	        }
	      else
	        {
	          add_histo (L7_UDP_num_nc_out, L7_FLOW_SKYPE_E2E);
	          L7_udp_bitrate.nc_out[L7_FLOW_SKYPE_E2E] += thisUdir->data_bytes;
	        }
	      break;
	    case L7_FLOW_SKYPE_E2O:
	      add_histo (L7_UDP_num_out, L7_FLOW_SKYPE_E2O);
	      L7_udp_bitrate.out[L7_FLOW_SKYPE_E2O] += thisUdir->data_bytes;
	      if ( (dir==C2S && pup->cloud_src) || (dir==S2C && pup->cloud_dst))
	        {
	          add_histo (L7_UDP_num_c_out, L7_FLOW_SKYPE_E2O);
	          L7_udp_bitrate.c_out[L7_FLOW_SKYPE_E2O] += thisUdir->data_bytes;
	        }
	      else
	        {
	          add_histo (L7_UDP_num_nc_out, L7_FLOW_SKYPE_E2O);
	          L7_udp_bitrate.nc_out[L7_FLOW_SKYPE_E2O] += thisUdir->data_bytes;
	        }
	      break;
	    }
	  break;

	case IN_FLOW:
	  switch (S2C_CSFT)
	    {
	    case L7_FLOW_SKYPE_E2E:
	      add_histo (L7_UDP_num_in, L7_FLOW_SKYPE_E2E);
	      L7_udp_bitrate.in[L7_FLOW_SKYPE_E2E] += thisUdir->data_bytes;
	      if ( (dir==C2S && pup->cloud_src) || (dir==S2C && pup->cloud_dst))
	        {
	          add_histo (L7_UDP_num_c_in, L7_FLOW_SKYPE_E2E);
	          L7_udp_bitrate.c_in[L7_FLOW_SKYPE_E2E] += thisUdir->data_bytes;
	        }
	      else
	        {
	          add_histo (L7_UDP_num_nc_in, L7_FLOW_SKYPE_E2E);
	          L7_udp_bitrate.nc_in[L7_FLOW_SKYPE_E2E] += thisUdir->data_bytes;
	        }
	      break;
	    case L7_FLOW_SKYPE_E2O:
	      add_histo (L7_UDP_num_in, L7_FLOW_SKYPE_E2O);
	      L7_udp_bitrate.in[L7_FLOW_SKYPE_E2O] += thisUdir->data_bytes;
	      if ( (dir==C2S && pup->cloud_src) || (dir==S2C && pup->cloud_dst))
	        {
	          add_histo (L7_UDP_num_c_in, L7_FLOW_SKYPE_E2O);
	          L7_udp_bitrate.c_in[L7_FLOW_SKYPE_E2O] += thisUdir->data_bytes;
	        }
	      else
	        {
	          add_histo (L7_UDP_num_nc_in, L7_FLOW_SKYPE_E2O);
	          L7_udp_bitrate.nc_in[L7_FLOW_SKYPE_E2O] += thisUdir->data_bytes;
	        }
	      break;
	    }
	  break;
	case LOC_FLOW:
	  switch (S2C_CSFT)
	    {
	    case L7_FLOW_SKYPE_E2E:
	      add_histo (L7_UDP_num_loc, L7_FLOW_SKYPE_E2E);
	      L7_udp_bitrate.loc[L7_FLOW_SKYPE_E2E] += thisUdir->data_bytes;
	      break;
	    case L7_FLOW_SKYPE_E2O:
	      add_histo (L7_UDP_num_loc, L7_FLOW_SKYPE_E2O);
	      L7_udp_bitrate.loc[L7_FLOW_SKYPE_E2O] += thisUdir->data_bytes;
	      break;
	    }
	  break;
	}
    }

  /* log flow if at least one of two dir is SKYPE */

  if ( ( C2S_is_Skype || S2C_is_Skype) && LOG_IS_ENABLED(LOG_SKYPE_COMPLETE) && fp_skype_logc != NULL  )
  {
    thisUdir = &(pup->c2s);
    pskype = thisUdir->skype;
 
    video_present =
      (100 * pskype->video_pkts / (pskype->audiovideo_pkts + 1) >
       10) ? TRUE : FALSE;

    //     #   Field Meaning
    //    --------------------------------------
    //     1   Client IP Address
    //     2   Client Port
    //     3   Internal address (0=no, 1=yes)

    if (pup->crypto_src==FALSE)
       wfprintf (fp_skype_logc,"%s %s %d %d",
  	     HostName (pup->addr_pair.a_address),
  	     ServiceName (pup->addr_pair.a_port), pup->internal_src, pup->crypto_src);
    else
       wfprintf (fp_skype_logc,"%s %s %d %d",
  	     HostNameEncrypted (pup->addr_pair.a_address),
  	     ServiceName (pup->addr_pair.a_port), pup->internal_src, pup->crypto_src);

    //     4   Flow Size [Bytes]
    wfprintf (fp_skype_logc, " %llu", thisUdir->data_bytes);

    //     5   No. of Total flow packets
    //     6   No. of End-2-End  packets
    //     7   No. of Skypeout   packets
    //     8   No. of Signaling  packets
    //     9   No. of Unknown	 packets
    //    10   No. of audio or audio+video packets
    //    11   No. of video only   packets
    wfprintf (fp_skype_logc,
  	     " %lld %d %d %d %d %d %d",
  	     thisUdir->packets,
  	     pskype->pkt_type_num[SKYPE_E2E_DATA],
  	     pskype->pkt_type_num[SKYPE_OUT_DATA],
  	     pskype->pkt_type_num[SKYPE_NAK] +
  	     pskype->pkt_type_num[SKYPE_FUN2] +
  	     pskype->pkt_type_num[SKYPE_FUN3],
  	     pskype->pkt_type_num[NOT_SKYPE],
  	     pskype->audiovideo_pkts, pskype->video_pkts);

    //    12   Average Pktsize
    //    13   Packet Size: Max Mean Belief
    //    14   Average Inter-packet Gap
    //    15   Average IPG: Max Mean Belief
    if (bayes_engine)
      {
  	wfprintf (fp_skype_logc,
  		 " %f %.3f",
  		 (double) thisUdir->data_bytes / (double) thisUdir->packets,
  		 pup->c2s.bc_pktsize->mean_max_belief);
  	wfprintf (fp_skype_logc,
  		 " %f %.3f",
  		 (double) elapsed (pup->first_time,
  				   pup->last_time) / 1000.0 /
  		 (double) thisUdir->packets,
  		 pup->c2s.bc_avgipg->mean_max_belief);
      }

  //	16  Chi-square: min E2O Header
  //	17  Chi-square: max E2E Header
  //	18  Chi-square: min E2E Header
  //	19  Chi-square: max Payload

    wfprintf (fp_skype_logc,
  	     " %.3f %.3f %.3f %.3f",
  	     c2s_minCHI_E2O_HDR, c2s_maxCHI_E2E_HDR, c2s_minCHI_E2E_HDR, c2s_maxCHI_PAY);

    //    20   Deterministic Flow Type
    //    21   Bayesian Flow Type
    //    22   Chi-square Flow Type
    //    23   Video present flag (0=no, 1=yes)

    wfprintf (fp_skype_logc,
  	     " %d %d %d %d",
  	     thisUdir->type,
  	     b_avgipg_c2s && b_pktsize_c2s ? 1 :
  	     (!b_avgipg_c2s && !b_pktsize_c2s) ? 0 :
  	     (!b_avgipg_c2s && b_pktsize_c2s) ? -1 :
  	     (b_avgipg_c2s && !b_pktsize_c2s) ? -2 : -255, C2S_CSFT, video_present);

  /*S2C*/

    thisUdir = &(pup->s2c);
    pskype = thisUdir->skype;


    // was video present? yes if video only pkts are larger than 10%

    video_present =
      (100 * pskype->video_pkts / (pskype->audiovideo_pkts + 1) >
       10) ? TRUE : FALSE;

    //     #   Field Meaning
    //    --------------------------------------
    //    24   Server IP Address
    //    25   Server Port
    //    26   Internal address (0=no, 1=yes)

    if (pup->crypto_dst==FALSE)
       wfprintf (fp_skype_logc, " %s %s %d %d",
  	     HostName (pup->addr_pair.b_address),
  	     ServiceName (pup->addr_pair.b_port), pup->internal_dst, pup->crypto_dst);
    else
       wfprintf (fp_skype_logc, " %s %s %d %d",
  	     HostNameEncrypted (pup->addr_pair.b_address),
  	     ServiceName (pup->addr_pair.b_port), pup->internal_dst, pup->crypto_dst);

    //    27	Flow Size [Bytes]
    wfprintf (fp_skype_logc, " %llu", thisUdir->data_bytes);

    //    28   No. of Total flow packets
    //    29   No. of End-2-End  packets
    //    30   No. of Skypeout   packets
    //    31   No. of Signaling  packets
    //    32   No. of Unknown	 packets
    //    33   No. of audio or audio+video packets
    //    34   No. of video only   packets
    wfprintf (fp_skype_logc,
  	     " %lld %d %d %d %d %d %d",
  	     thisUdir->packets,
  	     pskype->pkt_type_num[SKYPE_E2E_DATA],
  	     pskype->pkt_type_num[SKYPE_OUT_DATA],
  	     pskype->pkt_type_num[SKYPE_NAK] +
  	     pskype->pkt_type_num[SKYPE_FUN2] +
  	     pskype->pkt_type_num[SKYPE_FUN3],
  	     pskype->pkt_type_num[NOT_SKYPE],
  	     pskype->audiovideo_pkts, pskype->video_pkts);

    //    35   Average Pktsize
    //    36   Packet Size: Max Mean Belief
    //    37   Average Inter-packet Gap
    //    38   Average IPG: Max Mean Belief

    if (bayes_engine)
      {
  	wfprintf (fp_skype_logc,
  		 " %f %.3f",
  		 (double) thisUdir->data_bytes / (double) thisUdir->packets,
  		 pup->s2c.bc_pktsize->mean_max_belief);
  	wfprintf (fp_skype_logc,
  		 " %f %.3f",
  		 (double) elapsed (pup->first_time,
  				   pup->last_time) / 1000.0 /
  		 (double) thisUdir->packets,
  		 pup->s2c.bc_avgipg->mean_max_belief);
      }

    //    39  Chi-square: min E2O Header
    //    40  Chi-square: max E2E Header
    //    41  Chi-square: min E2E Header
    //    42  Chi-square: max Payload

    wfprintf (fp_skype_logc,
  	     " %.3f %.3f %.3f %.3f",
  	     s2c_minCHI_E2O_HDR, s2c_maxCHI_E2E_HDR, s2c_minCHI_E2E_HDR, s2c_maxCHI_PAY);


    //    43   Deterministic Flow Type
    //    44   Bayesian Flow Type
    //    45   Chi-square Flow Type
    //    46   Video present flag (0=no, 1=yes)

    wfprintf (fp_skype_logc,
  	     " %d %d %d %d",
  	     thisUdir->type,
  	     b_avgipg_s2c && b_pktsize_s2c ? 1 :
  	     (!b_avgipg_s2c && !b_pktsize_s2c) ? 0 :
  	     (!b_avgipg_s2c && b_pktsize_s2c) ? -1 :
  	     (b_avgipg_s2c && !b_pktsize_s2c) ? -2 : -255, S2C_CSFT, video_present);


    //    47   Flow Start Time [in Unix time]
    //    48   Flow Elapsed Time [s]

    wfprintf (fp_skype_logc,
  	     " %f %.3f",
  	     1e-6 * time2double (pup->first_time),
  	     elapsed (pup->first_time, pup->last_time) / 1000.0 / 1000.0);

    wfprintf (fp_skype_logc, " U\n");

  } 

}

void
print_skype_conn_stats_TCP (void *thisdir, int olddir)
{
  double chi_square[N_BLOCK];
  double expected_num;
  int i, j, dir;
  int C2S_CSFT = -1;
  int S2C_CSFT = -1;
  int C2S_is_Skype = 0;
  int S2C_is_Skype = 0;
  struct tcb *thisTdir;
  Bool video_present;
  float c2s_maxCHI_HDR, c2s_maxCHI_PAY;
  float s2c_maxCHI_HDR, s2c_maxCHI_PAY;

  Bool b_pktsize_c2s, b_avgipg_c2s;
  Bool b_pktsize_s2c, b_avgipg_s2c;

  struct skype_stat *pskype;
  struct stcp_pair *ptp;
  thisTdir = (tcb *) thisdir;
  ptp = thisTdir->ptp;
  pskype = thisTdir->skype;

  if (bayes_engine)
    {
      if (ptp->s2c.bc_pktsize->mean_max_belief == 0)
	{
	  ptp->s2c.bc_pktsize->mean_max_belief = MIN_TH_VALID_PERC;
	  ptp->s2c.bc_pktsize->argmax = -1;
	}
      if (ptp->c2s.bc_pktsize->mean_max_belief == 0)
	{
	  ptp->c2s.bc_pktsize->mean_max_belief = MIN_TH_VALID_PERC;
	  ptp->c2s.bc_pktsize->argmax = -1;
	}

      if (ptp->s2c.bc_avgipg->mean_max_belief == 0)
	{
	  ptp->s2c.bc_avgipg->mean_max_belief = MIN_TH_VALID_PERC;
	  ptp->s2c.bc_avgipg->argmax = -1;
	}
      if (ptp->c2s.bc_avgipg->mean_max_belief == 0)
	{
	  ptp->c2s.bc_avgipg->mean_max_belief = MIN_TH_VALID_PERC;
	  ptp->c2s.bc_avgipg->argmax = -1;
	}
    }
  // was video present? yes if video only pkts are larger than 10%

  thisTdir = &(ptp->c2s);
  pskype = thisTdir->skype;
  dir = C2S;

  b_pktsize_c2s = 0;
  b_avgipg_c2s = 0;

  if (bayes_engine)
    {
      b_pktsize_c2s = (ptp->c2s.bc_pktsize->mean_max_belief >=
		   ptp->c2s.bc_pktsize->settings->avg_threshold);
      b_avgipg_c2s = (ptp->c2s.bc_avgipg->mean_max_belief >=
		  ptp->c2s.bc_avgipg->settings->avg_threshold);
    }

  /* evaluate the chi_square as
     (x_i - E_i)^2
     sum -----------
     E_i
   */

  /* do the same for payload bytes after the 4th bytes */
  expected_num = (double) pskype->random.rnd_n_samples * OUT_EXPECTED_PROB;
//  expected_num = (double)thisTdir->packets*E2E_EXPECTED_PROB;

  for (j = 0; j < N_BLOCK; j++)
    {
      chi_square[j] = 0.0;
      for (i = 0; i < N_RANDOM_BIT_VALUES; i++)
	{
	  chi_square[j] +=
	    (pskype->random.rnd_bit_histo[i][j] - expected_num) *
	    (pskype->random.rnd_bit_histo[i][j] - expected_num);
	}
      chi_square[j] /= expected_num;
    }

  c2s_maxCHI_HDR = chi_square[0];
  for (i = 1; i < N_BLOCK / 2; i++)
    {
      if (c2s_maxCHI_HDR < chi_square[i])
	c2s_maxCHI_HDR = chi_square[i];
    }

  c2s_maxCHI_PAY = chi_square[8];
  for (i = 9; i < N_BLOCK; i++)
    {
      if (c2s_maxCHI_PAY < chi_square[i])
	c2s_maxCHI_PAY = chi_square[i];
    }

  if (c2s_maxCHI_HDR < 150 && c2s_maxCHI_PAY < 150)
    C2S_CSFT = L7_FLOW_SKYPE_TCP;	/* SKYPE senza distinzione E2E/E2O */
  else
    C2S_CSFT = NOT_SKYPE;

  if ((b_avgipg_c2s && b_pktsize_c2s) && C2S_CSFT != NOT_SKYPE)
    C2S_is_Skype = 1;

/* add this flow to the skype one */
/* decide if it is entering or going out */

  if (b_avgipg_c2s && b_pktsize_c2s && C2S_CSFT != NOT_SKYPE)
    {
      /* this is a Skype flow -> set the TCP flow type as well */
      ptp->con_type |= SKYPE_PROTOCOL;
      ptp->con_type &= ~OBF_PROTOCOL;
      ptp->con_type &= ~MSE_PROTOCOL;
      pskype->skype_type = C2S_CSFT;

      switch ((in_out_loc (ptp->internal_src, ptp->internal_dst, dir)))
	{
	case OUT_FLOW:
	  L7_bitrate.out[L7_FLOW_SKYPE_TCP] += thisTdir->data_bytes;
	  break;
	case IN_FLOW:
	  L7_bitrate.in[L7_FLOW_SKYPE_TCP] += thisTdir->data_bytes;
	  break;
	case LOC_FLOW:
	  L7_bitrate.loc[L7_FLOW_SKYPE_TCP] += thisTdir->data_bytes;
	  break;
	}
    }

/*S2C*/
  thisTdir = &(ptp->s2c);
  pskype = thisTdir->skype;
  dir = S2C;

  b_pktsize_s2c = 0;
  b_avgipg_s2c = 0;

  if (bayes_engine)
    {
      b_pktsize_s2c = (ptp->s2c.bc_pktsize->mean_max_belief >=
		   ptp->s2c.bc_pktsize->settings->avg_threshold);
      b_avgipg_s2c = (ptp->s2c.bc_avgipg->mean_max_belief >=
		  ptp->s2c.bc_avgipg->settings->avg_threshold);
    }

  /* evaluate the chi_square as
     (x_i - E_i)^2
     sum -----------
     E_i
   */

  /* do the same for payload bytes after the 4th bytes */
  expected_num = (double) pskype->random.rnd_n_samples * OUT_EXPECTED_PROB;
//  expected_num = (double)thisTdir->packets*E2E_EXPECTED_PROB;


  for (j = 0; j < N_BLOCK; j++)
    {
      chi_square[j] = 0.0;
      for (i = 0; i < N_RANDOM_BIT_VALUES; i++)
	{
	  chi_square[j] +=
	    (pskype->random.rnd_bit_histo[i][j] - expected_num) *
	    (pskype->random.rnd_bit_histo[i][j] - expected_num);
	}
      chi_square[j] /= expected_num;
    }

  s2c_maxCHI_HDR = chi_square[0];
  for (i = 1; i < N_BLOCK / 2; i++)
    {
      if (s2c_maxCHI_HDR < chi_square[i])
	s2c_maxCHI_HDR = chi_square[i];
    }

  s2c_maxCHI_PAY = chi_square[8];
  for (i = 9; i < N_BLOCK; i++)
    {
      if (s2c_maxCHI_PAY < chi_square[i])
	s2c_maxCHI_PAY = chi_square[i];
    }

  if (s2c_maxCHI_HDR < 150 && s2c_maxCHI_PAY < 150)
    S2C_CSFT = L7_FLOW_SKYPE_TCP;	/* SKYPE senza distinzione E2E/E2O */
  else
    S2C_CSFT = NOT_SKYPE;

  if ((b_avgipg_s2c && b_pktsize_s2c) && S2C_CSFT != NOT_SKYPE)
    S2C_is_Skype = 1;

/* add this flow to the skype one */
/* decide if it is entering or going out */

  if (b_avgipg_s2c && b_pktsize_s2c && S2C_CSFT != NOT_SKYPE)
    {
      /* this is a Skype flow -> set the TCP flow type as well */
      ptp->con_type |= SKYPE_PROTOCOL;
      ptp->con_type &= ~OBF_PROTOCOL;
      ptp->con_type &= ~MSE_PROTOCOL;
      pskype->skype_type = S2C_CSFT;

      switch ((in_out_loc (ptp->internal_src, ptp->internal_dst, dir)))
	{
	case OUT_FLOW:
	  L7_bitrate.out[L7_FLOW_SKYPE_TCP] += thisTdir->data_bytes;
	  break;
	case IN_FLOW:
	  L7_bitrate.in[L7_FLOW_SKYPE_TCP] += thisTdir->data_bytes;
	  break;
	case LOC_FLOW:
	  L7_bitrate.loc[L7_FLOW_SKYPE_TCP] += thisTdir->data_bytes;
	  break;
	}
    }

  /* log flow if at least one of two dir is SKYPE */

  if ((C2S_is_Skype || S2C_is_Skype) && LOG_IS_ENABLED(LOG_SKYPE_COMPLETE) && fp_skype_logc != NULL)
   {
     thisTdir = &(ptp->c2s);
     pskype = thisTdir->skype;
 
     video_present =
       (100 * pskype->video_pkts / (pskype->audiovideo_pkts + 1) >
   	10) ? TRUE : FALSE;

     //     #	Field Meaning
     //    --------------------------------------
     //     1	Client IP Address
     //     2	Client Port
     //     3	Internal address (0=no, 1=yes)

     if (ptp->crypto_src==FALSE)
        wfprintf (fp_skype_logc, "%s %s %d %d",
   	      HostName (ptp->addr_pair.a_address),
   	      ServiceName (ptp->addr_pair.a_port), ptp->internal_src, ptp->crypto_src);
     else
        wfprintf (fp_skype_logc, "%s %s %d %d",
   	      HostNameEncrypted (ptp->addr_pair.a_address),
   	      ServiceName (ptp->addr_pair.a_port), ptp->internal_src, ptp->crypto_src);
 
     //     4	Flow Size [Bytes]

     wfprintf (fp_skype_logc, " %lu", thisTdir->unique_bytes);

     //     5	No. of Total flow packets
     //     6	No. of Total audio or audio+video packets
     //     7	No. of Total video only packets

     wfprintf (fp_skype_logc, " %ld %d %d", thisTdir->packets,
   	      pskype->audiovideo_pkts, pskype->video_pkts);

     //     8	Average Pktsize
     //     9	Packet Size: Max Mean Belief
     //    10	Average Inter-packet Gap
     //    11	Average IPG: Max Mean Belief

     if (bayes_engine)
       {

   	 wfprintf (fp_skype_logc,
   		  " %f %.3f",
   		  (double) thisTdir->unique_bytes / (double)
   		  thisTdir->data_pkts, ptp->c2s.bc_pktsize->mean_max_belief);
   	 wfprintf (fp_skype_logc,
   		  " %f %.3f",
   		  (double) elapsed (ptp->first_time,
   				    ptp->last_time) / 1000.0 /
   		  (double) thisTdir->data_pkts,
   		  ptp->c2s.bc_avgipg->mean_max_belief);
       }

   //	 12  Chi-square: max Header
   //	 13  Chi-square: max Payload

     wfprintf (fp_skype_logc, " %.3f %.3f", c2s_maxCHI_HDR, c2s_maxCHI_PAY);

     //    16	Bayesian Flow Type
     //    17	Chi-square Flow Type
     //    18	Video present flag (0=no, 1=yes)

     wfprintf (fp_skype_logc,
   	      " %d %d %d",
   	      b_avgipg_c2s && b_pktsize_c2s ? 1 :
   	      (!b_avgipg_c2s && !b_pktsize_c2s) ? 0 :
   	      (!b_avgipg_c2s && b_pktsize_c2s) ? -1 :
   	      (b_avgipg_c2s && !b_pktsize_c2s) ? -2 : -255, C2S_CSFT, video_present);

   /*S2C*/
     thisTdir = &(ptp->s2c);
     pskype = thisTdir->skype;

     // was video present? yes if video only pkts are larger than 10%

     video_present =
       (100 * pskype->video_pkts / (pskype->audiovideo_pkts + 1) >
   	10) ? TRUE : FALSE;

     //     #	Field Meaning
     //    --------------------------------------
     //    14	Server IP Address
     //    15	Server Port
     //    16	Internal address (0=no, 1=yes)

     if (ptp->crypto_dst==FALSE)
        wfprintf (fp_skype_logc, " %s %s %d %d",
   	      HostName (ptp->addr_pair.b_address),
   	      ServiceName (ptp->addr_pair.b_port), ptp->internal_dst, ptp->crypto_dst);
     else
        wfprintf (fp_skype_logc, " %s %s %d %d",
   	      HostNameEncrypted (ptp->addr_pair.b_address),
   	      ServiceName (ptp->addr_pair.b_port), ptp->internal_dst, ptp->crypto_dst);

     //    17	Flow Size [Bytes]

     wfprintf (fp_skype_logc, " %lu", thisTdir->unique_bytes);

     //    18	No. of Total flow packets
     //    19	No. of Total audio or audio+video packets
     //    20	No. of Total video only packets

     wfprintf (fp_skype_logc, " %ld %d %d", thisTdir->packets,
   	      pskype->audiovideo_pkts, pskype->video_pkts);

     //    21	Average Pktsize
     //    22	Packet Size: Max Mean Belief
     //    23	Average Inter-packet Gap
     //    24	Average IPG: Max Mean Belief

     if (bayes_engine)
       {
   	 wfprintf (fp_skype_logc,
   		  " %f %.3f",
   		  (double) thisTdir->unique_bytes / (double)
   		  thisTdir->data_pkts, ptp->s2c.bc_pktsize->mean_max_belief);
   	 wfprintf (fp_skype_logc,
   		  " %f %.3f",
   		  (double) elapsed (ptp->first_time,
   				    ptp->last_time) / 1000.0 /
   		  (double) thisTdir->packets,
   		  ptp->s2c.bc_avgipg->mean_max_belief);
       }

     //    25  Chi-square: max Header
     //    26  Chi-square: max Payload

     wfprintf (fp_skype_logc, " %.3f %.3f", s2c_maxCHI_HDR, s2c_maxCHI_PAY);


     //    27	Bayesian Flow Type
     //    28	Chi-square Flow Type
     //    29	Video present flag (0=no, 1=yes)

     wfprintf (fp_skype_logc,
   	      " %d %d %d",
   	      b_avgipg_s2c && b_pktsize_s2c ? 1 :
   	      (!b_avgipg_s2c && !b_pktsize_s2c) ? 0 :
   	      (!b_avgipg_s2c && b_pktsize_s2c) ? -1 :
   	      (b_avgipg_s2c && !b_pktsize_s2c) ? -2 : -255, S2C_CSFT, video_present);

     //    30	Flow Start Time [in Unix time]
     //    31	Flow Elapsed Time [s]

     wfprintf (fp_skype_logc, " %f %.3f",
   	      1e-6 * time2double (ptp->first_time),
   	      elapsed (ptp->first_time, ptp->last_time) / 1000.0 / 1000.0);

     wfprintf (fp_skype_logc, " T\n");

   }

}
