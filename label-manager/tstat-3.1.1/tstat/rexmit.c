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


/* 
 * rexmit.c -- Determine if a segment is a retransmit and perform RTT stats
 * 
 * implements the algorithm described in 
 * Marco Mellia, Michela Meo, Luca Muscariello,
 * "TCP Anomalies: identification and analysis",
 * 2005 Tyrrhenian International Workshop on Digital Communications
 * Distributed Cooperative Laboratories - Issues in Networking,
 * Instrumentation and Measurements,
 * Sorrento, Italy, July 4-6
 */




/*
This function rexmit() checks to see if a particular packet
is a retransmit. It returns 0 if it isn't a retransmit and 
returns the number of bytes retransmitted if it is a retransmit - 
considering the fact that it might be a partial retransmit. 
It can also keep track of packets that come out of order.
*/

/*LM modified functions:
static segment *create_seg (seqnum, seglen, u_short);  
int rexmit (tcb * ptcb, seqnum seq, seglen len, Bool * pout_order, u_short this_ip_id)
static int addseg (tcb * ptcb,	quadrant * pquad, seqnum thisseg_firstbyte, seglen len, Bool * pout_order, u_short this_ip_id)
differences: added only the ip_id field in the segment struct for implementing a retransmission
identification heuristic. Functions have been modified to manage this new field.
*/

#include "tstat.h"

/* smooth parameter defined in RFC 2988 for srtt and rttvar estimation */
#define ALPHA 0.125
#define BETA 0.250

/* locally global variables*/


/* local routine definitions*/
static void insert_seg_between (quadrant *, segment *, segment *, segment *);
static void collapse_quad (quadrant *);
static segment *create_seg (seqnum, seglen, u_short);
static quadrant *whichquad (seqspace *, seqnum);
static quadrant *create_quadrant (void);
static int addseg (tcb *, quadrant *, seqnum, seglen, Bool *, u_short);
static void rtt_retrans (tcb *, segment *);
static enum t_ack rtt_ackin (tcb *, segment *, Bool rexmit);


/* LM start return the type of segment */
void rules_test (tcb *, segment *, seglen, quadrant *, u_short,
		 Bool pkt_already_seen, double recovery_time);
char real_rules_test (tcb * thisdir, segment * pseg, seglen len,
		      quadrant * pquad, u_short this_ip_id,
		      Bool pkt_already_seen, double *recovery_time);
/* LM stop*/

/*
 * rexmit: is the specified segment a retransmit?
 *   returns: number of retransmitted bytes in segment, 0 if not a rexmit
 *            *pout_order to to TRUE if segment is out of order
 */
int
rexmit (tcb * ptcb, seqnum seq, seglen len, Bool * pout_order,
	u_short this_ip_id)
{
  seqspace *sspace = ptcb->ss;
  seqnum seq_last = seq + len - 1;
  quadrant *pquad;
  int rexlen = 0;

  /* unless told otherwise, it's IN order */
  *pout_order = FALSE;


  /* see which quadrant it starts in */
  pquad = whichquad (sspace, seq);

  /* add the new segment into the segment database */
  if (BOUNDARY (seq, seq_last))
    {
      /* lives in two different quadrants (can't be > 2) */
      seqnum seq1, seq2;
      u_long len1, len2;

      /* in first quadrant */
      seq1 = seq;
      len1 = LAST_SEQ (QUADNUM (seq1)) - seq1 + 1;
      rexlen = addseg (ptcb, pquad, seq1, len1, pout_order, this_ip_id);

      /* in second quadrant */
      seq2 = FIRST_SEQ (QUADNUM (seq_last));
      len2 = len - len1;
      rexlen +=
	addseg (ptcb, pquad->next, seq2, len2, pout_order, this_ip_id);
    }
  else
    {
      rexlen = addseg (ptcb, pquad, seq, len, pout_order, this_ip_id);
    }

  return (rexlen);
}


/********************************************************************/
static int
addseg (tcb * ptcb,
	quadrant * pquad,
	seqnum thisseg_firstbyte, seglen len, Bool * pout_order,
	u_short this_ip_id)
{
  seqnum thisseg_lastbyte = thisseg_firstbyte + len - 1;
  segment *pseg;
  segment *pseg_new;
  int rexlen = 0;
  Bool split = FALSE;
  double recovery_time = 0;

  /* check each segment in the segment list */
  pseg = pquad->seglist_head;

  /* LM - all the segments are memorized in the seglist 
     Here has been implemented the heuristic discussed in
     S. Jaiswal, G.Iannaccone, C. Diot, J.F. Kurose, D.Towsley 
     Measurement and Classification of Out-of-Sequence Packets in a Tier-1 IP Backbone
     INFOCOM 2003 http://www.ieee-infocom.org/2003/technical_programs.htm
   */

  /* (optimize expected case, it just goes at the end) */
  if (pquad->seglist_tail &&
      (thisseg_firstbyte > pquad->seglist_tail->seq_lastbyte))
    pseg = NULL;
  for (; pseg != NULL; pseg = pseg->next)
    {

      if (thisseg_firstbyte > pseg->seq_lastbyte)
	{
	  /* goes beyond this one */
	  continue;
	}

      if (thisseg_firstbyte < pseg->seq_firstbyte)
	{
	  /* starts BEFORE this recorded segment */

	  /* if it also FINISHES before this segment, then it's */
	  /* out of order (otherwise it's a resend the collapsed */
	  /* multiple segments into one */
	  if (thisseg_lastbyte < pseg->seq_lastbyte)
	    *pout_order = TRUE;

	  /* make a new segment record for it */
	  pseg_new = create_seg (thisseg_firstbyte, len, this_ip_id);
	  insert_seg_between (pquad, pseg_new, pseg->prev, pseg);

	  /* see if we overlap the next segment in the list */
	  if (thisseg_lastbyte <= pseg->seq_firstbyte)
	    {
	      /* we don't overlap, so we're done */
	      // LM start
	      rules_test (ptcb, pseg, len, pquad, this_ip_id, FALSE,
			  recovery_time);
	      return (rexlen);
	    }
	  else
	    {
	      /* overlap him, split myself in 2 */
	      //fprintf(fp_stdout, "split %lu %lu\n", 
          //    len,  pseg_new->seq_lastbyte-pseg_new->seq_firstbyte);
	      /* adjust new piece to mate with old piece */
	      pseg_new->seq_lastbyte = pseg->seq_firstbyte - 1;

	      // LM start
	      rules_test (ptcb, pseg,
			  pseg_new->seq_lastbyte - pseg_new->seq_firstbyte,
			  pquad, this_ip_id, FALSE, recovery_time);

	      /* pretend to be just the second half of this segment */
	      thisseg_firstbyte = pseg->seq_firstbyte;
	      len = thisseg_lastbyte - thisseg_firstbyte + 1;

	      /* fall through */
	    }
	}

      /* no ELSE, we might have fallen through */
      if (thisseg_firstbyte >= pseg->seq_firstbyte)
	{
	  /* starts within this recorded sequence */
	  ++pseg->retrans;
	  recovery_time =
	    time2double (current_time) - time2double (pseg->time);
	  if (!split)
	    rtt_retrans (ptcb, pseg);	/* must be a retransmission */
	  if (thisseg_lastbyte <= pseg->seq_lastbyte)
	    {
	      /* entirely contained within this sequence */
	      rexlen += len;
	      // LM start
	      rules_test (ptcb, pseg, len, pquad, this_ip_id, TRUE,
			  recovery_time);

	      return (rexlen);
	    }
	  /* else */
	  /* we extend beyond this sequence, split ourself in 2 */
	  /* (pretend to be just the second half of this segment) */
	  split = TRUE;
	  rexlen += pseg->seq_lastbyte - thisseg_firstbyte + 1;
	  thisseg_firstbyte = pseg->seq_lastbyte + 1;

	  // LM start
	  rules_test (ptcb, pseg, rexlen, pquad, this_ip_id, TRUE,
		      recovery_time);
	  len = thisseg_lastbyte - thisseg_firstbyte + 1;
	}
    }
  /* if we got to the end, then it doesn't go BEFORE anybody, */
  /* tack it onto the end */

  pseg_new = create_seg (thisseg_firstbyte, len, this_ip_id);
  insert_seg_between (pquad, pseg_new, pquad->seglist_tail, NULL);

  /* MGM - management of the number of segments within this quadrant */

  if (pquad->no_of_segments > GLOBALS.Max_Seg_Per_Quad)
    {
      /* free up the first segment in this quadrant */
      segment *tmp_pseg = pquad->seglist_head;

      /* rebuild the list */
      if (tmp_pseg->next != NULL)
	tmp_pseg->next->prev = tmp_pseg->prev;
      pquad->seglist_head = tmp_pseg->next;
      /* recall the initial segment byte */
      pquad->seglist_head->seq_firstbyte = tmp_pseg->seq_firstbyte;

      /* remove the segment */
      segment_release (tmp_pseg);
      pquad->no_of_segments--;
    }


  pseg_new->type_of_segment = IN_SEQUENCE;
  /* LM : This is an IN_SEQUENCE segment */
  if (internal_src && !internal_dst)
    {
      add_histo (tcp_anomalies_out, IN_SEQUENCE);
    }
  else if (!internal_src && internal_dst)
    {
      add_histo (tcp_anomalies_in, IN_SEQUENCE);
    }
#ifndef LOG_UNKNOWN
  else if (internal_src && internal_dst)
#else
  else
#endif
    {
      add_histo (tcp_anomalies_loc, IN_SEQUENCE);
    }

  if ((&(ptcb->ptp->c2s)) == ptcb)	//(dir == C2S)
    {
      add_histo (tcp_anomalies_c2s, IN_SEQUENCE);
    }
  else
    {
      add_histo (tcp_anomalies_s2c, IN_SEQUENCE);
    }
  return (rexlen);
}



/**********************************************************************/
static segment *
create_seg (seqnum seq, seglen len, u_short this_ip_id)
{
  segment *pseg;

  //pseg = (segment *) MallocZ (sizeof (segment));

  pseg = (segment *) segment_alloc ();

  pseg->time = current_time;
  pseg->seq_firstbyte = seq;
  pseg->seq_lastbyte = seq + len - 1;
  /* LM start */
  pseg->ip_id = this_ip_id;
  /* LM stop */
  return (pseg);
}

/**********************************************************************/
static quadrant *
create_quadrant (void)
{
  quadrant *pquad;

  pquad = (quadrant *) quadrant_alloc ();

  return (pquad);
}

/********************************************************************/

static quadrant *
whichquad (seqspace * sspace, seqnum seq)
{
  quadnum qid = QUADNUM (seq);
  quadrant *pquad;
  int qix;
  int qix_next;
  int qix_opposite;
  int qix_prev;

  /* optimize expected case, it's all set up correctly already */
  qix = qid - 1;
  if ((pquad = sspace->pquad[qix]) && pquad->next && pquad->prev)
    return (pquad);

  /* determine indices of "neighbor" quadrants */
  qix_next = (qix + 1) % 4;
  qix_opposite = (qix + 2) % 4;
  qix_prev = (qix + 3) % 4;

  /* make sure that THIS quadrant exists */
  if (sspace->pquad[qix] == NULL)
    {
      sspace->pquad[qix] = create_quadrant ();
    }

  /* make sure that the quadrant AFTER this one exists */
  if (sspace->pquad[qix_next] == NULL)
    {
      sspace->pquad[qix_next] = create_quadrant ();
    }

  /* make sure that the quadrant BEFORE this one exists */
  if (sspace->pquad[qix_prev] == NULL)
    {
      sspace->pquad[qix_prev] = create_quadrant ();
    }

  /* clear out the opposite side, we don't need it anymore */
  if (sspace->pquad[qix_opposite] != NULL)
    {
      freequad (&sspace->pquad[qix_opposite]);

      sspace->pquad[qix_opposite] = NULL;
    }

  /* set all the pointers */
  sspace->pquad[qix]->prev = sspace->pquad[qix_prev];
  sspace->pquad[qix]->next = sspace->pquad[qix_next];
  sspace->pquad[qix_next]->prev = sspace->pquad[qix];
  sspace->pquad[qix_prev]->next = sspace->pquad[qix];
  sspace->pquad[qix_next]->next = NULL;
  sspace->pquad[qix_prev]->prev = NULL;

  return (sspace->pquad[qix]);
}



/*********************************************************************/
static void
collapse_quad (quadrant * pquad)
{
  Bool freed;
  segment *pseg;
  segment *tmpseg;

  if ((pquad == NULL) || (pquad->seglist_head == NULL))
    return;

  pseg = pquad->seglist_head;
  while (pseg != NULL)
    {
      freed = FALSE;
      if (pseg->next == NULL)
	break;

      /* if this segment has not been ACKed, then neither have the */
      /* ones that follow, so no need to continue */
      if (!pseg->acked)
	break;

      /* if this segment and the next one have both been ACKed and they */
      /* "fit together", then collapse them into one (larger) segment   */
      if (pseg->acked && pseg->next->acked &&
	  (pseg->seq_lastbyte + 1 == pseg->next->seq_firstbyte))
	{
	  pseg->seq_lastbyte = pseg->next->seq_lastbyte;

	  /* the new ACK count is the ACK count of the later segment */
	  pseg->acked = pseg->next->acked;

	  /* the new "transmit time" is the greater of the two */
	  /* the new "ip_id" is the greater of the two */
	  /* the new "type_of_segment" is the greater of the two */
	  if (tv_gt (pseg->next->time, pseg->time))
	    {
	      pseg->time = pseg->next->time;
	      pseg->ip_id = pseg->next->ip_id;
	      pseg->type_of_segment = pseg->next->type_of_segment;
	    }

	  tmpseg = pseg->next;
	  pseg->next = pseg->next->next;
	  if (pseg->next != NULL)
	    pseg->next->prev = pseg;
	  if (tmpseg == pquad->seglist_tail)
	    pquad->seglist_tail = pseg;
	  //free (tmpseg);
	  segment_release (tmpseg);
	  pquad->no_of_segments--;
	  //segment_list_info();
	  freed = TRUE;
	}

      if (!freed)
	pseg = pseg->next;
      /* else, see if the next one also can be collapsed into me */
    }

  /* see if the quadrant is now "full" */
  if ((pquad->seglist_head->seq_lastbyte -
       pquad->seglist_head->seq_firstbyte + 1) == QUADSIZE)
    {
      pquad->full = TRUE;
    }
}


static void
insert_seg_between (quadrant * pquad,
		    segment * pseg_new,
		    segment * pseg_before, segment * pseg_after)
{
  /* adding a new segment to this quadrant - MGM */
  pquad->no_of_segments++;

  /* fix forward pointers */
  pseg_new->next = pseg_after;
  if (pseg_after != NULL)
    {
      pseg_after->prev = pseg_new;
    }
  else
    {
      /* I'm the tail of the list */
      pquad->seglist_tail = pseg_new;
    }

  /* fix backward pointers */
  pseg_new->prev = pseg_before;
  if (pseg_before != NULL)
    {
      pseg_before->next = pseg_new;
    }
  else
    {
      /* I'm the head of the list */
      pquad->seglist_head = pseg_new;
    }
}


static enum t_ack
rtt_ackin (tcb * ptcb, segment * pseg, Bool rexmit_prev)
{
  double etime_rtt;
  enum t_ack ret;

  /* how long did it take */
  etime_rtt = elapsed (pseg->time, current_time);
//fprintf (fp_stdout, "%f\n",etime_rtt);
  if (rexmit_prev)
    {
      /* first, check for the situation in which the segment being ACKed */
      /* was sent a while ago, and we've been piddling around */
      /* retransmitting lost segments that came before it */
      ptcb->rtt_last = 0.0;	/* don't use this sample, it's very long */
      etime_rtt = 0.0;

      ++ptcb->rtt_nosample;	/* no sample, even though not ambig */
      ret = NOSAMP;
    }
  else if (pseg->retrans == 0)
    {
      ptcb->rtt_last = etime_rtt;
      if ((ptcb->rtt_min == 0) || (ptcb->rtt_min > etime_rtt))
	ptcb->rtt_min = etime_rtt;

      if (ptcb->rtt_max < etime_rtt)
	ptcb->rtt_max = etime_rtt;

      /* smoothed RTT and stdev estimation */
      /* see RFC 2988 */
      ptcb->rttvar =
	(1.0 - BETA) * ptcb->rttvar + BETA * abs (ptcb->srtt - etime_rtt);

      ptcb->srtt = (1.0 - ALPHA) * ptcb->srtt + BETA * etime_rtt;

//  if ((&(ptcb->ptp->c2s)) != ptcb)    //(dir == C2S)
//     fprintf (fp_stdout, "%f\n",ptcb->srtt);

      /* average over lifetime */
      ptcb->rtt_sum += etime_rtt;
      ptcb->rtt_sum2 += etime_rtt * etime_rtt;
      ++ptcb->rtt_count;
      ret = NORMAL;
    }
  else
    {
      /* retrans, can't use it */
      ret = AMBIG;
    }

  return (ret);
}



static void
rtt_retrans (tcb * ptcb, segment * pseg)
{
  double etime;

  if (!pseg->acked)
    {
      /* if it was acked, then it's been collapsed and these */
      /* are no longer meaningful */
      etime = elapsed (pseg->time, current_time);
      if (pseg->retrans > ptcb->retr_max)
	ptcb->retr_max = pseg->retrans;

      if (etime > ptcb->retr_max_tm)
	ptcb->retr_max_tm = etime;
      if ((ptcb->retr_min_tm == 0) || (etime < ptcb->retr_min_tm))
	ptcb->retr_min_tm = etime;

      ptcb->retr_tm_sum += etime;
      ptcb->retr_tm_sum2 += etime * etime;
      ++ptcb->retr_tm_count;
    }

  pseg->time = current_time;
}


enum t_ack
ack_in (tcb * ptcb, seqnum ack, unsigned tcp_data_length)
{
  quadrant *pquad;
  quadrant *pquad_prev;
  segment *pseg;
  Bool changed_one = FALSE;
  Bool intervening_xmits = FALSE;
  timeval last_xmit = { 0, 0 };
  enum t_ack ret = 0;

  /* check each segment in the segment list for the PREVIOUS quadrant */
  pquad = whichquad (ptcb->ss, ack);
  pquad_prev = pquad->prev;
  for (pseg = pquad_prev->seglist_head; pseg != NULL; pseg = pseg->next)
    {
      if (!pseg->acked)
	{
	  ++pseg->acked;
	  changed_one = TRUE;
	  ++ptcb->rtt_cumack;

	  /* keep track of the newest transmission */
	  if (tv_gt (pseg->time, last_xmit))
	    last_xmit = pseg->time;
	}
    }
  if (changed_one)
    collapse_quad (pquad_prev);

  /* check each segment in the segment list for the CURRENT quadrant */
  changed_one = FALSE;
  for (pseg = pquad->seglist_head; pseg != NULL; pseg = pseg->next)
    {
      if (ack <= pseg->seq_firstbyte)
	{
	  /* doesn't cover anything else on the list */
	  break;
	}

      /* keep track of the newest transmission */
      if (tv_gt (pseg->time, last_xmit))
	last_xmit = pseg->time;

      /* (ELSE) ACK covers this sequence */
      if (pseg->acked)
	{
	  /* already acked this one */
	  ++pseg->acked;
	  if (ack == (pseg->seq_lastbyte + 1))
	    {
	      ++ptcb->rtt_dupack;	/* one more duplicate ack */
	      ret = CUMUL;
	      if (pseg->acked == 4)
		{
		  /* some people say these CAN'T have data */
		  if ((tcp_data_length == 0))
		    {
		      ++ptcb->rtt_triple_dupack;
		      ret = TRIPLE;
		    }
		}
	    }
	  continue;
	}
      /* ELSE !acked */

      ++pseg->acked;
      changed_one = TRUE;

      if (ack == (pseg->seq_lastbyte + 1))
	{
	  /* if ANY preceding segment was xmitted after this one,
	     the the RTT sample is invalid */
	  intervening_xmits = (tv_gt (last_xmit, pseg->time));

	  ret = rtt_ackin (ptcb, pseg, intervening_xmits);
	}
      else
	{
	  /* cumulatively ACKed */
	  ++ptcb->rtt_cumack;
	  ret = CUMUL;
	}
    }
  if (changed_one)
    collapse_quad (pquad);
  return (ret);
}


 /* LM start - Rule number one
  ** R1.a IP_id_new not equal to IP_id_old 
  ** R1.b this_seg_time-prev_seg_time > 
  ** R1.c number of acks > 3 (or max number permitted)
  ** DeltaT1: Time between current segment and the last segment before a ooo
  ** DeltaT2: Time between current segment and the received segment with the maximum sequence number
  */
char
real_rules_test (tcb * thisdir, segment * pseg, seglen len, quadrant * pquad,
		 u_short this_ip_id, Bool pkt_already_seen,
		 double *recovery_time)
{
  double RTO, RTT, Mean_RTT;
  int Rule1a, Rule1b, Rule1d;
  int Rule2b, Rule2c;
  int RuleProbing;
  tcb *otherdir;
  char prev_tos;
  int validRTT;

  int dir = (&(thisdir->ptp->c2s) == thisdir);

  otherdir = (dir == C2S) ? &(thisdir->ptp->s2c) : &(thisdir->ptp->c2s);
  Mean_RTT =
    Average (thisdir->rtt_sum,
	     thisdir->rtt_count) + Average (otherdir->rtt_sum,
					    otherdir->rtt_count);
  RTO =
    Mean_RTT +
    4 *
    (Stdev
     (thisdir->rtt_sum + otherdir->rtt_sum,
      thisdir->rtt_sum2 + otherdir->rtt_sum2,
      thisdir->rtt_count + otherdir->rtt_count));
  RTT = (double) (thisdir->rtt_min + otherdir->rtt_min);
  validRTT = (thisdir->rtt_count != 0 && otherdir->rtt_count != 0);

  if (RTO < RTO_MIN)
    RTO = RTO_MIN;
  if (RTT < RTT_MIN)
    RTT = RTT_MIN;

  if (!pkt_already_seen)	/* if pkt_already_seen then *recovery_time is passed otherwise it is set below */
    *recovery_time =
      (pseg->prev->prev !=
       NULL) ? time2double (current_time) -
      time2double (pseg->prev->prev->time) : -1.0;
  /* take the previous packet classification */

  if (pseg->prev != NULL)
    {
      if (pkt_already_seen)
	prev_tos = pseg->prev->type_of_segment;
      else
	prev_tos =
	  (pseg->prev->prev !=
	   NULL) ? pseg->prev->prev->type_of_segment : IN_SEQUENCE;
    }
  else
    prev_tos = IN_SEQUENCE;

  if (!validRTT)
    {
      RTT = INITIAL_RTT_MIN;
      RTO = INITIAL_RTO;
      /* if *recovery_time is -1 then this is the first packet and use next segment as recovery time */
      if (*recovery_time == -1.0)
	*recovery_time =
	  time2double (current_time) - time2double (pseg->time);
    }

  Rule1a = (pseg->ip_id != this_ip_id);
  Rule1b = (*recovery_time > RTO);
  Rule1d = (*recovery_time < Mean_RTT);
  if (pkt_already_seen)
    Rule2b = (pseg->prev != NULL) ? (pseg->prev->acked > 3
				     && *recovery_time < RTO) : 0;
  else
    Rule2b = (pseg->prev->prev != NULL) ? (pseg->prev->prev->acked > 3
					   && *recovery_time < RTO) : 0;

  Rule2c = (time2double (current_time) - time2double (pseg->time) < RTT);

  RuleProbing = ((len == 1) && (otherdir->win_curr == 0)
		 && (thisdir->syn_count != 0) && (otherdir->syn_count != 0));

  if (RuleProbing)
    return FLOW_CONTROL;
  if (Rule1d && prev_tos != IN_SEQUENCE)
    return (prev_tos | BATCH_CLASSIFICATION);	/* Old Classification with the first bit is 1 */


  if (!pseg->acked)
    {
      if (pkt_already_seen)
	{
	  if (!Rule1a)
	    return CLASSIFICATION (NETWORK_DUPLICATE);
	  if (Rule1a && (Rule1b || Rule2b))
	    return CLASSIFICATION (Rule2b ? RETRANSMISSION_FR :
				   RETRANSMISSION_RTO);
	  if (Rule1d)
	    return
	      CLASSIFICATION (DUPLICATE_WITH_RC_LESS_THAN_RTT_NOT_3DUP_ACK);
	  if (!Rule1b)
	    return
	      CLASSIFICATION
	      (DUPLICATE_WITH_RC_LESS_THAN_RTO_AND_GREATER_THAN_RTT_NOT_3DUP_ACK);
	  return CLASSIFICATION (UNKNOWN);
	}

      if (Rule1b || Rule2b)
	return CLASSIFICATION (Rule2b ? RETRANSMISSION_FR :
			       RETRANSMISSION_RTO);
      if (Rule2c)
	return CLASSIFICATION (REORDERING);
      if (Rule1d)
	return CLASSIFICATION (OOO_WITH_RC_LESS_THAN_RTT_NOT_3DUP_ACK);
      if (!Rule1b)
	return
	  CLASSIFICATION
	  (OOO_WITH_RC_LESS_THAN_RTO_AND_GREATER_THAN_RTT_NOT_3DUP_ACK);
      return CLASSIFICATION (UNKNOWN);

    }

  if (!Rule1a)
    return CLASSIFICATION (NETWORK_DUPLICATE);
  if ((Rule1b || Rule2b))
    return CLASSIFICATION (Rule2b ? UNNECESSARY_RETRANSMISSION_FR :
			   UNNECESSARY_RETRANSMISSION_RTO);
  if (Rule1d)
    return
      CLASSIFICATION
      (UNNECESSARY_RETRANSMISSION_WITH_RC_LESS_THAN_RTT_NOT_3DUP_ACK);
  if (!Rule1b)
    return
      CLASSIFICATION
      (UNNECESSARY_RETRANSMISSION_WITH_RC_LESS_THAN_RTO_AND_GREATER_THAN_RTT_NOT_3DUP_ACK);
  return CLASSIFICATION (UNKNOWN);
}


/*  aggregate anomalies irrespectively of batch/no_rtt_sample classification */
#define aggregateType(type_of_segment) \
        ((type_of_segment & (255-(BATCH_CLASSIFICATION+NO_RTT_SAMPLE_CLASSIFICATION))) > UNNECESSARY_RETRANSMISSION_FR ? \
                           UNKNOWN : (type_of_segment & 7))

void
rules_test (tcb * thisdir, segment * pseg, seglen len, quadrant * pquad,
	    u_short this_ip_id, Bool pkt_already_seen, double recovery_time)
{
  double DeltaT2, RTO, Mean_RTT, RTT_min;
  char type_of_segment =
    real_rules_test (thisdir, pseg, len, pquad, this_ip_id, pkt_already_seen,
		     &recovery_time);
  tcb *otherdir;
  int dir, num_acked;
#ifdef LOG_OOO
  extern FILE *fp_dup_ooo_log;
#endif

  if (pkt_already_seen)
    {
      pseg->type_of_segment = type_of_segment;
      num_acked = (pseg->prev != NULL) ? pseg->prev->acked : 0;
    }
  else
    {
      pseg->prev->type_of_segment = type_of_segment;
      num_acked = (pseg->prev->prev != NULL) ? pseg->prev->prev->acked : 0;
    }
  /* LM added */

  dir = (&(thisdir->ptp->c2s)) == thisdir;
  otherdir = (dir == C2S) ? &(thisdir->ptp->s2c) : &(thisdir->ptp->c2s);

  DeltaT2 =
    time2double (current_time) - time2double (pquad->seglist_tail->time);

  Mean_RTT =
    Average (thisdir->rtt_sum,
	     thisdir->rtt_count) + Average (otherdir->rtt_sum,
					    otherdir->rtt_count);
  RTO =
    Mean_RTT +
    4 *
    (Stdev
     (thisdir->rtt_sum + otherdir->rtt_sum,
      thisdir->rtt_sum2 + otherdir->rtt_sum2,
      thisdir->rtt_count + otherdir->rtt_count));

  RTT_min = (double) (thisdir->rtt_min + otherdir->rtt_min);

#ifdef LOG_OOO
  if (type_of_segment != 0)
    {
      wfprintf (fp_dup_ooo_log, "T: %f ",
	       (elapsed (first_packet, current_time) / 1000.0));
      if (dir == C2S)
	{
	  wfprintf (fp_dup_ooo_log, "%s %s ",
		   HostName (thisdir->ptp->addr_pair.a_address),
		   ServiceName (thisdir->ptp->addr_pair.a_port));
	  wfprintf (fp_dup_ooo_log, "%s %s ",
		   HostName (thisdir->ptp->addr_pair.b_address),
		   ServiceName (thisdir->ptp->addr_pair.b_port));
	}
      else
	{
	  wfprintf (fp_dup_ooo_log, "%s %s ",
		   HostName (thisdir->ptp->addr_pair.b_address),
		   ServiceName (thisdir->ptp->addr_pair.b_port));
	  wfprintf (fp_dup_ooo_log, "%s %s ",
		   HostName (thisdir->ptp->addr_pair.a_address),
		   ServiceName (thisdir->ptp->addr_pair.a_port));
	}

      wfprintf (fp_dup_ooo_log,
	       "%lu %lu %d %d %u %d %u %d %lf %lf %lu %lf %lf %lf %d",
	       thisdir->data_pkts,
	       thisdir->data_bytes,
	       (type_of_segment & 15),
	       thisdir->fsack_req && otherdir->fsack_req,
	       thisdir->mss,
	       (dir == C2S),
	       (internal_dst),
	       thisdir->initialwin_bytes,
	       recovery_time / 1000.0,
	       DeltaT2 / 1000.0,
	       len, RTO / 1000.0, RTT_min / 1000.0, Mean_RTT / 1000.0,
	       num_acked);
      wfprintf (fp_dup_ooo_log, " %f %f %f %f\n", thisdir->srtt / 1000.0,
	       thisdir->rttvar / 1000.0, otherdir->srtt / 1000.0,
	       otherdir->rttvar / 1000.0);
    }

#endif

  if (internal_src && !internal_dst)
    {
      add_histo (tcp_anomalies_out, aggregateType (type_of_segment));
    }
  else if (!internal_src && internal_dst)
    {
      add_histo (tcp_anomalies_in, aggregateType (type_of_segment));
    }
#ifndef LOG_UNKNOWN
  else if (internal_src && internal_dst)
#else
  else
#endif
    {
      add_histo (tcp_anomalies_loc, aggregateType (type_of_segment));
    }
  if (dir == C2S)
    {
      add_histo (tcp_anomalies_c2s, aggregateType (type_of_segment));
    }
  else
    {
      add_histo (tcp_anomalies_s2c, aggregateType (type_of_segment));
    }

/* just keep the main classification  and discard bit larger than
   BATCH_CLASSIFICATION*/
  switch (type_of_segment & (BATCH_CLASSIFICATION - 1))
    {
    case IN_SEQUENCE:
      /* just ignore them */
      break;
    case RETRANSMISSION_RTO:
      thisdir->rtx_RTO++;
      break;
    case RETRANSMISSION_FR:
      thisdir->rtx_FR++;
      break;
    case REORDERING:
      thisdir->reordering++;
      break;
    case NETWORK_DUPLICATE:
      thisdir->net_dup++;
      break;
    case FLOW_CONTROL:
      thisdir->flow_control++;
      break;
    case UNNECESSARY_RETRANSMISSION_FR:
      thisdir->unnecessary_rtx_FR++;
      break;
    case UNNECESSARY_RETRANSMISSION_RTO:
      thisdir->unnecessary_rtx_RTO++;
      break;
    default:
      thisdir->unknown++;
    }
}
