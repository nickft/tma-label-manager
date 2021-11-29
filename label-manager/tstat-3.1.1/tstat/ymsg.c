#include "tstat.h"
#include "ymsg.h"
#include "tcpL7.h"

#ifdef YMSG_CLASSIFIER
/* define YMSG_DEBUG if you want to get more info */
/* #define YMSG_DEBUG */

extern FILE *fp_chat_logc;
extern FILE *fp_chat_log_msg;

win_stat ymsg_chat_number;
win_stat ymsg_presence_number;

void
init_ymsg ()
{
  AVE_init (&ymsg_chat_number, "YMSG chat", current_time);
  AVE_init (&ymsg_presence_number, "YMSG presence", current_time);
}

u_int32_t
FindConTypeYmsg (tcp_pair * ptp, struct ip *pip, struct tcphdr *ptcp,
		 void *plast, int dir)
{
  void *pdata;			/* start of TCP payload */
  tcb *tcp_stats;

  pdata = (char *) ptcp + ptcp->th_off * 4;
  unsigned int payload_len = getpayloadlength (pip, plast) - ptcp->th_off * 4;

  if (dir == C2S)
    tcp_stats = &(ptp->c2s);
  else
    tcp_stats = &(ptp->s2c);


  if ((char *) pdata + 4 > (char *) plast)
    return -1;

  switch (*((u_int32_t *) pdata))
    {

    case YMSG:
      if (tcp_stats->ymsg.YFT == YFT_UNKNOWN)
	ptp->c2s.ymsg.YFT = ptp->s2c.ymsg.YFT = YMSG_YMSG;
      if ((char *) pdata + 12 > (char *) plast)
	return -1;

      switch (*((u_int8_t *) (pdata + 11)))
	{

	case 0x54:		/* AUTH_RESP --> PRESENCE (C2S) */
	  // tcp_stats->ymsg.login = current_time;
	  tcp_stats->ymsg.YMSG_AUTH_RESP_count = 1;

	  return 0x54;
	  break;

	case 0x55:		/* LIST --> PRESENCE (S2C) */
	  tcp_stats->ymsg.YMSG_LIST_count = 1;

	  return 0x55;
	  break;

	case 0x15:		/* SKINNAME (C2S) */
	  tcp_stats->ymsg.YMSG_SKINNAME_count = 1;

	  return 0x15;
	  break;

	case 0x4b:		/* NOTIFY: typing a message --> CHAT */
	  tcp_stats->ymsg.YMSG_NOTIFY_count++;

	  return 0x4b;
	  break;

	case 0x06:		/* MESSAGE --> CHAT */
	  tcp_stats->ymsg.YMSG_MESSAGE_count++;

	  if (LOG_IS_ENABLED(LOG_CHAT_MESSAGES) && fp_chat_log_msg != NULL)
	    {
#if(BYTE_ORDER == BIG_ENDIAN)
	      wfprintf (fp_chat_log_msg,
		       "%ld MESSAGE %d %d %d %f %.3f %d\n", ptp->id_number,
		       dir, *((u_int16_t *) (pdata + 8)), payload_len,
		       time2double(ptp->first_time) / 1000.0 / 1000.0,
		       elapsed (ptp->first_time,
				current_time) / 1000.0 / 1000.0,
		       ptp->con_type);
#else
	      wfprintf (fp_chat_log_msg,
		       "%ld MESSAGE %d %d %d %f %.3f %d\n", ptp->id_number,
		       dir, *((u_int16_t *) (pdata + 9)), payload_len,
		       time2double(ptp->first_time) / 1000.0 / 1000.0,
		       elapsed (ptp->first_time,
				current_time) / 1000.0 / 1000.0,
		       ptp->con_type);
#endif
	    }

	  return 0x06;
	  break;

	case 0x4f:		/* P2P Request/Reply */
	  tcp_stats->ymsg.YMSG_P2Pcheck_count = 1;

	  return 0x4f;
	  break;

	case 0x4d:		/* P2P transfer */
	  tcp_stats->ymsg.YMSG_P2P_count = 1;

	  return 0x4d;
	  break;

	default:

	  return -1;
	  break;
	}

    default:

      return -1;
      break;
    }
  if (ptp->packets > MAX_UNKNOWN_PACKETS)
    ptp->state = IGNORE_FURTHER_PACKETS;
  return -1;
}

void
classify_ymsg_flow (tcp_pair * ptp, int dir)
{

  tcb *tcp_stats;
  int *YFT;

  if (dir == C2S)
    tcp_stats = &(ptp->c2s);
  else
    tcp_stats = &(ptp->s2c);

  /* try to classify this flow */
  YFT = &(tcp_stats->ymsg.YFT);

  if (*YFT == YMSG_PRESENCE)
    if (ptp->s2c.ymsg.YMSG_P2Pcheck_count)
      {
	/* *YFT = YMSG_P2P; force both to be the same */
	ptp->c2s.ymsg.YFT = ptp->s2c.ymsg.YFT = YMSG_P2P;
	AVE_departure (current_time, &ymsg_presence_number);
      }

  if (*YFT == YFT_UNKNOWN || *YFT == YMSG_YMSG || *YFT == YMSG_PRESENCE)
    if (tcp_stats->ymsg.YMSG_MESSAGE_count)
      {
	if (*YFT == YFT_UNKNOWN || *YFT == YMSG_YMSG)
	  ptp->c2s.ymsg.YFT = ptp->s2c.ymsg.YFT = YMSG_CHAT;	/* *YFT = YMSG_CHAT; force both to be the same */
	else
	  ptp->c2s.ymsg.YFT = ptp->s2c.ymsg.YFT = YMSG_PRESENCE_CHAT;
	AVE_arrival (current_time, &ymsg_chat_number);
	//  ptp->c2s.ymsg.arrived = ptp->s2c.ymsg.arrived = 1;

      }

  if (*YFT == YFT_UNKNOWN || *YFT == YMSG_YMSG)
    if (tcp_stats->ymsg.YMSG_AUTH_RESP_count)
      {
	/* *YFT = YMSG_PRESENCE; force both to be the same */
	ptp->c2s.ymsg.YFT = ptp->s2c.ymsg.YFT = YMSG_PRESENCE;
	AVE_arrival (current_time, &ymsg_presence_number);
	//  ptp->c2s.ymsg.arrived = ptp->s2c.ymsg.arrived = 1;
      }

  return;

}

void
print_ymsg_conn_stats (tcp_pair *ptp)
{
  tcb *thisTdir;
  struct ymsg_stat *pymsg;

  /* C2S */
  thisTdir = &(ptp->c2s);
  pymsg = &thisTdir->ymsg;

  if (pymsg->YFT == YMSG_CHAT)
    AVE_departure (current_time, &ymsg_chat_number);
  else if (pymsg->YFT == YMSG_PRESENCE)
    AVE_departure (current_time, &ymsg_presence_number);
  else if (pymsg->YFT == YMSG_PRESENCE_CHAT)
    {
      AVE_departure (current_time, &ymsg_chat_number);
      AVE_departure (current_time, &ymsg_presence_number);
    }
  else if (pymsg->YFT == YFT_UNKNOWN)
    return;

  if (!LOG_IS_ENABLED(LOG_CHAT_COMPLETE) || fp_chat_logc == NULL)
    return;

  //     #   Field Meaning
  //    --------------------------------------
  //     1   Client IP Address
  //     2   Client Port

  if (ptp->crypto_src==FALSE)
     wfprintf (fp_chat_logc, "%s %s", HostName (ptp->addr_pair.a_address),
	   ServiceName (ptp->addr_pair.a_port));
  else
     wfprintf (fp_chat_logc, "%s %s", HostNameEncrypted (ptp->addr_pair.a_address),
	   ServiceName (ptp->addr_pair.a_port));

  //     3   Flow Size [Bytes] 
  /*                            sum of TCP payload length excluding SYN/FIN and rexmits */
  wfprintf (fp_chat_logc, " %lu", thisTdir->unique_bytes);

  //     4   No. of Total flow packets
  wfprintf (fp_chat_logc, " %ld", thisTdir->packets);

  //     5   No. of total messages
  wfprintf (fp_chat_logc, " %d 0 0 0 0 0", pymsg->YMSG_MESSAGE_count);


  /* S2C */
  thisTdir = &(ptp->s2c);
  pymsg = &thisTdir->ymsg;

  //     6   Server IP Address
  //     7   Server Port

  if (ptp->crypto_dst==FALSE)
     wfprintf (fp_chat_logc, " %s %s", HostName (ptp->addr_pair.b_address),
	   ServiceName (ptp->addr_pair.b_port));
  else
     wfprintf (fp_chat_logc, " %s %s", HostNameEncrypted (ptp->addr_pair.b_address),
	   ServiceName (ptp->addr_pair.b_port));

  //     8   Flow Size [Bytes] 
  //                            sum of IP packets length (Hdr IP + Payload IP) 
  //wfprintf (fp_chat_logc, " %lu", thisTdir->ip_bytes);

  //                            sum of TCP payload length excluding SYN/FIN and rexmits
  wfprintf (fp_chat_logc, " %lu", thisTdir->unique_bytes);

  //     9   No. of Total flow packets
  wfprintf (fp_chat_logc, " %ld", thisTdir->packets);

  //    10   No. of total messages
  wfprintf (fp_chat_logc, " %d 0 0 0 0 0", pymsg->YMSG_MESSAGE_count);

  //    11   Flow Start Time
  //    12   Flow End Time

  wfprintf (fp_chat_logc, " %f %.3f",
	   1e-6 * time2double (ptp->first_time),
	   elapsed (ptp->first_time, ptp->last_time) / 1000.0 / 1000.0);

  //    13   YMSG Flow Type
  wfprintf (fp_chat_logc, " %d", pymsg->YFT);

  //    14   YMSG Protocol Version
  wfprintf (fp_chat_logc, " %d", pymsg->YMSGPversion);

  //    15  Client address is internal ? (0=no, 1=yes)
  //    16  TCP Flow ID Number
  //    17  T     [label to state a TCP flow]
  //    18  Type of Upper level Protocol        

  wfprintf (fp_chat_logc, " %d %ld T %d", ptp->internal_dst,
	   ptp->id_number, ptp->con_type);

  wfprintf (fp_chat_logc, " %d %d", ptp->crypto_src, ptp->crypto_dst);

//  if (debug > 2)
//    wfprintf (fp_chat_logc, " %d %d", pymsg->arrived, pymsg->departed);

#ifdef YMSG_DEBUG

  //    11  YMSG_AUTH_RESP
  //    12  YMSG_LIST
  //    13  YMSG_SKINNAME
  //    14  YMSG_NOTIFY
  //    15  YMSG_MESSAGE

  wfprintf (fp_chat_logc, " AUTH_RESP: %d LIST: %d SKINNAME: %d NOTIFY: %d MESSAGE: %d",
     pymsg->YMSG_AUTH_RESP_count,
     pymsg->YMSG_LIST_count,
     pymsg->YMSG_SKINNAME_count,
     pymsg->YMSG_NOTIFY_count, pymsg->YMSG_MESSAGE_count);
#endif

  wfprintf (fp_chat_logc, "\n");

}

void
ymsg_get_average ()
{
  set_histo (chat_flow_num, YMSG_CHAT_HISTO,
	     AVE_get_stat (current_time, &ymsg_chat_number));
  set_histo (chat_flow_num, YMSG_PRESENCE_HISTO,
	     AVE_get_stat (current_time, &ymsg_presence_number));
}


#endif

/*  END  */
/**************************************************************************************/
