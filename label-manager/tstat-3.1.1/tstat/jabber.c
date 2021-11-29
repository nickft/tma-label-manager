#include "tstat.h"
#include "jabber.h"
#include "tcpL7.h"

#ifdef XMPP_CLASSIFIER
/* define XMPP_DEBUG if you want to get more info */
/* #define XMPP_DEBUG */

extern FILE *fp_chat_logc;
extern FILE *fp_chat_log_msg;

win_stat jabber_chat_number;
win_stat jabber_presence_number;

void
init_jabber ()
{
  AVE_init (&jabber_chat_number, "Jabber chat", current_time);
  AVE_init (&jabber_presence_number, "Jabber presence", current_time);
}

u_int32_t
FindConTypeJabber (tcp_pair * ptp, struct ip *pip, struct tcphdr *ptcp,
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

  if (!strncmp
      ("<presence", (char *) pdata,
       min (strlen ("<presence"), strlen ((char *) pdata))))
    {
      tcp_stats->jabber.PRESENCE_count = 1;
      return XMPP_PRESENCE;
    }

  if (!strncmp
      ("<message ", (char *) pdata,
       min (strlen ("<message "), strlen ((char *) pdata))))
    {
      if (tcp_stats->jabber.JFT == JABBER_PRESENCE
	  || tcp_stats->jabber.JFT == JABBER_CHAT)
	{
	  tcp_stats->jabber.MESSAGE_count++;
	  if (LOG_IS_ENABLED(LOG_CHAT_MESSAGES) && fp_chat_log_msg != NULL)
	    {
	      wfprintf (fp_chat_log_msg,
		       "%ld MESSAGE %d ? %d %f %.3f %d\n",
		       ptp->id_number,
		       dir,
		       payload_len,
		       time2double(ptp->first_time) / 1000.0 / 1000.0,
		       elapsed (ptp->first_time,
				current_time) / 1000.0 / 1000.0,
		       ptp->con_type);
	    }
	}
      return XMPP_MESSAGE;
    }

  return -1;

  if (ptp->packets > MAX_UNKNOWN_PACKETS)
    ptp->state = IGNORE_FURTHER_PACKETS;
  return -1;
}

void
classify_jabber_flow (tcp_pair * ptp, int dir)
{

  tcb *tcp_stats;
  int *JFT;

  if (dir == C2S)
    tcp_stats = &(ptp->c2s);
  else
    tcp_stats = &(ptp->s2c);

  /* try to classify this flow */
  JFT = &(tcp_stats->jabber.JFT);

  if (*JFT == JABBER_PRESENCE)
    if (tcp_stats->jabber.MESSAGE_count)
      {
	/* *JFT = JABBER_CHAT; force both to be the same */
	ptp->c2s.jabber.JFT = ptp->s2c.jabber.JFT = JABBER_CHAT;
	AVE_arrival (current_time, &jabber_chat_number);
	//  ptp->c2s.jabber.arrived = ptp->s2c.jabber.arrived = 1;
      }

  if (*JFT == JFT_UNKNOWN)
    if (tcp_stats->jabber.PRESENCE_count)
      {
	/* *JFT = JABBER_PRESENCE; force both to be the same */
	ptp->c2s.jabber.JFT = ptp->s2c.jabber.JFT = JABBER_PRESENCE;
	AVE_arrival (current_time, &jabber_presence_number);
	//  ptp->c2s.jabber.arrived = ptp->s2c.jabber.arrived = 1;
      }

  return;

}

void
print_jabber_conn_stats (tcp_pair *ptp)
{
  tcb *thisTdir;
  struct jabber_stat *pjabber;

  /* C2S */
  thisTdir = &(ptp->c2s);
  pjabber = &thisTdir->jabber;

  if (pjabber->JFT == JABBER_CHAT)
    {
      AVE_departure (current_time, &jabber_chat_number);
      AVE_departure (current_time, &jabber_presence_number);
    }
  else if (pjabber->JFT == JABBER_PRESENCE)
    AVE_departure (current_time, &jabber_presence_number);
  else if (pjabber->JFT == JFT_UNKNOWN)
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

  wfprintf (fp_chat_logc, " %d 0 0 0 0 0", pjabber->MESSAGE_count);

  /* S2C */
  thisTdir = &(ptp->s2c);
  pjabber = &thisTdir->jabber;

  //     6   Server IP Address
  //     7   Server Port

  if (ptp->crypto_dst==FALSE)
     wfprintf (fp_chat_logc, " %s %s", HostName (ptp->addr_pair.b_address),
	   ServiceName (ptp->addr_pair.b_port));
  else
     wfprintf (fp_chat_logc, " %s %s", HostNameEncrypted (ptp->addr_pair.b_address),
	   ServiceName (ptp->addr_pair.b_port));

  //     8   Flow Size [Bytes] 
  /*                            sum of TCP payload length excluding SYN/FIN and rexmits */
  wfprintf (fp_chat_logc, " %lu", thisTdir->unique_bytes);

  //     9   No. of Total flow packets
  wfprintf (fp_chat_logc, " %ld", thisTdir->packets);

  //    10   No. of total messages

  wfprintf (fp_chat_logc, " %d 0 0 0 0 0", pjabber->MESSAGE_count);

  //    11   Flow Start Time
  //    12   Flow End Time

  wfprintf (fp_chat_logc, " %f %.3f",
	   1e-6 * time2double (ptp->first_time),
	   elapsed (ptp->first_time, ptp->last_time) / 1000.0 / 1000.0);

  //    13   Jabber Flow Type
  wfprintf (fp_chat_logc, " %d", pjabber->JFT);

  //    14   Jabber Protocol Version
  wfprintf (fp_chat_logc, " %s", "UNK");

  //    15  Client address is internal ? (0=no, 1=yes)
  //    16  TCP Flow ID Number
  //    17  T     [label to state a TCP flow]
  //    18  Type of Upper level Protocol

  wfprintf (fp_chat_logc, " %d %ld T %d", ptp->internal_dst,
	   ptp->id_number, ptp->con_type);

  wfprintf (fp_chat_logc, " %d %d", ptp->crypto_src, ptp->crypto_dst);

//  if (debug > 2)
//    wfprintf (fp_chat_logc, " %d %d", pjabber->arrived, pjabber->departed);

#ifdef XMPP_DEBUG

  //    11  PRESENCE
  //    12  MESSAGE

  wfprintf (fp_chat_logc, " PRESENCE: %d MESSAGE: %d",
     pjabber->PRESENCE_count, pjabber->MESSAGE_count);
#endif

  wfprintf (fp_chat_logc, "\n");

}

void
jabber_get_average ()
{
  set_histo (chat_flow_num, JABBER_CHAT_HISTO,
	     AVE_get_stat (current_time, &jabber_chat_number));
  set_histo (chat_flow_num, JABBER_PRESENCE_HISTO,
	     AVE_get_stat (current_time, &jabber_presence_number));
}


#endif

/*  END  */
/**************************************************************************************/
