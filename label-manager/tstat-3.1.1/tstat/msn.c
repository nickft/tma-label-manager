#include "tstat.h"
#include "msn.h"
#include "tcpL7.h"

#ifdef MSN_CLASSIFIER
/* define MSN_DEBUG if you want to get more info */
/* #define MSN_DEBUG */

extern FILE *fp_chat_logc;
extern FILE *fp_chat_log_msg;
extern FILE *fp_msn_log_othercomm;

char find_MSG_type (void *MSG_type, tcb * tcp_stats);

win_stat msn_chat_number;
win_stat msn_presence_number;

void
init_msn ()
{
  AVE_init (&msn_chat_number, "MSN chat", current_time);
  AVE_init (&msn_presence_number, "MSN presence", current_time);
}

u_int32_t
FindConTypeMsn (tcp_pair * ptp, struct ip *pip, struct tcphdr *ptcp,
		void *plast, int dir)
{
  char type = '?';
  void *pdata;			/* start of payload */
  int msg_len;
  char buffer[20];              /* buffer for the MSG header analysis*/
#ifdef MSN_OTHER_COMMANDS
  char new_comm[4];
#endif

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
    case VER:
      tcp_stats->msn.login = current_time;
      tcp_stats->msn.MSN_VER_count = 1;
      return VER;
      break;

    case CVR:
      tcp_stats->msn.MSN_CVR_count = 1;
      return CVR;
      break;

    case USR:
      tcp_stats->msn.MSN_USR_count = 1;
      return USR;
      break;

    case XFR:
      tcp_stats->msn.MSN_XFR_count = 1;
      return XFR;
      break;

    case PNG:
      tcp_stats->msn.MSN_PNG_count++;
      return PNG;
      break;

    case QNG:
      tcp_stats->msn.MSN_QNG_count++;
      return QNG;
      break;

    case CHL:
      tcp_stats->msn.MSN_CHL_count++;
      return CHL;
      break;

    case QRY:
      tcp_stats->msn.MSN_QRY_count++;
      return QRY;
      break;

    case CAL:
      tcp_stats->msn.MSN_CAL_count++;
      return CAL;
      break;

    case JOI:
      tcp_stats->msn.start_chat = current_time;
      tcp_stats->msn.MSN_JOI_count++;
      return JOI;
      break;

    case RNG:
      tcp_stats->msn.MSN_RNG_count = 1;
      return RNG;
      break;

    case ANS:
      tcp_stats->msn.MSN_ANS_count = 1;
      return ANS;
      break;

    case IRO:
      tcp_stats->msn.start_chat = current_time;
      tcp_stats->msn.MSN_IRO_count = 1;
      return IRO;
      break;

    case MSG:
      tcp_stats->msn.MSN_MSG_count++;

      char *msg_base = (char *) pdata + 4;
      int available_payload = (char *) plast - (char *)msg_base;

      if (available_payload < 1)
         return MSG;

      memset(buffer,0,sizeof(buffer));   
      memcpy(buffer,msg_base,(size_t)min(available_payload,19));
 
      if ( strlen(buffer)>=3 )
       {
         int trID,mresult,mlen;
         char mtype;
         mresult = sscanf(buffer,"%d %c %d",&trID,&mtype,&mlen);
         
         if (mresult>1)
          {
            type = find_MSG_type (&mtype, tcp_stats);
          }

         if (dir==C2S && type!='?' && mresult==3)
          {
            msg_len = mlen;
          }
         else
            msg_len = -1;
       }
      else
        msg_len = -1;

      if (LOG_IS_ENABLED(LOG_CHAT_MESSAGES) && fp_chat_log_msg != NULL) 
	{

	  wfprintf (fp_chat_log_msg,
		   "%ld MSG_%c %d %d %d %f %.3f %d\n",
		   ptp->id_number,
		   type,
		   dir,
		   msg_len,
		   payload_len,
		   time2double(ptp->first_time) / 1000.0 / 1000.0,
		   elapsed (ptp->first_time, current_time) / 1000.0 / 1000.0,
		   ptp->con_type);
	}

      return MSG;
      break;

    case UUM:			/* MSG in case of chat with a Yahoo! Messenger user - C2S - */
      tcp_stats->msn.MSN_MSG_count++;
      tcp_stats->msn.MSN_MSG_Y_count++;
      if (LOG_IS_ENABLED(LOG_CHAT_MESSAGES) && fp_chat_log_msg != NULL) 
	{

	  wfprintf (fp_chat_log_msg,
		   "%ld MSG_Y %d ? %d %f %.3f %d\n",
		   ptp->id_number,
		   dir,
		   payload_len,
		   time2double(ptp->first_time) / 1000.0 / 1000.0,
		   elapsed (ptp->first_time, current_time) / 1000.0 / 1000.0,
		   ptp->con_type);
	}
      return UUM;
      break;

    case UBM:			/* MSG in case of chat with a Yahoo! Messenger user - S2C - */
      tcp_stats->msn.MSN_MSG_count++;
      tcp_stats->msn.MSN_MSG_Y_count++;
      if (LOG_IS_ENABLED(LOG_CHAT_MESSAGES) && fp_chat_log_msg != NULL)
	{
	  wfprintf (fp_chat_log_msg,
		   "%ld MSG_Y %d ? %d %f %.3f %d\n",
		   ptp->id_number,
		   dir,
		   payload_len,
		   time2double(ptp->first_time) / 1000.0 / 1000.0,
		   elapsed (ptp->first_time, current_time) / 1000.0 / 1000.0,
		   ptp->con_type);
	}
      return UBM;
      break;
/*
    case ACK:

      if (log_engine && fp_chat_log_msg != NULL)
	{
	  wfprintf (fp_chat_log_msg,
		   "%ld ACK %d 0 %d '%s' %.3f\n",
		   ptp->id_number,
		   dir,
		   payload_len,
		   ts2ascii (&ptp->first_time),
		   elapsed (ptp->first_time, current_time) / 1000.0 / 1000.0);
	}

      //  tcp_stats->msn.MSN_ACK_count = 1;
      return ACK;
      break;
*/
    case BYE:
      tcp_stats->msn.end_chat = current_time;
      tcp_stats->msn.MSN_BYE_count = 1;
      return BYE;
      break;

    case OUT:
      tcp_stats->msn.logout = current_time;
      tcp_stats->msn.MSN_OUT_count = 1;
      return OUT;
      break;

    case OUT_SB:
      tcp_stats->msn.logout = current_time;
      tcp_stats->msn.MSN_OUT_count = 1;
      return OUT_SB;
      break;

    default:
#ifdef MSN_OTHER_COMMANDS
      if (isupper (*((char *) pdata)) && isupper (*((char *) pdata + 1))
	  && isupper (*((char *) pdata + 2)))
	{
	  sscanf ((char *) (pdata), "%3s", new_comm);
	  if (LOG_IS_ENABLED(LOG_CHAT_MSNOTHER) && fp_msn_log_othercomm != NULL)
	    {
	      wfprintf (fp_msn_log_othercomm,
		       "%ld %s %d %d %f %.3f\n",
		       ptp->id_number,
		       new_comm,
		       dir,
		       payload_len,
		       time2double(ptp->first_time) / 1000.0 / 1000.0,
		       elapsed (ptp->first_time,
				current_time) / 1000.0 / 1000.0);
	    }
	}
#endif
      return -1;
      break;
    }

  if (ptp->packets > MAX_UNKNOWN_PACKETS)
    ptp->state = IGNORE_FURTHER_PACKETS;
  return -1;
}

void
classify_msn_flow (tcp_pair * ptp, int dir)
{

  tcb *tcp_stats;
  int *MFT;

  if (dir == C2S)
    tcp_stats = &(ptp->c2s);
  else
    tcp_stats = &(ptp->s2c);

  /* try to classify this flow */
  MFT = &(tcp_stats->msn.MFT);

  if (*MFT == MFT_UNKNOWN || *MFT == MSN_LOGIN || *MFT == MSN_HTTP_TUNNELING)
    {
      if (tcp_stats->msn.MSN_MSG_count && *MFT != MSN_LOGIN )
	{
	  /* *MFT = MSN_CHAT; force both to be the same */
	  ptp->c2s.msn.MFT = ptp->s2c.msn.MFT = MSN_CHAT;
	  AVE_arrival (current_time, &msn_chat_number);
	  //  ptp->c2s.msn.arrived = ptp->s2c.msn.arrived = 1;

	}

      if (tcp_stats->msn.MSN_VER_count)
	{
	  if (tcp_stats->msn.MSN_USR_count)
	    {
	      /* *MFT = MSN_PRESENCE; force both to be the same */
	      ptp->c2s.msn.MFT = ptp->s2c.msn.MFT = MSN_PRESENCE;
	      AVE_arrival (current_time, &msn_presence_number);
	      //  ptp->c2s.msn.arrived = ptp->s2c.msn.arrived = 1;
	    }
	  else
	    /* *MFT = MSN_LOGIN; force both to be the same */
	    ptp->c2s.msn.MFT = ptp->s2c.msn.MFT = MSN_LOGIN;
	}

/* do not distinguish further chat sessions 
   if (dir == S2C)
     {
       if (! tcp_stats->msn.MSN_VER_count)
       {
         if (tcp_stats->msn.MSN_JOI_count && !tcp_stats->msn.MSN_IRO_count)
	   *MFT = MSN_CHAT_CALLER;
         else if (tcp_stats->msn.MSN_IRO_count)
	   *MFT = MSN_CHAT_CALLED;
	}
   else
     {
       if (! tcp_stats->msn.MSN_VER_count)
	 {
	   if (tcp_stats->msn.MSN_CAL_count && !tcp_stats->msn.MSN_ANS_count)
	     *MFT = MSN_CHAT_CALLER;
	   else if (tcp_stats->msn.MSN_ANS_count)
	     *MFT = MSN_CHAT_CALLED;
	 }	 
*/
    }
  /* chat session with a Yahoo! user */
  if (*MFT == MSN_PRESENCE
      && (!ptp->c2s.msn.arrived || !ptp->s2c.msn.arrived))
    if (tcp_stats->msn.MSN_MSG_Y_count)
      {
	AVE_arrival (current_time, &msn_chat_number);
	ptp->c2s.msn.arrived = ptp->s2c.msn.arrived = 1;
      }

  return;
}

char
find_MSG_type (void *MSG_type, tcb * tcp_stats)
{
  char t = *((char *) (MSG_type));

  switch (t)
    {
    case 'A':
      tcp_stats->msn.MSN_MSG_A_count++;
      break;
    case 'D':
      tcp_stats->msn.MSN_MSG_D_count++;
      break;
    case 'N':
      tcp_stats->msn.MSN_MSG_N_count++;
      break;
    case 'U':
      tcp_stats->msn.MSN_MSG_U_count++;
      break;
    default:
      return '?';
      break;

    }
  return t;
}


void
print_msn_conn_stats (tcp_pair *ptp)
{
  tcb *thisTdir;
  struct msn_stat *pmsn;

  /* C2S */
  thisTdir = &(ptp->c2s);
  pmsn = &thisTdir->msn;

  if (pmsn->MFT == MSN_CHAT)
    AVE_departure (current_time, &msn_chat_number);
  else if (pmsn->MFT == MSN_PRESENCE)
   { 
     AVE_departure (current_time, &msn_presence_number);

     /* chat session with Yahoo! user */
      if (pmsn->MSN_MSG_Y_count)
         AVE_departure (current_time, &msn_chat_number);
    }
  else if (pmsn->MFT == MFT_UNKNOWN)
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
  //     6   No. of MSG_A
  //     7   No. of MSG_D
  //     8   No. of MSG_N
  //     9   No. of MSG_U
  //    10   No. of MSG_Y

  wfprintf (fp_chat_logc, " %d %d %d %d %d %d", pmsn->MSN_MSG_count,
	   pmsn->MSN_MSG_A_count, pmsn->MSN_MSG_D_count,
	   pmsn->MSN_MSG_N_count, pmsn->MSN_MSG_U_count,
	   pmsn->MSN_MSG_Y_count);


  /* S2C */
  thisTdir = &(ptp->s2c);
  pmsn = &thisTdir->msn;

  //    11   Server IP Address
  //    12   Server Port

  if (ptp->crypto_dst==FALSE)
     wfprintf (fp_chat_logc, " %s %s", HostName (ptp->addr_pair.b_address),
	   ServiceName (ptp->addr_pair.b_port));
  else
     wfprintf (fp_chat_logc, " %s %s", HostNameEncrypted (ptp->addr_pair.b_address),
	   ServiceName (ptp->addr_pair.b_port));

  //    13   Flow Size [Bytes] 
  //                            sum of TCP payload length excluding SYN/FIN and rexmits
  wfprintf (fp_chat_logc, " %lu", thisTdir->unique_bytes);

  //    14   No. of Total flow packets
  wfprintf (fp_chat_logc, " %ld", thisTdir->packets);

  //    15   No. of total messages
  //    16   No. of MSG_A
  //    17   No. of MSG_D
  //    18   No. of MSG_N
  //    19   No. of MSG_U
  //    20   No. of MSG_Y

  wfprintf (fp_chat_logc, " %d %d %d %d %d %d", pmsn->MSN_MSG_count,
	   pmsn->MSN_MSG_A_count, pmsn->MSN_MSG_D_count,
	   pmsn->MSN_MSG_N_count, pmsn->MSN_MSG_U_count,
	   pmsn->MSN_MSG_Y_count);

  //    21   Flow Start Time
  //    22   Flow End Time

  wfprintf (fp_chat_logc, " %f %.3f",
	   1e-6 * time2double (ptp->first_time),
	   elapsed (ptp->first_time, ptp->last_time) / 1000.0 / 1000.0);

  //    23   MSN Flow Type
  wfprintf (fp_chat_logc, " %d", pmsn->MFT);

  //    24   MSN Protocol Version
  if (pmsn->MFT == MSN_CHAT)
    wfprintf (fp_chat_logc, " %s", "UNK");
  else
    wfprintf (fp_chat_logc, " %s", pmsn->MSNPversion);

  //    25  Client address is internal ? (0=no, 1=yes)
  //    26  TCP Flow ID Number
  //    27  T     [label to state a TCP flow]
  //    28  Type of Upper level Protocol

  wfprintf (fp_chat_logc, " %d %ld T %d", ptp->internal_dst,
	   ptp->id_number, ptp->con_type);

  wfprintf (fp_chat_logc, " %d %d", ptp->crypto_src, ptp->crypto_dst);

  // if (debug > 2)
  //   wfprintf (fp_chat_logc, " %d %d", pmsn->arrived, pmsn->departed);

#ifdef MSN_DEBUG

  //    11  MSN_VER
  //    12  MSN_CVR
  //    13  MSN_USR
  //    14  MSN_XFR
  //    15  MSN_GCF
  //    16  MSN_CHG
  //    17  MSN_CAL
  //    18  MSN_JOI
  //    19  MSN_RNG
  //    20  MSN_ANS
  //    21  MSN_IRO
  //    22  MSN_MSG
  //    23  MSN_BYE
  //    24  MSN_OUT

  wfprintf (fp_chat_logc, " VER: %d CVR: %d USR: %d XFR: %d GCF: %d PNG: %d QNG: %d CHL: %d QRY: %d CAL: %d JOI: %d RNG: %d ANS: %d IRO: %d MSG: %d BYE: %d OUT: %d POST: %d",
     pmsn->MSN_VER_count,
     pmsn->MSN_CVR_count,
     pmsn->MSN_USR_count,
     pmsn->MSN_XFR_count,
     pmsn->MSN_GCF_count,
     pmsn->MSN_PNG_count,
     pmsn->MSN_QNG_count,
     pmsn->MSN_CHL_count,
     pmsn->MSN_QRY_count,
     pmsn->MSN_CAL_count,
     pmsn->MSN_JOI_count,
     pmsn->MSN_RNG_count,
     pmsn->MSN_ANS_count,
     pmsn->MSN_IRO_count,
     pmsn->MSN_MSG_count, pmsn->MSN_BYE_count, pmsn->MSN_OUT_count,
     pmsn->POST_count);
#endif

  wfprintf (fp_chat_logc, "\n");

}

void
msn_get_average ()
{
  set_histo (chat_flow_num, MSN_CHAT_HISTO,
	     AVE_get_stat (current_time, &msn_chat_number));
  set_histo (chat_flow_num, MSN_PRESENCE_HISTO,
	     AVE_get_stat (current_time, &msn_presence_number));
}


#endif

/*  END  */
/**************************************************************************************/
