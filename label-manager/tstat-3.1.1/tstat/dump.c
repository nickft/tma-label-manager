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
#include "dump.h"
#include "tcpdump.h"
#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <sys/stat.h>
#include <time.h>
#include "p2p.h"
#include "names.h"

/* Note: 
 * is NOT possible to use libpcap writing functions because 
 * they use opaque structures that are availables only compiling
 * library sources. To bypass this problem, files are generated
 * using fwrite() and respecting pcap file format deduced from 
 * library sources.
 */

/* DUMP_WINDOW_SIZE control the traffic splitting of each application traffic
* creating a new dump file if between the current and the previous packet are
* elapsed more than the specifed value of usec
*/
//60min = 60 * 60 * 1000000usec
//#define DUMP_WINDOW_SIZE 3600000000UL
#define DUMP_WINDOW_SIZE -1

#define DUMP_DIR_BASENAME "traces"
#define DUMP_LOG_FNAME "log.txt"

struct dump_file {
    FILE            *fp;
    char            *protoname;
    struct timeval  win_start;
    Bool            enabled;
    int             type;
    int             seq_num;
};

enum dump_proto_index{
    /* all indexes lower than LAST_UDP_PROTOCOL are UDP_XXX types 
       to add a new protocol simply add a new label before DUMP_PROTOS
    */
    DUMP_IP_COMPLETE = LAST_UDP_PROTOCOL,
    DUMP_UDP_COMPLETE,
    DUMP_TCP_VIDEOSTREAMING,
    DUMP_TCP_COMPLETE,
    DUMP_PROTOS
};
struct dump_file proto2dump[DUMP_PROTOS];

static struct ether_header eth_header;
static char *outdir;
static char *log_basedir = NULL;
static FILE *fp_log;
static timeval first_dump_tm;
static timeval last_dump_tm;
static int dir_counter = 0;
static int snap_len = 0;    //snapshot length of the packet to dump
                            //0 == the complete packet
static long slice_win = 0;   //each trace generated contains packet 
                            //in a time window (in sec) as big as the specified value

static long udp_maxbytes = 0;
static long tcp_maxbytes = 0;
static long udp_maxpackets = 0;
static long tcp_maxpackets = 0;
static u_int32_t stop_dumping_mask = 0;

extern char *dns_namefilter_file;
extern Bool dns_namefilter_specified;

Bool dump_engine = FALSE;
extern Bool zlib_dump;

int search_dump_file(char *protoname, struct dump_file *proto2dump) {
    int i = 0;
    for (i = 0; i < DUMP_PROTOS; i++) {
        if (proto2dump[i].protoname[0] != '\0' &&
            strcmp(protoname, proto2dump[i].protoname) == 0)
            break;
    }
    return ((i == DUMP_PROTOS) ? -1 : i);
}


FILE * new_dump_file(struct dump_file *dump_file) {
    FILE *fp;
    struct pcap_file_header hdr;
    char *fname;

    /* three possible format names are defined:
    * no slice_window :   udp_XXX.pcap
    * slice_window 1  :   udp_XXX"%02d".pcap  try to have ordered list of files
    * slice_window 2  :   udp_XXX"%d".pcap    
    */
#ifdef HAVE_ZLIB
    if (zlib_dump)
     {
       if (slice_win != 0) {
           if (dump_file->seq_num < 100)
               fname = sprintf_safe("%s/%s%02d.pcap.gz", outdir, 
        	   dump_file->protoname, dump_file->seq_num);	  
           else
               fname = sprintf_safe("%s/%s%d.pcap.gz", outdir, 
        	   dump_file->protoname, dump_file->seq_num);	  
       }
       else
           fname = sprintf_safe("%s/%s.pcap.gz", outdir, dump_file->protoname);  

       fp = gzopen(fname, "w");
      }
    else
#endif
     {
       if (slice_win != 0) {
           if (dump_file->seq_num < 100)
               fname = sprintf_safe("%s/%s%02d.pcap", outdir, 
        	   dump_file->protoname, dump_file->seq_num);	  
           else
               fname = sprintf_safe("%s/%s%d.pcap", outdir, 
        	   dump_file->protoname, dump_file->seq_num);	  
       }
       else
           fname = sprintf_safe("%s/%s.pcap", outdir, dump_file->protoname);  

       fp = fopen(fname, "w");
      }
    
    if (fp == NULL) {
        fprintf(fp_stderr, "dump engine: unable to create '%s'\n", fname);
        exit(1);
    }

    // this code comes from libpcap sources!!!
    // (TCPDUMP_MAGIC is defined in tcpdump.h)
    hdr.magic = TCPDUMP_MAGIC;
    hdr.version_major = PCAP_VERSION_MAJOR;
    hdr.version_minor = PCAP_VERSION_MINOR;
    hdr.thiszone = 0;	            /* fake info */
    hdr.snaplen = 1000000;	        /* fake info */
    hdr.linktype = PCAP_DLT_EN10MB;	/* always Ethernet (10Mb) */
    hdr.sigfigs = 0;                /* fake info */
#ifdef HAVE_ZLIB
    if (zlib_dump)
     { 
       gzwrite(fp,(char *) &hdr, sizeof(hdr));
     }
    else 
#endif
     {   
       fwrite((char *) &hdr, sizeof(hdr), 1, fp);
     }
    return fp; 
}

//only for debug purpose
/*
void print_proto2dump(void) {
    int i, find;
    find = 0;
    for (i = 0; i < UDP_DPI_PROTOCOL; i++) {
        if (udp_dump_protos[i].enabled) {
            find = 1;
            fprintf(fp_stdout, "protoname: %s\n", udp_dump_protos[i].protoname);
        }
    }

    if (!find) {
        fprintf(fp_stdout, "no protocol dump enabled\n");
    }
}
*/

void dump_reset_dump_file(struct dump_file *proto2dump, int type, char *protoname) {
    proto2dump[type].fp = NULL;
    proto2dump[type].protoname = protoname;
    proto2dump[type].win_start.tv_sec = -1;
    proto2dump[type].win_start.tv_usec = -1;
    proto2dump[type].enabled = FALSE;
    proto2dump[type].type = type;
    proto2dump[type].seq_num = 0;
}

void dump_parse_ini_arg(char *param_name, param_value param_value) {
    int pos;

    if (param_value.type!=INTEGER) 
     {
       fprintf(fp_stderr, "dump engine: not integer value assigned to '%s'\n", 
                param_name);
       exit(1);
     }
        
    //check protocol name 
    pos = search_dump_file(param_name, proto2dump);
    if (pos != -1) {
        //syntax check
        if (param_value.value.ivalue != 0 && param_value.value.ivalue != 1) {
            fprintf(fp_stderr, "dump engine: '%s = %d' syntax error in config file\n", 
                param_name, param_value.value.ivalue);
            exit(1);
        }

        if (debug)
            fprintf(fp_stderr, "dump engine: %s dump for %s\n", 
                (param_value.value.ivalue == 1) ? "enabling" : "disabling",
                proto2dump[pos].protoname);
        proto2dump[pos].enabled = (param_value.value.ivalue == 0) ? FALSE : TRUE;
        dump_engine |= param_value.value.ivalue;
    }
    else if (strcmp(param_name, "snap_len") == 0) {
        if (param_value.value.ivalue < 0) {
            fprintf(fp_stderr, "dump engine: '%s = %d' syntax error in config file\n", 
                param_name, param_value.value.ivalue);
            exit(1);
        }
        snap_len = param_value.value.ivalue;
    }
    else if (strcmp(param_name, "slice_win") == 0) {
        if (param_value.value.ivalue < 0) {
            fprintf(fp_stderr, "dump_engine: '%s = %d' syntax error in config file\n",
                param_name, param_value.value.ivalue);
            exit(1);
        }
        slice_win = param_value.value.ivalue;
    }
    else if (strcmp(param_name, "tcp_maxpackets") == 0) {
        if (param_value.value.ivalue > 0) {
            tcp_maxpackets = param_value.value.ivalue;
        }
    }
    else if (strcmp(param_name, "tcp_maxbytes") == 0) {
        if (param_value.value.ivalue > 0) {
            tcp_maxbytes = param_value.value.ivalue;
        }
    }
    else if (strcmp(param_name, "udp_maxpackets") == 0) {
        if (param_value.value.ivalue > 0) {
            udp_maxpackets = param_value.value.ivalue;
        }
    }
    else if (strcmp(param_name, "udp_maxbytes") == 0) {
        if (param_value.value.ivalue > 0) {
            udp_maxbytes = param_value.value.ivalue;
        }
    }
    else if (strcmp(param_name, "stop_dumping_mask") == 0) {
        if (param_value.value.ivalue > 0) {
            stop_dumping_mask = param_value.value.ivalue;
        }
    }
    else if (strcmp(param_name, "dns_filter") == 0) {
#ifdef DNS_CACHE_PROCESSOR
        if (param_value.value.ivalue > 0) 
         {
           if (!dns_namefilter_specified)
            {
              fprintf(fp_stderr, "dump engine warning: no file provided for the DNS filter engine. Using the default values.\n");
            }
           enable_DNSfilter(TRUE);
         }
        else
           enable_DNSfilter(FALSE);
#endif
    }
    else {
        fprintf(fp_stderr, "dump engine err: '%s' - not valid command \n", param_name);
        exit(1);
    }
}

// this function is called the first time by the plugin system; 
// after by the dump_restart() every time the runtime configuration file is modified
void dump_init(void) {
    int i;

    dump_engine = FALSE;
    tcp_maxpackets = 0;
    udp_maxpackets = 0;
    tcp_maxbytes = 0;
    udp_maxbytes = 0;
    stop_dumping_mask = 0;
#ifdef DNS_CACHE_PROCESSOR
    if (dns_namefilter_specified)
     {
       if(!init_DNSfilter(dns_namefilter_file, TRUE)) 
        {
          fprintf(fp_stderr, "dump engine err: Problem in initializing the DNS filter engine\n");
          exit(1);
        }
     }   
    else
#endif
     {
       init_DNSfilter("", FALSE);
     }
    /* UDP dump protocols 
     * for semplicity we use a vector with as long as the number of classes
     * identified by the DPI. Among these there are some useless classes
     * (FIRST_RTP for example) so we REALLY register in the vector only 
     * a subset of the complete list of classes. 
     * */
    for (i = 0; i < DUMP_PROTOS; i++) {
        dump_reset_dump_file(proto2dump, i, "");
    }
    dump_reset_dump_file(proto2dump, UDP_UNKNOWN, "udp_unknown");
    dump_reset_dump_file(proto2dump, RTP, "udp_rtp");
    dump_reset_dump_file(proto2dump, RTCP, "udp_rtcp");
    dump_reset_dump_file(proto2dump, P2P_EDK, "udp_edk");
    dump_reset_dump_file(proto2dump, P2P_KAD, "udp_kad");
    dump_reset_dump_file(proto2dump, P2P_KADU, "udp_kadu");
    dump_reset_dump_file(proto2dump, P2P_OKAD, "udp_okad");
    dump_reset_dump_file(proto2dump, P2P_GNU, "udp_gnutella");
    dump_reset_dump_file(proto2dump, P2P_BT, "udp_bittorrent");
    dump_reset_dump_file(proto2dump, P2P_DC, "udp_dc");
    dump_reset_dump_file(proto2dump, P2P_KAZAA, "udp_kazaa");
    dump_reset_dump_file(proto2dump, P2P_PPLIVE, "udp_pplive");
    dump_reset_dump_file(proto2dump, P2P_SOPCAST, "udp_sopcast");
    dump_reset_dump_file(proto2dump, P2P_TVANTS, "udp_tvants");
    dump_reset_dump_file(proto2dump, DNS, "udp_dns");
    dump_reset_dump_file(proto2dump, P2P_UTP, "udp_utp");
    dump_reset_dump_file(proto2dump, UDP_VOD, "udp_vod");
    dump_reset_dump_file(proto2dump, P2P_PPSTREAM, "udp_ppstream");
    dump_reset_dump_file(proto2dump, TEREDO, "udp_teredo");
    dump_reset_dump_file(proto2dump, UDP_SIP, "udp_sip");
    dump_reset_dump_file(proto2dump, UDP_DTLS, "udp_dtls");
    dump_reset_dump_file(proto2dump, UDP_QUIC, "udp_quic");
    dump_reset_dump_file(proto2dump, DUMP_IP_COMPLETE, "ip_complete");
    dump_reset_dump_file(proto2dump, DUMP_UDP_COMPLETE, "udp_complete");
    dump_reset_dump_file(proto2dump, DUMP_TCP_VIDEOSTREAMING, "tcp_videostreaming");
    dump_reset_dump_file(proto2dump, DUMP_TCP_COMPLETE, "tcp_complete");
}

/*
 * This is a timeval as stored in a savefile.
 * It has to use the same types everywhere, independent of the actual
 * `struct timeval'; `struct timeval' has 32-bit tv_sec values on some
 * platforms and 64-bit tv_sec values on other platforms, and writing
 * out native `struct timeval' values would mean files could only be
 * read on systems with the same tv_sec size as the system on which
 * the file was written.
 */



struct pcap_timeval {
    bpf_int32 tv_sec;           /* seconds */
    bpf_int32 tv_usec;          /* microseconds */
};

struct pcap_sf_pkthdr {
    struct pcap_timeval ts;     /* time stamp */
    bpf_u_int32 caplen;         /* length of portion present */
    bpf_u_int32 len;            /* length this packet (off wire) */
};



void dump_packet(FILE *fp,
                 void *pip, 
                 void *plast)
{
    struct pcap_sf_pkthdr phdr;
    long cap_bytes;
    
    cap_bytes = (char *) plast - (char *) pip + 1;
    cap_bytes = (snap_len == 0) ? cap_bytes : (min(snap_len, cap_bytes));

    // create a pcap packet header (adding size of bogus ethernet header)
    // caplen = the portion of packet writed
    // len    = the real packet dimension
    phdr.ts.tv_sec = current_time.tv_sec;
    phdr.ts.tv_usec = current_time.tv_usec;
    phdr.caplen = cap_bytes;
    phdr.caplen += sizeof(struct ether_header); /* add in the ether header */
    if (PIP_ISV4(pip))
      phdr.len = sizeof(struct ether_header) + ntohs (PIP_LEN (pip));
    else
      // IPv6 PIP_LEN is the payload after the 40 bytes header, so the
      // datagram is always 40+ip6_lngth
      // gethdrlength computes the overall headers, but is not what we need here
      phdr.len = sizeof(struct ether_header) + ntohs (PIP_LEN (pip)) + 40; // gethdrlength(pip,plast);
      
#ifdef HAVE_ZLIB
    if (zlib_dump)
     { 
       gzwrite(fp,&phdr, sizeof(struct pcap_sf_pkthdr));
     }
    else 
#endif
     {   
       fwrite(&phdr, sizeof(struct pcap_sf_pkthdr), 1, fp);
     }

    // write a (bogus) ethernet header
    memset(&eth_header, 0, sizeof(struct ether_header));
    if (PIP_ISV4(pip))
      eth_header.ether_type = htons (ETHERTYPE_IP);
    else
      eth_header.ether_type = htons (ETHERTYPE_IPV6);
      
#ifdef HAVE_ZLIB
    if (zlib_dump)
     { 
       gzwrite (fp,&eth_header, sizeof(struct ether_header));

       // write the IP/TCP parts
       gzwrite(fp,pip, phdr.caplen - sizeof(struct ether_header));
     }
    else 
#endif
     {   
       fwrite (&eth_header, sizeof(struct ether_header), 1, fp);

       // write the IP/TCP parts
       fwrite(pip, phdr.caplen - sizeof(struct ether_header), 1, fp);
     }
}

void dump_to_file(struct dump_file *dump_file, 
                  void *pip, 
                  void *plast)
{
    //open a new dump file
    if (dump_file->win_start.tv_sec == -1 &&
        dump_file->win_start.tv_usec == -1) {
        dump_file->fp = new_dump_file(dump_file);
        dump_file->win_start.tv_sec = current_time.tv_sec;
        dump_file->win_start.tv_usec = current_time.tv_usec;
    }
    else if (slice_win > 0) {
        //check if current dump window is ended
        double diff = elapsed(dump_file->win_start, current_time) / 1000000;
        if (diff >= slice_win) {
#ifdef HAVE_ZLIB
	    if (zlib_dump)
             { 
               gzclose(dump_file->fp);
	     }
	    else
#endif
             { 
	       fflush(dump_file->fp);
               fclose(dump_file->fp);
	     }
            dump_file->seq_num++;

            // compute the current timestamp of dumping window
            // considering that there can be windows without traffic
            // associated
            dump_file->win_start.tv_sec += 
                ((long)diff / slice_win) * slice_win;
            dump_file->fp = new_dump_file(dump_file);
        }
    }

    //dump current packet
    dump_packet(dump_file->fp, pip, plast);

    //if (timestamp.tv_sec == -1) {
    //    fprintf(fp_log, "dump start: %s\n", Timestamp());
    //}
    last_dump_tm = current_time;
    if (first_dump_tm.tv_sec == -1) 
        first_dump_tm = current_time;
}

void dump_ip(void *pip, void *plast) {
    if (dump_engine && proto2dump[DUMP_IP_COMPLETE].enabled)
        dump_to_file(&proto2dump[DUMP_IP_COMPLETE], pip, plast);
}

void dump_flow_stat (struct ip *pip, 
                     void *pproto, 
                     int tproto, 
                     void *pdir,
	                 int dir, 
                     void *hdr, 
                     void *plast) 
{
    int ucb_type;

    if (!dump_engine)
        return;

    /***** TCP packets *****/
    if (tproto == PROTOCOL_TCP)
    /* It's TCP, there is still a flow associated to this, and we are not already discarding it */
     {
       struct stcp_pair *p = ((tcb *)pdir)->ptp;

       if (proto2dump[DUMP_TCP_COMPLETE].enabled && (p != NULL) && !(p->stop_dumping_tcp) ) 
         {
            /* are we still interested in this flow packets? */
            if ( ( p->con_type != UNKNOWN_PROTOCOL )  /* we always log unknowns */
                  &&
                 ( (p->con_type & stop_dumping_mask) != 0 ) /* after masking, we are not interested into it */
               )
             {
               p->stop_dumping_tcp = TRUE;
               if (debug>0)
                {
                  fprintf(fp_stderr, "Stopping dumping this flow - con_type = %d\n",p->con_type);
                }
             }
                
            if (!(p->stop_dumping_tcp))
             { 
               /* do we have to dump all the packets of all the flows */
               if (tcp_maxbytes == 0 && tcp_maxpackets == 0)
                {
                  dump_to_file(&proto2dump[DUMP_TCP_COMPLETE], pip, plast);
	            }
	            /* or we have to stop dumping acks and data packets up to reach 
                 * - tcp_maxbytes 
                 * - tcp_maxpackets 
                 */
               else
                {
                  struct tcphdr *ptcp = pproto;
                  /* check if the underlying flow struct tcb has not yet been released */
                  if ( p != NULL)
                   {
                     int tcp_data_length = getpayloadlength (pip, plast) - (4 * ptcp->th_off);

                     tcb *thisdir = (tcb*)pdir;
                     tcb *otherdir = (dir == C2S) ? &(thisdir->ptp->s2c) : &(thisdir->ptp->c2s);

                     if ((
                        /* packets with payload */
                        tcp_data_length > 0 && 
                            /* check the thresholds */
                            ((tcp_maxbytes > 0   && thisdir->seq - thisdir->syn - tcp_data_length <= tcp_maxbytes) || 
                             (tcp_maxpackets > 0 && thisdir->data_pkts <= tcp_maxpackets))
                        ) || (
                        /* this is a pure ack */
                        tcp_data_length == 0 && 
                            (otherdir->seq <= thisdir->ack && /* which is a valid ack */
                              ( /* and we are still interested in otherdir packets */
                                (tcp_maxbytes > 0 && otherdir->seq - otherdir->syn <= tcp_maxbytes) ||
                                (tcp_maxpackets > 0 && otherdir->data_pkts <= tcp_maxpackets) ||
                                (otherdir->fin_count >= 1 && thisdir->ack >= (otherdir->fin_seqno+1))
                            ))
                        ) ||
                        SYN_SET (ptcp) || 
                        FIN_SET(ptcp)
                       ) 
                        {
                            dump_to_file(&proto2dump[DUMP_TCP_COMPLETE], pip, plast);
                        }
                       
                    }
                   else
                    {
                      if (RESET_SET(ptcp))
                       {
                         dump_to_file(&proto2dump[DUMP_TCP_COMPLETE], pip, plast);
                       }
                    }
                 }
            } /* end !stop_dumping_tcp */
        } /* end DUMP_TCP_COMPLETE */

#ifdef STREAMING_CLASSIFIER
        if (proto2dump[DUMP_TCP_VIDEOSTREAMING].enabled && ((tcb*)pdir)->ptp != NULL)
         {
            struct stcp_pair *p = ((tcb *)pdir)->ptp;
            if (p->streaming.video_content_type || p->streaming.video_payload_type)
             {
               dump_to_file(&proto2dump[DUMP_TCP_VIDEOSTREAMING], pip, plast);
             }
         }
#endif
     }
    
    /***** UDP packets *****/
    else 
     {
        ucb *mydir = (ucb*)pdir;
        ucb *otherdir = (dir == C2S) ? &(mydir->pup->s2c) : &(mydir->pup->c2s);

        //specific controls to find kad obfuscated...
        ucb_type = UDP_p2p_to_logtype(mydir);

        /* dump to a specific DPI file */
        if (proto2dump[P2P_UTP].enabled)
         {
            /* 
               Since uTP classification is behavioral, we dump both already classified datagrams,
               and datagrams which are not classified, but that are already in a valid state of 
               the identification state machine.
            */
            if ( ucb_type == P2P_UTP || 
                 ucb_type == P2P_UTPBT ||
                 ( (ucb_type==UDP_UNKNOWN || ucb_type==FIRST_RTP || ucb_type==FIRST_RTCP || ucb_type==P2P_BT) &&
                   (mydir->uTP_state > UTP_UNKNOWN )
                 )
               )
             dump_to_file(&proto2dump[P2P_UTP], pip, plast);
         }
        if (proto2dump[UDP_QUIC].enabled)
         {
            /* 
               Since QUIC classification is behavioral, we dump both already classified datagrams,
               and datagrams which are not classified, but that are already in a valid state of 
               the identification state machine.
            */
            if ( ucb_type == UDP_QUIC || 
                 ( (ucb_type==UDP_UNKNOWN || ucb_type==FIRST_RTP || ucb_type==FIRST_RTCP ) &&
                   (mydir->QUIC_state > QUIC_UNKNOWN || otherdir->QUIC_state > QUIC_UNKNOWN)
                 )
               )
             dump_to_file(&proto2dump[UDP_QUIC], pip, plast);
         }
    	else if (proto2dump[ucb_type].enabled) 
    	 {
            dump_to_file(&proto2dump[ucb_type], pip, plast);
         }
        // dump to unknown
        // else if (proto2dump[UDP_UNKNOWN].enabled) {
        //    dump_to_file(&proto2dump[UDP_UNKNOWN], pip, plast);
        // }

        if (proto2dump[DUMP_UDP_COMPLETE].enabled) {
            /* dump all the packets of all the flows */
            if (udp_maxpackets == 0 && udp_maxbytes == 0) {
	            dump_to_file(&proto2dump[DUMP_UDP_COMPLETE], pip, plast);
            }
            else {
                /* check if the underlying flow struct ucb has not yet been released */
                if (((ucb*)pdir)->pup != NULL)
                {
                   ucb *thisdir = (ucb*)pdir;
                   /* dump acks and data packets up to reach 
                    * - udp_maxbytes 
                    * - udp_maxpackets 
                    */
                   if ( (thisdir->data_bytes <= udp_maxbytes) || 
                        (thisdir->packets <= udp_maxpackets)) 
                    {
                        dump_to_file(&proto2dump[DUMP_UDP_COMPLETE], pip, plast);
                    }
                }
                else /* it shouldn't happen, but in case dump the packet in any case */
                    dump_to_file(&proto2dump[DUMP_UDP_COMPLETE], pip, plast);
          }
        }
    }

}

void dump_flush(Bool trace_completed) {
    int i;

    if (!dump_engine)
        return;
    
    if (trace_completed && !con_cat)
        dir_counter = 0;

    //flush traces files
    for (i = 0; i < DUMP_PROTOS; i++) {
        if (proto2dump[i].enabled && proto2dump[i].fp) {
#ifdef HAVE_ZLIB
	    if (zlib_dump)
             { 
               gzclose(proto2dump[i].fp);
	     }
	    else
#endif
             { 
               fflush(proto2dump[i].fp);
               fclose(proto2dump[i].fp);
	     }
            proto2dump[i].fp = NULL;
            proto2dump[i].win_start.tv_sec = -1;
            proto2dump[i].win_start.tv_usec = -1;
        }
    }

    //write messages to log file
    if (fp_log) {
        if (first_dump_tm.tv_sec == -1)
            fprintf(fp_log, "no packets to dump\n");
        else
	  {
            fprintf(fp_log, 
                "dump start: %s",
                ctime(&first_dump_tm.tv_sec));
            fprintf(fp_log, 
                "dump stop:  %s",
                ctime(&last_dump_tm.tv_sec));
	  }
        fprintf(fp_log, 
            "---\n"
            "enabled protocols:\n"
            "---\n"); 
        for (i = 0; i <  DUMP_PROTOS; i++) {
            if (proto2dump[i].enabled)
                fprintf(fp_log, "%s\n", proto2dump[i].protoname);
        }
        fprintf(fp_log, 
            "---\n"
            "additional option:\n"
            "---\n"); 
        if (udp_maxpackets!=0)
          fprintf(fp_log,"udp_maxpackets = %d\n",udp_maxpackets);
        if (udp_maxbytes!=0)
          fprintf(fp_log,"udp_maxbytes = %d\n",  udp_maxbytes);
        if (tcp_maxpackets!=0)
          fprintf(fp_log,"tcp_maxpackets = %d\n",tcp_maxpackets);
        if (tcp_maxbytes!=0)
          fprintf(fp_log,"tcp_maxbytes = %d\n",  tcp_maxbytes);
        if (stop_dumping_mask!=0)
          fprintf(fp_log,"stop_dumping_mask =  %d # (0x%X)\n",stop_dumping_mask,stop_dumping_mask);
        fclose(fp_log);
        fp_log = NULL;
    }
}

void dump_create_outdir(char * basedir) {
    char *buf;

    if (!dump_engine)
        return;

    // store basedir to check when a new output directory is created
    if (log_basedir && strcmp(log_basedir, basedir) != 0) {
        dump_flush(TRUE);
        dir_counter = 0;
    }
    log_basedir = strdup(basedir);

    first_dump_tm.tv_sec = -1;
    first_dump_tm.tv_usec = -1;
    last_dump_tm.tv_sec = -1;
    last_dump_tm.tv_usec = -1;

    // compose the name of the directory...
    buf = sprintf_safe("%s/%s%02d", basedir, DUMP_DIR_BASENAME, dir_counter);
    if (outdir)
        free(outdir);
    outdir = MMmalloc(strlen(buf) + 1, "dump_create_outdir");
    memcpy(outdir, buf, strlen(buf) + 1);

    if (mkdir(outdir, 0777) != 0) {
        fprintf(fp_stderr, "dump engine err: error creating '%s'\n", outdir);
        exit(1);
    }
    fprintf(fp_stdout, "(%s) Creating output dir %s\n", Timestamp(), outdir);

    // ... and dumping log file
    buf = sprintf_safe("%s/%s", outdir, DUMP_LOG_FNAME);
    fp_log = fopen(buf, "w");
    if (fp_log == NULL) {
        fprintf(fp_stderr, "dump engine: error creating '%s'\n", buf);
        exit(1);
    }

    dir_counter++;

}

static Bool old_dump_engine;
void dump_ini_start_section(void) {
    extern int globals_set;

    if (globals_set!=0)
     {
       fprintf(fp_stderr,"ini reader: [dump] section only valid in the runtime configuration context\n");
       exit(1);
     }

    if (current_time.tv_sec != 0) {
        dump_flush(FALSE);
    }
    old_dump_engine = dump_engine;
    dump_init();
}

void dump_ini_end_section(void) {
    if (old_dump_engine != dump_engine || current_time.tv_sec == 0) {
        fprintf(fp_stdout, "[%s] %s dump engine\n", 
            Timestamp(), (dump_engine) ? "Enabling" : "Disabling");
    }
}
