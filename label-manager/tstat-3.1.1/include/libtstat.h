#ifndef H_LIBTSTAT
#define H_LIBTSTAT

#include <sys/types.h>
#include <sys/time.h>
#include <stdio.h>

typedef struct {
    u_long              pnum;               //total packet analized
    unsigned long int   fcount;             //total flows analized
    unsigned long int   f_TCP_count;        //total TCP flows
    unsigned long int   f_UDP_count;        //total UDP flows
    unsigned long int   f_RTP_count;        //total RTP flows
    unsigned long int   f_RTCP_count;       //total RTCP flows
    unsigned long int   f_RTP_tunneled_TCP_count; //total tunneled RTP flows
    int                 search_count;       //iterations spent in the hash search routine
    long int            tcp_packet_count;   //total analyzed TCP packet
    u_long              udp_trace_count;    //total analyzed UDP packet
    long                not_id_p;           //total trash TCP packet
    double              avg_search;         //average TCP search length
    unsigned long       tot_conn_TCP;       //current opened TCP flows
    unsigned long       tot_conn_UDP;       //current opened UDP flows
    int                 num_tcp_pairs;      //current flow vector index
    long int            tot_adx_hash_count; //total adx used in hash
    long int            tot_adx_list_count; //total adx used in list
    long int            adx_search_hash_count;  //total adx hash search
    long int            adx_search_list_count;  //total adx list search
    double              wallclock;          //elapsed wallclock time
    int                 pcktspersec;         //pkts/sec analyzed
    int                 flowspersec;         //flows/sec analyzed
} tstat_report;

#ifdef __cplusplus
extern "C" {
#endif
extern long int tcp_cleaned;
extern long int udp_cleaned;
int tstat_init (char *config_fname);
void tstat_new_logdir (char *filename, struct timeval *pckt_time);
int tstat_next_pckt (struct timeval *pckt_time, void *ip_hdr, void *last_ip_byte, int tlen, int ip_direction); 
void tstat_print_report (tstat_report *report, FILE *file);
tstat_report *tstat_close (tstat_report *report);
#ifdef __cplusplus
}
#endif

#endif
