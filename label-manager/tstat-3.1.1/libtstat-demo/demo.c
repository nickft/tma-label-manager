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
 * Author:	Marco Mellia, Andrea Carpani, Luca Muscariello, Dario Rossi
 * 		Telecomunication Networks Group
 * 		Politecnico di Torino
 * 		Torino, Italy
 *              http://www.tlc-networks.polito.it/index.html
 *		mellia@mail.tlc.polito.it, rossi@mail.tlc.polito.it
 *
 * Tstat is deeply based on TCPTRACE. The authors would like to thank
 * Shawn Ostermann for the development of TCPTRACE.
 *
*/

#include <pcap.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <libtstat.h>
#include <unistd.h>
#include "pcapwrapper.h"


int main(int argc, char *argv[]) {
    int res;
    tstat_report report;
    char *conf_fname, *trace_fname;
    pcapwrapper_pfunc *pcktread;

    struct timeval current_time;
    int tlen;
    void *phys, *plast;
    struct ip *pip;
    
    if (argc == 1) {
        fprintf(stderr, 
            "missing input arguments\n"
            "using: %s <trace_fname> [<tstat_conf_file>]", argv[0]);
        exit(1);
    }
    trace_fname = argv[1];

    conf_fname = NULL;
    if (argc > 2)
        conf_fname = argv[2];

    /***************
     * 1) init internal variables using command line options
     **************/
    tstat_init(conf_fname);

    /***************
     * 2) open trace file as stdin!!!
     ***************/
    if (trace_fname[0] != '-') {
        //close(0);
        open(trace_fname, O_RDONLY);
    }


    /***************
     * 2.1) init demo internal structs to read a pcap file
     *      (this code is derived from original tcpdump.c)
     ***************/
    pcktread = pcapwrapper_init(trace_fname);
    if (pcktread == NULL) {
        printf("errore di apertura del file %s\n", trace_fname);
        return 1;
    }

    /****************
     * 3) read first packet to have the timestamp needed
     *    to create tstat output logs directory
     ****************/
    res = (*pcktread)(&current_time, &pip, &plast, &tlen);
    if (trace_fname[0] == '-')
        tstat_new_logdir("stdin", &current_time);
    else
        tstat_new_logdir(trace_fname, &current_time);

    do {
        // 4) elaborate current packet
        res = tstat_next_pckt(&current_time, pip, plast, tlen, 0);

        // 5) read the next packet
        //    res == 0  : no more packets
        //    res == 1  : one packet readed
        //    res == -1 : error
        res = (*pcktread)(&current_time, &pip, &plast, &tlen);
    }        
    while(res == 1);

    /***************
     * 6) flush statistics and print a report
     ***************/
    tstat_close(&report);
    tstat_print_report(&report, stdout);

    if (res != 0)
        return 1;
    return 0;
}
