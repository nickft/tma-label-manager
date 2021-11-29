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

#ifdef HAVE_RRDTOOL
#include <rrd.h>
/*-----------------------------------------------------------*/
/* RRDtools 				                     

  whether rrdconf.rrd is set to one, every time the histo is 
  dumped, it will also call ``rrdtools update filename N:value''
  the filename is chosen as follows, where name is the char *nome 
  of histo structures.

	name.idx%d
	name.prc%f
 	name.var (var in {avg, min, max, var, stdev})
	

#define RRA_1H   "RRA:AVERAGE:0.5:1:720"
#define RRA_4H   "RRA:AVERAGE:0.5:4:720"
#define RRA_12H  "RRA:AVERAGE:0.5:12:720"
#define RRA_24H  "RRA:AVERAGE:0.5:24:720"
#define RRA_48H  "RRA:AVERAGE:0.5:48:720"

	    where the following table has been used:
		   Hr   Q[s] Q'   #
		   1    5    1    720
		   4    20   4    720
		   12	60   12   720     	      
		   24	120  24   720 
		   48	240  48   720
		   

*/
#define RRA_DAILY   "RRA:AVERAGE:0.5:1:600"
#define RRA_WEEKLY  "RRA:AVERAGE:0.5:6:700"
#define RRA_MONTHLY "RRA:AVERAGE:0.5:24:775"
#define RRA_YEARLY  "RRA:AVERAGE:0.5:288:797"
/*
	      rrdtool create test.rrd       
        	       --start 920804400     
        	       DS:%d:LAST:600:U:U    
        	       RRA:AVERAGE:0.5:1:24   
        	       RRA:AVERAGE:0.5:6:10

	    as suggested in:
	    http://people.ee.ethz.ch/~oetiker/webtools/rrdtool/tutorial/rrdtutorial.html	    

		1 sample "averaged" stays 1 period of 5 minutes
		6 samples averaged become one average on 30 minutes
		24 samples averaged become one average on 2 hours
		288 samples averaged become one average on 1 day

	       Lets try to be compatible with MRTG: MRTG stores about the following amount of data:

		600 5-minute samples:    2   days and 2 hours
		600 30-minute samples:  12.5 days
		600 2-hour samples:     50   days
		732 1-day samples:     732   days

	       These ranges are appended so the total amount of data kept is approximately 
	       797 days. RRDtool stores the data differently, it doesn't start the ``weekly'' archive where the ``daily'' archive stopped. For both archives the most recent data will be near ``now'' and therefore we will need to keep more data than MRTG does!
	       We will need:

		600 samples of 5 minutes  (2 days and 2 hours)
		700 samples of 30 minutes (2 days and 2 hours, plus 12.5 days)
		775 samples of 2 hours    (above + 50 days)
		797 samples of 1 day      (above + 732 days, rounded up to 797)	    
*/




/*-----------------------------------------------------------*/
/* RRDtools Prototypes  		                     */
void rrdtool_update_all();
void rrdtool_set_conf (char *file);
void rrdtool_set_path (char *path);
void rrdtool_init ();
/*-----------------------------------------------------------*/


#endif
