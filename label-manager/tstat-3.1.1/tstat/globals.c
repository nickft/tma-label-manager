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
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include "globals.h"

/*
  GLOBALS is a global struct containing mirroring the constants defined in param.h
  Its scope is to have sensitive constants in param.h, that might be overridden 
  at startup reading the new values from a file.
*/
void InitGlobals (void)
{
  GLOBALS.Max_ADX_Slots         = MAX_ADX_SLOTS;

  GLOBALS.Max_Internal_Ethers   = MAX_INTERNAL_ETHERS;
  GLOBALS.Max_Internal_Hosts    = MAX_INTERNAL_HOSTS;
  GLOBALS.Max_Cloud_Hosts       = MAX_CLOUD_HOSTS;
  GLOBALS.Max_Crypto_Hosts      = MAX_CRYPTO_HOSTS;
  GLOBALS.Max_White_Hosts       = MAX_WHITE_HOSTS;

  GLOBALS.Max_Seg_Per_Quad      = MAX_SEG_PER_QUAD;

  GLOBALS.TCP_Idle_Time         = TCP_IDLE_TIME;
  GLOBALS.UDP_Idle_Time         = UDP_IDLE_TIME;
  GLOBALS.TCP_Singleton_Time    = TCP_SINGLETON_TIME;
  GLOBALS.UDP_Singleton_Time    = UDP_SINGLETON_TIME;

  GLOBALS.GC_Cycle_Time         = GARBAGE_PERIOD;
  GLOBALS.GC_Split_Ratio        = GARBAGE_SPLIT_RATIO;
  GLOBALS.GC_Fire_Time          = GLOBALS.GC_Cycle_Time / GLOBALS.GC_Split_Ratio;

  GLOBALS.Runtime_Config_Idle   = RUNTIME_CONFIG_IDLE;
  GLOBALS.Runtime_Mtime_Counter = RUNTIME_MTIME_COUNTER;

  GLOBALS.Max_TCP_Pairs         = MAX_TCP_PAIRS;
  GLOBALS.Max_UDP_Pairs         = MAX_UDP_PAIRS;
  // GLOBALS.Max_TCP_Pairs_Burst	= MAX_TCP_PAIRS_BURST;
  // GLOBALS.Max_UDP_Pairs_Burst	= MAX_UDP_PAIRS_BURST;

  GLOBALS.List_Search_Dept      = LIST_SEARCH_DEPT;

  GLOBALS.Hash_Table_Size       = HASH_TABLE_SIZE;

  GLOBALS.Max_Time_Step         = MAX_TIME_STEP;

  GLOBALS.Dirs                  = DIRS;

  GLOBALS.Min_Delta_T_UDP_Dup_Pkt = MIN_DELTA_T_UDP_DUP_PKT;
  GLOBALS.Min_Delta_T_TCP_Dup_Pkt = MIN_DELTA_T_TCP_DUP_PKT;

  GLOBALS.Entropy_Sample        = ENTROPY_SAMPLE;
  GLOBALS.Entropy_Threshold     = ENTROPY_THRESHOLD;

  GLOBALS.Rate_Sampling         = RATE_SAMPLING;

  GLOBALS.Max_Crypto_Cache_Size = MAX_CRYPTO_CACHE_SIZE;

  GLOBALS.DNS_Cache_Size        = DNS_CACHE_SIZE;
#ifdef SUPPORT_IPV6
  GLOBALS.DNS_Cache_Size_IPv6   = DNS_CACHE_SIZE_IPV6;
#endif
}

void PrintGlobals (void)
{
  fprintf (fp_stdout,"\n");
  fprintf (fp_stdout,"Globals (-G):\n");
  fprintf (fp_stdout,"\t# Current value of internal global constants (-G option)\n");

  fprintf (fp_stdout,"\t[globals]\n");
  
  fprintf (fp_stdout,"\tMax_TCP_Pairs = %d\n",GLOBALS.Max_TCP_Pairs);
  fprintf (fp_stdout,"\tMax_UDP_Pairs = %d\n",GLOBALS.Max_UDP_Pairs);
  fprintf (fp_stdout,"\tHash_Table_Size = %d\n",GLOBALS.Hash_Table_Size);
  
  fprintf (fp_stdout,"\tTCP_Idle_Time = %f\n",GLOBALS.TCP_Idle_Time*1.0/1000000.0);
  fprintf (fp_stdout,"\tUDP_Idle_Time = %f\n",GLOBALS.UDP_Idle_Time*1.0/1000000.0);
  fprintf (fp_stdout,"\tTCP_Singleton_Time = %f\n",GLOBALS.TCP_Singleton_Time*1.0/1000000.0);
  fprintf (fp_stdout,"\tUDP_Singleton_Time = %f\n",GLOBALS.UDP_Singleton_Time*1.0/1000000.0);
  fprintf (fp_stdout,"\tGC_Cycle_Time = %f\n",GLOBALS.GC_Cycle_Time*1.0/1000000.0);
  fprintf (fp_stdout,"\tGC_Split_Ratio = %d\n",GLOBALS.GC_Split_Ratio);

  fprintf (fp_stdout,"\tMax_ADX_Slots = %d\n",GLOBALS.Max_ADX_Slots);
  fprintf (fp_stdout,"\tMax_Internal_Ethers = %d\n",GLOBALS.Max_Internal_Ethers);
  fprintf (fp_stdout,"\tMax_Internal_Hosts = %d\n",GLOBALS.Max_Internal_Hosts);
  fprintf (fp_stdout,"\tMax_Cloud_Hosts = %d\n",GLOBALS.Max_Cloud_Hosts);
  fprintf (fp_stdout,"\tMax_Crypto_Hosts = %d\n",GLOBALS.Max_Crypto_Hosts);
  fprintf (fp_stdout,"\tMax_White_Hosts = %d\n",GLOBALS.Max_White_Hosts);
  fprintf (fp_stdout,"\tMax_Crypto_Cache_Size = %d\n",GLOBALS.Max_Crypto_Cache_Size);
  fprintf (fp_stdout,"\tDNS_Cache_Size = %d\n",GLOBALS.DNS_Cache_Size);
#ifdef SUPPORT_IPV6
  fprintf (fp_stdout,"\tDNS_Cache_Size_IPv6 = %d\n",GLOBALS.DNS_Cache_Size_IPv6);
#endif

  fprintf (fp_stdout,"\tRuntime_Config_Idle = %f\n",GLOBALS.Runtime_Config_Idle);
  fprintf (fp_stdout,"\tRuntime_Mtime_Counter = %d\n",GLOBALS.Runtime_Mtime_Counter);
  fprintf (fp_stdout,"\tMax_Time_Step = %f\n",GLOBALS.Max_Time_Step/1000000.0);
  fprintf (fp_stdout,"\tDirs = %d\n",GLOBALS.Dirs);
  fprintf (fp_stdout,"\tRate_Sampling = %f\n",GLOBALS.Rate_Sampling*1.0/1000000.0);
  
  fprintf (fp_stdout,"\tMax_Seg_Per_Quad = %d\n",GLOBALS.Max_Seg_Per_Quad);
  fprintf (fp_stdout,"\tList_Search_Dept = %d\n",GLOBALS.List_Search_Dept);
  fprintf (fp_stdout,"\tEntropy_Sample = %d\n",GLOBALS.Entropy_Sample);
  fprintf (fp_stdout,"\tEntropy_Threshold = %f\n",GLOBALS.Entropy_Threshold);
  fprintf (fp_stdout,"\tMin_Delta_T_UDP_Dup_Pkt = %f\n",GLOBALS.Min_Delta_T_UDP_Dup_Pkt);
  fprintf (fp_stdout,"\tMin_Delta_T_TCP_Dup_Pkt = %f\n",GLOBALS.Min_Delta_T_TCP_Dup_Pkt);

}

void InitGlobalArrays (void)
{
  extern struct in_addr *internal_net_list;
  extern int *internal_net_mask;

  extern struct in_addr *cloud_net_list;
  extern int *cloud_net_mask;

  extern struct in_addr *crypto_net_list;
  extern int *crypto_net_mask;

  extern struct in_addr *white_net_list;
  extern int *white_net_mask;
  extern eth_filter mac_filter;

  extern struct in6_addr *internal_net_listv6;
  extern int *internal_net_maskv6;
  
  extern struct in6_addr *cloud_net_listv6;
  extern int *cloud_net_maskv6;
  
  extern struct in6_addr *crypto_net_listv6;
  extern int *crypto_net_maskv6;

  extern struct in6_addr *white_net_listv6;
  extern int *white_net_maskv6;
  
  static Bool initted = FALSE;
  int i;

  if (initted)
    return;

  initted = TRUE;

  internal_net_list  = (struct in_addr *) MallocZ (GLOBALS.Max_Internal_Hosts * sizeof (struct in_addr));
  internal_net_mask  = (int *) MallocZ (GLOBALS.Max_Internal_Hosts * sizeof (int));

  cloud_net_list  = (struct in_addr *) MallocZ (GLOBALS.Max_Cloud_Hosts * sizeof (struct in_addr));
  cloud_net_mask  = (int *) MallocZ (GLOBALS.Max_Cloud_Hosts * sizeof (int));
  
  crypto_net_list  = (struct in_addr *) MallocZ (GLOBALS.Max_Crypto_Hosts * sizeof (struct in_addr));
  crypto_net_mask  = (int *) MallocZ (GLOBALS.Max_Crypto_Hosts * sizeof (int));

  white_net_list  = (struct in_addr *) MallocZ (GLOBALS.Max_White_Hosts * sizeof (struct in_addr));
  white_net_mask  = (int *) MallocZ (GLOBALS.Max_White_Hosts * sizeof (int));

  mac_filter.addr = (uint8_t **) MallocZ (GLOBALS.Max_Internal_Ethers * sizeof ( uint8_t *));
  for (i = 0; i<GLOBALS.Max_Internal_Ethers; i++)
   {
     mac_filter.addr[i] = (uint8_t *) MallocZ ( 6 * sizeof(uint8_t) );
   }
   
  // IPv6 Address structures, even if unused 
  internal_net_listv6 = (struct in6_addr *) MallocZ (GLOBALS.Max_Internal_Hosts * sizeof (struct in6_addr));
  internal_net_maskv6 = (int *) MallocZ (GLOBALS.Max_Internal_Hosts * sizeof (int));

  cloud_net_listv6 = (struct in6_addr *) MallocZ (GLOBALS.Max_Cloud_Hosts * sizeof (struct in6_addr));
  cloud_net_maskv6 = (int *) MallocZ (GLOBALS.Max_Cloud_Hosts * sizeof (int));

  crypto_net_listv6 = (struct in6_addr *) MallocZ (GLOBALS.Max_Crypto_Hosts * sizeof (struct in6_addr));
  crypto_net_maskv6 = (int *) MallocZ (GLOBALS.Max_Crypto_Hosts * sizeof (int));
  
  white_net_listv6  = (struct in6_addr *) MallocZ (GLOBALS.Max_White_Hosts * sizeof (struct in6_addr));
  white_net_maskv6  = (int *) MallocZ (GLOBALS.Max_White_Hosts * sizeof (int));
  
}

int LoadGlobals (char *globals_file) 
{
  int retval;
  extern int globals_set;
    
  if (globals_file!=NULL)
   {
     globals_set = 1;
     ini_read(globals_file);
     globals_set = 0;
     retval=1;
   }
  else
    retval=0;

 return retval;
}


/****************************************************
 * MMM: these functions are for parsing globals.conf
 ****************************************************/

/* this function is to apply the same logic to different log files
 * Note: 'log_type' is one of the LOG_XXX values in tstat.h
 */

void globals_parse_start_section(void) {
  extern int globals_set;
  
  if (globals_set!=1)
   {
     fprintf(fp_stderr,"ini reader: [globals] section not valid in the runtime configuration context\n");
     exit(1);
   } 
}

void globals_parse_end_section(void) {
  
      // runtime_config_idle*runtime_mtime_counter > 60.0
  if (GLOBALS.Runtime_Config_Idle * GLOBALS.Runtime_Mtime_Counter <= 60.0)
   {
     fprintf(fp_stderr, "global conf: Warning: Runtime_Config_Idle * Runtime_Mtime_Counter is less than 1 minute\n"); 
     fprintf(fp_stderr, "             Changes to the Runtime configuration might cancel previous logs.\n"); 
   }
  
  if ( GLOBALS.Hash_Table_Size < max(GLOBALS.Max_TCP_Pairs,GLOBALS.Max_UDP_Pairs) )
   {
     fprintf(fp_stderr, "global conf: Error: Hash_Table_Size is %d, smaller than Max_TCP_Pairs or Max_UDP_Pairs\n",
	                 GLOBALS.Hash_Table_Size); 
     fprintf(fp_stderr, "             Increase its value\n"); 
     exit(1);
   }

  if ( GLOBALS.Max_TCP_Pairs != (( GLOBALS.Max_TCP_Pairs / GLOBALS.GC_Split_Ratio ) * GLOBALS.GC_Split_Ratio ) )
   {
     fprintf(fp_stderr, "global conf: Error: Max_TCP_Pairs and Max_UDP_Pairs must be multiple of GC_Split_Ratio\n");
     exit(1);
   }

  if ( GLOBALS.Max_UDP_Pairs != (( GLOBALS.Max_UDP_Pairs / GLOBALS.GC_Split_Ratio ) * GLOBALS.GC_Split_Ratio ) )
   {
     fprintf(fp_stderr, "global conf: Error: Max_TCP_Pairs and Max_UDP_Pairs must be multiple of GC_Split_Ratio\n");
     exit(1);
   }

  if ( GLOBALS.GC_Cycle_Time != (( GLOBALS.GC_Cycle_Time / GLOBALS.GC_Split_Ratio ) * GLOBALS.GC_Split_Ratio ) )
   {
     fprintf(fp_stderr, "global conf: Error: GC_Cycle_Time (in microseconds, as an integer) must be multiple of GC_Split_Ratio\n");
     exit(1);
   }
   
  // max_tcp_pairs / max_udp_pairs / GC_Split_Ratio / hash_table_size

   GLOBALS.GC_Fire_Time = GLOBALS.GC_Cycle_Time / GLOBALS.GC_Split_Ratio;

}

void croak_global_integer(char *param_name)
{ 
  fprintf(fp_stderr, "global conf: error: '%s' must have an positive integer value\n", 
     param_name);
  exit(1);  
}

void croak_global_double(char *param_name)
{ 
  fprintf(fp_stderr, "global conf: error: '%s' must have a positive floating point value\n", 
     param_name);
  exit(1);  
}

void globals_parse_ini_arg(char *param_name, param_value param_value)
{
    if (strcasecmp(param_name,"max_adx_slots") == 0) 
     {
       if (param_value.type == INTEGER && param_value.value.ivalue > 0) 
        {
	  GLOBALS.Max_ADX_Slots = param_value.value.ivalue;
        }
       else
	 croak_global_integer(param_name);
     }
    else if (strcasecmp(param_name,"max_internal_ethers") == 0) 
     {
       if (param_value.type == INTEGER && param_value.value.ivalue > 0) 
        {
	  GLOBALS.Max_Internal_Ethers = param_value.value.ivalue;
        }
       else
	 croak_global_integer(param_name);
     }
    else if (strcasecmp(param_name,"max_internal_hosts") == 0) 
     {
       if (param_value.type == INTEGER && param_value.value.ivalue > 0) 
        {
	  GLOBALS.Max_Internal_Hosts = param_value.value.ivalue;
        }
       else
	 croak_global_integer(param_name);
     }
    else if (strcasecmp(param_name,"max_cloud_hosts") == 0) 
     {
       if (param_value.type == INTEGER && param_value.value.ivalue > 0) 
        {
	  GLOBALS.Max_Cloud_Hosts = param_value.value.ivalue;
        }
       else
	 croak_global_integer(param_name);
     }
    else if (strcasecmp(param_name,"max_crypto_hosts") == 0) 
     {
       if (param_value.type == INTEGER && param_value.value.ivalue > 0) 
        {
	  GLOBALS.Max_Crypto_Hosts = param_value.value.ivalue;
        }
       else
	 croak_global_integer(param_name);
     }
    else if (strcasecmp(param_name,"max_white_hosts") == 0) 
     {
       if (param_value.type == INTEGER && param_value.value.ivalue > 0) 
        {
	  GLOBALS.Max_White_Hosts = param_value.value.ivalue;
        }
       else
	 croak_global_integer(param_name);
     }
    else if (strcasecmp(param_name,"max_seg_per_quad") == 0) 
     {
       if (param_value.type == INTEGER && param_value.value.ivalue >= 0) 
        {
	  if (param_value.value.ivalue == 0)
	    GLOBALS.Max_Seg_Per_Quad = -1;
          else
	    GLOBALS.Max_Seg_Per_Quad = param_value.value.ivalue;
        }
       else
	 croak_global_integer(param_name);
     }
    else if (strcasecmp(param_name,"tcp_idle_time") == 0) 
     {
       if (param_value.type == INTEGER && param_value.value.ivalue > 0) 
        {
	  GLOBALS.TCP_Idle_Time = param_value.value.ivalue * 1000000;
        }
       else if (param_value.type == DOUBLE && param_value.value.dvalue > 0.0) 
        {
	  GLOBALS.TCP_Idle_Time = (int) (param_value.value.dvalue * 1000000.0);
        }
       else
	 croak_global_double(param_name);
     }
    else if (strcasecmp(param_name,"udp_idle_time") == 0) 
     {
       if (param_value.type == INTEGER && param_value.value.ivalue > 0) 
        {
	  GLOBALS.UDP_Idle_Time = param_value.value.ivalue * 1000000;
        }
       else if (param_value.type == DOUBLE && param_value.value.dvalue > 0.0) 
        {
	  GLOBALS.UDP_Idle_Time = (int) (param_value.value.dvalue * 1000000.0);
        }
       else
	 croak_global_double(param_name);
     }
    else if (strcasecmp(param_name,"tcp_singleton_time") == 0) 
     {
       if (param_value.type == INTEGER && param_value.value.ivalue > 0) 
        {
	  GLOBALS.TCP_Singleton_Time = param_value.value.ivalue * 1000000;
        }
       else if (param_value.type == DOUBLE && param_value.value.dvalue > 0.0) 
        {
	  GLOBALS.TCP_Singleton_Time = (int) (param_value.value.dvalue * 1000000.0);
        }
       else
	 croak_global_double(param_name);
     }
    else if (strcasecmp(param_name,"udp_singleton_time") == 0) 
     {
       if (param_value.type == INTEGER && param_value.value.ivalue > 0) 
        {
	  GLOBALS.UDP_Singleton_Time = param_value.value.ivalue * 1000000;
        }
       else if (param_value.type == DOUBLE && param_value.value.dvalue > 0.0) 
        {
	  GLOBALS.UDP_Singleton_Time = (int) (param_value.value.dvalue * 1000000.0);
        }
       else
	 croak_global_double(param_name);
     }
    else if (strcasecmp(param_name,"gc_cycle_time") == 0) 
     {
       if (param_value.type == INTEGER && param_value.value.ivalue > 0) 
        {
	  GLOBALS.GC_Cycle_Time = param_value.value.ivalue * 1000000;
        }
       else if (param_value.type == DOUBLE && param_value.value.dvalue > 0.0) 
        {
	  GLOBALS.GC_Cycle_Time = (int) (param_value.value.dvalue * 1000000.0);
        }
       else
	 croak_global_double(param_name);
     }
    else if (strcasecmp(param_name,"gc_split_ratio") == 0) 
     {
       if (param_value.type == INTEGER && param_value.value.ivalue > 0) 
        {
	  GLOBALS.GC_Split_Ratio = param_value.value.ivalue;
        }
       else
	 croak_global_integer(param_name);
     }
    else if (strcasecmp(param_name,"runtime_config_idle") == 0) 
     {
       if (param_value.type == DOUBLE && param_value.value.dvalue > 0) 
        {
	  GLOBALS.Runtime_Config_Idle = param_value.value.dvalue;
        }
       else
	 croak_global_double(param_name);
     }
    else if (strcasecmp(param_name,"runtime_mtime_counter") == 0) 
     {
       if (param_value.type == INTEGER && param_value.value.ivalue > 0) 
        {
	  GLOBALS.Runtime_Mtime_Counter = param_value.value.ivalue;
        }
       else
	 croak_global_integer(param_name);
     }
    else if (strcasecmp(param_name,"max_tcp_pairs") == 0) 
     {
       if (param_value.type == INTEGER && param_value.value.ivalue > 0) 
        {
	  GLOBALS.Max_TCP_Pairs = param_value.value.ivalue;
        }
       else
	 croak_global_integer(param_name);
     }
    else if (strcasecmp(param_name,"max_udp_pairs") == 0) 
     {
       if (param_value.type == INTEGER && param_value.value.ivalue > 0) 
        {
	  GLOBALS.Max_UDP_Pairs = param_value.value.ivalue;
        }
       else
	 croak_global_integer(param_name);
     }
    else if (strcasecmp(param_name,"list_search_dept") == 0) 
     {
       if (param_value.type == INTEGER && param_value.value.ivalue > 0) 
        {
	  GLOBALS.List_Search_Dept = param_value.value.ivalue;
        }
       else
	 croak_global_integer(param_name);
     }
    else if (strcasecmp(param_name,"hash_table_size") == 0) 
     {
       if (param_value.type == INTEGER && param_value.value.ivalue > 0) 
        {
	  GLOBALS.Hash_Table_Size = param_value.value.ivalue;
        }
       else
	 croak_global_integer(param_name);
     }
    else if (strcasecmp(param_name,"max_time_step") == 0) 
     {
       if (param_value.type == INTEGER && param_value.value.ivalue > 0) 
        {
	  GLOBALS.Max_Time_Step = param_value.value.ivalue * 1000000.0;
        }
       else if (param_value.type == DOUBLE && param_value.value.dvalue > 0.0) 
        {
	  GLOBALS.Max_Time_Step = param_value.value.dvalue * 1000000.0;
        }
       else
	 croak_global_double(param_name);
     }
    else if (strcasecmp(param_name,"dirs") == 0) 
     {
       if (param_value.type == INTEGER && param_value.value.ivalue > 0) 
        {
	  GLOBALS.Dirs = param_value.value.ivalue;
        }
       else
	 croak_global_integer(param_name);
     }
    else if (strcasecmp(param_name,"min_delta_t_udp_dup_pkt") == 0) 
     {
       if (param_value.type == INTEGER && param_value.value.ivalue > 0) 
        {
	  GLOBALS.Min_Delta_T_UDP_Dup_Pkt = param_value.value.ivalue * 1.0;
        }
       else if (param_value.type == DOUBLE && param_value.value.dvalue > 0.0) 
        {
	  GLOBALS.Min_Delta_T_UDP_Dup_Pkt = param_value.value.dvalue;
        }
       else
	 croak_global_double(param_name);
     }
    else if (strcasecmp(param_name,"min_delta_t_tcp_dup_pkt") == 0) 
     {
       if (param_value.type == INTEGER && param_value.value.ivalue > 0) 
        {
	  GLOBALS.Min_Delta_T_TCP_Dup_Pkt = param_value.value.ivalue * 1.0;
        }
       else if (param_value.type == DOUBLE && param_value.value.dvalue > 0.0) 
        {
	  GLOBALS.Min_Delta_T_TCP_Dup_Pkt = param_value.value.dvalue;
        }
       else
	 croak_global_double(param_name);
     }
    else if (strcasecmp(param_name,"entropy_sample") == 0) 
     {
       if (param_value.type == INTEGER && param_value.value.ivalue > 0) 
        {
	  GLOBALS.Entropy_Sample = param_value.value.ivalue;
        }
       else
	 croak_global_integer(param_name);
     }
    else if (strcasecmp(param_name,"entropy_threshold") == 0) 
     {
       if (param_value.type == DOUBLE && param_value.value.dvalue > 0.0) 
        {
          if ( param_value.value.dvalue <= 4.0 )
	    GLOBALS.Entropy_Threshold = param_value.value.dvalue;
	  else
	  {
            fprintf(fp_stderr, "globals conf: warning: '%s' must be smaller than 4.0. Using default value %f\n",
                param_name, GLOBALS.Entropy_Threshold );
	  }
	}
       else
	 croak_global_double(param_name);
     }
    else if (strcasecmp(param_name,"rate_sampling") == 0) 
     {
       if (param_value.type == INTEGER && param_value.value.ivalue > 0) 
        {
	  GLOBALS.Rate_Sampling = param_value.value.ivalue * 1000000;
        }
       else if (param_value.type == DOUBLE && param_value.value.dvalue > 0.0) 
        {
	  GLOBALS.Rate_Sampling = (int) (param_value.value.dvalue * 1000000.0);
        }
       else
	 croak_global_double(param_name);
     }
    else if (strcasecmp(param_name,"max_crypto_cache_size") == 0) 
     {
       if (param_value.type == INTEGER && param_value.value.ivalue > 0) 
        {
	  GLOBALS.Max_Crypto_Cache_Size = param_value.value.ivalue;
        }
       else
	 croak_global_integer(param_name);
     }
    else if (strcasecmp(param_name,"dns_cache_size") == 0) 
     {
       if (param_value.type == INTEGER && param_value.value.ivalue > 0) 
        {
	  GLOBALS.DNS_Cache_Size = param_value.value.ivalue;
        }
       else
	 croak_global_integer(param_name);
     }
#ifdef SUPPORT_IPV6     
    else if (strcasecmp(param_name,"dns_cache_size_ipv6") == 0) 
     {
       if (param_value.type == INTEGER && param_value.value.ivalue > 0) 
        {
	  GLOBALS.DNS_Cache_Size_IPv6 = param_value.value.ivalue;
        }
       else
	 croak_global_integer(param_name);
     }
#endif 
    else {
        fprintf(fp_stderr, "global conf: '%s' - unknown keyword\n", param_name);
        exit(1);
    }
}

