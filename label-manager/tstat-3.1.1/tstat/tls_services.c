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
#include <regex.h>

/* Patterns for TLS classifications*/
regex_t services_tls_sni_re[30];
regex_t services_tls_cn_re[30];
regex_t services_fqdn_re[30];

void init_tls_patterns();
void init_services_tls_sni_patterns();
void init_services_tls_cn_patterns();
void init_services_fqdn_patterns();
Bool is_tls_google(tcp_pair *ptp_save);
Bool is_tls_facebook(tcp_pair *ptp_save);
Bool is_tls_netflix(tcp_pair *ptp_save);
Bool is_tls_dropbox(tcp_pair *ptp_save);
Bool is_tls_microsoft(tcp_pair *ptp_save);
Bool is_tls_apple(tcp_pair *ptp_save);

enum service_names {
    FACEBOOK_S = 0,
    YOUTUBE_S,
    GOOGLE_S,
    DROPBOX_S,
    NETFLIX_S,
    MICROSOFT_S,
    APPLE_S,
    LAST_S
};

/* Arrays of start (_s_) and end (_e_) indexes to iterate over services */
int tls_sni_s_index[LAST_S],
    tls_sni_e_index[LAST_S],
    tls_cn_s_index[LAST_S],
    tls_cn_e_index[LAST_S],
    fqdn_s_index[LAST_S],
    fqdn_e_index[LAST_S];

void init_services_tls_sni_patterns()
{
  
  int i = 0;
  
  /* YouTube */
  tls_sni_s_index[YOUTUBE_S] = i;
  regcomp(&services_tls_sni_re[i++],"\\.googlevideo\\.com$",REG_NOSUB);
  regcomp(&services_tls_sni_re[i++],"\\.gvt1\\.com$",REG_NOSUB);
  regcomp(&services_tls_sni_re[i++],"\\.youtube\\.com$",REG_NOSUB);
  regcomp(&services_tls_sni_re[i++],"\\.youtube-nocookie\\.com$",REG_NOSUB);
  regcomp(&services_tls_sni_re[i++],"\\.ytimg\\.com$",REG_NOSUB); /* Google or YouTube? */
  
  tls_sni_e_index[YOUTUBE_S] = i-1;
  
  /* Google */  
  tls_sni_s_index[GOOGLE_S] = i;
  regcomp(&services_tls_sni_re[i++],"\\.google\\.com$",REG_NOSUB);
  regcomp(&services_tls_sni_re[i++],"\\.googleusercontent\\.com$",REG_NOSUB);
  regcomp(&services_tls_sni_re[i++],"\\.googleapis\\.com$",REG_NOSUB);
  regcomp(&services_tls_sni_re[i++],"\\.gstatic\\.com$",REG_NOSUB);
  
  tls_sni_e_index[GOOGLE_S] = i-1;

  /* Netflix */
  
  tls_sni_s_index[NETFLIX_S] = i;
  regcomp(&services_tls_sni_re[i++],"\\.nflxvideo\\.net$",REG_NOSUB);
  tls_sni_e_index[NETFLIX_S] = i-1;

  /* Facebook */
  tls_sni_s_index[FACEBOOK_S] = i;
  regcomp(&services_tls_sni_re[i++],"\\.facebook\\.com$",REG_NOSUB);
  regcomp(&services_tls_sni_re[i++],"\\.fbcdn\\.net$",REG_NOSUB);
  regcomp(&services_tls_sni_re[i++],"\\.facebook\\.net$",REG_NOSUB);
  regcomp(&services_tls_sni_re[i++],"^fbcdn",REG_NOSUB);
  regcomp(&services_tls_sni_re[i++],"^fbstatic",REG_NOSUB);
  regcomp(&services_tls_sni_re[i++],"^fbexternal",REG_NOSUB);
  tls_sni_e_index[FACEBOOK_S] = i-1;
  
  /* Dropbox */
  
  tls_sni_s_index[DROPBOX_S] = i;
  regcomp(&services_tls_sni_re[i++],"\\.dropbox\\.com$",REG_NOSUB);
  regcomp(&services_tls_sni_re[i++],"\\.dropboxstatic\\.com$",REG_NOSUB);
  regcomp(&services_tls_sni_re[i++],"\\.dropboxusercontent\\.com$",REG_NOSUB);
  tls_sni_e_index[DROPBOX_S] = i-1;

  /* Microsoft */
  
  tls_sni_s_index[MICROSOFT_S] = i;
  regcomp(&services_tls_sni_re[i++],"\\.live\\.com$",REG_NOSUB);
  regcomp(&services_tls_sni_re[i++],"\\.microsoft\\.com$",REG_NOSUB);
  regcomp(&services_tls_sni_re[i++],"\\.windows\\.net$",REG_NOSUB);
  regcomp(&services_tls_sni_re[i++],"\\.live\\.net$",REG_NOSUB);
  tls_sni_e_index[MICROSOFT_S] = i-1;

  /* Apple */
  
  tls_sni_s_index[APPLE_S] = i;
  regcomp(&services_tls_sni_re[i++],"\\.apple\\.com$",REG_NOSUB);
  regcomp(&services_tls_sni_re[i++],"\\.icloud\\.com$",REG_NOSUB);
  regcomp(&services_tls_sni_re[i++],"\\.apple\\.com\\.$",REG_NOSUB);
  regcomp(&services_tls_sni_re[i++],"\\.icloud\\.com\\.$",REG_NOSUB);
  regcomp(&services_tls_sni_re[i++],"\\.icloud-content\\.com$",REG_NOSUB);
  tls_sni_e_index[APPLE_S] = i-1;

}

void init_services_tls_cn_patterns()
{
  int i = 0;
  
  tls_cn_s_index[DROPBOX_S] = i;
  regcomp(&services_tls_cn_re[i++],"\\.dropbox\\.com$",REG_NOSUB);
  regcomp(&services_tls_cn_re[i++],"\\.dropboxusercontent\\.com$",REG_NOSUB);
  regcomp(&services_tls_cn_re[i++],"\\.dropboxapi\\.com$",REG_NOSUB);
  tls_cn_e_index[DROPBOX_S] = i-1;
}

void init_services_fqdn_patterns()
{
//  int i = 0;

/*
Here we will define REs to be matched against the FQDN, if we decide the FQDN should be consulted
to identify the TLS flow
*/
}

void init_tls_patterns()
{
  init_services_tls_sni_patterns();
  init_services_tls_cn_patterns();
  init_services_fqdn_patterns();
}

/*
General idea:
The tls_service will be stored in the ptp as soon as the TLS state is consolidated.
Step 1: We normally use only the SNI indicated by the client
Step 2: If needed, and the SNI is missing, we use the CommonName in the server certificate (often too broad)
Step 3: If both the SNI and the CN are missing, we might thing about using the FQDN
*/

Bool is_tls_facebook(tcp_pair *ptp_save)
{
  int idx;

  if (!(ptp_save->con_type & SSL_PROTOCOL))
    return FALSE;

  if (ptp_save->ssl_client_subject!=NULL)
   {
     for (idx = tls_sni_s_index[FACEBOOK_S]; idx < tls_sni_e_index[FACEBOOK_S]; idx++)
      {
        if (regexec(&services_tls_sni_re[idx],ptp_save->ssl_client_subject,0,NULL,0)==0) 
          return TRUE;
      }
   }
   
 return FALSE;
}

Bool is_tls_youtube(tcp_pair *ptp_save)
{
  int idx;

  if (!(ptp_save->con_type & SSL_PROTOCOL))
    return FALSE;

  if (ptp_save->ssl_client_subject!=NULL)
   {
     for (idx = tls_sni_s_index[YOUTUBE_S]; idx <= tls_sni_e_index[YOUTUBE_S]; idx++)
      {
        if (regexec(&services_tls_sni_re[idx],ptp_save->ssl_client_subject,0,NULL,0)==0) 
          return TRUE;
      }
   }
   
 return FALSE;
}

Bool is_tls_google(tcp_pair *ptp_save)
{
  int idx;

  if (!(ptp_save->con_type & SSL_PROTOCOL))
    return FALSE;

  if (ptp_save->ssl_client_subject!=NULL)
   {
     for (idx = tls_sni_s_index[GOOGLE_S]; idx <= tls_sni_e_index[GOOGLE_S]; idx++)
      {
        if (regexec(&services_tls_sni_re[idx],ptp_save->ssl_client_subject,0,NULL,0)==0) 
          return TRUE;
      }
   }
   
 return FALSE;
}

Bool is_tls_netflix(tcp_pair *ptp_save)
{
  int idx;

  if (!(ptp_save->con_type & SSL_PROTOCOL))
    return FALSE;

  if (ptp_save->ssl_client_subject!=NULL)
   {
     for (idx = tls_sni_s_index[NETFLIX_S]; idx <= tls_sni_e_index[NETFLIX_S]; idx++)
      {
        if (regexec(&services_tls_sni_re[idx],ptp_save->ssl_client_subject,0,NULL,0)==0) 
          return TRUE;
      }
   }
   
 return FALSE;
}

Bool is_tls_microsoft(tcp_pair *ptp_save)
{
  int idx;

  if (!(ptp_save->con_type & SSL_PROTOCOL))
    return FALSE;

  if (ptp_save->ssl_client_subject!=NULL)
   {
     for (idx = tls_sni_s_index[MICROSOFT_S]; idx <= tls_sni_e_index[MICROSOFT_S]; idx++)
      {
        if (regexec(&services_tls_sni_re[idx],ptp_save->ssl_client_subject,0,NULL,0)==0) 
          return TRUE;
      }
   }
   
 return FALSE;
}

Bool is_tls_apple(tcp_pair *ptp_save)
{
  int idx;

  if (!(ptp_save->con_type & SSL_PROTOCOL))
    return FALSE;

  if (ptp_save->ssl_client_subject!=NULL)
   {
     for (idx = tls_sni_s_index[APPLE_S]; idx <= tls_sni_e_index[APPLE_S]; idx++)
      {
        if (regexec(&services_tls_sni_re[idx],ptp_save->ssl_client_subject,0,NULL,0)==0) 
          return TRUE;
      }
   }
   
 return FALSE;
}

Bool is_tls_dropbox(tcp_pair *ptp_save)
{
  int idx;

  if (!(ptp_save->con_type & SSL_PROTOCOL))
    return FALSE;

  if (ptp_save->ssl_client_subject!=NULL)
   {
     for (idx = tls_sni_s_index[DROPBOX_S]; idx <= tls_sni_e_index[DROPBOX_S]; idx++)
      {
        if (regexec(&services_tls_sni_re[idx],ptp_save->ssl_client_subject,0,NULL,0)==0) 
          return TRUE;
      }
      
   }
  else if (ptp_save->ssl_client_subject!=NULL)
  {
     for (idx = tls_cn_s_index[DROPBOX_S]; idx <= tls_cn_e_index[DROPBOX_S]; idx++)
      {
        if (regexec(&services_tls_sni_re[idx],ptp_save->ssl_client_subject,0,NULL,0)==0) 
          return TRUE;
      }
  }
//  else if (ptp_save->dns_name!=NULL)
//   {
//     if (0)
//       return TRUE;
//     else
//       return FALSE;
//   }
   
 return FALSE;
}

void map_tls_service(tcp_pair *ptp)
{
//  printf("Yeah, TLS! %s!\n",(ptp->ssl_client_subject!=NULL ? ptp->ssl_client_subject:"--"));
  if (is_tls_facebook(ptp))
   {
     ptp->tls_service = TLS_FACEBOOK;
   }
  else if (is_tls_google(ptp))
   {
     ptp->tls_service = TLS_GOOGLE;
   }
  else if (is_tls_youtube(ptp))
   {
     ptp->tls_service = TLS_YOUTUBE;
   }
  else if (is_tls_dropbox(ptp))
   {
     ptp->tls_service = TLS_DROPBOX;
   }
  else if (is_tls_microsoft(ptp))
   {
     ptp->tls_service = TLS_MICROSOFT;
   }
  else if (is_tls_apple(ptp))
   {
     ptp->tls_service = TLS_APPLE;
   }
  else if (is_tls_netflix(ptp))
   {
     ptp->tls_service = TLS_NETFLIX;
   }
/* 
  Another possible idea: there might be a catch-all matching for CDNs like Akamai to be matched if 
  everithing else failed (if we ever decide to have an Akamai category)
*/
  else
   {
     ptp->tls_service = TLS_OTHER;
   }
  
  return;
}
