/*
 *
 * Copyright (c) 2001-2008
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
#include "tcpL7.h"
#include <regex.h>

extern enum video_content VIDEO_MAP(tcp_pair *);
extern enum http_content YTMAP(enum http_content );


char *patterns[21];
char match_buffer[904];
char yt_id[50];
char yt_itag[5];
int  yt_seek;
char yt_seek_char[10];
char yt_redir[7];
int  yt_redir_mode;
int  yt_redir_count;
int  yt_mobile;
int  yt_stream;
regex_t re[21];
regmatch_t re_res[2];

/* Indexes for YouTube Mobile parameters */
#define PARAM_APP	 0
#define PARAM_CLIENT	 1
#define PARAM_KEY	 2
#define PARAM_ANDROIDCID 3

void init_web_patterns()
{
  int i;
  
  patterns[0] = "[?&]id=([0-9a-f]{16})[& ]";
  patterns[1] = "[?&]begin=([0-9]+)[& ]";
  patterns[2] = "[?&]itag=([0-9]+)[& ]";
  patterns[3] = "[?&]st=(lc|nx|tcts)[& ]";
  patterns[4] = "[?&]redirect_counter=([0-9]+)[& ]";
  patterns[5] = "[?&]?video_id=([A-Za-z0-9_-]{11})[& ]";
  patterns[6] = "[?&]app=([^&]+)[& ]";
  patterns[7] = "[?&]client=([^&]+)[& ]";
  patterns[8] = "[?&]key=([^& ]+)[& ]";
  patterns[9] = "[?&]androidcid=([^& ]+)[& ]";
  patterns[10] = "/[0-9]{8,15}/picture[?/ ]"; /* graph.facebook.com */
  patterns[11] = "[?&]id=(o-[A-Za-z0-9_-]{44})[& ]";
// HLS YouTube
  patterns[12] = "/id/([A-Za-z0-9_-]{11})[.]";
  patterns[13] = "/id/([0-9a-f]{16})/";
  patterns[14] = "/id/(o-[A-Za-z0-9_-]{44})/";
  patterns[15] = "/itag/([0-9]+)/";
  patterns[16] = "/source/([^/]+)/";
  patterns[17] = "[?&]id=([A-Za-z0-9_-]{11})[& ]";
  patterns[18] = "/key/([^/?]+)[/?]";
  patterns[19] = "[?&]?upn=([A-Za-z0-9_-]{11})[& ]";
  patterns[20] = "/upn/([A-Za-z0-9_-]{11})[.]";
  
  for (i=0;i<21;i++)
   {
     regcomp(&re[i],patterns[i],REG_EXTENDED);
   }

}

double read_double(char *base)
{
  unsigned long tmp1;
  unsigned long tmp2;
  union { double dbl;
          unsigned long long ull;
  } double_ull;

  memcpy(&tmp1,base,4);
  memcpy(&tmp2,base+4,4);

  tmp1 = ntohl(tmp1);
  tmp2 = ntohl(tmp2);
  double_ull.ull = (unsigned long long) tmp1 << 32 | tmp2;
  return double_ull.dbl;
}

void parse_flv_header(tcp_pair *ptp, void *pdata,int data_length)
{
  struct flv_metadata *meta;
  char *base = (char *)pdata;
  int available_data = data_length - 4 ;

  meta = &(ptp->http_meta);

  switch (*((u_int32_t *) base))
    { 
      case FLV:
        /* Full FLV header */
        base = base+44;
	break;
      case FLV2:
        /* Reduced FLV header */
        base = base+31;
	break;
      default:
        return;
    }

  /* Read the duration of the FLV - We need at least 58+4 bytes in the payload */
  /* All minimum sizes are referred to the usage of the full FLV header */

  if (available_data < 58)
    return;

  if (memcmp(base, "duration", 8) == 0)
   {
     meta->duration = read_double(base+9);
   } 
  else
    return;

  /* Read the starttime of the FLV - We need at least 79+4 bytes in the payload */

  if (available_data < 79) 
    return;

  base = base+19;
  if (memcmp(base, "starttime", 9) == 0)
   {
     meta->starttime = read_double(base+10);
   } 
  else
    return;

  /* Read the total duration of the FLV - We need at least 102+4 bytes in the payload */

  if (available_data < 102)
    return;

  base = base+20;
  if (memcmp(base, "totalduration", 13) == 0)
   {
     meta->totalduration = read_double(base+14);
   } 
  else
    return;

  /* Read the video width of the FLV - We need at least 118+4 bytes in the payload */

  if (available_data < 118)
    return;

  base = base+24;
  if (memcmp(base, "width", 5) == 0)
   {
     meta->width = (int)floor(read_double(base+6));
   } 
  else
    return;

  /* Read the video height of the FLV - We need at least 135+4 bytes in the payload */

  if (available_data < 135)
    return;

  base = base+16;
  if (memcmp(base, "height", 6) == 0)
   {
     meta->height = (int)floor(read_double(base+7));
   } 
  else
    return;

  /* Read the video datarate of the FLV - We need at least 159+4 bytes in the payload */

  if (available_data < 159)
    return;

  base = base+17;
  if (memcmp(base, "videodatarate", 13) == 0)
   {
     meta->videodatarate = read_double(base+14);
   } 
  else
    return;

  /* Read the audio datarate of the FLV - We need at least 183+4 bytes in the payload */

  if (available_data < 183)
    return;

  base = base+24;
  if (memcmp(base, "audiodatarate",13) == 0)
   {
     meta->audiodatarate = read_double(base+14);
   } 
  else
    return;

  /* Read the total datarate of the FLV - We need at least 207+4 bytes in the payload */

  if (available_data < 207)
    return;

  base = base+24;
  if (memcmp(base, "totaldatarate", 13) == 0)
   {
     meta->totaldatarate = read_double(base+14);
   } 
  else
    return;

  /* Read the frame rate of the FLV - We need at least 227+4 bytes in the payload */

  if (available_data < 227)
    return;

  base = base+24;
  if (memcmp(base, "framerate", 9) == 0)
   {
     meta->framerate = read_double(base+10);
   } 
  else
    return;

  /* Read the bytelength of the FLV - We need at least 248+4 bytes in the payload */

  if (available_data < 248)
    return;

  base = base+20;
  if (memcmp(base, "bytelength", 10) == 0)
   {
     meta->bytelength = (int)floor(read_double(base+11));
   }

  return;
}

enum http_content classify_flickr(char *base, int available_data)
{
  char c;
  int i;
  int status1,status2;

  status1=0;
  status2=0;
  i = 3;
  while (i<6)
   {
     c = *(char *)(base + i );
     if (c=='/') 
      {
	status2=1;
	break;
      }
     if (!isdigit(c)) 
      {
	status1=1;
	break;
      }
     i++;
   }
  if (status1==0 && status2==1)
   {
     int digit_count = 0;
     status1=0;
     status2=0;
     i++;
     while (i < 20)
      {
	c = *(char *)(base + i );
	if (c=='_') 
	 {
	   status2=1;
	   break;
	 }
	if (!isdigit(c)) 
	 {
	   status1=1;
	   break;
	 }
        digit_count++;
	i++;
      }
     if (status1==0 && status2==1 && digit_count>8)
      {
	status1=0;
	i++;
	digit_count = 0;
        while (digit_count<10 && i < available_data)
	 {
	   c = *(char *)(base + i );
	   if (!isxdigit(c)) 
	    {
	      status1=1;
	      break;
	    }
	   i++;
	   digit_count++;
	 }
	if (status1==0 && digit_count==10)
	  return HTTP_FLICKR;
      }
   }
  return HTTP_GET;
}

enum http_content classify_social(char *base, int available_data)
{
  char c;
  int i;
  int status1;

  status1=0;
  i = 3;
  while (i<16)
   {
     c = *(char *)(base + i );
     if (c!='/' && !isdigit(c)) 
      {
	status1=1;
	break;
      }
     i++;
   }
  if (status1==1)
   {
     if ((memcmp(base + i,"thumb/",
     	    ((available_data - i ) < 6 ? available_data - i : 6)) == 0)
     	 || (memcmp(base + i,"other/",
     	    ((available_data - i ) < 6 ? available_data - i : 6)) == 0)
     	 || (memcmp(base + i,"main/",
     	    ((available_data - i ) < 5 ? available_data - i : 5)) == 0)
     	)
     return HTTP_SOCIAL;
   }

  return HTTP_GET;
}

enum http_content classify_vimeo(char *base, int available_data)
{
  char c;
  int i;
  int status1;

  status1=0;
  i = 3;
  while (i<23)
   {
     c = *(char *)(base + i );
     if (c!='/' && !isdigit(c)) 
      {
	status1=1;
	break;
      }
     i++;
   }
  if (status1==1)
   {
     if ((memcmp(base + i,".mp4?ak",
     	    ((available_data - i ) < 7 ? available_data - i : 7)) == 0)
     	)
      {
        return HTTP_VIMEO;
      }
     else if ((memcmp(base + i,".mp4?token",
     	    ((available_data - i ) < 10 ? available_data - i : 10)) == 0)
     	)
      {	
        return HTTP_VIMEO;
      }
   }

  return HTTP_GET;
}


enum http_content classify_http_get(void *pdata,int data_length)
{
  char *base = (char *)pdata+4;
  int available_data = data_length - 4 ;

  char c;
  int i;
  int status1,status2;
  
  if (available_data < 1)
    return HTTP_GET;

  if (*base != 0x2f)
    return HTTP_GET;

  switch (*(base+1))
   {
     case 'A':
       if (memcmp(base, "/ADSAdClient",
               ( available_data < 12 ? available_data : 12)) == 0)
         return HTTP_ADV;
       break;
     case 'a':
       if (memcmp(base, "/api/stats/",
        	      ( available_data < 11 ? available_data : 21)) == 0)
         return HTTP_YOUTUBE_SITE;
       else if (memcmp(base, "/ads3/flyers/",
        	      ( available_data < 13 ? available_data : 13)) == 0)
         return HTTP_FACEBOOK;
       else if (memcmp(base, "/ads2/flyers/",
        	      ( available_data < 13 ? available_data : 13)) == 0)
         return HTTP_FACEBOOK;
       else if (memcmp(base, "/ads-ak-snc",
        	      ( available_data < 11 ? available_data : 11)) == 0)
         return HTTP_FACEBOOK;
       else if (memcmp(base, "/album.php?",
        	      ( available_data < 11 ? available_data : 11)) == 0)
         return HTTP_FACEBOOK;
       else if (memcmp(base, "/apps/application.php",
        	     ( available_data < 21 ? available_data : 21)) == 0)
          return HTTP_FACEBOOK;
       else if (memcmp(base, "/ai.php?aed=",
        	     ( available_data < 12 ? available_data : 12)) == 0)
          return HTTP_FACEBOOK;
       else if (memcmp(base, "/adj/",
        	     ( available_data < 5 ? available_data : 5)) == 0)
          return HTTP_ADV;
       else if (memcmp(base, "/ajax_boxes/last_photos",
        	     ( available_data < 23 ? available_data : 23)) == 0)
          return HTTP_SOCIAL;
       else if ( available_data > 10 && (memcmp(base, "/ajax/",6) == 0) )
         {
	   switch (*(base+6))
	    {
	      case 'a':
                if (memcmp(base + 6, "apps/usage_update.php",
        	      ((available_data - 6) < 21 ? available_data - 6 : 21)) == 0)
                  return HTTP_FACEBOOK;
	        break;

	      case 'b':
                if (memcmp(base + 6, "browse_history.php",
        	      ((available_data - 6) < 18 ? available_data - 6 : 18)) == 0)
                  return HTTP_FACEBOOK;
	        break;

	      case 'c':
           	if (memcmp(base + 6, "chat/",
        		   ((available_data - 6) < 5 ? available_data - 6 : 5)) == 0)
           	  return HTTP_FACEBOOK;
           	else if (memcmp(base + 6, "composer/",
        		   ((available_data - 6) < 9 ? available_data - 6 : 9)) == 0)
           	  return HTTP_FACEBOOK;
           	else if (memcmp(base + 6, "ct.php?",
        		   ((available_data - 6) < 7 ? available_data - 6 : 7)) == 0)
           	  return HTTP_FACEBOOK;
	        break;

	      case 'e':
	      	if (memcmp (base + 6, "ego_height.php",
	      		   ((available_data - 6) < 14 ? available_data - 6 : 14)) == 0)
	      	  return HTTP_FACEBOOK;
	        break;

	      case 'f':
           	if (memcmp(base + 6, "f2.php?",
        		   ((available_data - 6) < 7 ? available_data - 6 : 7)) == 0)
           	  return HTTP_FACEBOOK;
           	else if (memcmp(base + 6, "feed/",
        		   ((available_data - 6) < 5 ? available_data - 6 : 5)) == 0)
           	  return HTTP_FACEBOOK;
           	else if (memcmp(base + 6, "f.php?",
        		   ((available_data - 6) < 6 ? available_data - 6 : 6)) == 0)
           	  return HTTP_FACEBOOK;
	        break;

	      case 'g':
	      	if (memcmp (base + 6, "gigaboxx/",
	      		   ((available_data - 6) < 9 ? available_data - 6 : 9)) == 0)
	      	  return HTTP_FACEBOOK;
	        break;

	      case 'h':
	      	if (memcmp (base + 6, "hovercard/",
	      		   ((available_data - 6) < 10 ? available_data - 6 : 10)) == 0)
	      	  return HTTP_FACEBOOK;
	      	else if (memcmp (base + 6, "home/",
	      		   ((available_data - 6) < 5 ? available_data - 6 : 5)) == 0)
	      	  return HTTP_FACEBOOK;
	        break;

	      case 'i':
	      	if (memcmp (base + 6, "intent.php",
	      		   ((available_data - 6) < 10 ? available_data - 6 : 10)) == 0)
	      	  return HTTP_FACEBOOK;
	        break;

	      case 'l':
           	if (memcmp(base + 6, "like/participants.php",
        		   ((available_data - 6) < 21 ? available_data - 6 : 21)) == 0)
           	  return HTTP_FACEBOOK;
           	else if (memcmp(base + 6, "log_ticker_render.php",
        		   ((available_data - 6) < 21 ? available_data - 6 : 21)) == 0)
           	  return HTTP_FACEBOOK;
	        break;

	      case 'n':
           	if (memcmp(base + 6, "nectar.php",
        		   ((available_data - 6) < 10 ? available_data - 6 : 10)) == 0)
           	  return HTTP_FACEBOOK;
           	else if (memcmp(base + 6, "nectar_photos.php",
        		   ((available_data - 6) < 17 ? available_data - 6 : 17)) == 0)
           	  return HTTP_FACEBOOK;
           	else if (memcmp(base + 6, "notes_upload_ajax.php",
        		   ((available_data - 6) < 21 ? available_data - 6 : 21)) == 0)
           	  return HTTP_FACEBOOK;
           	else if (memcmp(base + 6, "notifications/",
        		   ((available_data - 6) < 14 ? available_data - 6 : 14)) == 0)
           	  return HTTP_FACEBOOK;
	        break;

	      case 'p':
           	if (memcmp(base + 6, "presence/",
        		   ((available_data - 6) < 9 ? available_data - 6 : 9)) == 0)
           	  return HTTP_FACEBOOK;
           	else if (memcmp(base + 6, "profile/",
        		   ((available_data - 6) < 8 ? available_data - 6 : 8)) == 0)
           	  return HTTP_FACEBOOK;
           	else if (memcmp(base + 6, "photos",
        		   ((available_data - 6) < 8 ? available_data - 6 : 8)) == 0)
           	  return HTTP_FACEBOOK;
           	else if (memcmp(base + 6, "pagelet/generic.php",
        		   ((available_data - 6) < 19 ? available_data - 6 : 19)) == 0)
           	  return HTTP_FACEBOOK;
	        break;

	      case 'r':
           	if (memcmp(base + 6, "recent_pics.php",
        		   ((available_data - 6) < 15 ? available_data - 6 : 15)) == 0)
           	  return HTTP_FACEBOOK;
	        break;

	      case 's':
           	if (memcmp(base + 6, "share_dialog.php",
        		   ((available_data - 6) < 16 ? available_data - 6 : 16)) == 0)
           	  return HTTP_FACEBOOK;
           	else if (memcmp(base + 6, "stream/profile.php",
        		   ((available_data - 6) < 18 ? available_data - 6 : 18)) == 0)
           	  return HTTP_FACEBOOK;
	   	     break;

	      case 't':
                if (memcmp(base + 6, "typeahead",
                	   ((available_data - 6) < 9 ? available_data - 6 : 9)) == 0)
                  return HTTP_FACEBOOK;
	        break;

	      case 'v':
           	if (memcmp(base + 6, "video/",
        		   ((available_data - 6) < 6 ? available_data - 6 : 6)) == 0)
           	  return HTTP_FACEBOOK;
	        break;
	      default:
	        break;
	    }
         }
       else if ( available_data > 19 && (memcmp(base, "/albums_list/",13) == 0) )
         {
	   if ( isdigit(*(char *)(base + 13 )) &&
	        isdigit(*(char *)(base + 14 )) &&
	        isdigit(*(char *)(base + 15 )) &&
	        isdigit(*(char *)(base + 16 )) &&
	        isdigit(*(char *)(base + 17 )) &&
	        isdigit(*(char *)(base + 18 ))
              )
             return HTTP_SOCIAL;
	 }
       break;

     case 'b':
       if (memcmp(base, "/blog/ajax_",
        	     ( available_data < 11 ? available_data : 11)) == 0)
          return HTTP_SOCIAL;
       break;

     case 'B':
       if (memcmp(base, "/Bursting",
        	     ( available_data < 9 ? available_data : 9)) == 0 )
          return HTTP_ADV;
       break;

     case 'c':
      /* */
       if (memcmp(base, "/cgi-bin/rsapi.cgi",
        	       ( available_data < 18 ? available_data : 18)) == 0)
         return HTTP_RAPIDSHARE;
       else if (memcmp(base, "/cgi-bin/m?ci=",
        	       ( available_data < 14 ? available_data : 14)) == 0)
         return HTTP_ADV;
       else if (memcmp(base, "/cgi-bin/m?rnd=",
        	       ( available_data < 15 ? available_data : 15)) == 0)
         return HTTP_ADV;
       else if (memcmp(base, "/cgi-bin/count?cid=",
        	       ( available_data < 19 ? available_data : 19)) == 0)
         return HTTP_ADV;
       else if (memcmp(base, "/cgi-bin/count?url=",
        	       ( available_data < 19 ? available_data : 19)) == 0)
         return HTTP_ADV;
       else if (memcmp(base, "/cgi-bin/count?rnd=",
        	       ( available_data < 19 ? available_data : 19)) == 0)
         return HTTP_ADV;
       else if (memcmp(base, "/cbk?output=",
               ( available_data < 12 ? available_data : 12)) == 0)
         return HTTP_GMAPS;
       else if (memcmp(base, "/connect.php/",
               ( available_data < 13 ? available_data : 13)) == 0)
         return HTTP_FACEBOOK;
       else if (memcmp(base, "/connect/connect.php",
               ( available_data < 20 ? available_data : 20)) == 0)
         return HTTP_FACEBOOK;
       else if (memcmp(base, "/connect/xd_proxy.php",
               ( available_data < 21 ? available_data : 21)) == 0)
         return HTTP_FACEBOOK;
       else if (memcmp(base, "/connect/xd_arbiter/",
               ( available_data < 20 ? available_data : 20)) == 0)
         return HTTP_FACEBOOK;
       else if (memcmp(base, "/connect/xd_arbiter.php",
               ( available_data < 23 ? available_data : 23)) == 0)
         return HTTP_FACEBOOK;
       else if (memcmp(base, "/cfs-ak-",
               ( available_data < 8 ? available_data : 8)) == 0)
         return HTTP_FACEBOOK;
       else if (memcmp(base, "/cfs-l3-",
               ( available_data < 8 ? available_data : 8)) == 0)
         return HTTP_FACEBOOK;
       else if (memcmp(base, "/common/history_manager.php",
               ( available_data < 27 ? available_data : 27)) == 0)
         return HTTP_FACEBOOK;
       else if (memcmp(base, "/common/redirectiframe.html",
               ( available_data < 27 ? available_data : 27)) == 0)
         return HTTP_FACEBOOK;
       else if (available_data > 30 && memcmp(base, "/common/image/",14)==0 )
         {
	   if ( 
                memcmp(base + 14, "albums/",7)==0 || 
                memcmp(base + 14, "card/",5)==0 || 
	        memcmp(base + 14, "clearbox/",9)==0 || 
                memcmp(base + 14, "emoticons/",10)==0 || 
                memcmp(base + 14, "facelift/",9)==0 || 
                memcmp(base + 14, "flash/",6)==0 || 
                memcmp(base + 14, "icon_",5)==0 || 
                memcmp(base + 14, "logo_",5)==0 ||
                memcmp(base + 14, "share/",6)==0  
              )
           return HTTP_SOCIAL;
	 }
       /* */
       break;

     case 'd':
       if ( available_data > 46 && (memcmp(base, "/dl/",4) == 0) &&
                (*(char *)(base + 36 ))=='/' &&
		(*(char *)(base + 45 ))=='/' )
         /* matching '/dl/[a-zA-Z0-9]{32}/[a-zA-Z0-9]{8}/" */
	 /* mostly video downloads, seldom file downloads */
          return HTTP_FLASHVIDEO;
       else if (memcmp(base, "/dialog/oauth?api_key=",
               ( available_data < 22 ? available_data : 22)) == 0)
         return HTTP_FACEBOOK;
       break;

     case 'e':
      if (available_data > 19 && (memcmp(base, "/embed/",7) == 0) )
        {
          c = *(char *)(base + 18);
	  if (c==' ' || c== '&' || c== '?')
	    {
    	      status1=0;
    	      i = 7;
    	      while (i<18)
    	       {
    		 c = *(char *)(base + i );
    		 if (!( 
		     ( c>=65 && c<=90 ) ||   /* [A-Z] */
		     ( c>=97 && c<=122 ) ||  /* [a-z] */
		     ( c>=48 && c<=57 ) ||   /* [0-9] */
		       c==45 || c==95        /* '-' '_' */
		     ))
    		  {
    		    status1=1;
    		    break;
    		  }
    		 i++;
    	       }
    	      if (status1==0)
               {
#ifdef VIDEO_DETAILS
	         memcpy(yt_id,base+7,11);
                 yt_id[11]='\0';
#endif
    		return HTTP_YOUTUBE_SITE_EMBED;
               }
	    }
	    }
       else if (memcmp(base, "/editapps.php",
        	     ( available_data < 13 ? available_data : 13)) == 0)
          return HTTP_FACEBOOK;
       else if (memcmp(base, "/editnote.php",
        	     ( available_data < 13 ? available_data : 13)) == 0)
          return HTTP_FACEBOOK;
       else if (memcmp(base, "/extern/login_status.php",
        	     ( available_data < 24 ? available_data : 24)) == 0)
          return HTTP_FACEBOOK;
       else if (memcmp(base, "/email_open_log_pic.php",
        	     ( available_data < 23 ? available_data : 23)) == 0)
          return HTTP_FACEBOOK;
       else if (memcmp(base, "/e4/flv/",
        	     ( available_data < 8 ? available_data : 8)) == 0)
          return HTTP_FLASHVIDEO;
       break;

     case 'f':
       if (memcmp(base, "/friends/",
               ( available_data < 9 ? available_data : 9)) == 0)
         return HTTP_FACEBOOK;
       if (memcmp(base, "/friends.php",
               ( available_data < 12 ? available_data : 12)) == 0)
         return HTTP_FACEBOOK;
       else if (memcmp(base, "/feeds/notifications.php",
               ( available_data < 24 ? available_data : 24)) == 0)
         return HTTP_FACEBOOK;
       else if (memcmp(base, "/feeds/api/videos/",
               ( available_data < 18 ? available_data : 18)) == 0)
         {
#ifdef VIDEO_DETAILS
           if (available_data>30)
            {
              status1=0;
              i = 18;
              while (i<29)
               {
                 c = *(char *)(base + i );
                 if (!(
                     ( c>=65 && c<=90 ) ||   /* [A-Z] */
                     ( c>=97 && c<=122 ) ||  /* [a-z] */
                     ( c>=48 && c<=57 ) ||   /* [0-9] */
                       c==45 || c==95        /* '-' '_' */
                     ))
                  {
                    status1=1;
                    break;
                  }
                 i++;
               }
              if (status1==0)
               {
                 memcpy(yt_id,base+18,11);
                 yt_id[11]='\0';
               }
             }
#endif
           return HTTP_YOUTUBE_SITE;
	 }
       else if (memcmp(base, "/feeds/api/users/",
               ( available_data < 17 ? available_data : 17)) == 0)
         return HTTP_YOUTUBE_SITE;
       else if (memcmp(base, "/feeds/base/",
               ( available_data < 12 ? available_data : 12)) == 0)
         return HTTP_YOUTUBE_SITE;

       else if ( available_data > 27 && (memcmp(base, "/friends_online_list/",21) == 0) )
         {
	   if ( isdigit(*(char *)(base + 21 )) &&
	        isdigit(*(char *)(base + 22 )) &&
	        isdigit(*(char *)(base + 23 )) &&
	        isdigit(*(char *)(base + 24 )) &&
	        isdigit(*(char *)(base + 25 )) &&
	        isdigit(*(char *)(base + 26 ))
              )
             return HTTP_SOCIAL;
	 }
       else if ( available_data > 20 && (memcmp(base, "/friends_list/",14) == 0) )
         {
	   if ( isdigit(*(char *)(base + 14 )) &&
	        isdigit(*(char *)(base + 15 )) &&
	        isdigit(*(char *)(base + 16 )) &&
	        isdigit(*(char *)(base + 17 )) &&
	        isdigit(*(char *)(base + 18 )) &&
	        isdigit(*(char *)(base + 19 ))
              )
             return HTTP_SOCIAL;
	 }
       else if ( available_data > 38 && (memcmp(base, "/flv/",5) == 0) )
         {
	   if ( (*(char *)(base + 37 ))=='/' )
             return HTTP_FLASHVIDEO;
	 }
       else if (available_data>15 && (memcmp(base, "/files/",7) ==0) )
        {
     	  status1=0;
     	  status2=0;
     	  i = 7;
     	  while (i<available_data)
     	   {
     	     c = *(char *)(base + i );
	     if (c=='/')
	        break;
             if (!isdigit(c)) status1=1;
     	     if (!isxdigit(c)) 
     	      {
     		status2=1;
     		break;
     	      }
     	     i++;
     	   }
     	  if (i>15 && status2==0 && status1==1)
            return HTTP_MEGAUPLOAD;	     

          status1=0;
          for (i=0;i<8;i++)		     
           {				     
             c = *(char *)(base + 7 + i );
             if (!isdigit(c)) status1=1;
           }				     
          if (status1==0)		     
            return HTTP_RAPIDSHARE;	     
        }
       break;

     case 'g':
       if (memcmp (base, "/generate_204?",
                  ( available_data < 14 ? available_data : 14)) == 0)
         {
	   /* YouTube connection */
#ifdef VIDEO_DETAILS
           int st_redir_mode,rc_redir_mode;
           int rc_redir_count;
	   char url_param[4][80];
	   int  url_found[4];
	   int  idx;
           int  yt_mobile2,mobile_set;
	   int  yt_device2;

           memcpy(match_buffer,base,(available_data<900?available_data:900));
           match_buffer[(available_data<900?available_data:900)]='\0';

           for (idx=0;idx<4;idx++)
	    {
	      url_found[idx]=0;
	      url_param[idx][0]='\0';
	    }

           for (idx=0;idx<4;idx++)
	    {
	      /* Match from pattern[6] to pattern[9] */ 
              if (regexec(&re[6+idx],match_buffer,(size_t) 2,re_res,0)==0)
               {
                int msize = re_res[1].rm_eo-re_res[1].rm_so;
                 memcpy(url_param[idx],match_buffer+re_res[1].rm_so,
                  (msize<79?msize:79));
                  url_param[idx][msize<79?msize:79]='\0';
		 url_found[idx]=1;
               }
	    }
           
	   /* Normally here we have the potentially mobile connection 
	      In any case we apply the complete rule, that is:
	      If key==yt1 and app==youtube_mobile -> mobile
	      else -> nomobile
	      We keep also the rule for the device, that is:
	      if (client =~ /apple/ || client =~ /iPhone/) -> apple
	      else if (client =~ /android/ || androidcid !empty) -> android
	      else -> other
	      
           */
 
           yt_mobile2 = 0;
           mobile_set = 0;

           if (url_found[PARAM_KEY]!=0 && memcmp(url_param[PARAM_KEY],"yt1",3)==0)
	    {
	      if ( url_found[PARAM_APP]!=0 && 
	                 memcmp(url_param[PARAM_APP],"youtube_mobile",14)==0)
		{ 
		  yt_mobile2 = 1;
                  mobile_set = 1;
		}	 
	      else if ( url_found[PARAM_APP]!=0 && 
	                 memcmp(url_param[PARAM_APP],"youtube_mobile",14)!=0)
		{ 
		  /* I had, at least, the data to decide that it might have been mobile */
                  mobile_set = 1;
		}	 
	    }
	   else
	    {
	      /* key==yt5 or dg_yt0 => desktop */
	      /* other key (yta2, ck1, etc...) => mobile */
	      if (url_found[PARAM_KEY]!=0 && 
	             ( memcmp(url_param[PARAM_KEY],"yt1",3)!=0 &&
		       memcmp(url_param[PARAM_KEY],"dg_yt0",6)!=0 &&
		       memcmp(url_param[PARAM_KEY],"yt5",3)!=0 &&
		       memcmp(url_param[PARAM_KEY],"cms1",4)!=0   /* cms is quite common, and not only necessarly mobile */
                     )
		 )
		{ 
		  yt_mobile2 = 1;
                  mobile_set = 1;
		}
	    } 
	     
	   yt_device2 = 1;

	   if ( (url_found[PARAM_CLIENT]!=0) && 
	         ( memcmp(url_param[PARAM_CLIENT],"ytapi-apple",11)==0 ||
                   memcmp(url_param[PARAM_CLIENT],"iPhone",6)==0 ) 
	      )
	    {
	      yt_device2 = 2;
	    }
	   else if ( (url_found[PARAM_CLIENT]!=0) && 
	             ( memcmp(url_param[PARAM_CLIENT],"mvapp-android",13)==0 )
	           )
	    { 
	      yt_device2 = 3;
	    }
	   else if ( (url_found[PARAM_ANDROIDCID]!=0))
	    { 
	      yt_device2 = 3;
	    }
	   else if ( (url_found[PARAM_CLIENT]!=0))
	    { 
	      yt_device2 = 1;
	    }
	   else if (url_found[PARAM_KEY]!=0 && 
	              ( memcmp(url_param[PARAM_KEY],"yt1",3)!=0 &&
		        memcmp(url_param[PARAM_KEY],"dg_yt0",6)!=0 &&
			memcmp(url_param[PARAM_KEY],"yt5",3)!=0 &&
		        memcmp(url_param[PARAM_KEY],"cms1",4)!=0 )   /* cms is quite common, and not only necessarly mobile */
		   )
	    { 
	      yt_device2 = 1;
	    }


            /* itag=fmt */
           if (regexec(&re[2],match_buffer,(size_t) 2,re_res,0)==0)
            {
             int msize = re_res[1].rm_eo-re_res[1].rm_so;
              memcpy(yt_itag,match_buffer+re_res[1].rm_so,
               (msize<4?msize:4));
               yt_itag[msize<4?msize:4]='\0';
            }

            /* id = id16 */
           if (regexec(&re[0],match_buffer,(size_t) 2,re_res,0)==0)
            {
             int msize = re_res[1].rm_eo-re_res[1].rm_so;
              memcpy(yt_id,match_buffer+re_res[1].rm_so,
               (msize<49?msize:49));
               yt_id[msize<49?msize:49]='\0';
	    }
            /* id = id46 */
           else if (regexec(&re[11],match_buffer,(size_t) 2,re_res,0)==0)
            {
             int msize = re_res[1].rm_eo-re_res[1].rm_so;
              memcpy(yt_id,match_buffer+re_res[1].rm_so,
               (msize<49?msize:49));
               yt_id[msize<49?msize:49]='\0';
	    }
	   
	   /* begin = */ 
           if (regexec(&re[1],match_buffer,(size_t) 2, re_res, 0)==0)
	    {
              int msize2 = re_res[1].rm_eo-re_res[1].rm_so;
               memcpy(yt_seek_char,match_buffer+re_res[1].rm_so,
               (msize2<9?msize2:9));
               yt_seek_char[msize2<9?msize2:9]='\0';
	       sscanf(yt_seek_char,"%d",&yt_seek);
	    }
	   else
	    {
	      yt_seek = 0;
	    }
	       
           /* st=mode */
	   st_redir_mode = 0;
           rc_redir_mode = 0;
	   rc_redir_count = 0;
           if (regexec(&re[3],match_buffer,(size_t) 2, re_res, 0)==0)
	    {
	      int msize2 = re_res[1].rm_eo-re_res[1].rm_so;
               memcpy(yt_redir,match_buffer+re_res[1].rm_so,
             	  (msize2<6?msize2:6));
               yt_redir[msize2<6?msize2:6]='\0';

	      if (memcmp(yt_redir,"lc",2)==0)
	       { 
	   	 st_redir_mode = 1;
	       }
	      else if (memcmp(yt_redir,"nx",2)==0)
	       { 
	   	 st_redir_mode = 2;
	       }
	      else
	       { 
	   	 st_redir_mode = 3;
	       }
	    }

           /* redirect_counter= */
	   if (regexec(&re[4],match_buffer,(size_t) 2, re_res, 0)==0)
	    {
	      int msize2 = re_res[1].rm_eo-re_res[1].rm_so;
               memcpy(yt_redir,match_buffer+re_res[1].rm_so,
             	  (msize2<4?msize2:4));
               yt_redir[msize2<4?msize2:4]='\0';
	      rc_redir_mode = 1;
	      sscanf(yt_redir,"%d",&rc_redir_count);
	    }
	    
	   /*
	     redir_mode redir_count
	       0 0 (no redir)
	       1 X ( redirect_counter=X, no st=)
	       2 X+1 ( redirect_counter=X, st=tcts)
	       3 X+1 ( redirect_counter=X, st=nx)
	       4 1 ( no redirect_counter, st=lc)
	       5 1 ( no redirect_couter, st=nx)
	       6 X+1 (another combination)
	   */
	
	   yt_redir_mode = 0;
	   yt_redir_count = 0;

	   if (rc_redir_mode==0 && st_redir_mode==0)
	    {
	      yt_redir_mode = 0;
	      yt_redir_count = 0;
	    }
	   else if (rc_redir_mode==1 && st_redir_mode==0)
	    {
	      yt_redir_mode = 1;
	      yt_redir_count = rc_redir_count;
	    }
	   else if (rc_redir_mode==1 && st_redir_mode==3)
	    {
	      yt_redir_mode = 2;
	      yt_redir_count = rc_redir_count+1;
	    }
	   else if (rc_redir_mode==1 && st_redir_mode==2)
	    {
	      yt_redir_mode = 3;
	      yt_redir_count = rc_redir_count+1;
	    }
           else if (rc_redir_mode==0 && st_redir_mode==1)
	    {
	      yt_redir_mode = 4;
	      yt_redir_count = 1;
	    }
           else if (rc_redir_mode==0 && st_redir_mode==2)
	    {
	      yt_redir_mode = 5;
	      yt_redir_count = 1;
	    }
	   else
	    {
	      yt_redir_mode = 6;
	      yt_redir_count = rc_redir_count+1;
	    }

	  if (mobile_set==0 && yt_mobile2==0)
	   {
	     yt_mobile = 0;
	     yt_stream = 0;
	   }
	  else
	   {
	     yt_mobile = yt_device2;
	     yt_stream = 0;
	   }
//        yt_mobile = mobile_set==1 ? yt_mobile2 : 0 ;
#endif
          return HTTP_YOUTUBE_204;
         }
       else if (memcmp (base, "/get_video_info?",
                  ( available_data < 16 ? available_data : 16)) == 0)
         {
#ifdef VIDEO_DETAILS
	   if (available_data>36)
	    {
              memcpy(match_buffer,base,(available_data<195?available_data:195));
              match_buffer[(available_data<195?available_data:195)]='\0';
              if (regexec(&re[5],match_buffer,(size_t) 2,re_res,0)==0)
              {
                int msize = re_res[1].rm_eo-re_res[1].rm_so;
                memcpy(yt_id,match_buffer+re_res[1].rm_so,
                 (msize<49?msize:49));
                 yt_id[msize<49?msize:49]='\0';
              }
	    }
#endif
          return HTTP_YOUTUBE_SITE;
	 }
       else if (memcmp (base, "/get_video?",
                  ( available_data < 11 ? available_data : 11)) == 0)
         {
#ifdef VIDEO_DETAILS
	   if (available_data>36)
	    {
              memcpy(match_buffer,base,(available_data<195?available_data:195));
              match_buffer[(available_data<195?available_data:195)]='\0';
              if (regexec(&re[5],match_buffer,(size_t) 2,re_res,0)==0)
              {
                int msize = re_res[1].rm_eo-re_res[1].rm_so;
                memcpy(yt_id,match_buffer+re_res[1].rm_so,
                 (msize<49?msize:49));
                 yt_id[msize<49?msize:49]='\0';
              }
	    }
#endif
          return HTTP_YOUTUBE_SITE;
	 }
       else if (memcmp(base, "/group.php?",
               ( available_data < 11 ? available_data : 11)) == 0)
         return HTTP_FACEBOOK;
       else if (memcmp(base, "/groups.php?",
               ( available_data < 12 ? available_data : 12)) == 0)
         return HTTP_FACEBOOK;
       else if ( available_data > 23 && (memcmp(base, "/get/",5) == 0) &&
                (*(char *)(base + 13 ))=='/')
         {
          status1=0;
          for (i=5;i<13;i++)		     
           {				     
             c = *(char *)(base + i );
             if (!isalnum(c)) status1=1;
           }				     
          if (status1==0)
	   {
	     if ((*(char *)(base + 22 ))=='/')
               return HTTP_HOTFILE;
	     else
               return HTTP_STORAGE;
	   }
	 }
       else if ( available_data >21 && memcmp(base, "/gadgets/",9)==0 )
         {
	   if (
                memcmp(base + 9 , "concat?", 7)==0 || 
                memcmp(base + 9 , "ifr?", 4)==0 || 
                memcmp(base + 9 , "js/rpc?", 7)==0 || 
                memcmp(base + 9 , "makeRequest", 11)==0 || 
                memcmp(base + 9 , "proxy?", 6)==0  
	      )
            return HTTP_SOCIAL;
	 }
       else if ( available_data > 25 && (memcmp(base, "/gallery/",9) == 0) )
         {
     	  status1=0;
     	  status2=0;
     	  i = 9;
     	  while (i<24)
     	   {
     	     c = *(char *)(base + i );
	     if (c=='/')
               status1=1;
     	     if (!isdigit(c) && c!='/') 
     	      {
     		break;
     	      }
	     status2 = isdigit(c) ? 1 : 0 ; 
     	     i++;
     	   }
     	  if ( c==' ' && status2==1 && status1==1)
            return HTTP_SOCIAL;
	 }
       break;

     case 'h':
       if (memcmp(base, "/home.php?ref=",
               ( available_data < 14 ? available_data : 14)) == 0)
         return HTTP_FACEBOOK;
       else if (memcmp (base, "/hls_stream.ts?",
                  ( available_data < 15 ? available_data : 15)) == 0)
         {
	   /* YouTube HLS live streaming connection */
#ifdef VIDEO_DETAILS
	   char url_param[80];

           memcpy(match_buffer,base,(available_data<900?available_data:900));
           match_buffer[(available_data<900?available_data:900)]='\0';

            /* &itag = fmt */
           if (regexec(&re[2],match_buffer,(size_t) 2,re_res,0)==0)
            {
             int msize = re_res[1].rm_eo-re_res[1].rm_so;
              memcpy(yt_itag,match_buffer+re_res[1].rm_so,
               (msize<4?msize:4));
               yt_itag[msize<4?msize:4]='\0';
            }

            /* id = id11 */
           if (regexec(&re[17],match_buffer,(size_t) 2,re_res,0)==0)
            {
             int msize = re_res[1].rm_eo-re_res[1].rm_so;
              memcpy(yt_id,match_buffer+re_res[1].rm_so,
               (msize<49?msize:49));
               yt_id[msize<49?msize:49]='\0';
	    }
            /* id = id16 */
           else if (regexec(&re[0],match_buffer,(size_t) 2,re_res,0)==0)
            {
             int msize = re_res[1].rm_eo-re_res[1].rm_so;
              memcpy(yt_id,match_buffer+re_res[1].rm_so,
               (msize<49?msize:49));
               yt_id[msize<49?msize:49]='\0';
	    }
            /* id = id46 */
           else if (regexec(&re[14],match_buffer,(size_t) 2,re_res,0)==0)
            {
             int msize = re_res[1].rm_eo-re_res[1].rm_so;
              memcpy(yt_id,match_buffer+re_res[1].rm_so,
               (msize<49?msize:49));
               yt_id[msize<49?msize:49]='\0';
	    }

           yt_mobile = 0;
           yt_stream = 4;
           
	   url_param[0] = '\0';
	   
	   /* key = yt1 | yta2 */
           if (regexec(&re[8],match_buffer,(size_t) 2,re_res,0)==0)
            {
             int msize = re_res[1].rm_eo-re_res[1].rm_so;
              memcpy(url_param,match_buffer+re_res[1].rm_so,
               (msize<79?msize:79));
               url_param[msize<79?msize:79]='\0';
            }
 
	   if (memcmp(url_param,"yt1",3)==0)
	    {
              /* key = yt1 => desktop */
		  yt_mobile = 0;
	    }
	   else 
	    {
              /* key = yta2 or something else => mobile (Apple?) */
		  yt_mobile = 0;
	    }
           
	   yt_seek = 0;
	   yt_redir_mode = 0;
	   yt_redir_count = 0;

#endif
          return HTTP_YOUTUBE_VIDEO;
         }
       break;

     case 'i':
       if (available_data > 31 && (memcmp(base, "/i/",3) == 0) )
        {
	  if (memcmp(base + 26, "1.jpg",5) == 0)
           return HTTP_YOUTUBE_SITE;
	}
       else if (memcmp(base, "/i/widget-logo.png",
               ( available_data < 18 ? available_data : 18)) == 0)
         return HTTP_TWITTER;
       else if (memcmp(base, "/iframe/12?r=",
               ( available_data < 13 ? available_data : 13)) == 0)
         return HTTP_FACEBOOK;
       else if (memcmp(base, "/iframe/11?r=",
               ( available_data < 13 ? available_data : 13)) == 0)
         return HTTP_FACEBOOK;
       else if (memcmp(base, "/iframe/10?r=",
               ( available_data < 13 ? available_data : 13)) == 0)
         return HTTP_FACEBOOK; /* Obsolete */
       break;

     case 'j':
       if (memcmp(base, "/js/api_lib/v0.4/",
               ( available_data < 17 ? available_data : 17)) == 0)
         return HTTP_FACEBOOK;
       else if (memcmp(base, "/j/2/",
               ( available_data < 5 ? available_data : 5)) == 0)
         return HTTP_TWITTER;
       else if (memcmp(base, "/j/1/",
               ( available_data < 5 ? available_data : 5)) == 0)
         return HTTP_TWITTER;
       break;

     case 'k':
       if (memcmp(base, "/kh/v=",
               ( available_data < 6 ? available_data : 6)) == 0)
         return HTTP_GMAPS;
       break;

     case 'l':
       if (memcmp (base, "/liveplay?",
                  ( available_data < 10 ? available_data : 10)) == 0)
         {
	   /* YouTube live FLV connection */
#ifdef VIDEO_DETAILS
	   char url_param[80];

           memcpy(match_buffer,base,(available_data<900?available_data:900));
           match_buffer[(available_data<900?available_data:900)]='\0';

            /* &itag = fmt */
           if (regexec(&re[2],match_buffer,(size_t) 2,re_res,0)==0)
            {
             int msize = re_res[1].rm_eo-re_res[1].rm_so;
              memcpy(yt_itag,match_buffer+re_res[1].rm_so,
               (msize<4?msize:4));
               yt_itag[msize<4?msize:4]='\0';
            }

            /* id = id11 */
           if (regexec(&re[17],match_buffer,(size_t) 2,re_res,0)==0)
            {
             int msize = re_res[1].rm_eo-re_res[1].rm_so;
              memcpy(yt_id,match_buffer+re_res[1].rm_so,
               (msize<49?msize:49));
               yt_id[msize<49?msize:49]='\0';
	    }
            /* id = id16 */
           else if (regexec(&re[0],match_buffer,(size_t) 2,re_res,0)==0)
            {
             int msize = re_res[1].rm_eo-re_res[1].rm_so;
              memcpy(yt_id,match_buffer+re_res[1].rm_so,
               (msize<49?msize:49));
               yt_id[msize<49?msize:49]='\0';
	    }
            /* id = id46 */
           else if (regexec(&re[14],match_buffer,(size_t) 2,re_res,0)==0)
            {
             int msize = re_res[1].rm_eo-re_res[1].rm_so;
              memcpy(yt_id,match_buffer+re_res[1].rm_so,
               (msize<49?msize:49));
               yt_id[msize<49?msize:49]='\0';
	    }

           yt_mobile = 0;
           yt_stream = 5;
           
	   url_param[0] = '\0';
	   
	   /* key = yt1 */
           if (regexec(&re[8],match_buffer,(size_t) 2,re_res,0)==0)
            {
             int msize = re_res[1].rm_eo-re_res[1].rm_so;
              memcpy(url_param,match_buffer+re_res[1].rm_so,
               (msize<79?msize:79));
               url_param[msize<79?msize:79]='\0';
            }
 
	   if (memcmp(url_param,"yt1",3)==0)
	    {
              /* key = yt1 => desktop */
		  yt_mobile = 0;
	    }
	   else 
	    {
              /* something else => suppose desktop, since it is FLV streaming */
	      /* The little evidence for key=yt5 points to desktop connections */
		  yt_mobile = 0;
	    }
           
	   yt_seek = 0;
	   yt_redir_mode = 0;
	   yt_redir_count = 0;

#endif
          return HTTP_YOUTUBE_VIDEO;
         }
       break;

     case 'm':
       if ( available_data >16 && memcmp(base, "/maps",5)==0 )
         {
	   if (
                memcmp(base + 5 , "/gen_", 5)==0 || 
                memcmp(base + 5 , "/vp?", 4)==0 || 
                memcmp(base + 5 , "/l?", 3)==0 || 
                memcmp(base + 5 , "/trends?", 8)==0 || 
                memcmp(base + 5 , "lt?lyrs=", 8)==0 || 
                memcmp(base + 5 , "/api/", 5)==0 || 
                memcmp(base + 5 , "lt/ft?lyrs=", 11)==0
	      )     
           return HTTP_GMAPS;
	  }
       else if (memcmp(base, "/mapfiles/",
               ( available_data < 10 ? available_data : 10)) == 0)
         return HTTP_GMAPS;
       else if (memcmp(base, "/might_know/listJSON/",
               ( available_data < 21 ? available_data : 21)) == 0)
         return HTTP_SOCIAL;
       break;
       
     case 'n':
       if (memcmp(base, "/notifications.php",
               ( available_data < 18 ? available_data : 18)) == 0)
         return HTTP_FACEBOOK;
       else if (memcmp(base, "/new_messages_json/top/",
               ( available_data < 23 ? available_data : 23)) == 0)
         return HTTP_SOCIAL;
       else if (memcmp(base, "/new_messages_get_mail/",
               ( available_data < 23 ? available_data : 23)) == 0)
         return HTTP_SOCIAL;
       else if (memcmp(base, "/nktalk/",
        	      ( available_data < 8 ? available_data : 8)) == 0)
         return HTTP_SOCIAL;
       break;

     case 'o':
       if ( available_data > 19 && (memcmp(base, "/online_list/",13) == 0) )
         {
	   if ( isdigit(*(char *)(base + 13 )) &&
	        isdigit(*(char *)(base + 14 )) &&
	        isdigit(*(char *)(base + 15 )) &&
	        isdigit(*(char *)(base + 16 )) &&
	        isdigit(*(char *)(base + 17 )) &&
	        isdigit(*(char *)(base + 18 ))
              )
             return HTTP_SOCIAL;
	 }
       else if ( available_data > 14 && (memcmp(base, "/object",7) == 0) )
     	{
     	  status1=0;
     	  i = 7;
     	  while (i<14)
     	   {
     	     c = *(char *)(base + i );
     	     if (!isdigit(c) && c!='/') 
     	      {
     		status1=1;
     		break;
     	      }
     	     i++;
     	   }
     	  if (status1==0)
     	    return HTTP_FACEBOOK;
     	}		 
       break;

     case 'p':
      if (memcmp(base, "/pagead/",
        	    ( available_data < 8 ? available_data : 8)) == 0)
         return HTTP_ADV;
      else if (memcmp(base, "/pull?channel=",
        	       ( available_data < 14 ? available_data : 14)) == 0)
         return HTTP_FACEBOOK;
      else if (memcmp(base, "/photo.php?fbid=",
        	    ( available_data < 16 ? available_data : 16)) == 0)
         return HTTP_FACEBOOK;
      else if (memcmp(base, "/photo.php?pid=",
        	    ( available_data < 15 ? available_data : 15)) == 0)
         return HTTP_FACEBOOK;
      else if (memcmp(base, "/photo_search.php?",
        	    ( available_data < 18 ? available_data : 18)) == 0)
         return HTTP_FACEBOOK;
      else if (memcmp(base, "/posted.php?",
        	    ( available_data < 12 ? available_data : 12)) == 0)
         return HTTP_FACEBOOK;
       else if (memcmp(base, "/profile.php?id=",
        	       ( available_data < 16 ? available_data : 16)) == 0)
         return HTTP_FACEBOOK;
       else if (memcmp(base, "/pagelet/generic.php",
        	       ( available_data < 20 ? available_data : 20)) == 0)
         return HTTP_FACEBOOK;
       else if (memcmp(base, "/ping?partition=",
        	       ( available_data < 16 ? available_data : 16)) == 0)
         return HTTP_FACEBOOK;
       else if (memcmp(base, "/p?partition=",
        	       ( available_data < 13 ? available_data : 13)) == 0)
         return HTTP_FACEBOOK;
       else if ( available_data >29 && memcmp(base, "/plugins/",9)==0 )
         {
	   if (
                memcmp(base + 9 , "activity.php?", 13)==0 || 
                memcmp(base + 9 , "likebox.php?", 12)==0 || 
                memcmp(base + 9 , "like_box.php?", 13)==0 || 
                memcmp(base + 9 , "like.php?", 9)==0 || 
                memcmp(base + 9 , "login_button.php?", 17)==0 || 
                memcmp(base + 9 , "subscribe.php?", 14)==0 || 
                memcmp(base + 9 , "registration.php?", 17)==0 || 
                memcmp(base + 9 , "facepile.php?", 12)==0 || 
                memcmp(base + 9 , "fan.php?", 8)==0 || 
		memcmp(base + 9 , "send.php?", 9)==0 || 
                memcmp(base + 9 , "share_button.php?", 17)==0 || 
                memcmp(base + 9 , "comments.php?", 13)==0 || 
                memcmp(base + 9 , "recommendations.php?", 20)==0 
	      )
            return HTTP_FACEBOOK;
	 }
       else if ( available_data > 24 && memcmp(base, "/profile_images/",16)==0 )
         {
           status1=0;
   	   i = 16;
    	   while (i<24)
   	    {
   	      c = *(char *)(base + i );
    	      if (!isdigit(c))
   	       {
   		 status1=1;
   	 	 break;
   	       }
   	      i++;
   	    }
   	   if (status1==0)
             return HTTP_TWITTER;
	 }

       else if ( available_data >22 && memcmp(base, "/pages/",7)==0 )
         {
	   if (
                memcmp(base + 7 , "activity/", 9)==0 || 
                memcmp(base + 7 , "application/", 12)==0 || 
                memcmp(base + 7 , "community/", 10)==0 || 
                memcmp(base + 7 , "image/", 6)==0 || 
                memcmp(base + 7 , "listing/", 8)==0 || 
                memcmp(base + 7 , "main/", 5)==0 || 
                memcmp(base + 7 , "message/", 8)==0 || 
                memcmp(base + 7 , "micrologin/", 11)==0 || 
                memcmp(base + 7 , "misc/", 5)==0 || 
                memcmp(base + 7 , "share/", 6)==0 || 
                memcmp(base + 7 , "timeline/", 9)==0 || 
                memcmp(base + 7 , "user/", 5)==0 
	      )
            return HTTP_SOCIAL;
	 }
       else if ( available_data >16 && memcmp(base, "/poczta/",8)==0 )
         {
	   if (
		isdigit( *(char *)(base + 8 )) ||
                memcmp(base + 8 , "choose", 6)==0 ||
                memcmp(base + 8 , "compose", 7)==0 || 
                memcmp(base + 8 , "inbox", 5)==0 || 
                memcmp(base + 8 , "outbox", 6)==0 || 
                memcmp(base + 8 , "null", 4)==0 || 
                memcmp(base + 8 , "trash", 5)==0
	      )
            return HTTP_SOCIAL;
	 }
       else if ( available_data >26 && memcmp(base, "/profile/",9)==0 )
         {
	   if (
                memcmp(base + 9 , "edit ", 5)==0 ||
                memcmp(base + 9 , "advanced", 8)==0 || 
                memcmp(base + 9 , "black_list", 10)==0 || 
                memcmp(base + 9 , "card", 4)==0 || 
                memcmp(base + 9 , "gallery", 7)==0 || 
                memcmp(base + 9 , "null", 4)==0 || 
                memcmp(base + 9 , "preference", 10)==0 || 
                memcmp(base + 9 , "privacy_settings", 16)==0 || 
                memcmp(base + 9 , "ratings", 7)==0 || 
                memcmp(base + 9 , "sledzik", 7)==0
	      )
            return HTTP_SOCIAL;
	 }
       break;

     case 'R':
       if ( available_data > 23 && (memcmp(base, "/RealMedia/ads/",15) == 0) )
        {
	   switch (*(base+15))
	    {
              case 'a':
                if (memcmp(base + 15, "adstream",
                      ((available_data - 15) < 8 ? available_data - 15 : 8)) == 0)
                  return HTTP_ADV;
	        break;
              case 'C':
                if (memcmp(base + 15, "Creatives",
                      ((available_data - 15) < 9 ? available_data - 15 : 9)) == 0)
                  return HTTP_ADV;
	        break;
              case 'c':
                if (memcmp(base + 15, "cap.cgi",
                      ((available_data - 15) < 7 ? available_data - 15 : 7)) == 0)
                  return HTTP_ADV;
                else if (memcmp(base + 15, "click_lx.ads",
                      ((available_data - 15) < 12 ? available_data - 15 : 12)) == 0)
                  return HTTP_ADV;
	        break;
	      default:
	        break;
	    }
	}
       break;

     case 'r':
       if (memcmp(base, "/reqs.php?",
               ( available_data < 10 ? available_data : 10)) == 0)
         return HTTP_FACEBOOK;
       else if (memcmp(base, "/restserver.php",
        	      ( available_data < 15 ? available_data : 15)) == 0)
         return HTTP_FACEBOOK;
       else if (memcmp(base, "/rsrc.php/",
               ( available_data < 10 ? available_data : 10)) == 0)
         return HTTP_FACEBOOK;
       else if (memcmp(base, "/rest/person/",
        	    ( available_data < 13 ? available_data : 13)) == 0)
         return HTTP_SOCIAL;
       else if (available_data > 44 &&  (memcmp(base, "/range/",7) == 0) )
        {
           status1=0;
   	   i = 7;
    	   while (i<40)
   	    {
   	      c = *(char *)(base + i );
    	      if (!isdigit(c) && c!='-')
   	       {
   	 	 break;
   	       }
   	      i++;
   	    }
   	   if (i<40 && memcmp(base+i,"?o=A",4)==0)
	    {
             return HTTP_NETFLIX; /* Netflix */
	    }
	  
        }
       break;

     case 's':
       if (memcmp(base, "/subscribe?host_int=",
        	       ( available_data < 20 ? available_data : 20)) == 0)
        {
#ifdef SNOOP_DROPBOX	
   	  i = 20;
    	  while (i<32)
   	   {
   	     c = *(char *)(base + i );
    	     if (!isdigit(c))
   	      {
   	 	break;
   	      }
	     else
	      yt_id[i-20]=c;
   	     i++;
   	   }
	  yt_id[i-20]='\0';
#endif
          return HTTP_DROPBOX;
	}
       else if (memcmp(base, "/safe_image.php?d=",
        	       ( available_data < 18 ? available_data : 18)) == 0)
         return HTTP_FACEBOOK;
       else if (memcmp(base, "/s.php?",
        	    ( available_data < 7 ? available_data : 7)) == 0)
         return HTTP_FACEBOOK;
       else if (memcmp(base, "/static/v0.4/",
        	    ( available_data < 13 ? available_data : 13)) == 0)
         return HTTP_FACEBOOK;
       else if (memcmp(base, "/stage.static/rsrc.php/",
               ( available_data < 23 ? available_data : 23)) == 0)
         return HTTP_FACEBOOK;
       else if (memcmp(base, "/static-ak/rsrc.php/",
               ( available_data < 20 ? available_data : 20)) == 0)
         return HTTP_FACEBOOK;
       else if (memcmp(base, "/search/pages/",
        	    ( available_data < 14 ? available_data : 14)) == 0)
         return HTTP_SOCIAL;
       else if (memcmp(base, "/school/",
        	    ( available_data < 8 ? available_data : 8)) == 0)
         return HTTP_SOCIAL;
       else if (memcmp(base, "/sledzik/",
        	    ( available_data < 9 ? available_data : 9)) == 0)
         return HTTP_SOCIAL;
       else if (memcmp(base, "/storage/gifts/",
        	    ( available_data < 15 ? available_data : 15)) == 0)
         return HTTP_SOCIAL;
       else if (memcmp(base, "/storage/smileys/",
        	    ( available_data < 17 ? available_data : 17)) == 0)
         return HTTP_SOCIAL;
       else if (memcmp(base, "/style/",
        	    ( available_data < 7 ? available_data : 7)) == 0)
        {
	  status1=0;
	  i = 7;
          while (i<available_data-5)
           {
             c = *(char *)(base + i );
             if (c==':') 
              {
        	status1=1;
        	break;
              }
             i++;
           }
          if (status1==1)
           {
	     if ( isxdigit(*(char *)(base + i + 1)) &&
	          isxdigit(*(char *)(base + i + 2)) &&
	          isxdigit(*(char *)(base + i + 3)) &&
	          isxdigit(*(char *)(base + i + 4)) &&
		  (*(char *)(base + i + 5)) == ' '
		 )
             return HTTP_SOCIAL;
	   }
        }
       else if (memcmp(base, "/script/",
        	    ( available_data < 8 ? available_data : 8)) == 0)
        {
	  status1=0;
	  i = 8;
          while (i<available_data-5)
           {
             c = *(char *)(base + i );
             if (c==':') 
              {
        	status1=1;
        	break;
              }
             i++;
           }
          if (status1==1)
           {
	     if ( isxdigit(*(char *)(base + i + 1)) &&
	          isxdigit(*(char *)(base + i + 2)) &&
	          isxdigit(*(char *)(base + i + 3)) &&
	          isxdigit(*(char *)(base + i + 4)) &&
		  (*(char *)(base + i + 5)) == ' '
		 )
             return HTTP_SOCIAL;
	   }
        }
       break;

     case 'u':
       if (available_data > 33 && (memcmp(base, "/u/",3) == 0) )
        {
	  if (memcmp(base + 26, "watch_",6) == 0)
           return HTTP_YOUTUBE_SITE;
	}
       break;

     case '?':
       if (available_data > 5 && (memcmp(base, "/?o=A",5) == 0) )
        {	      
           return HTTP_NETFLIX; /* Netflix */
	}
       break;

     case 'v':
       if (memcmp (base, "/videoplayback?",
                  ( available_data < 15 ? available_data : 15)) == 0)
         {
	   /* YouTube connection */
#ifdef VIDEO_DETAILS
           int st_redir_mode,rc_redir_mode;
           int rc_redir_count;
	   char url_param[4][80];
	   int  url_found[4];
	   int  idx;
           int  yt_mobile2,mobile_set;
	   int yt_device2;

           memcpy(match_buffer,base,(available_data<900?available_data:900));
           match_buffer[(available_data<900?available_data:900)]='\0';

           for (idx=0;idx<4;idx++)
	    {
	      url_found[idx]=0;
	      url_param[idx][0]='\0';
	    }

           for (idx=0;idx<4;idx++)
	    {
	      /* Match from pattern[6] to pattern[9] */ 
              if (regexec(&re[6+idx],match_buffer,(size_t) 2,re_res,0)==0)
               {
                int msize = re_res[1].rm_eo-re_res[1].rm_so;
                 memcpy(url_param[idx],match_buffer+re_res[1].rm_so,
                  (msize<79?msize:79));
                  url_param[idx][msize<79?msize:79]='\0';
		 url_found[idx]=1;
               }
	    }
           
	   /* Normally here we have the potentially mobile connection 
	      In any case we apply the complete rule, that is:
	      If key==yt1 and app==youtube_mobile -> mobile
	      else -> nomobile
	      We keep also the rule for the device, that is:
	      if (client =~ /apple/ || client =~ /iPhone/) -> apple
	      else if (client =~ /android/ || androidcid !empty) -> android
	      else -> other
	      
           */
 
           yt_mobile2 = 0;
           mobile_set = 0;

           if (url_found[PARAM_KEY]!=0 && memcmp(url_param[PARAM_KEY],"yt1",3)==0)
	    {
	      if ( url_found[PARAM_APP]!=0 && 
	                 memcmp(url_param[PARAM_APP],"youtube_mobile",14)==0)
		{ 
		  yt_mobile2 = 1;
                  mobile_set = 1;
		}	 
	      else if ( url_found[PARAM_APP]!=0 && 
	                 memcmp(url_param[PARAM_APP],"youtube_mobile",14)!=0)
		{ 
		  /* I had, at least, the data to decide that it might have been mobile */
                  mobile_set = 1;
		}	 
	    }
	   else
	    {
	      /* key==yt5 or dg_yt0 => desktop */
	      /* other key (yta2, ck1, etc...) => mobile */
	      if (url_found[PARAM_KEY]!=0 && 
	             ( memcmp(url_param[PARAM_KEY],"yt1",3)!=0 &&
		       memcmp(url_param[PARAM_KEY],"dg_yt0",6)!=0 &&
		       memcmp(url_param[PARAM_KEY],"yt5",3)!=0 &&
		       memcmp(url_param[PARAM_KEY],"cms1",4)!=0   /* cms is quite common, and not only necessarly mobile */
                     )
		 )
		{ 
		  yt_mobile2 = 1;
                  mobile_set = 1;
		}
	    } 
	     
	   yt_device2 = 1;

	   if ( (url_found[PARAM_CLIENT]!=0) && 
	         ( memcmp(url_param[PARAM_CLIENT],"ytapi-apple",11)==0 ||
                   memcmp(url_param[PARAM_CLIENT],"iPhone",6)==0 ) 
	      )
	    {
	      yt_device2 = 2;
	    }
	   else if ( (url_found[PARAM_CLIENT]!=0) && 
	             ( memcmp(url_param[PARAM_CLIENT],"mvapp-android",13)==0 )
	           )
	    { 
	      yt_device2 = 3;
	    }
	   else if ( (url_found[PARAM_ANDROIDCID]!=0))
	    { 
	      yt_device2 = 3;
	    }
	   else if ( (url_found[PARAM_CLIENT]!=0))
	    { 
	      yt_device2 = 1;
	    }
	   else if (url_found[PARAM_KEY]!=0 && 
	              ( memcmp(url_param[PARAM_KEY],"yt1",3)!=0 &&
		        memcmp(url_param[PARAM_KEY],"dg_yt0",6)!=0 &&
			memcmp(url_param[PARAM_KEY],"yt5",3)!=0 &&
		        memcmp(url_param[PARAM_KEY],"cms1",4)!=0 )  /* cms is quite common, and not only necessarly mobile */
		   )
	    { 
	      yt_device2 = 1;
	    }

            /* itag=fmt */
           if (regexec(&re[2],match_buffer,(size_t) 2,re_res,0)==0)
            {
             int msize = re_res[1].rm_eo-re_res[1].rm_so;
              memcpy(yt_itag,match_buffer+re_res[1].rm_so,
               (msize<4?msize:4));
               yt_itag[msize<4?msize:4]='\0';
            }

            /* id = id16 */
           if (regexec(&re[0],match_buffer,(size_t) 2,re_res,0)==0)
            {
             int msize = re_res[1].rm_eo-re_res[1].rm_so;
              memcpy(yt_id,match_buffer+re_res[1].rm_so,
               (msize<49?msize:49));
               yt_id[msize<49?msize:49]='\0';
	    }
            /* id = id46 */
           else if (regexec(&re[11],match_buffer,(size_t) 2,re_res,0)==0)
            {
             int msize = re_res[1].rm_eo-re_res[1].rm_so;
              memcpy(yt_id,match_buffer+re_res[1].rm_so,
               (msize<49?msize:49));
               yt_id[msize<49?msize:49]='\0';
	    }
	   
	   /* begin = */ 
           if (regexec(&re[1],match_buffer,(size_t) 2, re_res, 0)==0)
	    {
              int msize2 = re_res[1].rm_eo-re_res[1].rm_so;
               memcpy(yt_seek_char,match_buffer+re_res[1].rm_so,
               (msize2<9?msize2:9));
               yt_seek_char[msize2<9?msize2:9]='\0';
	       sscanf(yt_seek_char,"%d",&yt_seek);
	    }
	   else
	    {
	      yt_seek = 0;
	    }
	       
           /* st=mode */
	   st_redir_mode = 0;
           rc_redir_mode = 0;
	   rc_redir_count = 0;
           if (regexec(&re[3],match_buffer,(size_t) 2, re_res, 0)==0)
	    {
	      int msize2 = re_res[1].rm_eo-re_res[1].rm_so;
               memcpy(yt_redir,match_buffer+re_res[1].rm_so,
             	  (msize2<6?msize2:6));
               yt_redir[msize2<6?msize2:6]='\0';

	      if (memcmp(yt_redir,"lc",2)==0)
	       { 
	   	 st_redir_mode = 1;
	       }
	      else if (memcmp(yt_redir,"nx",2)==0)
	       { 
	   	 st_redir_mode = 2;
	       }
	      else
	       { 
	   	 st_redir_mode = 3;
	       }
	    }

           /* redirect_counter= */
	   if (regexec(&re[4],match_buffer,(size_t) 2, re_res, 0)==0)
	    {
	      int msize2 = re_res[1].rm_eo-re_res[1].rm_so;
               memcpy(yt_redir,match_buffer+re_res[1].rm_so,
             	  (msize2<4?msize2:4));
               yt_redir[msize2<4?msize2:4]='\0';
	      rc_redir_mode = 1;
	      sscanf(yt_redir,"%d",&rc_redir_count);
	    }
	    
	   /*
	     redir_mode redir_count
	       0 0 (no redir)
	       1 X ( redirect_counter=X, no st=)
	       2 X+1 ( redirect_counter=X, st=tcts)
	       3 X+1 ( redirect_counter=X, st=nx)
	       4 1 ( no redirect_counter, st=lc)
	       5 1 ( no redirect_couter, st=nx)
	       6 X+1 (another combination)
	   */
	
	   yt_redir_mode = 0;
	   yt_redir_count = 0;

	   if (rc_redir_mode==0 && st_redir_mode==0)
	    {
	      yt_redir_mode = 0;
	      yt_redir_count = 0;
	    }
	   else if (rc_redir_mode==1 && st_redir_mode==0)
	    {
	      yt_redir_mode = 1;
	      yt_redir_count = rc_redir_count;
	    }
	   else if (rc_redir_mode==1 && st_redir_mode==3)
	    {
	      yt_redir_mode = 2;
	      yt_redir_count = rc_redir_count+1;
	    }
	   else if (rc_redir_mode==1 && st_redir_mode==2)
	    {
	      yt_redir_mode = 3;
	      yt_redir_count = rc_redir_count+1;
	    }
           else if (rc_redir_mode==0 && st_redir_mode==1)
	    {
	      yt_redir_mode = 4;
	      yt_redir_count = 1;
	    }
           else if (rc_redir_mode==0 && st_redir_mode==2)
	    {
	      yt_redir_mode = 5;
	      yt_redir_count = 1;
	    }
	   else
	    {
	      yt_redir_mode = 6;
	      yt_redir_count = rc_redir_count+1;
	    }

	  if (mobile_set==0 && yt_mobile2==0)
	   {
	     yt_mobile = 0;
	     yt_stream = 0;
	   }
	  else
	   {
	     yt_mobile = yt_device2;
	     yt_stream = 0;
	   }
//        yt_mobile = mobile_set==1 ? yt_mobile2 : 0 ;
#endif
          return HTTP_YOUTUBE_VIDEO;
         }
       else if (memcmp (base, "/videoplayback/",
                  ( available_data < 15 ? available_data : 15)) == 0)
         {
	   /* YouTube HLS connection or video advertisement*/
#ifdef VIDEO_DETAILS
	   char url_param[80];
	   int  android_cid;

           memcpy(match_buffer,base,(available_data<900?available_data:900));
           match_buffer[(available_data<900?available_data:900)]='\0';

            /* /itag/fmt/ */
           if (regexec(&re[15],match_buffer,(size_t) 2,re_res,0)==0)
            {
             int msize = re_res[1].rm_eo-re_res[1].rm_so;
              memcpy(yt_itag,match_buffer+re_res[1].rm_so,
               (msize<4?msize:4));
               yt_itag[msize<4?msize:4]='\0';
            }

            /* id = id11 */
           if (regexec(&re[12],match_buffer,(size_t) 2,re_res,0)==0)
            {
             int msize = re_res[1].rm_eo-re_res[1].rm_so;
              memcpy(yt_id,match_buffer+re_res[1].rm_so,
               (msize<49?msize:49));
               yt_id[msize<49?msize:49]='\0';
	    }
            /* id = id16 */
           else if (regexec(&re[13],match_buffer,(size_t) 2,re_res,0)==0)
            {
             int msize = re_res[1].rm_eo-re_res[1].rm_so;
              memcpy(yt_id,match_buffer+re_res[1].rm_so,
               (msize<49?msize:49));
               yt_id[msize<49?msize:49]='\0';
	    }
            /* id = id46 */
           else if (regexec(&re[14],match_buffer,(size_t) 2,re_res,0)==0)
            {
             int msize = re_res[1].rm_eo-re_res[1].rm_so;
              memcpy(yt_id,match_buffer+re_res[1].rm_so,
               (msize<49?msize:49));
               yt_id[msize<49?msize:49]='\0';
	    }

           yt_mobile = 0;
           yt_stream = 0;
           android_cid = 0;
	   
	   url_param[0] = '\0';
	   
           if (regexec(&re[9],match_buffer,(size_t) 2,re_res,0)==0)
            {
	       android_cid = 1;
            }
	   
           if (regexec(&re[16],match_buffer,(size_t) 2,re_res,0)==0)
            {
             int msize = re_res[1].rm_eo-re_res[1].rm_so;
              memcpy(url_param,match_buffer+re_res[1].rm_so,
               (msize<79?msize:79));
               url_param[msize<79?msize:79]='\0';
            }
 
	   if (memcmp(url_param,"yt_live_",8)==0)
	    {
              /* yt_live_broadcast */
              /* yt_live_monitoring */
		  yt_stream = 2;
	    }
	   else if (memcmp(url_param,"youtube",7)==0)
	    {
              /* youtube */
		  yt_stream = 1;
	    }
	   else // if (memcmp(url_param,"doubleclick",11)==0)
	    {
              /* gfp_video_ads */
              /* web_video_ads */
              /* doubleclick */
		  yt_stream = 3;
	    }

	   url_param[0] = '\0';
	   
           if (regexec(&re[18],match_buffer,(size_t) 2,re_res,0)==0)
            {
             int msize = re_res[1].rm_eo-re_res[1].rm_so;
              memcpy(url_param,match_buffer+re_res[1].rm_so,
               (msize<79?msize:79));
               url_param[msize<79?msize:79]='\0';
            }
	   else if (regexec(&re[8],match_buffer,(size_t) 2,re_res,0)==0)
            {
             int msize = re_res[1].rm_eo-re_res[1].rm_so;
              memcpy(url_param,match_buffer+re_res[1].rm_so,
               (msize<79?msize:79));
               url_param[msize<79?msize:79]='\0';
            }
 
	   if (memcmp(url_param,"dg_yt0",6)==0 && yt_stream!=2 )
	    {
               yt_mobile = android_cid==1? 3 : 2;
	    }
           
	   yt_seek = 0;
	   yt_redir_mode = 0;
	   yt_redir_count = 0;

#endif
          return HTTP_YOUTUBE_VIDEO;
         }
       else if (memcmp(base, "/vimeo/v/",
                  ( available_data < 9 ? available_data : 9)) == 0)
          return HTTP_VIMEO;
       else if (memcmp(base, "/videos/flv/",
                  ( available_data < 12 ? available_data : 12)) == 0)
          return HTTP_FLASHVIDEO;
       else if (memcmp(base, "/vt/v=",
               ( available_data < 6 ? available_data : 6)) == 0)
         return HTTP_GMAPS;
       else if (memcmp(base, "/vt/lyrs=",
               ( available_data < 9 ? available_data : 9)) == 0)
         return HTTP_GMAPS;
       else if (memcmp(base, "/vt?lyrs=",
               ( available_data < 9 ? available_data : 9)) == 0)
         return HTTP_GMAPS;
       else if (memcmp(base, "/vt/ft?lyrs=",
               ( available_data < 12 ? available_data : 12)) == 0)
         return HTTP_GMAPS;
       else if (available_data > 29 && (memcmp(base, "/vi/",4) == 0) )
        {
	  if (memcmp(base + 16, "default.jpg",11) == 0 ||
              memcmp(base + 16, "hqdefault.jpg",13) == 0 ||
              memcmp(base + 16, "mqdefault.jpg",13) == 0 ||
              memcmp(base + 16, "sddefault.jpg",13) == 0 ||
              memcmp(base + 16, "0.jpg",5) == 0 ||
              memcmp(base + 16, "1.jpg",5) == 0 ||
              memcmp(base + 16, "2.jpg",5) == 0 ||
              memcmp(base + 16, "3.jpg",5) == 0 
	      )
           return HTTP_YOUTUBE_SITE;
	}
       else if (available_data > 15 && (memcmp(base, "/v/",3) == 0) )
        {
          c = *(char *)(base + 14);
	  if (c==' ' || c== '&' || c== '?')
	    {
    	      status1=0;
    	      i = 3;
    	      while (i<14)
    	       {
    		 c = *(char *)(base + i );
    		 if (!( 
		     ( c>=65 && c<=90 ) ||   /* [A-Z] */
		     ( c>=97 && c<=122 ) ||  /* [a-z] */
		     ( c>=48 && c<=57 ) ||   /* [0-9] */
		       c==45 || c==95        /* '-' '_' */
		     ))
    		  {
    		    status1=1;
    		    break;
    		  }
    		 i++;
    	       }
    	      if (status1==0)
               {
#ifdef VIDEO_DETAILS
	         memcpy(yt_id,base+3,11);
                 yt_id[11]='\0';
#endif
    		return HTTP_YOUTUBE_SITE_EMBED;
               }
	    }  
	}
       else if (available_data > 16 && 
               /* (memcmp(base, "/v",2) == 0) && */ /* Implicit */ 
		(memcmp(base + 8, "/flyers/",8) == 0))
        {
   	  return HTTP_FACEBOOK;
	}
       else if (available_data > 15 && 
               /* (memcmp(base, "/v",2) == 0) && */ /* Implicit */ 
		(memcmp(base + 7, "/flyers/",8) == 0))
        {
   	  return HTTP_FACEBOOK;
	}
       else if (available_data > 12 && (memcmp(base, "/v",2) == 0) )
   	{
	  /* Possibly obsolete - It was Facebook, now mostly VK.com */
          status1=0;
   	  i = 2;
   	  while (i<12)
   	   {
   	     c = *(char *)(base + i );
    	     if (!isdigit(c) && c!='/')
   	      {
   		status1=1;
   		break;
   	      }
   	     i++;
   	   }
   	  if (status1==0)
   	    return HTTP_SOCIAL;
   	}		 
       break;

     case 'w':
       if (memcmp(base, "/w/index.php?title=",
        	      ( available_data < 19 ? available_data : 19)) == 0)
         return HTTP_WIKI;
       else if (memcmp(base, "/wiki/",
        	       ( available_data < 6 ? available_data : 6)) == 0)
         return HTTP_WIKI;
       else if (memcmp(base, "/wikipedia/",
        	       ( available_data < 11 ? available_data : 11)) == 0)
         return HTTP_WIKI;
       else if (memcmp(base, "/www/app_full_proxy.php?app=",
        	       ( available_data < 28 ? available_data : 28)) == 0)
         return HTTP_FACEBOOK;
       else if ( available_data >22 && memcmp(base, "/widgets/",9)==0 )
         {
	   if (
                memcmp(base + 9 , "comments.php?", 13)==0 || 
                memcmp(base + 9 , "fan.php?", 8)==0 || 
                memcmp(base + 9 , "like.php?", 9)==0 
	      )
            return HTTP_FACEBOOK;
           else if (memcmp(base + 9, "follow_button",13) ==0 ||
                memcmp(base + 9 , "hub.", 4)==0 || 
                memcmp(base + 9 , "images/f.gif?", 13)==0 || 
                memcmp(base + 9 , "images/t.gif?", 13)==0 || 
                memcmp(base + 9 , "tweet_button.", 13)==0
	      )
            return HTTP_TWITTER;
	 }
       else if ( available_data >48 && memcmp(base, "/widgets.js",11)==0 )
         {
	   if (
                memcmp(base + 11 , "?_=", 3)==0 || 
		memcmp(base + 22 , "Host: platform.twitter.com", 26)==0 
	      )
            return HTTP_TWITTER;
	 }
       else if (memcmp(base, "/watch?v=",
        	       ( available_data < 9 ? available_data : 9)) == 0)
         {
#ifdef VIDEO_DETAILS
           if (available_data>20)
            {
    	      status1=0;
    	      i = 9;
    	      while (i<20)
    	       {
    		 c = *(char *)(base + i );
    		 if (!( 
		     ( c>=65 && c<=90 ) ||   /* [A-Z] */
		     ( c>=97 && c<=122 ) ||  /* [a-z] */
		     ( c>=48 && c<=57 ) ||   /* [0-9] */
		       c==45 || c==95        /* '-' '_' */
		     ))
    		  {
    		    status1=1;
    		    break;
    		  }
    		 i++;
    	       }
    	      if (status1==0)
               {
	         memcpy(yt_id,base+9,11);
                 yt_id[11]='\0';
	       }
	     }
#endif
           return HTTP_YOUTUBE_SITE_DIRECT;
         }
       else if (memcmp(base, "/watch#!v=",
        	       ( available_data < 10 ? available_data : 10)) == 0)
         {
#ifdef VIDEO_DETAILS
           if (available_data>21)
            {
    	      status1=0;
    	      i = 10;
    	      while (i<21)
    	       {
    		 c = *(char *)(base + i );
    		 if (!( 
		     ( c>=65 && c<=90 ) ||   /* [A-Z] */
		     ( c>=97 && c<=122 ) ||  /* [a-z] */
		     ( c>=48 && c<=57 ) ||   /* [0-9] */
		       c==45 || c==95        /* '-' '_' */
		     ))
    		  {
    		    status1=1;
    		    break;
    		  }
    		 i++;
    	       }
    	      if (status1==0)
               {
	         memcpy(yt_id,base+10,11);
                 yt_id[11]='\0';
	       }
	     }
#endif
           return HTTP_YOUTUBE_SITE_DIRECT;
         }
       else if (memcmp(base, "/watched_events ",
        	       ( available_data < 16 ? available_data : 16)) == 0)
         return HTTP_SOCIAL;
       break;

     case 'x':
       if (available_data>16 && (memcmp(base, "/x/", 3) == 0))
        {
          status1=0;
          status2=0;
  	  i = 3;
  	  
	  while (i<14)
  	   {
  	     c = *(char *)(base + i );
  	     if (c=='/') 
  	      {
  	     	status2=1;
  	     	break;
  	      }
  	     if (!isdigit(c)) 
  	      {
  	     	status1=1;
  	     	break;
  	      }
  	     i++;
  	   }
  	 if (status1==0 && status2==1)
  	   {
  	     if ((memcmp(base + i,"/false/p_",
     	     	    ((available_data - i ) < 9 ? available_data - i : 9)) == 0)
  	     	 || (memcmp(base + i,"/true/p_",
     	     	    ((available_data - i ) < 8 ? available_data - i : 8)) == 0)
  	     	)
	         return HTTP_FACEBOOK;
	     else
	      {
	        status1=0;
                status2=0;
		i++;
		
	  	while (i<25)
  	  	 {
  	  	   c = *(char *)(base + i );
  	  	   if (c=='/') 
  	  	    {
  	  	      status2=1;
  	  	      break;
  	  	    }
  	  	   if (!isdigit(c)) 
  	  	    {
  	  	      status1=1;
  	  	      break;
  	  	    }
  	  	   i++;
  	  	 }
  	  	if (status1==0 && status2==1)
  	  	 {
  	     	   if ((memcmp(base + i,"/false/p_",
     	     	   	  ((available_data - i ) < 9 ? available_data - i : 9)) == 0)
  	     	       || (memcmp(base + i,"/true/p_",
     	     	   	  ((available_data - i ) < 8 ? available_data - i : 8)) == 0)
  	     	      )
    		     return HTTP_FACEBOOK;
		 }
	      } 
  	   }
     	 }
       break;

     case 'y':
       if ( available_data > 10 && (memcmp(base, "/yt/",4) == 0) )
        {
	   switch (*(base+4))
	    {
              case 'c':
                if (memcmp(base + 4, "cssbin/",
                      ((available_data - 4) < 7 ? available_data - 4 : 7)) == 0)
                  return HTTP_YOUTUBE_SITE;
	        break;
              case 'f':
                if (memcmp(base + 4, "favicon",
                      ((available_data - 4) < 7 ? available_data - 4 : 7)) == 0)
                  return HTTP_YOUTUBE_SITE;
	        break;
              case 'i':
                if (memcmp(base + 4, "img/",
                      ((available_data - 4) < 4 ? available_data - 4 : 4)) == 0)
                  return HTTP_YOUTUBE_SITE;
	        break;
              case 'j':
                if (memcmp(base + 4, "js/",
                      ((available_data - 4) < 3 ? available_data - 4 : 3)) == 0)
                  return HTTP_YOUTUBE_SITE;
                else if (memcmp(base + 4, "jsbin/",
                      ((available_data - 4) < 6 ? available_data - 4 : 6)) == 0)
                  return HTTP_YOUTUBE_SITE;
	        break;
              case 's':
                if (memcmp(base + 4, "swf/",
                      ((available_data - 4) < 4 ? available_data - 4 : 4)) == 0)
                  return HTTP_YOUTUBE_SITE;
	        break;
	      default:
	        break;
	    }
	}
       break;

     case '_':
       if (memcmp(base, "/_videos_t4vn",
        	      ( available_data < 13 ? available_data : 13)) == 0)
         return HTTP_FLASHVIDEO;
       else if (memcmp(base, "/_thumbs/",
        	      ( available_data < 9 ? available_data : 9)) == 0)
         return HTTP_FLASHVIDEO;
       break;

     case '4':
       if (memcmp(base, "/467f9bca32b1989",
        	      ( available_data < 16 ? available_data : 16)) == 0)
         return HTTP_FLASHVIDEO;
	 /* no break here to fall back to the other rules for digits */
     case '0':
       if (available_data > 12 &&  memcmp(base+5, "/club/", 6)==0)
         return HTTP_SOCIAL;
       else if (available_data > 12 &&  memcmp(base+5, "/user/", 6)==0)
         return HTTP_SOCIAL;
       else if (available_data > 15 &&  memcmp(base+5, "/listing/", 9)==0)
         return HTTP_SOCIAL;
	 /* no break here to fall back to the other rules for digits */
     case '1':
       if ( *(base+2)=='/' )
        {
          if (memcmp(base, "/1/statuses/",
          		 ( available_data < 12 ? available_data : 12)) == 0)
            return HTTP_TWITTER;
          else if (memcmp(base, "/1/urls/count.json?",
          		 ( available_data < 19 ? available_data : 19)) == 0)
            return HTTP_TWITTER;
          else if (memcmp(base, "/1/users/show",
          		 ( available_data < 13 ? available_data : 13)) == 0)
            return HTTP_TWITTER;
        }
     case '2':
     case '3':
     case '5':
     case '6':
     case '7':
     case '8':
     case '9':
       if (available_data>25)
        {
  	  c = *(char *)(base + 2 );
          if (!isdigit(c))
	    break;

          memcpy(match_buffer,base,(available_data<30?available_data:30));
          match_buffer[(available_data<30?available_data:30)]='\0';

	  if (regexec(&re[10],match_buffer,(size_t) 0,NULL,0)==0)
	    return HTTP_FACEBOOK;
	  else if (classify_flickr(base,available_data)==HTTP_FLICKR)
	    return HTTP_FLICKR;
	  else if (classify_vimeo(base,available_data)==HTTP_VIMEO)
	    return HTTP_VIMEO;
	  else if (classify_social(base,available_data)==HTTP_SOCIAL)
	    return HTTP_SOCIAL;
	}
       break;
     
     default:
       break;
   }

  if ( available_data > 14 && 
           (memcmp(base + 6, "-ak-",4) == 0 ||
            memcmp(base + 7, "-ak-",4) == 0 ||
            memcmp(base + 8, "-ak-",4) == 0 ||
	    memcmp(base + 9, "-ak-",4) == 0))
    return HTTP_FACEBOOK;
  else if ( available_data > 14 && 
           *(char *)(base + 3) == '_' &&
           (memcmp(base + 6, "/all.js",7) == 0))
    return HTTP_FACEBOOK;
  else if ( available_data > 36 &&
           *(char *)(base + 12) == 'g' &&
           *(char *)(base + 13) == '/' &&
           ( *(char *)(base + 25) == '/' ||
	     *(char *)(base + 29) == '/' ) 
	  )
    {
      /* Possible Mediafire.com matching ' /[^/_]{11}g/[^/ ]{11}/'
         or better ' /[^/_]{11}g/[^/ ]{11}/[^/]+ ' */
      /* Possible Mediafire.com matching ' /[^/_]{11}g/[^/ ]{15}/'
         or better ' /[^/_]{11}g/[^/ ]{15}/[^/]+ ' */

      status1=0;
      status2=0;
      
      for (i=1;i<12;i++)
       {
         c = *(char *)(base + i );
	 if (c=='/' || c=='_')
	  {
	    status1=1;
	    break;
	  }
       }      

      if (status1==0) 
       {
         int limit;
	 limit = ( *(char *)(base + 25) == '/' ) ? 25 : 29;
	      
      	 for (i=14;i<limit;i++)
      	  {
      	    c = *(char *)(base + i );
	    if (c=='/' || c==' ')
	     {
	       status2=1;
	       break;
	     }
      	  }	 
      
      	 if (status2==0)
	  {
      	    status1 = 0;
      	    status2 = 0;
      	    for (i=limit+1; i< available_data; i++)
      	     {
      	       c = *(char *)(base + i );
      	       if (c=='/')
	    	{
	    	  status1=1;
	    	  break;
	    	}
	       if (c==' ')
	    	{
	    	  status2=1;
	    	  break;
	    	}
	     }
      	    if (status1==0 && (status2==1 || i==available_data))
      	     {
	       return HTTP_MEDIAFIRE;
	     }
	  }
       }
    }
  else if (available_data > 43 && 
           *(char *)(base + 41) == ' ')
    {
      status1=0;
      
      for (i=1;i<41;i++)
       {
         c = *(char *)(base + i );
	 if (!(isxdigit(c) && (islower(c)||isdigit(c))))
	  {
	    status1=1;
	    break;
	  }
       }      
     if (status1==0)
      {
     	return HTTP_MEGAUPLOAD;
      }

    }      

  return HTTP_GET;

}

enum http_content classify_http_post(void *pdata,int data_length)
{
  char *base = (char *)pdata+5;
  int available_data = data_length - 5 ;

  char c;
  int i;
  int status1;
  
  if (available_data < 1)
    return HTTP_POST;

  if (*base != 0x2f)
    return HTTP_POST;

  switch (*(base+1))
   {
     case 'a':
       if (memcmp(base, "/ajax/presence/",
        	      ( available_data < 15 ? available_data : 15)) == 0)
         return HTTP_FACEBOOK;
       else if (memcmp(base, "/ajax/chat/",
        	      ( available_data < 11 ? available_data : 11)) == 0)
         return HTTP_FACEBOOK;
       else if (memcmp(base, "/ajax/",
        	      ( available_data < 6 ? available_data : 6)) == 0)
         return HTTP_FACEBOOK;
       else if (memcmp(base, "/accept/",
        	      ( available_data < 8 ? available_data : 8)) == 0)
        {
          status1=0;
          for (i=8;i<13;i++)		     
           {				     
             c = *(char *)(base + i );
             if (!isdigit(c)) status1=1;
           }				     
          if (status1==0)		     
            return HTTP_SOCIAL;
        }
       break;

     case 'c':
       if (memcmp(base, "/cgi-bin/rsapi.cgi",
        	       ( available_data < 18 ? available_data : 18)) == 0)
         return HTTP_RAPIDSHARE;
       else if (memcmp(base, "/close/",
        	      ( available_data < 7 ? available_data : 7)) == 0)
         return HTTP_RTMPT;
       else if (memcmp(base, "/current/flashservices/",
        	      ( available_data < 23 ? available_data : 23)) == 0)
         return HTTP_FACEBOOK;
       else if (memcmp(base, "/cbk?output=",
               ( available_data < 12 ? available_data : 12)) == 0)
         return HTTP_GMAPS;
       break;

     case 'C':
       if (memcmp(base, "/CLOSE/",
        	      ( available_data < 7 ? available_data : 7)) == 0)
         return HTTP_RTMPT;
       break;

     case 'f':
       if (memcmp(base, "/fbml/",
        	      ( available_data < 6 ? available_data : 6)) == 0)
         return HTTP_FACEBOOK;
       else if (memcmp(base, "/flashservices/gateway.php",
        	      ( available_data < 26 ? available_data : 26)) == 0)
            /* Facebook Farmville (but sometimes also xvideos.com) */
         return HTTP_FACEBOOK;
       else if (available_data>15 && (memcmp(base, "/files/",7) ==0) )
        {
          status1=0;
          for (i=0;i<8;i++)		     
           {				     
             c = *(char *)(base + 7 + i );
             if (!isdigit(c)) status1=1;
           }				     
          if (status1==0)		     
            return HTTP_RAPIDSHARE;	     
        }
       break;

     case 'g':
       if (memcmp(base, "/gateway/gateway.dll?Action=",
        	      ( available_data < 28 ? available_data : 28)) == 0)
         return HTTP_MSN;
       else if (memcmp(base, "/gateway/gateway.dll?SessionID=",
        	      ( available_data < 31 ? available_data : 31)) == 0)
         return HTTP_MSN;
       else if (memcmp(base, "/glm/mmap ",
               ( available_data < 10 ? available_data : 10)) == 0)
         return HTTP_GMAPS;
       else if (memcmp(base, "/gadgets/makeRequest ",
               ( available_data < 21 ? available_data : 21)) == 0)
         return HTTP_SOCIAL;
       break;

     case 'h':
       if (memcmp(base, "/http-bind ",
        	      ( available_data < 11 ? available_data : 11)) == 0)
         return HTTP_SOCIAL;
       break;

     case 'i':
       if (memcmp(base, "/idle/",
        	      ( available_data < 6 ? available_data : 6)) == 0)
         return HTTP_RTMPT;
       else if (memcmp(base, "/invite/",
        	      ( available_data < 8 ? available_data : 8)) == 0)
        {
          status1=0;
          for (i=8;i<13;i++)		     
           {				     
             c = *(char *)(base + i );
             if (!isdigit(c)) status1=1;
           }				     
          if (status1==0)		     
            return HTTP_SOCIAL;
        }
       break;
     case 'I':
       if (memcmp(base, "/IDLE/",
        	      ( available_data < 6 ? available_data : 6)) == 0)
         return HTTP_RTMPT;
       break;

     case 'm':
       if (memcmp(base, "/might_know/unwanted/",
        	      ( available_data < 21 ? available_data : 21)) == 0)
         return HTTP_SOCIAL;
       break;

     case 'n':
       if (memcmp(base, "/nktalk/",
        	      ( available_data < 8 ? available_data : 8)) == 0)
         return HTTP_SOCIAL;
       break;

     case 'o':
       if (memcmp(base, "/open/",
        	      ( available_data < 6 ? available_data : 6)) == 0)
         return HTTP_RTMPT;
       break;
     case 'O':
       if (memcmp(base, "/OPEN/",
        	      ( available_data < 6 ? available_data : 6)) == 0)
         return HTTP_RTMPT;
       break;

     case 'p':
       if (memcmp(base, "/profile_ajax?action_ajax=",
        	      ( available_data < 26 ? available_data : 26)) == 0)
         return HTTP_YOUTUBE_SITE;
       else if (memcmp(base, "/pins/friends ",
        	      ( available_data < 14 ? available_data : 14)) == 0)
         return HTTP_SOCIAL;
       else if (memcmp(base, "/pins/get ",
        	      ( available_data < 10 ? available_data : 10)) == 0)
         return HTTP_SOCIAL;
       else if (memcmp(base, "/poczta/",
        	      ( available_data < 8 ? available_data : 8)) == 0)
         return HTTP_SOCIAL;
       else if ( available_data >26 && memcmp(base, "/profile/",9)==0 )
         {
	   if (
		isdigit( *(char *)(base + 9 )) ||
                memcmp(base + 9 , "privacy_settings", 16)==0 || 
                memcmp(base + 9 , "edit ", 5)==0 || 
                memcmp(base + 9 , "black_list", 10)==0 
	      )
            return HTTP_SOCIAL;
	 }
       else if ( available_data >22 && memcmp(base, "/pages/",7)==0 )
         {
	   if (
                memcmp(base + 7 , "activity/", 9)==0 || 
                memcmp(base + 7 , "application/", 12)==0 || 
                memcmp(base + 7 , "community/", 10)==0 || 
                memcmp(base + 7 , "image/", 6)==0 || 
                memcmp(base + 7 , "listing/", 8)==0 || 
                memcmp(base + 7 , "main/", 5)==0 || 
                memcmp(base + 7 , "message/", 8)==0 || 
                memcmp(base + 7 , "micrologin/", 11)==0 || 
                memcmp(base + 7 , "misc/", 5)==0 || 
                memcmp(base + 7 , "share/", 6)==0 || 
                memcmp(base + 7 , "timeline/", 9)==0 || 
                memcmp(base + 7 , "user/", 5)==0 
	      )
            return HTTP_SOCIAL;
	 }
       break;

     case 'r':
       if (memcmp(base, "/restserver.php",
        	      ( available_data < 15 ? available_data : 15)) == 0)
         return HTTP_FACEBOOK;
       else if (memcmp(base, "/reject/",
        	    ( available_data < 8 ? available_data : 8)) == 0)
         return HTTP_SOCIAL;
       else if (memcmp(base, "/rendering_measurement",
        	    ( available_data < 22 ? available_data : 22)) == 0)
         return HTTP_SOCIAL;
       break;

     case 's':
       if (memcmp(base, "/send/",
        	      ( available_data < 6 ? available_data : 6)) == 0)
         return HTTP_RTMPT;
       else if (memcmp(base, "/social/rpc?st=",
        	      ( available_data < 15 ? available_data : 15)) == 0)
         return HTTP_SOCIAL;
       else if (memcmp(base, "/sledzik/",
        	    ( available_data < 9 ? available_data : 9)) == 0)
         return HTTP_SOCIAL;
       else if (memcmp(base, "/school/",
        	    ( available_data < 8 ? available_data : 8)) == 0)
         return HTTP_SOCIAL;
       else if (memcmp(base, "/search.json?",
        	    ( available_data < 13 ? available_data : 13)) == 0)
         return HTTP_TWITTER;
       break;
     case 'S':
       if (memcmp(base, "/SEND/",
        	      ( available_data < 6 ? available_data : 6)) == 0)
         return HTTP_RTMPT;
       break;

     case 'u':
       if (memcmp(base, "/url_validator",
        	      ( available_data < 14 ? available_data : 14)) == 0)
         return HTTP_SOCIAL;
       break;

     case 'v':
       if (memcmp(base, "/video_info_ajax?",
        	      ( available_data < 17 ? available_data : 17)) == 0)
         return HTTP_YOUTUBE_SITE;
       break;

     case 'w':
       if (memcmp(base, "/watched_events/",
        	      ( available_data < 16 ? available_data : 16)) == 0)
         return HTTP_SOCIAL;
       else if (memcmp(base, "/watch_actions_ajax?",
        	      ( available_data < 20 ? available_data : 20)) == 0)
         return HTTP_YOUTUBE_SITE;
       break;

     default:
       break;
   }

  return HTTP_POST;

}

enum web_category map_http_to_web(tcp_pair *ptp)
{
  enum http_content http_type = YTMAP(ptp->http_data);
  enum video_content video_type = VIDEO_MAP(ptp);

  if (video_type == VIDEO_NOT_DEFINED)
   {
     switch(http_type)
      {
   	case HTTP_GET:
   	  return WEB_GET;

   	case HTTP_POST:
   	  return WEB_POST;

   	case HTTP_MSN:
   	case HTTP_RTMPT:
   	case HTTP_FACEBOOK:
   	case HTTP_SOCIAL:
   	case HTTP_TWITTER:
   	  return WEB_SOCIAL;
 
   	case HTTP_YOUTUBE_VIDEO:
   	case HTTP_YOUTUBE_VIDEO204:
   	case HTTP_YOUTUBE_204:
   	  return WEB_YOUTUBE;

   	case HTTP_VIDEO_CONTENT:
   	case HTTP_VIMEO:
   	case HTTP_FLASHVIDEO:
   	  return WEB_VIDEO;

   	case HTTP_NETFLIX:
   	  return WEB_NETFLIX;
	  
   	case HTTP_RAPIDSHARE:
   	case HTTP_MEGAUPLOAD:
   	case HTTP_MEDIAFIRE:
   	case HTTP_HOTFILE:
   	case HTTP_STORAGE:
   	  return WEB_STORAGE;

   	case HTTP_WIKI:
   	case HTTP_ADV:
   	case HTTP_FLICKR:
   	case HTTP_GMAPS:
   	case HTTP_YOUTUBE_SITE:
   	case HTTP_YOUTUBE_SITE_DIRECT:
   	case HTTP_YOUTUBE_SITE_EMBED:
   	case HTTP_DROPBOX:
   	  return WEB_OTHER;

   	default:
   	  return WEB_OTHER;
      }
   }
  else
   {
     switch(http_type)
      {
   	case HTTP_MSN:
   	case HTTP_RTMPT:
   	case HTTP_FACEBOOK:
   	case HTTP_SOCIAL:
   	case HTTP_TWITTER:
   	  return WEB_SOCIAL;

   	case HTTP_YOUTUBE_VIDEO:
   	case HTTP_YOUTUBE_VIDEO204:
   	case HTTP_YOUTUBE_204:
   	  return WEB_YOUTUBE;

   	case HTTP_NETFLIX:
   	  return WEB_NETFLIX;

	default:
   	  return WEB_VIDEO;
      }
   }
  
}
