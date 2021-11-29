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
#include "videoL7.h"
#include "tcpL7.h"
#include <regex.h>

#define get_u8(X,O)   (*(tt_uint8  *)(X + O))
#define get_u16(X,O)  (*(tt_uint16 *)(X + O))
#define get_u32(X,O)  (*(tt_uint32 *)(X + O))

#define BUFFER_SIZE 1520

char *v_patterns[2];

regex_t vre[2];
regmatch_t vre_res[2];

int map_video_flow_type(tcp_pair *thisflow);
enum video_content VIDEO_MAP(tcp_pair *thisflow);

extern double read_double(char *base);
extern struct VIDEO_rates VIDEO_rate;

void init_reg_v_patterns()
{
 v_patterns[0] = "Content-Type: ([a-z0-9\x22/.-]+)";
 v_patterns[1] = "\x0D\x0A\x0D\x0A";
 
 regcomp(&vre[0], v_patterns[0], REG_EXTENDED | REG_ICASE);
 regcomp(&vre[1], v_patterns[1], REG_EXTENDED);
}

void parse_flv_metadata(struct video_metadata *meta, void *pdata, int data_length) 
{
  char *base = (char *) pdata;
  int available_data = data_length;
  int pos;
  int i = 0;
  u_int16_t nMeta, sizeMeta;
  char metaString[30];

  double metaDvalue = 0;
  char metaSvalue[500];
  uint8_t metaBvalue;
  Bool found;

  found = FALSE;
  for (pos = 0; ((pos < data_length) && !found); pos++)
   {
     if (*(base + pos) == 'o')
      {
        if (memcmp(base + pos, "onMetaData", 10) == 0)
         {
  	   found = TRUE;
  	   base += pos + 9; //Advance 9bytes = len(onMetadata)
  	 }
      }
   }
   
  /* base points at the end of onMetaData */
  if (available_data - (base - (char *) pdata) < 20)
    return;

  nMeta = ntohs(get_u16(base,4));
  base += 6;

  for (i = 0; i < nMeta; i++)
   {
     sizeMeta = ntohs(get_u16(base,0));
     
     if (available_data - (base - (char *) pdata) < sizeMeta + 2)
        return;
	
     base += 2; // points to the beginning of MetadataDescription

     memcpy(metaString, base, (sizeMeta < 25 ? sizeMeta : 24));
     metaString[(sizeMeta < 25 ? sizeMeta : 24)] = '\0';
     base += sizeMeta;

     u_int8_t type = (get_u8(base,0));
     switch (type)
      {
        case 0:
  	  if (available_data - (base - (char *) pdata) < 9)
  	     return;
  	  metaDvalue = read_double(base + 1);
  	  //		    printf("D> %s : %f\n", metaString,metaDvalue);
  	  base += 9; //Advance 9bytes > 1type 8double
          break;
	case 1:
  	  if (available_data - (base - (char *) pdata) < 2)
  	     return;
  	  metaBvalue = (get_u8(base,1));
  	  //		    printf("B> %s : %d\n", metaString,metaBvalue);
  	  base += 2; //Advance 2bytes > 1type 1bool
          break;
	case 2: //02 XX XX String
  	  if (available_data - (base - (char *) pdata) < 2)
  	     return;
  	  u_int16_t strSize = ntohs(get_u16(base,1));
  	  if (available_data - (base - (char *) pdata) < strSize)
  	     return;

  	  memcpy(metaSvalue, base + 3, (strSize < 500 ? strSize : 499));
  	  metaSvalue[(strSize < 500 ? strSize : 499)] = '\0';
  	  //		    printf("S> %s : %s %d\n", metaString,metaSvalue,strlen(metaSvalue));
  	  base += strSize + 3; //Advance s1type 2len(string)  nStrSize
          break;
	case 10:  /* type: SCRIPTDATASTRICTARRAY = ArrayLen(UI32) +Values */
  	  if (available_data - (base - (char *) pdata) < 4)
  	     return;
  	  u_int32_t meta32bitValue = 0;
  	  meta32bitValue = ntohs(get_u32(base,1));
  	  //		    printf("10 > %s : %d\n", metaString,meta32bitValue);
  	  base += 5 + meta32bitValue;
          break;
	case 11: /* type: SCRIPTDATADATE = DOUBLE+16bits */
  	  if (available_data - (base - (char *) pdata) < 2)
  	    return;
  	  base = base + 11;
          break;
	default:
          break;
      }

     switch (metaString[0])
      {
        case 'a':
          if (memcmp(metaString, "audiodatarate", 13) == 0) 
	   {
  	     meta->audiodatarate = metaDvalue;
  	     if (meta->audiodatarate / 100000 > 1)
  	   	     meta->audiodatarate = meta->audiodatarate / 1000; //Force to Kbps
	   }
	  break;
        case 'b':
          if (memcmp(metaString, "bytelength", 10) == 0)
  	     meta->bytelength = (u_int32_t) metaDvalue;
	  break;
        case 'd':
          if (memcmp(metaString, "duration", 8) == 0)
  	     meta->duration = metaDvalue;
	  break;
        case 'f':
          if (memcmp(metaString, "framerate", 9) == 0)
  	     meta->framerate = metaDvalue;
          else if (memcmp(metaString, "filesize", 8) == 0)
  	     meta->bytelength = (u_int32_t) metaDvalue;
	  break;
        case 'h':
          if (memcmp(metaString, "height", 6) == 0)
  	     meta->height = (int) floor(metaDvalue);
	  break;
        case 's':
          if (memcmp(metaString, "starttime", 9) == 0)
  	     meta->starttime = metaDvalue;
	  break;
        case 't':
          if (memcmp(metaString, "totalduration", 13) == 0)
  	     meta->totalduration = metaDvalue;
          else if (memcmp(metaString, "totaldatarate", 13) == 0)
	   {
  	     meta->totaldatarate = metaDvalue;
  	     if (meta->totaldatarate / 100000 > 1)
  	   	     meta->totaldatarate = meta->totaldatarate / 1000; //Force to Kbps
           }
	  break;
        case 'v':
          if (memcmp(metaString, "videodatarate", 13) == 0)
	   {
  	     meta->videodatarate = metaDvalue;
  	     if (meta->videodatarate / 100000 > 1)
  	   	     meta->videodatarate = meta->videodatarate / 1000; //Force to Kbps
	   }
	  break;
        case 'w':
          if (memcmp(metaString, "width", 5) == 0)
  	     meta->width = (int) floor(metaDvalue);
	  break;
        default:
	  break;
      }
   }
}

void parse_mp4_metadata(struct video_metadata *meta, void *pdata, int data_length)
{
  Bool found = FALSE;
  int pos = 0;
  char *base = (char *) pdata;
  unsigned long tmp1, tmp2;

  for (pos = 0; ((pos < data_length) && !found); pos++)
   {
     // if (memcmp( base+pos, "m", 1) == 0 )
     if (*(base + pos) == 'm') 
      {
        if (memcmp(base + pos, "mvhd", 4) == 0)
         {
  	   found = TRUE;
  	   base += pos;
  	 }
      }
   }
  if (!found || (data_length - (base - (char *) pdata) < 24))
     return;
  //Need 24 bytes of further payload

  tmp1 = ntohl(get_u32(base,16)); // > timescale
  tmp2 = ntohl(get_u32(base,20)); // > this is the duration not scaled

  if (tmp1 > 0)
     meta->duration = ((double) tmp2 / (double) tmp1);

  found = FALSE;
  for (pos = 0; ((pos < data_length) && !found); pos++)
   {
     if (*(base + pos) == 't') 
      {
        if (memcmp(base + pos, "tkhd", 4) == 0)
	 {
  	   found = TRUE;
  	   base += pos;
  	 }
      }
   }
  if (!found || (data_length - (base - (char *) pdata) < 84))
     return;

  base += (4 + 74);
  meta->width = (u_int32_t) ntohl(get_u32(base,0)) & 0x0000FFFF;
  meta->height = (u_int32_t) ntohl(get_u32(base,4)) & 0x0000FFFF;

  found = FALSE;
  for (pos = 0; ((pos < data_length) && !found); pos++)
   {
     if (*(base + pos) == 'b')
      {
        if (memcmp(base + pos, "btrt", 4) == 0)
	 {
  	   found = TRUE;
  	   base += pos;
         }
      }
   }
  if (!found || (data_length - (base - (char *) pdata) < 16))
     return;

  base += 4;
  tmp1 = ntohl(get_u32(base,4)); // > maxbitrate - Not Used
  tmp2 = ntohl(get_u32(base,8)); // > avg bitrate

  meta->videodatarate = (double) tmp2;

}

void parse_avi_metadata(struct video_metadata *meta, void *pdata, int data_length) 
{
  Bool found = FALSE;
  int pos = 0;
  char *base = (char *) pdata;
  double totalFrames;
  unsigned long rate, scale;

  for (pos = 0; ((pos < data_length) && !found); pos++)
   {
     if (*(base + pos) == 'a')
      {
        if (memcmp(base + pos, "avih", 4) == 0)
	 {
  	   found = TRUE;
  	   base += pos;
  	 }
      }
   }

  if (!found || (data_length - (base - (char *) pdata) < (7 * 4))) // 7 dWords of OFFSET
     return;

  totalFrames = get_u32(base,(6*4));
  meta->totalFrames = totalFrames;
  base += (7 * 4);

  if (!found || (data_length - (base - (char *) pdata) < (5 * 4))) // 5 dWords of OFFSET
     return;

  meta->width = (u_int32_t) get_u32(base,(3*4));
  meta->height = (u_int32_t) get_u32(base,(4*4));
  base += (5 * 4);

  found = FALSE;
  for (pos = 4; ((pos < data_length) && !found); pos++)
   {
     if (*(base + pos) == 's')
      {
        if (memcmp(base + pos, "strh", 4) == 0)
	 {
  	   found = TRUE;
           base += pos;
         }
      }
   }
  /*	  8 bytes  Little-Endian encoding - OFFSET of 8bytes not documented ????   */
  if (!found || (data_length - (base - (char *) pdata) < (9 * 4))) //
     return;

  scale = get_u32(base,(7*4));
  rate = get_u32(base,(8*4));
  if (scale > 0 && rate > 0)
    meta->duration = (meta->totalFrames / ((double) rate / (double) scale));

  return;
}

int extract_payload_contentType(void *pdata, int data_length)
{
  char *base = (char *) pdata;
  int available_data = data_length;
  int res_regex;
  char last_payload_char;

  if (available_data <= 4)
  	  return -1;

  if ((available_data > 4) && memcmp(pdata, "HTTP", 4) == 0)
   {
     if ((available_data > 8 && 
          memcmp((pdata + available_data - 4), "\x0D\x0A\x0D\x0A", 4) == 0)
	)
       return -1; //special case where the HTTP header is sent in 1 packet

     last_payload_char =  *((char *)(pdata + data_length));
     *(char *)(pdata + data_length) = '\0';

     res_regex = regexec(&vre[1], base, (size_t) 2, vre_res, 0);
     *(char *)(pdata + data_length) = last_payload_char;

     if (res_regex == 0)
      {
        if (available_data != vre_res[0].rm_eo)
	 {
	   // End of header = End of packet
  	   base += vre_res[0].rm_eo;
  	   available_data -= vre_res[0].rm_eo;
  	   return (base - (char *) pdata);
  	 } 
	else
  	  return -1;
      } 
     else
       return -1;
   } 
  else 
   {
     return (base - (char *) pdata);
   }
}

enum video_content classify_video_by_payload(tcp_pair *ptp, void *pdata,
           int data_length, int offset)
{
  struct video_metadata *meta;
  meta = &(ptp->streaming.metadata);
  char *base = (char *) (pdata + offset);
  int available_data = data_length - offset;

  switch (*((u_int32_t *) base)) 
   {
     case VL7_FLV: /* parse header of an FLV video */
     case VL7_FLV2: /* parse header of an FLV video */
       if (available_data >= 27)
	{
	  parse_flv_metadata(meta, base, available_data);
	  if (meta->duration > 0 && meta->bytelength > 0
			  && meta->videodatarate == 0)
	    {
	      meta->videodatarate = (double) 8 * meta->bytelength
				  / meta->duration / 1000;
	    }
	  else if (meta->videodatarate != 0 && meta->audiodatarate != 0)
            {
	      meta->videodatarate += meta->audiodatarate;
	    }
	  if (debug > 0)
            {
	      fprintf(fp_stdout,"FLV - Duration[min]: %.2f Res: %dx%d Bitrate: %.2f\n",
		  meta->duration / 60, meta->width, meta->height,
		  meta->videodatarate);
	    }
	  return VIDEO_FLV;
	}
       break;
     case AVI: /* parse header of an AVI container */
       if ((available_data >= 16) && memcmp(base + 8, "AVI LIST", 8) == 0)
        {
	  parse_avi_metadata(meta, base, available_data);
	  if (debug > 0)
	     fprintf(fp_stdout,"AVI - Duration[min]: %.2f Res: %dx%d Bitrate: %.2f\n",
		  meta->duration / 60, meta->width, meta->height,
		  meta->videodatarate / 1000);
	  return VIDEO_AVI;
	}
       break;
     case WMV_1: /* parse header of an ASF container */
     case WMV_2:
       if ((available_data >= 8) && 
           (memcmp(base + 4, "\x8E\x66\xCF\x11", 4) == 0 || 
            memcmp(base + 4, "\x00\x62\xCE\x6C", 4) == 0)) 
        {
	  return VIDEO_WMV;
	}
       break;
     case WEBM: /* parse header of an WEBM container */
       if (((available_data >= 28) && memcmp(base + 24, "webm", 4) == 0) || 
           ((available_data >= 36) && memcmp(base + 31, "webm", 4) == 0))
	{
	  return VIDEO_WEBM;
	}
       break;
     case OGG: /* parse header of an OGG container
			   Obs. can also match OGG audio files*/
       if (((available_data >= 8) && memcmp(base + 4, "\x00\x02\x00\x00", 4) == 0))
	{
	  return VIDEO_OGG;
	}
       break;
     default:
       /* parse header of an MP4 container
	* As suggested in http://www.garykessler.net/library/file_sigs.html
	* MP4 container is matched as 00 00 00 XX 66 74 79 70*/

       if ((available_data >= 12) && 
            memcmp(base, "\x00\x00\x00", 3) == 0 && 
            memcmp(base + 4, "ftyp", 4) == 0)
	{
	  if ((*(base +3 ) == 0x14)  //3GPP v1
	      || (*(base ) == 0x20)  //3GPP v2
	      || (*(base ) == 0x1C)) //3GPP Release 4
	   {
	     return VIDEO_3GPP;
	   }
          else
           {
	     parse_mp4_metadata(meta, base, available_data);
	     if (debug > 0)
               {
		 fprintf(fp_stdout,"MP4 - Duration[min]: %.2f Res: %dx%d Bitrate: %.2f\n",
		       meta->duration / 60, meta->width, meta->height,
		       meta->videodatarate / 1000);
	       }
	     return VIDEO_MP4;
	   }
	}
       else if ((available_data >= 8) && memcmp(base + 4, "moof", 4) == 0)
        {
	  return VIDEO_MP4;
	}
       else if ((available_data >= 4) && 
        	 memcmp(base, "\x00\x00\x01", 3) == 0 && 
        	 HINIBBLE(*(base+3)) == 0xB) 
        {
	  return VIDEO_MPEG;
	}
       else if ((available_data >= 16) && 
        	 memcmp(base, "\x24\x4D", 2) == 0 && 
        	 memcmp(base + 12, "play", 4) == 0)
        {
	  return VIDEO_WMV;
	}
       else if ((available_data >= 400) &&
                (*(base) == 0x47) &&  
                (*(base+188) == 0x47) &&  
                (*(base+376) == 0x47)
		)
        { /* MPEG TS framing used in HLS */
          /* Since NDS is also using MPEG TS framing, it will also patch partial
             NDS flows */
          // printf(" video mpegts \n");
          return VIDEO_HLS;
        }
       else if ((available_data >= 16) &&
                 memcmp(base, "\x47\x1F\xFF\x10", 4) == 0 &&
                 memcmp(base + 4, "NDS File", 8) == 0)
        { /* NDS File Format - Cisco Videoscape - Sky+ VOD stream */
          /* Actually a NULL MPEG TS frame */
          return VIDEO_NFF;
        }
       return VIDEO_NOT_DEFINED;
   }
  return VIDEO_NOT_DEFINED;
}

enum video_content classify_video_by_ctype(void *pdata, int data_length)
{
  char *base = (char *) pdata + 4;
  int available_data = data_length - 4;
  char content_type[65];
  int cType_len, res_regex,subType_len;
  char last_payload_char;

  if (available_data < 1)
    return VIDEO_NOT_DEFINED;

  if (*base != 0x2F)
    return VIDEO_NOT_DEFINED;

  last_payload_char = *(char*) (pdata + data_length);
  *(char *)(pdata + data_length) = '\0' ;

  res_regex = regexec(&vre[0], (char *) pdata, (size_t) 2, vre_res, 0);
  *(char *)(pdata + data_length) = last_payload_char;

  if (res_regex == 0)
   {
     int msize = vre_res[1].rm_eo - vre_res[1].rm_so;
     if (msize > 0) 
      {
  	if (*((char *)(pdata + vre_res[1].rm_so)) == 0x22)
	 {
  	   vre_res[1].rm_so += 1;
  	   msize -= 1;
  	 }
        if (*((char *)(pdata + vre_res[1].rm_eo - 1)) == 0x22)
	 {
  	   vre_res[1].rm_eo -= 1;
  	   msize -= 1;
         }
        if (msize>0)
         {
           memcpy(content_type, (char *) (pdata + vre_res[1].rm_so),(msize < 60 ? msize : 60));
  	   content_type[(msize < 60 ? msize : 60)] = '\0';
         }
        else
         {
           return VIDEO_NOT_DEFINED;
         }
      } 
     else
      {
        return VIDEO_NOT_DEFINED;
      }
   } 
  else 
   {
     return VIDEO_NOT_DEFINED;
   }

  cType_len = strlen(content_type);

  switch (*content_type)
   {
     case 'a':
       if (memcmp(content_type, "application",
             (cType_len < 11 ? cType_len : 11)) == 0)
        {
	  if (cType_len <=12) 
  	    return VIDEO_NOT_DEFINED;
	    
	  subType_len = cType_len - 12;

  	  if (memcmp(content_type + 12, "x-mms-framed",
  				  (subType_len < 12 ? subType_len : 12)) == 0)
	   {
     	     return VIDEO_WMV;
  	   } 
          else if (memcmp(content_type + 12, "x-mpegURL",
                                  (subType_len < 9 ? subType_len  : 9)) == 0)
           {
             return VIDEO_HLS;
           }
          else if (memcmp(content_type + 12, "vnd.apple.mpegurl",
                                  (subType_len < 17 ? subType_len  : 17)) == 0)
           {
             return VIDEO_HLS;
           }
	  else if (memcmp(content_type + 12, "mp4",
  				  (subType_len < 3 ? subType_len  : 3)) == 0)
	   {
  	     return VIDEO_MP4;
  	   }
  	  else
  	    return VIDEO_NOT_DEFINED;
  	} 
       else if (memcmp(content_type, "audio",
  			      (cType_len < 5 ? cType_len : 5)) == 0)
        {
	  if (cType_len <= 6 ) 
  	    return VIDEO_NOT_DEFINED;

	  subType_len = cType_len - 6;

	  if (memcmp(content_type + 6, "mp4",
  			      (subType_len < 3 ? subType_len : 3)) == 0)
	   {
  	     return VIDEO_MP4;
  	   } 
	  else
  	    return VIDEO_NOT_DEFINED;
  	} 
       else
         return VIDEO_NOT_DEFINED;
       break;
     case 'v':
       if (memcmp(content_type, "video",
  			      (cType_len < 5 ? cType_len : 5)) == 0)
	{
	  
	  if (cType_len <= 6 ) 
  	    return VIDEO_NOT_DEFINED;

	  subType_len = cType_len - 6;

	  switch(*(content_type+6))
	   {
	     case 'x':
	       if (memcmp(content_type + 6, "x-mp4",
  				  (subType_len < 5 ? subType_len : 5)) == 0)
	        {
  	          return VIDEO_MP4;
  	        } 
	       else if (memcmp(content_type + 6, "x-m4v",
  				  (subType_len < 5 ? subType_len : 5)) == 0)
	        {
     	          return VIDEO_MP4;
  	        }
	       else if (memcmp(content_type + 6, "x-flv",
  				  (subType_len < 5 ? subType_len : 5)) == 0)
	        {
  	          return VIDEO_FLV;
  	        }
	       else if (memcmp(content_type + 6, "x-f4v",
  				  (subType_len < 5 ? subType_len : 5)) == 0)
	        {
  	          return VIDEO_MP4;
  	        }
               /* Adobe Dynamic Streaming - Content-Type: video/(f4m|f4f|abst) */
	       else if (memcmp(content_type + 6, "x-f4f",
  				  (subType_len < 5 ? subType_len : 5)) == 0)
	        {
  	          return VIDEO_MP4;
  	        }
	       else if (memcmp(content_type + 6, "x-msvideo",
  				  (subType_len < 9 ? subType_len : 9)) == 0)
	        {
       	          return VIDEO_AVI;
                }
	       else if (memcmp(content_type + 6, "x-ms-asf",
  				  (subType_len < 8 ? subType_len : 8)) == 0)
	        {
  	          return VIDEO_ASF;
  	        }
	       else if (memcmp(content_type + 6, "x-ms-wmv",
  				  (subType_len < 8 ? subType_len : 8)) == 0)
	        {
  	          return VIDEO_WMV;
  	        }
	       else
  	         return VIDEO_UNKNOWN;
 	       break;
	     case 'm':
  	       if (memcmp(content_type + 6, "mp4",
  				  (subType_len < 3 ? subType_len : 3))== 0) 
	        {
     	          return VIDEO_MP4;
  	        }
	       else if (memcmp(content_type + 6, "mpeg",
  				  (subType_len < 4 ? subType_len : 4)) == 0)
	        {
  	          return VIDEO_MPEG;
  	        } 
	       else if (memcmp(content_type + 6, "mp2t",
	        		  (subType_len < 4 ? subType_len : 4))== 0)
	        {
	          return VIDEO_HLS;
	        }
	       else
  	         return VIDEO_UNKNOWN;
 	       break;
             case 'M':
               if (memcmp(content_type + 6, "MP2T",
                                 (subType_len < 4 ? subType_len : 4))== 0)
                {
	          return VIDEO_HLS;
                }
               else
                 return VIDEO_UNKNOWN;
               break;
	     case 'f':
	       if (memcmp(content_type + 6, "flv",
  				  (subType_len < 3 ? subType_len : 3)) == 0)
	        {
    	          return VIDEO_FLV;
  	        }
	       else if (memcmp(content_type + 6, "f4v",
  				  (subType_len < 3 ? subType_len : 3)) == 0)
	        {
    	          return VIDEO_MP4;
  	        } 
               /* Adobe Dynamic Streaming - Content-Type: video/(f4m|f4f|abst) */
	       else if (memcmp(content_type + 6, "f4m",
  				  (subType_len < 3 ? subType_len : 3)) == 0)
	        {
    	          return VIDEO_MP4;
  	        } 
	       else if (memcmp(content_type + 6, "f4f",
  				  (subType_len < 3 ? subType_len : 3)) == 0)
	        {
    	          return VIDEO_MP4;
  	        } 
	       else
  	         return VIDEO_UNKNOWN;
 	       break;
	     case 'a':
               /* Adobe Dynamic Streaming - Content-Type: video/(f4m|f4f|abst) */
	       if (memcmp(content_type + 6, "abst",
  				  (subType_len < 4 ? subType_len : 4)) == 0)
	        {
    	          return VIDEO_MP4;
  	        } 
	       else
  	         return VIDEO_UNKNOWN;
 	       break;
	     case '3':
	       if (memcmp(content_type + 6, "3gpp",
  				  (subType_len < 4 ? subType_len : 4)) == 0)
	        {
    	          return VIDEO_3GPP;
  	        } 
	       else
  	         return VIDEO_UNKNOWN;
 	       break;
             case 'n':
               if (memcmp(content_type + 6, "nff",
                                  (subType_len < 3 ? subType_len : 3)) == 0)
                {
                  /* NDS File Format - Cisco Videoscape - Sky+ VOD stream */
                  return VIDEO_NFF;
                }
               else
                 return VIDEO_UNKNOWN;
               break;
	     case 'o':
	       if (memcmp(content_type + 6, "ogg",
  				  (subType_len < 3 ? subType_len : 3)) == 0)
	        {
  	          return VIDEO_OGG;
  	        } 
	       else
  	         return VIDEO_UNKNOWN;
 	       break;
	     case 'q':
	       if (memcmp(content_type + 6, "quicktime",
  				  (subType_len < 9 ? subType_len : 9)) == 0)
	        {
    	          return VIDEO_QUICKTIME;
  	        } 
	       else
  	         return VIDEO_UNKNOWN;
 	       break;
	     case 'w':
               if (memcmp(content_type + 6, "webm",
  				  (subType_len < 4 ? subType_len : 4)) == 0)
	        {
    	          return VIDEO_WEBM;
  	        }
	       else
  	         return VIDEO_UNKNOWN;
 	       break;
	     default:
  	       return VIDEO_UNKNOWN;
	   }
  	} 
       else
  	 return VIDEO_NOT_DEFINED;
       break;
     case 'f':
       if (memcmp(content_type, "flv-application",
  			  (cType_len < 15 ? cType_len : 15)) == 0) 
        {
          return VIDEO_FLV;
        }
       else
         return VIDEO_NOT_DEFINED;
       break;
     default:
       return VIDEO_NOT_DEFINED;
  }
}

void videoL7_init()
{
  /* nothing to do so far */
  init_reg_v_patterns();
}

void *
getvideoL7(struct udphdr *pudp, int tproto, void *pdir, void *plast)
{
  /* just pass the complete packet and let the tcpL7_flow_stat decide */

  return (void *) pudp;
}

void videoL7_flow_stat(struct ip *pip, void *pproto, int tproto, void *pdir,
		int dir, void *hdr, void *plast)
{
  tcp_pair *ptp;

  void *pdata; /*start of payload */
  int data_length, payload_len;
  tcb *tcp_stats;
  enum video_content temp_class;

  tcphdr *ptcp;
  ptcp = (tcphdr *) hdr;

  if (tproto == PROTOCOL_UDP) {
  	  return;
  }

  ptp = ((tcb *) pdir)->ptp;

  if (ptp == NULL || ptp->streaming.state == IGNORE_FURTHER_PACKETS)
  	  return;

  /* Content of the old FindConType function */

  pdata = (char *) ptcp + ptcp->th_off * 4;
  payload_len = getpayloadlength(pip, plast) - ptcp->th_off * 4;
  data_length = (char *) plast - (char *) pdata + 1;
  int offset = -1;

  if (data_length <= 0 || payload_len == 0)
    return;

  if (dir == C2S)
    tcp_stats = &(ptp->c2s);
  else
    tcp_stats = &(ptp->s2c);

  switch (ptp->streaming.state)
   {
     case UNKNOWN_TYPE:
       if ((char *) pdata + 4 > (char *) plast)
     	 return;
       switch (*((u_int32_t *) pdata)) 
        {
          case GET:
     	    if (dir == C2S) 
     	      ptp->streaming.state = HTTP_COMMAND;
     	    break;
          case POST:
     	    if (dir == C2S)
     	      ptp->streaming.state = HTTP_COMMAND;
     	    break;
          case HEAD:
     	    if (dir == C2S)
     	      ptp->streaming.state = HTTP_COMMAND;
     	    break;
          default:
     	    if (ptp->packets > MAX_UNKNOWN_PACKETS)
     	      ptp->streaming.state = IGNORE_FURTHER_PACKETS;
     	    break;
        }
       break;
     case HTTP_COMMAND:
       if (dir == S2C && ((char *) pdata + 4 <= (char *) plast))
        {
     	  ptp->streaming.packets++;

     	  if (ptp->streaming.video_content_type == VIDEO_NOT_DEFINED)
	   {
     	     temp_class = classify_video_by_ctype(pdata, data_length);
     	     ptp->streaming.video_content_type = (temp_class != VIDEO_NOT_DEFINED ? 
	                   temp_class : ptp->streaming.video_content_type);
     	   }

     	  offset = extract_payload_contentType(pdata, data_length);

     	  if ((data_length - offset) > 4 && offset != -1)
	   {
     	     temp_class = classify_video_by_payload(ptp, pdata, data_length, offset);
     	     ptp->streaming.video_payload_type = (temp_class!= VIDEO_NOT_DEFINED ? 
	                   temp_class : ptp->streaming.video_payload_type);
     	   }

     	  if (( ptp->streaming.video_content_type != VIDEO_NOT_DEFINED && 
	        ptp->streaming.video_payload_type != VIDEO_NOT_DEFINED ) || 
	      ( ptp->streaming.packets >= MAX_HTTP_STREAMING_DEPTH )
	     ) 
	    {
     	      ptp->streaming.state = IGNORE_FURTHER_PACKETS;
     	    }
        }
       break;
     default:
       break;
   }

  if (ptp->packets > MAX_PACKETS_CON)
    ptp->streaming.state = IGNORE_FURTHER_PACKETS;

  return;
}

void make_videoL7_rate_stats(tcp_pair *thisflow, int len) 
{
  int type;
  type = map_video_flow_type(thisflow);

  if (type != VIDEO_FLOW_TRUE)
    return;

  if (internal_src && !internal_dst) 
   {
     VIDEO_rate.out[VIDEO_MAP(thisflow)] += len;
     if (cloud_dst)
  	VIDEO_rate.c_out[VIDEO_MAP(thisflow)] += len;
     else 
  	VIDEO_rate.nc_out[VIDEO_MAP(thisflow)] += len;
   }
  else if (!internal_src && internal_dst) 
   {
     VIDEO_rate.in[VIDEO_MAP(thisflow)] += len;
     if (cloud_src)
  	VIDEO_rate.c_in[VIDEO_MAP(thisflow)] += len;
     else 
  	VIDEO_rate.nc_in[VIDEO_MAP(thisflow)] += len;
   } 
#ifndef LOG_UNKNOWN
  else if (internal_src && internal_dst)
#else
  else
#endif
   {
     VIDEO_rate.loc[VIDEO_MAP(thisflow)] += len;
   }

  return;
}

void make_videoL7_conn_stats(void *thisflow, int tproto)
{
  int type;
  tcp_pair * ptp = (tcp_pair *) thisflow;

  type = map_video_flow_type(ptp);
  if (type != VIDEO_FLOW_TRUE)
   return;

  switch ((in_out_loc(ptp->internal_src, ptp->internal_dst, C2S))) 
   {
     case OUT_FLOW:
       add_histo (L7_VIDEO_num_out, VIDEO_MAP(thisflow));
       if (ptp->cloud_dst) 
        {
          add_histo (L7_VIDEO_num_c_out, VIDEO_MAP(thisflow));
        } 
       else 
        {
          add_histo (L7_VIDEO_num_nc_out, VIDEO_MAP(thisflow));
        }
       break;
     case IN_FLOW:
       add_histo (L7_VIDEO_num_in, VIDEO_MAP(thisflow));
       if (ptp->cloud_src) 
        {
          add_histo (L7_VIDEO_num_c_in, VIDEO_MAP(thisflow));
        } 
       else 
        {
          add_histo (L7_VIDEO_num_nc_in, VIDEO_MAP(thisflow));
        }
       break;
     case LOC_FLOW:
       add_histo (L7_VIDEO_num_loc, VIDEO_MAP(thisflow));
       break;
   }
  return;
}

int map_video_flow_type(tcp_pair *thisflow) 
{
  int type = VIDEO_FLOW_NOT_VIDEO;

  //   /* RTMP */
  //  if(thisflow->con_type & RTMP_PROTOCOL)
  //   {
  //	 return VIDEO_FLOW_TRUE;
  //   }

  /* HTTP */

  if (thisflow->con_type & HTTP_PROTOCOL)
   {
     if ((thisflow->streaming.video_content_type == VIDEO_NOT_DEFINED) && 
         (thisflow->streaming.video_payload_type == VIDEO_NOT_DEFINED)) 
       {
  	 return VIDEO_FLOW_NOT_VIDEO;
       } 
     else 
       {
         return VIDEO_FLOW_TRUE;
       }
  }
  return type;
}

enum video_content VIDEO_MAP(tcp_pair *thisflow) 
{
  enum video_content class = VIDEO_UNKNOWN;

  // if(thisflow->con_type & RTMP_PROTOCOL)
  //  {
  //	return VIDEO_RTMP;
  //  }

  if ( thisflow->streaming.video_content_type == VIDEO_NOT_DEFINED ) 
   {
     class = thisflow->streaming.video_payload_type;
   } 
  else if ( thisflow->streaming.video_payload_type == VIDEO_NOT_DEFINED ) 
   {
     class = thisflow->streaming.video_content_type;
   } 
  else 
   {
     class = thisflow->streaming.video_payload_type;
   }

  switch (class)
   {
     case VIDEO_3GPP:
     case VIDEO_QUICKTIME:
     case VIDEO_OGG:
       return VIDEO_QUICKTIME;
     default:
       return class;
   }
  return class;
}

