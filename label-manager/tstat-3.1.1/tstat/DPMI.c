#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef GROK_DMPI

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include "tstat.h"
#include "DPMI_utils/cap_utils_tstat.h"

#define STPBRIDGES 0x0026
#define CDPVTP 0x016E
#define ETHERTYPE_VLAN 0x8100

#define APP_VERSION_MAJOR 0
#define APP_VERSION_MINOR 2


extern Bool coming_in;

struct _dpmi
{
  struct filter *myFilter;
  struct stream myStream;
  int streamType;
  int portNumber;
  char *nic;
  char *inMP;
  char *inCI;

  Bool first;			// for default MP:CI selection
  int argc;			// arguments from dpmi.conf or equivalent
  char **argv;
} dpmi;

//global flag in case DPMI.conf is not provided
Bool first = TRUE;


int
pread_DPMI (struct timeval *ptime,
	    int *plen,
	    int *ptlen,
	    void **pphys, int *pphystype, struct ip **ppip, void **pplast)
{
  cap_head *caphead;
  int rpStatus;
  char *data;
  struct ether_header *ether;

  // we use ``while'' rather than ``if'' since we may discard non-IP packets
  while ((rpStatus = read_post (&dpmi.myStream, &data, dpmi.myFilter)) != 0)
    {
      caphead = (cap_head *) data;

      ptime->tv_usec = caphead->ts.tv_psec / 1000 / 1000;
      ptime->tv_sec = caphead->ts.tv_sec;

      ether = (struct ether_header *) (data + sizeof (cap_head));
      *plen = caphead->len;
      /* Lenght of the packet on the wire */
      *ptlen = caphead->caplen;
      /* Portion of the Lenght of captured packet present in this
         sample */
      *pphys = ether;
      *pphystype = PHYS_ETHER;
      *ppip =
	(struct ip *) (data + sizeof (cap_head) + sizeof (struct ethhdr));
      *pplast = (char *) data + *ptlen + sizeof (cap_head);

      /* if it's not IP, then skip it */
      if ((ntohs (ether->ether_type) != ETHERTYPE_IP) &&
	  (ntohs (ether->ether_type) != ETHERTYPE_IPV6))
	{
	  if (debug > 2)
	    fprintf (fp_stderr, "pread_tcpdump: not an IP packet\n");
	  continue;
	}

      // this is used depending on internal_wired value
      // char nic[8];     // Identifies the CI where the frame was caught
      // char mampid[8];  // Identifies the MP where the frame was caught,
      if (dpmi.first || first)
	{
	  // unless, otherwise specified, the first frame
	  // is assumed to be ``incoming'', and thus determines
	  // the incoming CI:MP couple
	  dpmi.inCI = strdup (caphead->nic);
	  dpmi.inMP = strdup (caphead->mampid);
	  dpmi.first = first = FALSE;
	}
      coming_in = !strcmp (caphead->nic, dpmi.inCI) &&
	!strcmp (caphead->mampid, dpmi.inMP);

      // ok, so we read the packet and returned 
      // ppip and pplast pointers to tstat
      return 1;
    }

  closestream (&dpmi.myStream);
  return 0;
}




pread_f *
is_DPMI (char *filename)
{
// currently, this does NOT work with stdin

  if (!openstream
      (&dpmi.myStream, filename, dpmi.streamType, dpmi.nic, dpmi.portNumber))
    {
      if (debug > 1)
	fprintf (fp_stderr, "This is not a DPMI trace\n");
      rewind (stdin);
      return (NULL);
    }
  if (debug > 1)
    {
      fprintf (fp_stdout, 
        "DPMI trace\n:Comment size: %d, ver: %d.%d id: %s \n comments: %s\n",
	    dpmi.myStream.FH.comment_size, dpmi.myStream.FH.version.major,
	    dpmi.myStream.FH.version.minor, dpmi.myStream.FH.mpid,
	    dpmi.myStream.comment);
    }
  if (!net_conf)
    internal_wired = TRUE;

  return (pread_DPMI);
}




int
dpmi_parse_config (const char *fname)
{
  int i;
  fprintf (fp_stderr, "Parsing %s ...", fname);

  /*
   *  setting default dpmi configuration
   */
  dpmi.first = TRUE;
  dpmi.nic = NULL;
  dpmi.inMP = NULL;		// incoming Measurement Point (live DPMI capture, internal_wired)
  dpmi.inCI = NULL;		// incoming Capture Interface (live DPMI capture, internal_wired)
  dpmi.myFilter = NULL;
  dpmi.streamType = 0;
  dpmi.portNumber = 0;

  /*
   *  parse file and create filters.
   *  Tstat-DPMI keywords:  
   type of stream:      tstat:(file|(tcp|udp|eth)[:port])   
   measurement in:      tstat:[MP:CI]
   */
  dpmi.argv = ArgsFromFile(fname, &dpmi.argc);
  if (debug)
    fprintf (fp_stderr, "dmpi_ArgsFromFile[%s] returned %d arguments\n", fname,
	     dpmi.argc);


  for (i = 0; i < dpmi.argc; i++)
    {
      char *arg = dpmi.argv[i];
      char *tok = strtok (arg, ":");
      if (debug)
	{
	  fprintf (fp_stderr, "dmpi_conf[%d]=%s\n", i, arg);
	  fprintf (fp_stderr, "\t%s\n", tok);
	}

      if (strcmp (tok, "tstat"))
	continue;

      tok = strtok (NULL, ":");
      if (tok == NULL)
	continue;

      if (!strcmp (tok, "file"))
	{
	  dpmi.streamType = 0;
	  if (debug)
	    fprintf (fp_stderr, "\tusing trace file\n");

	}
      else
	{
	  if (!strcmp (tok, "tcp"))
	    {
	      dpmi.streamType = 3;
	      dpmi.portNumber = atoi (strtok (NULL, ":"));
	      if (debug)
		fprintf (fp_stderr, "\tusing TCP socket (port %d)\n",
			 dpmi.portNumber);

	    }
	  else if (!strcmp (tok, "udp"))
	    {
	      dpmi.streamType = 2;
	      dpmi.portNumber = atoi (strtok (NULL, ":"));
	      if (debug)
		fprintf (fp_stderr, "\tusing UDP socket (port %d)\n",
			 dpmi.portNumber);

	    }
	  else if (!strcmp (tok, "eth"))
	    {
	      dpmi.streamType = 1;
	      dpmi.portNumber = atoi (strtok (NULL, ":"));
	      if (debug)
		fprintf (fp_stderr, "\tusing ETH medium (port %d)\n",
			 dpmi.portNumber);

	    }
	  else
	    {
	      dpmi.inMP = strdup (tok);
	      dpmi.inCI = strdup (strtok (NULL, ":"));
	      dpmi.first = FALSE;
	      if (debug)
		fprintf (fp_stderr, "\tinternal_wired (%s:%s)\n", dpmi.inMP,
			 dpmi.inCI);
	    }
	}
    }

  if ((dpmi.inMP == NULL) && (dpmi.inCI == NULL))
    {
      if (debug)
	fprintf (fp_stderr,
		 "\tarbitrary assuming first packet's MP:CI as internal\n");
    }

  fprintf (fp_stderr, " done (messages below are from DPMI libraries)\n");

  if (debug)
    fprintf (fp_stderr, "Creating DPMI filter\n");
  dpmi.myFilter = createfilter (dpmi.argc, dpmi.argv);

  fprintf (fp_stderr, "Created DPMI filter... control back to tstat !\n\n");


//         case 'i':
//      fprintf(fp_stdout, "Ethernet Argument %s\n", optarg);
//      l=strlen(optarg);
//      nic=(char*)malloc(l+1);
//      strcpy(nic,optarg);
//      streamType=1;
//      break;
}
#endif
