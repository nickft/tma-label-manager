#include <stdio.h>
#include <assert.h>
#include <unistd.h>
#include <string.h>
#include "panon.h"
#include "tstat.h"
#include "crypto.h"
#include "base64.h"

/* Redefine the initial hash size to a large value, to avoid/reduce the automatic rehashing */

#define HASH_INITIAL_NUM_BUCKETS 131072      /* initial number of buckets        */
#define HASH_INITIAL_NUM_BUCKETS_LOG2 17     /* lg2 of initial number of buckets */

/* Use the Bernstein hash function */
#define HASH_FUNCTION HASH_BER

#include "uthash.h" /* Include the generic hash table */

#ifndef MAX_CRYPTO_CACHE_SIZE
#define MAX_CRYPTO_CACHE_SIZE HASH_INITIAL_NUM_BUCKETS
#endif

#define KEY_SIZE 32

struct key_hashT {
  in_addr_t key;
  in_addr_t cpan_addr;
  UT_hash_handle hh;
};

#ifdef SUPPORT_IPV6
struct key6_hashT {
  struct in6_addr key;
  struct in6_addr cpan_addr;
  UT_hash_handle hh;
};
#endif

struct key_hashT *address_hash = NULL;
#ifdef SUPPORT_IPV6
struct key6_hashT *address6_hash = NULL;
#endif

void add_address(in_addr_t src, in_addr_t cpan_addr) {
    struct key_hashT *s,*tmp_entry;

    s = (struct key_hashT *)malloc(sizeof(struct key_hashT));
    s->key = src;
    s->cpan_addr = cpan_addr;
    HASH_ADD_INT( address_hash, key, s );  /* id: name of key field */
    
    /* Manage the hash as a LRU cache */
    if (HASH_COUNT(address_hash) > GLOBALS.Max_Crypto_Cache_Size)
      {
        HASH_ITER(hh, address_hash, s, tmp_entry)
         {
            // prune the first entry (loop is based on insertion order so this deletes the oldest item)
           HASH_DELETE(hh, address_hash, s);
           free(s);
           break;
	 }
      }
}

#ifdef SUPPORT_IPV6
void add_address6(struct in6_addr *src, struct in6_addr *cpan_addr) {
    struct key6_hashT *s,*tmp_entry;

    s = (struct key6_hashT *)malloc(sizeof(struct key6_hashT));
    memcpy(&(s->key),src,sizeof(struct in6_addr));
    memcpy(&(s->cpan_addr),cpan_addr,sizeof(struct in6_addr));
    HASH_ADD( hh, address6_hash, key, sizeof(s->key), s );  /* id: name of key field */
    
    /* Manage the hash as a LRU cache */
    if (HASH_COUNT(address6_hash) > GLOBALS.Max_Crypto_Cache_Size)
      {
        HASH_ITER(hh, address6_hash, s, tmp_entry)
         {
            // prune the first entry (loop is based on insertion order so this deletes the oldest item)
           HASH_DELETE(hh, address6_hash, s);
           free(s);
           break;
	 }
      }
}
#endif

struct key_hashT *find_address(in_addr_t src) {
    struct key_hashT *s;

    HASH_FIND_INT( address_hash, &src, s );  /* s: output pointer */
    
    /* Manage the hash as a LRU cache */
    if (s) {
      // remove it (so the subsequent add will throw it on the front of the list)
      HASH_DELETE(hh, address_hash, s);
      HASH_ADD(hh,address_hash, key, sizeof(s->key), s);
      return s;
     }
    return s;
}

#ifdef SUPPORT_IPV6
struct key6_hashT *find_address6(struct in6_addr *src) {
    struct key6_hashT *s;

    HASH_FIND( hh, address6_hash, src, sizeof(s->key), s );  /* s: output pointer */
    
    /* Manage the hash as a LRU cache */
    if (s) {
      // remove it (so the subsequent add will throw it on the front of the list)
      HASH_DELETE(hh, address6_hash, s);
      HASH_ADD(hh,address6_hash, key, sizeof(s->key), s);
      return s;
     }
    return s;
}
#endif

int crypto_total_hit,crypto_total_insert,crypto_total_miss;
#ifdef SUPPORT_IPV6
int crypto_total_hit_ipv6,crypto_total_insert_ipv6,crypto_total_miss_ipv6;
#endif

void initialize_crypto(int key_source, char *value, char *basenamedir)
{
  FILE *fp;
  char *key;
  char *keyfile;
  char *enc_key;
  char date[50];
  char line[121];
  char *decoded_key = NULL;
  int flen,i;
  in_addr_t ip1,ip2;
#ifdef SUPPORT_IPV6
  struct in6_addr ip6_1,ip6_2;
#endif

  key = (char *) malloc(sizeof(char) * KEY_SIZE);
  memset(key,0,KEY_SIZE*sizeof(char));

  switch (key_source)
   {
    case CPKEY_RANDOM:
      fprintf(fp_stdout,"Generating random key (might take some time)...\n");
      fp = fopen("/dev/random", "r");

      if (fp==NULL)
      {
	fprintf(fp_stderr,"Error opening /dev/random. Exiting\n");
	exit(1);
      }
      
      if (fread(key,1, KEY_SIZE, fp) != KEY_SIZE)
      {
	fprintf(fp_stderr,"Cannot generate random key\n");
	exit(1);
      }
      fprintf(fp_stdout,"... done\n");
      
      fclose(fp);
      break;
    case CPKEY_FILE:
      if (value==NULL)
       {
	 fprintf(fp_stderr,"Invalid key file name\n");
	 exit(1);
       }
       
      fprintf(fp_stdout,"Reading plain text key from file %s ...\n",value);
      fp = fopen(value, "r");

      if (fp==NULL)
      {
	fprintf(fp_stderr,"Error opening file %s. Exiting\n",value);
	exit(1);
      }
      
      if (fgets(line,120,fp) == NULL)
      {
	fprintf(fp_stderr,"Cannot read plain text key from file\n");
	exit(1);
      }
      fprintf(fp_stdout,"... done\n");
      
      if (line[strlen(line)-1]=='\n')
       {
	 line[strlen(line)-1]='\0';
       }

      // printf(">>%s<<\n",line);
      
      if (strlen(line)<1)
       {
	 fprintf(fp_stderr,"Plain text key empty. Exiting\n");
	 exit(1);
       }
      decoded_key=strdup(line);
      flen = strlen(decoded_key);

      if (flen>KEY_SIZE)
       {
	 fprintf(fp_stdout,"Key is too long: using only the first %d bytes\n",KEY_SIZE);
         memcpy(key,decoded_key,KEY_SIZE*sizeof(char));
       }
      else
       {
         memcpy(key,decoded_key,flen*sizeof(char));
       }
	
      if (flen<KEY_SIZE)
       {
	 fprintf(fp_stdout,"Key shorter than %d bytes: padding with zeros\n",KEY_SIZE);
       }

      if (debug>2)
       {
         for (i=0;i<KEY_SIZE;i++)
          {
 	    fprintf(fp_stdout,"%hhx ",(char)key[i]);
          }
         fprintf(fp_stdout,"\n");
       }
       
      fclose(fp);
      break;
    case CPKEY_FILE64:
      if (value==NULL)
       {
	 fprintf(fp_stderr,"Invalid key file name\n");
	 exit(1);
       }
       
      fprintf(fp_stdout,"Reading Base64 encoded key from file %s ...\n",value);
      fp = fopen(value, "r");

      if (fp==NULL)
      {
	fprintf(fp_stderr,"Error opening file %s. Exiting\n",value);
	exit(1);
      }
      
      if (fgets(line,120,fp) == NULL)
      {
	fprintf(fp_stderr,"Cannot read Base64 encoded key from file\n");
	exit(1);
      }
      fprintf(fp_stdout,"... done\n");
      
      if (line[strlen(line)-1]=='\n')
       {
	 line[strlen(line)-1]='\0';
       }

      // printf(">>%s<<\n",line);
      
      /* The line is supposed to be Base64 encoded */
      /* This version of unbase64() does trust the input and does not
         implements any check on the input format. Invalid characters are
         considered as 0 ('A') */
      decoded_key = (char *)unbase64(line,strlen(line),&flen);
      if (decoded_key==NULL)
       {
	 fprintf(fp_stderr,"Base64 decoding failed. Exiting\n");
	 exit(1);
       }

      if (flen>KEY_SIZE)
       {
	 fprintf(fp_stdout,"Key is too long: using only the first %d bytes\n",KEY_SIZE);
         memcpy(key,decoded_key,KEY_SIZE*sizeof(char));
       }
      else
       {
         memcpy(key,decoded_key,flen*sizeof(char));
       }
	
      if (flen<KEY_SIZE)
       {
	 fprintf(fp_stdout,"Key shorter than %d bytes: padding with zeros\n",KEY_SIZE);
       }

      if (debug>2)
       {
         for (i=0;i<KEY_SIZE;i++)
          {
 	    fprintf(fp_stdout,"%hhx ",(char)key[i]);
          }
         fprintf(fp_stdout,"\n");
       }
       
      fclose(fp);
      break;
    case CPKEY_CLI:
      if (value==NULL)
       {
	 fprintf(fp_stderr,"Invalid key\n");
	 exit(1);
       }
       
      fprintf(fp_stdout,"Using plain text key from command line\n");

      // printf(">>%s<<\n",value);
      
      // duplicate the string
      decoded_key=strdup(value);
      flen = strlen(decoded_key);

      if (flen>KEY_SIZE)
       {
	 fprintf(fp_stdout,"Key is too long: using only the first %d bytes\n",KEY_SIZE);
         memcpy(key,decoded_key,KEY_SIZE*sizeof(char));
       }
      else
       {
         memcpy(key,decoded_key,flen*sizeof(char));
       }
	
      if (flen<KEY_SIZE)
       {
	 fprintf(fp_stdout,"Key shorter than %d bytes: padding with zeros\n",KEY_SIZE);
       }

      if (debug>2)
       {
         for (i=0;i<KEY_SIZE;i++)
          {
 	    fprintf(fp_stdout,"%hhx ",(char)key[i]);
          }
         fprintf(fp_stdout,"\n");
       }
      
      break;
    default:
      fprintf(fp_stderr,"Invalid key source\n");
      exit(1);
      break;
   }

  encrypt_init(key,KEY_SIZE);

  strftime (date, 49, "%Y_%m_%d_%H_%M", localtime (&current_time.tv_sec));
  keyfile = (char *)malloc(strlen(basenamedir)+strlen("/CPanKey_")+strlen(date)+2);
  
  strcpy(keyfile,basenamedir);
  strcat(keyfile,"/CPanKey_");
  strcat(keyfile,date);

  enc_key = base64(key,KEY_SIZE,&flen);
  
  fp = fopen(keyfile,"w");
  if (fp!=NULL)
   {
     fprintf(fp,"%s\n",enc_key);
   }
  else
   {
     fprintf(fp_stderr,"Error opening %s. CPan key not stored\n",keyfile);
   }
  fclose(fp);
  
  /* There is a "bug" due to encrypt_ip internal cache initialization, 
     so "0.0.0.0" is actually not encrypted if it is the argument of 
     either the first or the second function call.
     Call the function twice with other arguments.
  */
  encrypt_ip(1);
  encrypt_ip(2);

  /* Insert one address (0.0.0.0) just to inizialize the hash to the full size */
  ip1 = inet_addr("0.0.0.0");
  ip2 = htonl(encrypt_ip(htonl(ip1)));
  add_address(ip1,ip2);
  
  crypto_total_hit = 0;
  crypto_total_insert = 1;
  crypto_total_miss = 0;

#ifdef SUPPORT_IPV6
  /* Insert one address (::) just to inizialize the hash to the full size */
  inet_pton(AF_INET6,"::",&ip6_1);
  encrypt_ipv6(&ip6_2,&ip6_1);
  add_address6(&ip6_1,&ip6_2);
  
  crypto_total_hit_ipv6    = 0;
  crypto_total_insert_ipv6 = 1;
  crypto_total_miss_ipv6   = 0;
#endif
  
  
  if (enc_key!=NULL) free(enc_key);
  if (keyfile!=NULL) free(keyfile);
  if (decoded_key!=NULL) free(decoded_key);

  return;

}

void encrypt_init(char *key, int keysize)
{
  char cryptopan_key[32];
  memset(cryptopan_key,0,sizeof(cryptopan_key));

  memcpy(cryptopan_key,key,keysize<sizeof(cryptopan_key)?keysize:sizeof(cryptopan_key));
  panon_init(cryptopan_key);
}

uint32_t encrypt_ip(uint32_t orig_addr) 
{
  return cpp_anonymize(orig_addr);
}

void store_crypto_ip(struct in_addr *address)
{
  in_addr_t ip_entry;
  struct key_hashT *entry;
  
  entry = find_address(address->s_addr);

  if (entry == NULL)
   {
     ip_entry = htonl(encrypt_ip(htonl(address->s_addr)));
     add_address(address->s_addr,ip_entry);
     crypto_total_insert++;
   }
  else
  {
    crypto_total_hit++;
  }

}

in_addr_t retrieve_crypto_ip(struct in_addr *address)
{
  in_addr_t ip_entry;
  struct key_hashT *entry;
  
  entry = find_address(address->s_addr);

  if (entry==NULL)
   {
     ip_entry = htonl(encrypt_ip(htonl(address->s_addr)));
     add_address(address->s_addr,ip_entry);
     crypto_total_insert++;
     crypto_total_miss++;

     return ip_entry;
   }
  else
  {
    return entry->cpan_addr;
  }
}

#ifdef SUPPORT_IPV6
void encrypt_ipv6(struct in6_addr *enc_addr,struct in6_addr *orig_addr)
{
  /*
   This is a horrendous hack, but the simplest way to encrypt our IPv6 address is to apply
   the cryptopan encryption on the 4 dwords making the IP address.
   Since the same dword would be encrypted to the same pattern beside the position, 
   addresses like ::1 or with a lot of adjacent :0:0: would be immediately identified.
   For this reason we actually XOR a different bit-pattern to each dword. 
   This should in any case maintain the prefix-preservation property.
   The least significant dword is encrypted without the XOR, 
   so the IPv4 address x.y.z.w and the IPv6 address ::x.y.z.w will share the 
   same encoding in the last dword.
  */
  enc_addr->s6_addr32[0] = htonl(encrypt_ip(htonl(orig_addr->s6_addr32[0] ^ 0xffff )));
  enc_addr->s6_addr32[1] = htonl(encrypt_ip(htonl(orig_addr->s6_addr32[1] ^ 0xf0f0 )));
  enc_addr->s6_addr32[2] = htonl(encrypt_ip(htonl(orig_addr->s6_addr32[2] ^ 0x0f0f )));
  enc_addr->s6_addr32[3] = htonl(encrypt_ip(htonl(orig_addr->s6_addr32[3] ^ 0x0000 )));
}

void store_crypto_ipv6(struct in6_addr *address)
{
  struct in6_addr ip6_entry;
  struct key6_hashT *entry;
  
  entry = find_address6(address);

  if (entry == NULL)
   {
     encrypt_ipv6(&ip6_entry,address);
     add_address6(address,&ip6_entry);
     crypto_total_insert_ipv6++;
   }
  else
  {
    crypto_total_hit_ipv6++;
  }

}

struct in6_addr *retrieve_crypto_ipv6(struct in6_addr *address)
{
  static struct in6_addr ip6_entry;
  struct key6_hashT *entry;
  
  entry = find_address6(address);

  if (entry==NULL)
   {
     encrypt_ipv6(&ip6_entry,address);
     add_address6(address,&ip6_entry);
     crypto_total_insert_ipv6++;
     crypto_total_miss_ipv6++;

     return &ip6_entry;
   }
  else
  {
    return &(entry->cpan_addr);
  }
}

#endif

char *HostNameEncrypted(ipaddr ipaddress)
{
  char *adr;
  ipaddr encrypted;

#ifdef SUPPORT_IPV6
  if (ADDR_ISV6 (&ipaddress))
    {
      encrypted.addr_vers = 6;
      memcpy(&encrypted.un.ip6,retrieve_crypto_ipv6(&(ipaddress.un.ip6)),sizeof(struct in6_addr));
      adr = HostAddr (encrypted);
      return (adr);
    }
  else
#endif
    {
      encrypted.addr_vers = 4;
      encrypted.un.ip4.s_addr = retrieve_crypto_ip(&(ipaddress.un.ip4));
      adr = HostName(encrypted);
      return (adr);
    }
}