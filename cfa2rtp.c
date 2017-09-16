#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define _XOPEN_SOURCE     /* See feature_test_macros(7) */
#define __USE_XOPEN       /* See feature_test_macros(7) */
#include <time.h>
#include <sys/time.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>



typedef unsigned int u_int32;
typedef unsigned short u_int16;

/* http://www.cs.columbia.edu/irt/software/rtptools/ */
typedef struct {
  struct timeval start;  /* start of recording (GMT) */
  u_int32 source;        /* network source (multicast address) */
  u_int16 port;          /* UDP port */
} RD_hdr_t;

typedef struct {
  u_int16 length;    /* length of packet, including this header (may 
                        be smaller than plen if not whole packet recorded) */
  u_int16 plen;      /* actual header+payload length for RTP, 0 for RTCP */
  u_int32 offset;    /* milliseconds since the start of recording */
} RD_packet_t;

struct param {
  char *addr;
  int port;
  int rtpoffset;
  char *rtphdr;
};



#define MTU 1500
#define RTP_MCADDR "239.255.0.1"
#define RTP_PORT 5004
#define RTP_HDR "80 60"

#define DEBUG



int datestr2tv(const char *datestr, struct timeval *tv)
{
  struct tm time;
  time_t timet;
  char *p;

  p = strptime(datestr, "%Y/%m/%d %T", &time);
  if (p == NULL)
    return -1;

  timet = mktime(&time);
  tv->tv_sec = timet;

  if (*p == '.')   /* sub seconds */
    tv->tv_usec = atoi(p + 1);   /* +1 skips period */
  else
    tv->tv_usec = 0;

#ifdef DEBUG
  fprintf(stderr, "tv_sec  = %ld\n", tv->tv_sec);
  fprintf(stderr, "tv_usec = %ld\n", tv->tv_usec);
#endif
  
  return 0;
}



int writehdr(const char *addrstr, int port, const struct timeval starttv, FILE *wfp)
{
  struct in_addr addr;
  RD_hdr_t hdr;
  u_int16 padding;

  if (inet_aton(addrstr, &addr) == 0)
    return -1;

  if (fprintf(wfp, "#!rtpplay1.0 %s/%d\n", addrstr, port) < 0)
    return -1;

  /* https://code.wireshark.org/review/gitweb?p=wireshark.git;a=blob;f=ui/tap-rtp-common.c */
  hdr.start.tv_sec  = htonl(starttv.tv_sec);
  hdr.start.tv_usec = htonl(starttv.tv_usec);
  hdr.source = htonl(addr.s_addr);
  hdr.port   = htons(port);
  padding = htons(0);

  if (fwrite(&hdr.start.tv_sec,  4, 1, wfp) == 0)
    return -1;
  if (fwrite(&hdr.start.tv_usec, 4, 1, wfp) == 0)
    return -1;
  if (fwrite(&hdr.source, 4, 1, wfp) == 0)
    return -1;
  if (fwrite(&hdr.port,   2, 1, wfp) == 0)
    return -1;
  if (fwrite(&padding, 2, 1, wfp) == 0)
    return -1;

  return 0;
}




int payloadstr2bin(const char *str, unsigned char *bin)
{
  int len = 0, hex;

  while (1) {
    if (sscanf(str, "%x", &hex) < 1)
      break;   /* maybe reach to end */
    *bin++ = (unsigned char)hex;
    len++;
    str += 3;   /* hex str(2) + white space(2) = 3 */
  }

  return len;
}

int writepacket(const char *payloadstr, int rtpoffset, struct timeval offsettv, FILE *wfp)
{
  RD_packet_t packet;
  unsigned char payloadbin[MTU];
  int len;

  len = payloadstr2bin(payloadstr + rtpoffset , payloadbin);

#ifdef DEBUG
  fprintf(stderr, "rtphdr = %.5s...\n", payloadstr + rtpoffset);
  fprintf(stderr, "len = %d\n", len);
#endif

  /* https://code.wireshark.org/review/gitweb?p=wireshark.git;a=blob;f=ui/tap-rtp-common.c */
  packet.length = htons(len + 8);
  packet.plen   = htons(len);
  packet.offset = htonl(offsettv.tv_sec * 1000 + offsettv.tv_usec / 1000);   /* in msec */

  if (fwrite(&packet.length, 2, 1, wfp) == 0)
    return -1;
  if (fwrite(&packet.plen,   2, 1, wfp) == 0)
    return -1;
  if (fwrite(&packet.offset, 4, 1, wfp) == 0)
    return -1;

  if (fwrite(&payloadbin, len, 1, wfp) == 0)
    return -1;
  
  return len;
}



int parse(FILE *rfp, FILE *wfp, struct param *pm)
{
  int num, ret, rtpoffset;
  char datestr[27], payload[MTU * 3];
  struct timeval starttv, tv, offsettv;
  int hdr = 0;;

  while (1) {

    /* find payload line */
    ret = fscanf(rfp, "%d,%[^,\r\n],%[^,\r\n]", &num, datestr, payload);
    if (ret == EOF)
      break;   /* end */
    else if (ret < 3) {
      fprintf(stderr, "warning: no payload line\n");
      fscanf(rfp, "%*[^\r\n]");   /* skip */
      continue;
    }

    /* found payload line */
#ifdef DEBUG
    fprintf(stderr, "num = %d\n", num);
#endif

    datestr2tv(datestr, &tv);

    /* create rtpdump header */
    if (!hdr) {
      starttv.tv_sec  = tv.tv_sec;
      starttv.tv_usec = tv.tv_usec;
      if (writehdr(pm->addr, pm->port, starttv, wfp) < 0)
	return -1;
      hdr = 1;   /* done */
    }

    /* find rtp header if offset is not set */
    if (pm->rtpoffset < 0) {
      char *p;

      p = strstr(payload, pm->rtphdr);
      if (p == NULL) {
	fprintf(stderr, "warning: rtp header not found\n");
	fscanf(rfp, "%*[^\r\n]");   /* skip */
	continue;
      }

      rtpoffset = p - payload;
    } else
      rtpoffset = pm->rtpoffset;

    timersub(&tv, &starttv, &offsettv);

    if (writepacket(payload, rtpoffset, offsettv, wfp) < 0)
      return -1;
  }

  return 0;
}



int main(int argc, char *argv[])
{
  int opt;
  FILE *rfp = stdin, *wfp = stdout;
  struct param pm;

  /* set default parameters */
  pm.addr = RTP_MCADDR;
  pm.port = RTP_PORT;
  pm.rtpoffset = -1;
  pm.rtphdr = RTP_HDR;

  while ((opt = getopt(argc, argv, "r:w:a:p:o:h:")) != -1) {
    switch (opt) {
    case 'r':
      rfp = fopen(optarg, "r");
      if (rfp == NULL) {
	perror("can't open");
	return 1;
      }
      break;
    case 'w':
      wfp = fopen(optarg, "w");
      if (wfp == NULL) {
	perror("can't open");
	return 1;
      }
      break;
    case 'a':
      pm.addr = malloc(strlen(optarg) + 1);
      if (pm.addr == NULL) {
	perror("malloc");
	return 1;
      }
      strcpy(pm.addr, optarg);
      break;
    case 'p':
      pm.port = atoi(optarg);
      break;
    case 'o':
      pm.rtpoffset = atoi(optarg);
      break;
    case 'h':
      pm.rtphdr = malloc(strlen(optarg) + 1);
      if (pm.rtphdr == NULL) {
	perror("malloc");
	return 1;
      }
      strcpy(pm.rtphdr, optarg);
      break;
    default:
      fprintf(stderr, "usage: %s [-r <input filename>] [-w <output filename>] [-a <IPv4 address>] [-p <port>] [-o <rtp header offset>] [-h <rtp header strings>]\n", argv[0]);
      return 1;
      break;
    }
  }

  if (parse(rfp, wfp, &pm) < 0) {
    perror("error");
    return 1;
  }

  fclose(rfp);
  fclose(wfp);
  return 0;
}
