/*
 * scamper_tracebox.c
 *
 *
 *
 * @author: K.Edeline
 */

#ifndef lint
static const char rcsid[] =
  "$Id: scamper_tracebox.c,v 1.24 2013/08/07 21:30:02 mjl Exp $";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "internal.h"

#include "scamper_addr.h"
#include "scamper_list.h"
#include "scamper_tracebox.h"
#include "utils.h"

int scamper_tracebox_pkt_iplen(const scamper_tracebox_pkt_t *pkt)
{
  uint8_t v = pkt->data[0] >> 4;
  int rc = -1;

  if(v == 4)
    rc = bytes_ntohs(pkt->data+2);
  else if(v == 6)
    rc = bytes_ntohs(pkt->data+4) + 40;

  return rc;
}

int scamper_tracebox_pkt_iph(const scamper_tracebox_pkt_t *pkt,
			 uint8_t *proto, uint8_t *iphlen, uint16_t *iplen)
{
  uint8_t v = pkt->data[0] >> 4;

  if(v == 4)
    {
      *iphlen = (pkt->data[0] & 0xf) * 4;
      *iplen = bytes_ntohs(pkt->data+2);
      *proto = pkt->data[9];
      return 0;
    }

  if(v == 6)
    {
      *iphlen = 40;
      *iplen = bytes_ntohs(pkt->data+4) + 40;
      *proto = pkt->data[6];
      for(;;)
	{
	  switch(*proto)
	    {
	    case IPPROTO_HOPOPTS:
	    case IPPROTO_DSTOPTS:
	    case IPPROTO_ROUTING:
	      *proto = pkt->data[*iphlen];
	      *iphlen += (pkt->data[(*iphlen)+1] * 8) + 8;
	      continue;
	    case IPPROTO_FRAGMENT:
	      *proto = pkt->data[*iphlen];
	      if((bytes_ntohs(pkt->data+(*iphlen)+2) & 0xfff8) != 0) /* off */
		return -1;
	      if((pkt->data[(*iphlen)+3] & 0x1) != 0) /* mf */
		return -1;
	      *iphlen += 8;
	      continue;
	    }
	  break;
	}
      return 0;
    }

  return -1;
}

char *scamper_tracebox_type2str(const scamper_tracebox_t *tracebox, char *buf, size_t len)
{
  static char *t[] = {
    NULL,
    "pmtud",
    "ecn",
    "null",
    "sack-rcvr",
  };

  if(tracebox->type > sizeof(t) / sizeof(char *) || t[tracebox->type] == NULL)
    {
      snprintf(buf, len, "%d", tracebox->type);
      return buf;
    }

  return t[tracebox->type];
}

char *scamper_tracebox_res2str(const scamper_tracebox_t *tracebox, char *buf, size_t len)
{
  static char *t[] = {
    "none",                /* 0 */
    "tcp-noconn",
    "tcp-rst",
    "tcp-error",
    "sys-error",
    "aborted",
    "destination-unreachable",
    "halted",
    "tcp-badopt",
    "tcp-fin",
    "tcp-zerowin",         /* 10 */
    "icmp-ttlexp",
    "success",
    "timeouted",
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    "pmtud-noack",         /* 20 */
    "pmtud-nodata",
    "pmtud-toosmall",
    "pmtud-nodf",
    "pmtud-fail",
    "pmtud-success",
    "pmtud-cleardf",
    NULL,
    NULL,
    NULL,
    "ecn-success",         /* 30 */
    "ecn-incapable",
    "ecn-badsynack",
    "ecn-noece",
    "ecn-noack",
    "ecn-nodata",
    NULL,
    NULL,
    NULL,
    NULL,
    "null-success",        /* 40 */
    "null-nodata",
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    "sack-incapable",      /* 50 */
    "sack-rcvr-success",
    "sack-rcvr-shifted",
    "sack-rcvr-timeout",
    "sack-rcvr-nosack",
  };

  if(tracebox->result > sizeof(t) / sizeof(char *) || t[tracebox->result] == NULL)
    {
      snprintf(buf, len, "%d", tracebox->result);
      return buf;
    }

  return t[tracebox->result];
}

scamper_tracebox_pkt_t *scamper_tracebox_pkt_alloc(uint8_t dir, uint8_t *data,
					   uint16_t len, struct timeval *tv)
{
  scamper_tracebox_pkt_t *pkt;

  if((pkt = malloc_zero(sizeof(scamper_tracebox_pkt_t))) == NULL)
    goto err;

  pkt->dir = dir;
  if(len != 0 && data != NULL)
    {
      if((pkt->data = memdup(data, len)) == NULL)
	goto err;
      pkt->len = len;
    }
  if(tv != NULL) timeval_cpy(&pkt->tv, tv);
  return pkt;

 err:
  free(pkt);
  return NULL;
}

void scamper_tracebox_pkt_free(scamper_tracebox_pkt_t *pkt)
{
  if(pkt == NULL)
    return;
  if(pkt->data != NULL) free(pkt->data);
  free(pkt);
  return;
}

int scamper_tracebox_pkts_alloc(scamper_tracebox_t *tracebox, uint32_t count)
{
  size_t size = count * sizeof(scamper_tracebox_pkt_t *);
  if((tracebox->pkts = (scamper_tracebox_pkt_t **)malloc_zero(size)) == NULL)
    return -1;
  return 0;
}

int scamper_tracebox_record_pkt(scamper_tracebox_t *tracebox, scamper_tracebox_pkt_t *pkt)
{
  size_t len = (tracebox->pktc + 1) * sizeof(scamper_tracebox_pkt_t *);

  /* Add a new element to the pkts array */
  if(realloc_wrap((void**)&tracebox->pkts, len) != 0)
    return -1;

  tracebox->pkts[tracebox->pktc++] = pkt;
  return 0;
}

/* Free the tracebox object. */
void scamper_tracebox_free(scamper_tracebox_t *tracebox)
{
  uint32_t i;

  if(tracebox == NULL)
    return;

  if(tracebox->src != NULL)   scamper_addr_free(tracebox->src);
  if(tracebox->dst != NULL)   scamper_addr_free(tracebox->dst);
  if(tracebox->list != NULL)  scamper_list_free(tracebox->list);
  if(tracebox->cycle != NULL) scamper_cycle_free(tracebox->cycle);

  /* Free the recorded packets */
  if(tracebox->pkts != NULL)
    {
      for(i=0; i<tracebox->pktc; i++)
	scamper_tracebox_pkt_free(tracebox->pkts[i]);
      free(tracebox->pkts);
    }

  free(tracebox);
  return;
}

scamper_tracebox_t *scamper_tracebox_alloc(void)
{
  return (scamper_tracebox_t *)malloc_zero(sizeof(scamper_tracebox_t));
}

