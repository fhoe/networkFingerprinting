/*
 * scamper_do_tracebox.c
 *
 *
 *
 * @author: K.Edeline
 */

#ifndef lint
static const char rcsid[] =
  "$Id: scamper_tracebox_do.c,v 1.102 2014/04/22 21:55:29 mjl Exp $";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "internal.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "scamper.h"
#include "scamper_addr.h"
#include "scamper_list.h"
#include "scamper_task.h"
#include "scamper_dl.h"
#include "scamper_fds.h"
#include "scamper_dlhdr.h"
#include "scamper_firewall.h"
#include "scamper_rtsock.h"
#include "scamper_if.h"
#include "scamper_probe.h"
#include "scamper_getsrc.h"
#include "scamper_tcp4.h"
#include "scamper_ip4.h"
#include "scamper_ip6.h"
#include "scamper_tcp6.h"
#include "scamper_queue.h"
#include "scamper_file.h"
#include "scamper_options.h"
#include "scamper_debug.h"
#include "utils.h"
#include "mjl_list.h"
#include "scamper_tracebox.h"
#include "scamper_tracebox_do.h"
#include "scamper_tracebox_text.h"

/* Defaul parameters value */
#define TRACEBOX_RETX_DEFAULT           3
#define TRACEBOX_TIMEOUT_DEFAULT        3000
#define TRACEBOX_TIMEOUT_LONG           70000
#define TRACEBOX_SINGLE_HOP_MAX_REPLAYS 3
#define TRACEBOX_TOTAL_MAX_REPLAYS   	5
#define TRACEBOX_MAX_HOPS               64
#define TRACEBOX_DEFAULT_MSS		    1460
#define TRACEBOX_DEFAULT_WSCALE		    14

typedef struct tracebox_options
{
  uint8_t   udp;
  uint8_t   ipv6;
  uint8_t   rtt;
  uint8_t   icmp_quote_type;
  uint8_t   python_bindings;
  uint16_t  dport;
  uint16_t  secondary_dport;
  char      *probe;
  int 	    printmode;

  uint8_t app;

} tracebox_options_t;

typedef struct tracebox_segment
{
  uint8_t        *data;
  uint16_t        len;
} tracebox_segment_t;

typedef struct tracebox_frag
{
  uint16_t         off;
  uint8_t         *data;
  uint16_t         datalen;
} tracebox_frag_t;

typedef struct tracebox_frags
{
  struct timeval   tv;
  uint32_t         id;
  tracebox_frag_t    **frags;
  int              fragc;
  uint8_t          gotlast;
} tracebox_frags_t;

typedef struct tracebox_probe
{
  uint8_t type;
  int     wait;
  union
  {
    struct tp_tcp
    {
      uint16_t len;
      uint8_t  flags;
      uint8_t  sackb;
      uint32_t seq;
      uint32_t ack;
      uint32_t sack[8];
    } tcp;
  } un;
} tracebox_probe_t;

#define tp_len   un.tcp.len
#define tp_flags un.tcp.flags
#define tp_sackb un.tcp.sackb
#define tp_seq   un.tcp.seq
#define tp_ack   un.tcp.ack
#define tp_sack  un.tcp.sack

typedef struct tracebox_state
{

  uint16_t                  last_ttl;
  uint8_t                   replaying;  
  uint8_t                   timeout_count;
  uint8_t                   loop;

#ifndef _WIN32
  scamper_fd_t               *rtsock;
#endif
  scamper_fd_t               *dl;
  scamper_dlhdr_t            *dlhdr;
  scamper_route_t            *route;
  scamper_firewall_entry_t   *fw;
  uint8_t                     mode;
  uint8_t                     attempt;
  uint16_t                    flags;
  struct timeval              timeout;
  uint16_t                    ipid;

  slist_t                    *tx;
  slist_t                    *segments;
  uint32_t                    snd_nxt;
  uint32_t                    rcv_nxt;

  tracebox_frags_t              **frags;
  int                         fragc;

} tracebox_state_t;

#define pmtud_ptb_data        un.pmtud.ptb_data
#define pmtud_ptb_datalen     un.pmtud.ptb_datalen
#define pmtud_ptb_c           un.pmtud.ptb_c
#define sackr_rx              un.sackr.rx
#define sackr_x               un.sackr.x
#define sackr_flags           un.sackr.flags
#define sackr_timeout         un.sackr.timeout
#define ecn_flags             un.ecn.flags

/* The callback functions registered with the tracebox task */
static scamper_task_funcs_t tracebox_funcs;

/* Address cache used to avoid reallocating the same address multiple times */
extern scamper_addrcache_t *addrcache;

/* Options that tracebox supports */
#define TRACEBOX_OPT_DPORT                 1
//#define TRACEBOX_OPT_DONOTRESOLV           2
#define TRACEBOX_OPT_IPV6                  3
#define TRACEBOX_OPT_UDP                   4
#define TRACEBOX_OPT_MAXHOPS               5
#define TRACEBOX_OPT_PROBE                 6
#define TRACEBOX_OPT_RTT                   7
#define TRACEBOX_OPT_ICMP_QUOTE_TYPE       8
#define TRACEBOX_OPT_PYTHON_BINDINGS       9

#define TRACEBOX_OPT_FRAGS                 10

#define TRACEBOX_OPT_SIMPLIFIED_OUTPUT     12
#define TRACEBOX_OPT_PROXY                 13
#define TRACEBOX_OPT_STATEFULL             14
#define TRACEBOX_OPT_PROXY_SECONDARY_DPORT 15

/* types of tracebox probe packets */
#define TRACEBOX_PROBE_TYPE_TCP 1
#define TRACEBOX_PROBE_TYPE_UDP 2

static const scamper_option_in_t opts[] = {
  {'6', "ipv6", TRACEBOX_OPT_IPV6,              SCAMPER_OPTION_TYPE_NULL},
  {'d', "dport", TRACEBOX_OPT_DPORT,             SCAMPER_OPTION_TYPE_NUM},
  {'p', "probe", TRACEBOX_OPT_PROBE,             SCAMPER_OPTION_TYPE_STR},
  {'u', "udp", TRACEBOX_OPT_UDP,               SCAMPER_OPTION_TYPE_NULL},
  {'r', "rtt", TRACEBOX_OPT_RTT,             SCAMPER_OPTION_TYPE_NULL},
  {'t', "icmp-quote-type", TRACEBOX_OPT_ICMP_QUOTE_TYPE,               SCAMPER_OPTION_TYPE_NULL},
  {'s', "simplified", TRACEBOX_OPT_SIMPLIFIED_OUTPUT,               SCAMPER_OPTION_TYPE_NULL},
  {'\0', "python", TRACEBOX_OPT_PYTHON_BINDINGS,               SCAMPER_OPTION_TYPE_NULL},
  {'\0', "frags", TRACEBOX_OPT_FRAGS,             SCAMPER_OPTION_TYPE_NULL},
  {'\0', "proxy", TRACEBOX_OPT_PROXY,             SCAMPER_OPTION_TYPE_NULL}, 
  {'\0', "proxy-secondary-dport", TRACEBOX_OPT_PROXY_SECONDARY_DPORT,             SCAMPER_OPTION_TYPE_NUM},     
  {'\0', "stateful", TRACEBOX_OPT_STATEFULL,         SCAMPER_OPTION_TYPE_NULL},
};
static const int opts_cnt = SCAMPER_OPTION_COUNT(opts);

static const uint8_t MODE_RTSOCK    =  1; /* waiting for rtsock */
static const uint8_t MODE_DLHDR     =  2; /* waiting for dlhdr to use */
static const uint8_t MODE_PROXY     =  3; 
static const uint8_t MODE_DONE      =  4; /* test finished */
static const uint8_t MODE_SYN       =  5; /* waiting for syn/ack */

const char *scamper_do_tracebox_usage(void)
{
  return "tracebox [-6usrt] [-p probe] [-d dport] [--frags] [--stateful] [--proxy] [--proxy-secondary-dport]";
}

static scamper_tracebox_t *tracebox_getdata(const scamper_task_t *task)
{
  return scamper_task_getdata(task);
}

static tracebox_state_t *tracebox_getstate(const scamper_task_t *task)
{
  return scamper_task_getstate(task);
}

static void tracebox_queue(scamper_task_t *task)
{
  tracebox_state_t *state = tracebox_getstate(task);

  if(slist_count(state->tx) > 0)
    scamper_task_queue_probe(task);
  else if(state->mode == MODE_DONE)
    scamper_task_queue_done(task, 0);
  else
    scamper_task_queue_wait_tv(task, &state->timeout);

  return;
}

/*
 * tracebox_result:
 *
 * record the result, and then begin to gracefully end the connection.
 */
static void tracebox_result(scamper_task_t *task, uint8_t result)
{
  scamper_tracebox_t *tracebox = tracebox_getdata(task);
  tracebox_state_t *state = tracebox_getstate(task);
  char buf[16], addr[64];
  int d = 0;
  switch(result)
    {
    case SCAMPER_TRACEBOX_RESULT_SUCCESS:
    case SCAMPER_TRACEBOX_RESULT_NONE:
    case SCAMPER_TRACEBOX_RESULT_TCP_NOCONN:
    case SCAMPER_TRACEBOX_RESULT_DEST_UNREACHABLE:
    case SCAMPER_TRACEBOX_RESULT_TCP_ERROR:
    case SCAMPER_TRACEBOX_RESULT_TCP_RST:
    case SCAMPER_TRACEBOX_RESULT_TCP_BADOPT:
    case SCAMPER_TRACEBOX_RESULT_TCP_FIN:
    case SCAMPER_TRACEBOX_RESULT_ERROR:
    case SCAMPER_TRACEBOX_RESULT_ABORTED:
    case SCAMPER_TRACEBOX_RESULT_TIMEOUT:
    case SCAMPER_TRACEBOX_RESULT_HALTED:
      d = 1;
      break;
    }

  if(tracebox->result == SCAMPER_TRACEBOX_RESULT_NONE)
    {
      tracebox->result = result;
      scamper_addr_tostr(tracebox->dst, addr, sizeof(addr));
      scamper_debug(__func__, "%s %s", addr,
		    scamper_tracebox_res2str(tracebox, buf, sizeof(buf)));
    }

  if(d == 1)
    {
      state->mode = MODE_DONE;
      scamper_task_queue_done(task, 0);
    }

  return;
}

static void tracebox_handleerror(scamper_task_t *task, int error)
{
  scamper_tracebox_t *tracebox = tracebox_getdata(task);
  tracebox_state_t *state = tracebox_getstate(task);
  tracebox->result = SCAMPER_TRACEBOX_RESULT_ERROR;
  if(state != NULL) state->mode = MODE_DONE;
  scamper_task_queue_done(task, 0);
  return;
}

static void tp_free(tracebox_probe_t *tp)
{ 
  if(tp == NULL)
    return;
  free(tp);
  return;
}

static tracebox_probe_t *tp_alloc(tracebox_state_t *state, uint8_t type)
{ 
  tracebox_probe_t *tp;
  if((tp = malloc_zero(sizeof(tracebox_probe_t))) == NULL)
    {
      printerror(errno, strerror, __func__, "could not malloc tp");
      return NULL;
    }
  if(slist_tail_push(state->tx, tp) == NULL)
    {
      printerror(errno, strerror, __func__, "could not queue tp");
      free(tp);
      return NULL;
    }
  tp->type = type;
  return tp;
}

static tracebox_probe_t *tp_tcp(tracebox_state_t *state, uint16_t len)
{ 
  tracebox_probe_t *tp;

  if((tp = tp_alloc(state, TRACEBOX_PROBE_TYPE_TCP)) == NULL)
    return NULL;

  tp->tp_flags = TH_ACK;
  tp->tp_seq   = state->snd_nxt;
  tp->tp_ack   = state->rcv_nxt;
  tp->tp_len   = len;

  return tp;
}

static void tracebox_segment_free(tracebox_segment_t *seg)
{ 
  if(seg == NULL)
    return;
  if(seg->data != NULL)
    free(seg->data);
  free(seg);
  return;
}

static int tracebox_segment(tracebox_state_t *state, const uint8_t *data, uint16_t len)
{  
  tracebox_segment_t *seg = NULL;

  if((seg = malloc_zero(sizeof(tracebox_segment_t))) == NULL)
    {
      printerror(errno, strerror, __func__, "could not malloc seg");
      goto err;
    }
  if((seg->data = memdup(data, len)) == NULL)
    {
      printerror(errno, strerror, __func__, "could not malloc seg->data");
      goto err;
    }
  seg->len = len;
  if(slist_tail_push(state->segments, seg) == NULL)
    {
      printerror(errno, strerror, __func__, "could not add seg");
      goto err;
    }

  return 0;

 err:
  tracebox_segment_free(seg);
  return -1;
}

/*
 * dl_syn:
 *
 * 
 */
static void dl_syn(scamper_task_t *task, scamper_dl_rec_t *dl)
{
  scamper_tracebox_t *tracebox = tracebox_getdata(task);
  tracebox_state_t *state = tracebox_getstate(task);
  tracebox_probe_t *tp;
  //int rc, wait = TRACEBOX_TIMEOUT_DEFAULT;
   

  if(SCAMPER_DL_IS_ICMP(dl)) {
    if (SCAMPER_DL_IS_ICMP_TTL_EXP(dl)) {
      slist_tail_push(state->tx, tp); 
      //tracebox_queue(task);
      /*if (tracebox->printmode == TRACEBOX_PRINT_MODE_STATEFULL && state->loop == 1 
	  && state->last_ttl == tracebox->srv_ttl - 1)     */
    
        
    } else if (SCAMPER_DL_IS_ICMP_UNREACH(dl))
      scamper_debug(__func__,"ICMP_UNREACH");
    else if (SCAMPER_DL_IS_ICMP_PACKET_TOO_BIG(dl))
      scamper_debug(__func__,"ICMP_PACKET_TOO_BIG") ;
  }

  //measurement loops
  else if (tracebox->printmode == TRACEBOX_PRINT_MODE_PROXY && SCAMPER_DL_IS_TCP_SYNACK(dl) && state->loop == 0) {
    slist_tail_push(state->tx, tp);
    state->loop++;      
  } else if (tracebox->printmode == TRACEBOX_PRINT_MODE_STATEFULL /*|| (dl->dl_tcp_flags & TH_RST) != 0)*/ && state->loop < 5) {
    slist_tail_push(state->tx, tp);
    state->loop++;
  }

/*(tracebox->printmode == TRACEBOX_PRINT_MODE_FRAGS)

  }*/
  tracebox_queue(task);
  return;

 err:
  tracebox_handleerror(task, errno);
  return;
}

static void dl_proxy(scamper_task_t *task, scamper_dl_rec_t *dl)
{
  scamper_tracebox_t *tracebox = tracebox_getdata(task);
  tracebox_state_t *state = tracebox_getstate(task);
  //scamper_tracebox_null_t *null;
  tracebox_probe_t *tp;
  int rc, wait = TRACEBOX_TIMEOUT_DEFAULT;

  if(SCAMPER_DL_IS_ICMP(dl)) {
    if (SCAMPER_DL_IS_ICMP_TTL_EXP(dl)) {
      
      slist_tail_push(state->tx, tp);
      //scamper_debug(__func__,"a %d",slist_count(state->tx));  
      
      //tracebox_queue(task);
      //return;
    } else if (SCAMPER_DL_IS_ICMP_UNREACH(dl))
      scamper_debug(__func__,"b");
    else if (SCAMPER_DL_IS_ICMP_PACKET_TOO_BIG(dl))
      scamper_debug(__func__,"c") ;

  }
  tracebox_queue(task);
  return;

 err:
  tracebox_handleerror(task, errno);
  return;
}

static void reset_timeout_counters(tracebox_state_t *state) {
  state->replaying     = 0;
  state->timeout_count = 0;
  state->attempt       = 0;
}

static void timeout_rt(scamper_task_t *task)
{
  tracebox_result(task, SCAMPER_TRACEBOX_RESULT_ERROR);
  return;
}

static void timeout_dlhdr(scamper_task_t *task)
{
  tracebox_result(task, SCAMPER_TRACEBOX_RESULT_ERROR);
  return;
}

static void timeout_syn(scamper_task_t *task)
{
  scamper_tracebox_t *tracebox = tracebox_getdata(task);
  tracebox_state_t *state = tracebox_getstate(task);
  
  state->timeout_count++;

  if(state->timeout_count >= TRACEBOX_TOTAL_MAX_REPLAYS) {
    tracebox_result(task, SCAMPER_TRACEBOX_RESULT_TIMEOUT);
    return;
  }

  if (state->attempt < TRACEBOX_SINGLE_HOP_MAX_REPLAYS) {
    state->last_ttl--;
    state->replaying = 1;
  } else if (state->attempt == TRACEBOX_SINGLE_HOP_MAX_REPLAYS) {
    if (tracebox->printmode == TRACEBOX_PRINT_MODE_STATEFULL && state->loop == 2) {
      tracebox->seq       += 10;
      state->last_ttl      = 0;
      reset_timeout_counters(state);
      state->loop          = 3;
    }
    state->replaying = 0;
    state->attempt=0;
    scamper_debug(__func__," max replay for single hops: skipping...");
    if (tracebox->printmode == TRACEBOX_PRINT_MODE_FRAGS) state->timeout_count=0;
  }


  return;
}

static void timeout_proxy(scamper_task_t *task)
{
  scamper_tracebox_t *tracebox = tracebox_getdata(task);
  tracebox_state_t *state = tracebox_getstate(task);
  
  state->timeout_count++;

  if(state->timeout_count >= TRACEBOX_TOTAL_MAX_REPLAYS) {
    tracebox_result(task, SCAMPER_TRACEBOX_RESULT_TIMEOUT);
    return;
  }

  if (state->attempt < TRACEBOX_SINGLE_HOP_MAX_REPLAYS) {
    state->last_ttl--;
    state->replaying = 1;
  } else if (state->attempt == TRACEBOX_SINGLE_HOP_MAX_REPLAYS) {
    state->replaying = 0;
    state->attempt=0;
    scamper_debug(__func__,"max replay for single hops: skipping...");
  }


  return;
}

/*
 * do_tracebox_handle_dl
 *
 * for each packet received, check that the addresses and ports make sense,
 * and that the packet is not a reset.
 */
static void do_tracebox_handle_dl(scamper_task_t *task, scamper_dl_rec_t *dl)
{
  
  static void (* const func[])(scamper_task_t *, scamper_dl_rec_t *) =
    {
      NULL,
      NULL,          /* MODE_RTSOCK */
      NULL,          /* MODE_DLHDR */
      dl_proxy,          /* MODE_PROXY */
      NULL,          /* MODE_DONE */
      dl_syn,        /* MODE_SYN */
    };

  scamper_tracebox_t *tracebox = tracebox_getdata(task);
  tracebox_state_t *state = tracebox_getstate(task);
  scamper_tracebox_pkt_t *pkt = NULL;
  scamper_dl_rec_t *newp = NULL;
  int more = 0;
  char addr[64];
  //FreeBSD correction for double register packets
  if (!scamper_addr_raw_cmp(tracebox->src, dl->dl_ip_src) && !SCAMPER_DL_IS_ICMP(dl)) return;
  /* reset timeout and replay watchers */
  reset_timeout_counters(state);

  if(SCAMPER_DL_IS_ICMP(dl)) {
    scamper_debug(__func__,"received ICMP");
    if (SCAMPER_DL_IS_ICMP_TTL_EXP(dl)) {

      if (SCAMPER_DL_IS_IPV4(dl)) {
        scamper_addr_t *a=scamper_addr_alloc(SCAMPER_ADDR_TYPE_IPV4,dl->dl_ip_src);
        scamper_addr_tostr(a,addr,sizeof(addr));
        scamper_addr_free(a);
      } else if (SCAMPER_DL_IS_IPV6(dl)) {
         scamper_addr_t *a=scamper_addr_alloc(SCAMPER_ADDR_TYPE_IPV6,dl->dl_ip_src);
         scamper_addr_tostr(a,addr,sizeof(addr));
         scamper_addr_free(a);
      } else strcpy(addr,"unkown transport");

      scamper_debug(__func__,"TTL exp from %s",addr);

      if (tracebox->printmode == TRACEBOX_PRINT_MODE_STATEFULL && state->loop == 1 
	  &&  state->last_ttl == tracebox->srv_ttl - 1) {
        tracebox->seq       -= 10;
        state->last_ttl      = 0;
        reset_timeout_counters(state);
        state->loop++;  
      }
      more = 1;
    } else if (SCAMPER_DL_IS_ICMP_UNREACH(dl)) {
      scamper_debug(__func__,"Destination unreachable");
      tracebox_result(task, SCAMPER_TRACEBOX_RESULT_DEST_UNREACHABLE);
    } else if (SCAMPER_DL_IS_ICMP_PACKET_TOO_BIG(dl)) {
      scamper_debug(__func__,"Pkt too big");
      tracebox_result(task, SCAMPER_TRACEBOX_RESULT_DEST_UNREACHABLE);
      
   }
  } else if (SCAMPER_DL_IS_TCP(dl)) {
    scamper_debug(__func__,"received TCP");
    if (SCAMPER_DL_IS_TCP_SYNACK(dl)) {
      scamper_debug(__func__,"SYNACK");
    } else if ((dl->dl_tcp_flags & TH_RST) != 0)
      scamper_debug(__func__,"RST");


  } else if (SCAMPER_DL_IS_UDP(dl)) {
    scamper_debug(__func__,"received UDP");
  }

  //save packet
  pkt = scamper_tracebox_pkt_alloc(SCAMPER_TRACEBOX_PKT_DIR_RX, dl->dl_net_raw,
			       dl->dl_ip_size, &dl->dl_tv);
  if(pkt == NULL || scamper_tracebox_record_pkt(tracebox, pkt) != 0) {
    if(pkt != NULL) scamper_tracebox_pkt_free(pkt);
        goto err;
  }
  
    /* test if reached the server */
  if (!scamper_addr_raw_cmp(tracebox->dst, dl->dl_ip_src)) {

    if (tracebox->printmode == TRACEBOX_PRINT_MODE_PROXY && state->loop == 0) {
      tracebox->udp        = 1;
      state->last_ttl      = 0;
      reset_timeout_counters(state);
      if (tracebox->secondary_dport != 0)
        tracebox->dport    = tracebox->secondary_dport;
      more = 1;
    } else if (tracebox->printmode == TRACEBOX_PRINT_MODE_STATEFULL 
               && state->loop < 4 && state->loop != 2) {
        tracebox->seq       -= 10;
        tracebox->srv_ttl    = state->last_ttl;
        state->last_ttl      = 0;
        reset_timeout_counters(state);
        more = 1;
    } else /*if (tracebox->printmode == TRACEBOX_PRINT_MODE_FRAGS 
               && state->loop ==0) {

    } else*/  {
      tracebox_result(task, SCAMPER_TRACEBOX_RESULT_SUCCESS);
      goto done;
    }
  }
  // prevent looping
  if (state->last_ttl >= TRACEBOX_MAX_HOPS) {
    
    tracebox_result(task, SCAMPER_TRACEBOX_RESULT_ABORTED);
    goto done;
  }

  if(func[state->mode] == NULL)
    goto done;
  if (more) func[state->mode](task, dl);

 done:
  return;

 err:
  tracebox_handleerror(task, errno);
  return;
}

static void do_tracebox_handle_timeout(scamper_task_t *task)
{ 
  /* Array of timeout functions */
  static void (* const func[])(scamper_task_t *) =
    {
      NULL,
      timeout_rt,         /* MODE_RTSOCK */
      timeout_dlhdr,      /* MODE_DLHDR */
      timeout_proxy,               /* MODE_PROXY */
      NULL,               /* MODE_DONE */
      timeout_syn,        /* MODE_SYN */

    };
  tracebox_state_t *state = tracebox_getstate(task);

  /* Call the appropriate timeout function */
  if(func[state->mode] != NULL)
    func[state->mode](task);

  return;
}

static void tracebox_handle_dlhdr(scamper_dlhdr_t *dlhdr)
{  
  scamper_task_t *task = dlhdr->param;
  tracebox_state_t *state = tracebox_getstate(task);

  if(dlhdr->error != 0)
    {
      scamper_task_queue_done(task, 0);
      return;
    }

  state->mode = MODE_SYN;
  scamper_task_queue_probe(task);
  return;
}

static void tracebox_handle_rt(scamper_route_t *rt)
{
  scamper_task_t *task = rt->param;
  scamper_tracebox_t *tracebox = tracebox_getdata(task);
  tracebox_state_t *state = tracebox_getstate(task);
  scamper_dl_t *dl;
  uint16_t mtu;
  
  if(state->mode != MODE_RTSOCK || state->route != rt)
    goto done;

#ifndef _WIN32
  if(state->rtsock != NULL)
    {
      scamper_fd_free(state->rtsock);
      state->rtsock = NULL;
    }
#endif

  if(rt->error != 0 || rt->ifindex < 0)
    {
      printerror(errno, strerror, __func__, "could not get ifindex");
      tracebox_handleerror(task, errno);
      goto done;
    }

  /*
   * scamper needs the datalink to transmit packets; try and get a
   * datalink on the ifindex specified.
   */
  if((state->dl = scamper_fd_dl(rt->ifindex)) == NULL)
    {
      scamper_debug(__func__, "could not get dl for %d", rt->ifindex);
      tracebox_handleerror(task, errno);
      goto done;
    }

  /*
   * determine the underlying framing to use with each probe packet that will
   * be sent on the datalink.
   */
  state->mode = MODE_DLHDR;
  if((state->dlhdr = scamper_dlhdr_alloc()) == NULL)
    {
      tracebox_handleerror(task, errno);
      goto done;
    }
  dl = scamper_fd_dl_get(state->dl);
  state->dlhdr->dst = scamper_addr_use(tracebox->dst);
  state->dlhdr->gw = rt->gw != NULL ? scamper_addr_use(rt->gw) : NULL;
  state->dlhdr->ifindex = rt->ifindex;
  state->dlhdr->txtype = scamper_dl_tx_type(dl);
  state->dlhdr->param = task;
  state->dlhdr->cb = tracebox_handle_dlhdr;
  if(scamper_dlhdr_get(state->dlhdr) != 0)
    {
      tracebox_handleerror(task, errno);
      goto done;
    }

  if(scamper_task_queue_isdone(task) == 0)
    
 done:
  scamper_route_free(rt);
  if(state->route == rt)
    state->route = NULL;
  return;
}

static void do_tracebox_write(scamper_file_t *sf, scamper_task_t *task)
{
  scamper_file_write_tracebox(sf, tracebox_getdata(task));
  return;
}

static void tracebox_state_free(scamper_task_t *task)
{  
  scamper_tracebox_t *tracebox = tracebox_getdata(task);
  tracebox_state_t *state = tracebox_getstate(task);
  tracebox_segment_t *seg;
  tracebox_probe_t *tp;
  int i;

  if(state == NULL)
    return;
  assert(tracebox != NULL);
  
#ifndef _WIN32
  if(state->rtsock != NULL)
    scamper_fd_free(state->rtsock);
#endif

  if(state->dl != NULL)
    scamper_fd_free(state->dl);

  if(state->dlhdr != NULL)
    scamper_dlhdr_free(state->dlhdr);

  if(state->route != NULL)
    scamper_route_free(state->route);

  if(state->segments != NULL)
    {
      while((seg = slist_head_pop(state->segments)) != NULL)
	tracebox_segment_free(seg);
      slist_free(state->segments);
    }

  if(state->tx != NULL)
    {
      while((tp = slist_head_pop(state->tx)) != NULL)
	tp_free(tp);
      slist_free(state->tx);
    }

  free(state);
  return;
}

static int tracebox_state_alloc(scamper_task_t *task)
{ 
  scamper_tracebox_t *tracebox = tracebox_getdata(task);
  tracebox_state_t *state;
  uint16_t seq;

  if((state = malloc_zero(sizeof(tracebox_state_t))) == NULL)
    {
      printerror(errno, strerror, __func__, "could not malloc state");
      goto err;
    }

  scamper_task_setstate(task, state);


  if((state->segments = slist_alloc()) == NULL)
    {
      printerror(errno, strerror, __func__, "could not create segments list");
      goto err;
    }
  if((state->tx = slist_alloc()) == NULL)
    {
      printerror(errno, strerror, __func__, "could not create tx list");
      goto err;
    }

  /*
   * generate a random 16 bit sequence number so we don't have to deal
   * with sequence number wrapping for now.
   */
  if(random_u16(&seq) != 0)
    {
      printerror(errno, strerror, __func__, "could not get random isn");
      goto err;
    }
  state->snd_nxt = seq;

#ifndef _WIN32
  if((state->rtsock = scamper_fd_rtsock()) == NULL)
    {
      printerror(errno, strerror, __func__, "could not get rtsock");
      goto err;
    }
#endif
  state->mode = MODE_RTSOCK;
  state->last_ttl=0;
  reset_timeout_counters(state);

  return 0;

err:
  return -1;
}

static void do_tracebox_halt(scamper_task_t *task)
{
  tracebox_result(task, SCAMPER_TRACEBOX_RESULT_HALTED);
  return;
}

static void do_tracebox_free(scamper_task_t *task)
{  
  scamper_tracebox_t *tracebox = tracebox_getdata(task);
  if(tracebox == NULL)
    return;
  tracebox_state_free(task);
  scamper_tracebox_free(tracebox);
  return;
}

static scamper_probe_t build_probe(scamper_task_t *task, scamper_probe_t probe, uint8_t update_ttl) {

  scamper_tracebox_t     *tracebox = tracebox_getdata(task);
  tracebox_state_t       *state = tracebox_getstate(task);

 /* Common to all probes */
  probe.pr_dl     = scamper_fd_dl_get(state->dl);
  probe.pr_dl_buf = state->dlhdr->buf;
  probe.pr_dl_len = state->dlhdr->len;
  probe.pr_ip_src = tracebox->src;
  probe.pr_ip_dst = tracebox->dst;

  if (update_ttl) state->last_ttl++;
  probe.pr_ip_ttl = state->last_ttl;
  

  if (tracebox->ect) 
    probe.pr_ip_tos |= 0x02; // ECN Capable Transport ECT(0)
  if (tracebox->ce) 
    probe.pr_ip_tos |= 0x03; // Congestion Encountered — CE
 
  if (tracebox->dscp)
    probe.pr_ip_tos |= 0x80;

 /* IP Version dependent options */
  if(tracebox->dst->type == SCAMPER_ADDR_TYPE_IPV4) {
      if (tracebox->ipid) 
        probe.pr_ip_id = tracebox->ipid_value;
      
      if (tracebox->printmode == TRACEBOX_PRINT_MODE_FRAGS) {

          probe.pr_ip_proto = IPPROTO_TCP;
          scamper_probe_t full_probe;
          memset(&full_probe, 0, sizeof(full_probe));
          tracebox->printmode = TRACEBOX_PRINT_MODE_STANDARD;
          full_probe = build_probe(task, full_probe, 0);
          tracebox->printmode = TRACEBOX_PRINT_MODE_FRAGS;
      
          uint8_t *test = malloc(40);
          size_t test_len = 40;
          scamper_tcp4_build(&full_probe, test, &test_len);

          if (!state->loop) {
            probe.pr_no_trans=1;
            probe.pr_ip_off = IP_MF;
            probe.pr_len = 8;
            probe.pr_data = malloc(8);
            int i;
            for (i=0;i<probe.pr_len;i++)
              probe.pr_data[i]=test[20+i];
          } else {
      
            probe.pr_ip_off = 0x0001;
            probe.pr_len = 12;
            probe.pr_data = malloc(12);
            int i;
            for (i=0;i<probe.pr_len;i++)
              probe.pr_data[i]=test[28+i];
            tracebox->ipid_value++;
          }
          free(test);
           return probe;
      }

      //probe.pr_ip_off = IP_DF;//donot fragment flag
   } else if (tracebox->dst->type == SCAMPER_ADDR_TYPE_IPV6) {
     if (tracebox->ipid && tracebox->printmode != TRACEBOX_PRINT_MODE_FRAGS) 
       probe.pr_ip_flow = tracebox->ipid_value;
      
      if (tracebox->printmode == TRACEBOX_PRINT_MODE_FRAGS) {

          probe.pr_ip_proto = IPPROTO_FRAGMENT;
          scamper_probe_t full_probe;
          memset(&full_probe, 0, sizeof(full_probe));
          tracebox->printmode = TRACEBOX_PRINT_MODE_STANDARD;
          full_probe = build_probe(task, full_probe, 0);
          tracebox->printmode = TRACEBOX_PRINT_MODE_FRAGS;
      
          uint8_t *test = malloc(60);
          size_t test_len = 60;
          scamper_tcp6_build(&full_probe, test, &test_len);
          int i;
          for (i=0;i<60;i+=4)
            scamper_debug(__func__,"%x %x %x %x",test[i],test[i+1],test[i+2],test[i+3]);   

          if (!state->loop) {
            probe.pr_no_trans=1;
            probe.pr_len = 16;
            probe.pr_data = malloc(16);
            probe.pr_data[0] = 0x06; // tcp
            probe.pr_data[1] = 0x00;
            probe.pr_data[2] = 0x00;
            probe.pr_data[3] = 0x01;
            bytes_htonl(probe.pr_data+4, tracebox->ipid_value);
            for (i=8;i<probe.pr_len;i++)
              probe.pr_data[i]=test[32+i];
          } else {
            probe.pr_no_trans=1;     
            probe.pr_len = 20;
            probe.pr_data = malloc(20);
            probe.pr_data[0] = 0x06;
            probe.pr_data[1] = 0x00;
            probe.pr_data[2] = 0x00;
            probe.pr_data[3] = 0x08;
            bytes_htonl(probe.pr_data+4, tracebox->ipid_value++);
            for (i=8;i<probe.pr_len;i++)
              probe.pr_data[i]=test[40+i];
            for (i=0;i<20;i+=4)
              scamper_debug(__func__,"%x %x %x %x",probe.pr_data[i],probe.pr_data[i+1],probe.pr_data[i+2],probe.pr_data[i+3]);  
          }

          free(test);
          return probe;
      }
   }


  /* Transport type dependent options */
  if (tracebox->udp) {
    probe.pr_ip_proto = IPPROTO_UDP;  
    probe.pr_udp_sport = tracebox->sport;
    probe.pr_udp_dport = tracebox->dport;

  } else { //tcp
    probe.pr_ip_proto = IPPROTO_TCP;
    probe.pr_tcp_sport = tracebox->sport;
    probe.pr_tcp_dport = tracebox->dport;
    probe.pr_tcp_flags |= TH_SYN;
    probe.pr_tcp_seq   =  tracebox->seq;
    probe.pr_tcp_win   = 65535;	
   
    if (tracebox->mss)
      probe.pr_tcp_mss   = tracebox->mss;
    if (tracebox->wscale)
      probe.pr_tcp_wscale = tracebox->wscale;

    if (tracebox->mpcapable) {
      probe.pr_tcp_mpcapable  = tracebox->h_skey; 
      probe.pr_tcp_mpcapable2 = tracebox->l_skey;
    }
    if (tracebox->mpjoin) {
      probe.pr_tcp_mpjoin  = tracebox->rec_token; 
      probe.pr_tcp_mpjoin2 = tracebox->send_rnum;
    }
    if (tracebox->sack) {
      probe.pr_tcp_sackb = 1;
      probe.pr_tcp_sack[0] = tracebox->sack_sle;
      probe.pr_tcp_sack[1] = tracebox->sack_sre;
    }
    if (tracebox->sackp)
      probe.pr_tcp_opts |= SCAMPER_PROBE_TCPOPT_SACK;
    if (tracebox->ts) {
	probe.pr_tcp_opts |= SCAMPER_PROBE_TCPOPT_TS;
        probe.pr_tcp_tsval = tracebox->tsval;
        probe.pr_tcp_tsecr = tracebox->tsecr;
    }
    if (tracebox->ece) probe.pr_tcp_flags |= (TH_ECE|TH_CWR);
    if (tracebox->md5) {
      probe.pr_tcp_md5=1;
      int i;
      for (i=0;i<4;i++)
        probe.pr_tcp_md5digest[i]=tracebox->md5digest[i];
    }
    if (tracebox->ao) {
      probe.pr_tcp_auth=1;
      probe.pr_tcp_authkeyid=tracebox->aokeyid;
      probe.pr_tcp_authrnextkeyid=tracebox->aornextkeyid;
      int i;
      for (i=0;i<4;i++)
        probe.pr_tcp_authmac[i]=tracebox->aomac[i];
    }
  }
  
   return probe;
}

static void do_tracebox_probe(scamper_task_t *task)
{
  scamper_tracebox_t     *tracebox = tracebox_getdata(task);
  tracebox_state_t       *state = tracebox_getstate(task);
  scamper_tracebox_pkt_t *pkt;
  scamper_probe_t     probe;
  tracebox_probe_t       *tp = NULL;
  int                 wait, rc;

  if(state == NULL)
    {
      /* Fill in the test start time */
      gettimeofday_wrap(&tracebox->start);

      /* Allocate space to store task state */
      if(tracebox_state_alloc(task) != 0)
	goto err;

      state = tracebox_getstate(task);
    }

  if(state->mode == MODE_RTSOCK)
    {
      state->route = scamper_route_alloc(tracebox->dst, task, tracebox_handle_rt);
      if(state->route == NULL)
	goto err;

#ifndef _WIN32
      if(scamper_rtsock_getroute(state->rtsock, state->route) != 0)
	goto err;
#else
      if(scamper_rtsock_getroute(state->route) != 0)
	goto err;
#endif

      if(scamper_task_queue_isdone(task))
	return;

	  scamper_task_queue_wait(task, 1000);
	  return;

    }

  if (tracebox->dst->type == SCAMPER_ADDR_TYPE_IPV4) 
    scamper_debug(__func__,"IPV4 addr");
  else if (tracebox->dst->type == SCAMPER_ADDR_TYPE_IPV6)
    scamper_debug(__func__,"IPV6 addr");
  else scamper_debug(__func__,"Unknown addr type");

  memset(&probe, 0, sizeof(probe));

  probe = build_probe(task, probe, 1);
  wait = TRACEBOX_TIMEOUT_DEFAULT;
  tp = slist_head_pop(state->tx);
   
  /* Send the probe */
  if(scamper_probe(&probe) != 0)
    {
      errno = probe.pr_errno;
      printerror(errno, strerror, __func__, "could not send probe");
      goto err;
    }


  if((pkt = scamper_tracebox_pkt_alloc(SCAMPER_TRACEBOX_PKT_DIR_TX, probe.pr_tx_raw,
				   probe.pr_tx_rawlen, &probe.pr_tx))==NULL ||
     scamper_tracebox_record_pkt(tracebox, pkt) != 0)
  {
      printerror(errno, strerror, __func__, "could not record packet");
      goto err;
  }
  
  if (tracebox->printmode == TRACEBOX_PRINT_MODE_FRAGS && !state->loop) {
    state->loop=1;

    memset(&probe, 0, sizeof(probe));
    probe = build_probe(task, probe, 0);
    tp = slist_head_pop(state->tx);
   
    /* Send the probe */
    if(scamper_probe(&probe) != 0)
    {
      errno = probe.pr_errno;
      printerror(errno, strerror, __func__, "could not send probe");
      goto err;
    }


    if((pkt = scamper_tracebox_pkt_alloc(SCAMPER_TRACEBOX_PKT_DIR_TX, probe.pr_tx_raw,
				   probe.pr_tx_rawlen, &probe.pr_tx))==NULL ||
     scamper_tracebox_record_pkt(tracebox, pkt) != 0)
    {
        printerror(errno, strerror, __func__, "could not record packet");
        goto err;
    }
    state->loop=0;
  }


  state->attempt++;
  if(wait > 0)
    timeval_add_ms(&state->timeout, &probe.pr_tx, wait);

  tracebox_queue(task);
  return;

err:
  tracebox_handleerror(task, errno);
  return;
done:
  return;
}

static int tracebox_param_probe_validate(char* probe) {


  return 1;
}

static int tracebox_arg_param_validate(int optid, char *param, long *out)
{
  long tmp;
  switch(optid)
    {

    case TRACEBOX_OPT_PROXY_SECONDARY_DPORT:
    case TRACEBOX_OPT_DPORT:
        if(string_tolong(param, &tmp) != 0 || tmp < 0 || tmp > 65535)
            goto err;
        break;

    case TRACEBOX_OPT_PROXY:
    case TRACEBOX_OPT_IPV6:        
    case TRACEBOX_OPT_UDP: 
    case TRACEBOX_OPT_FRAGS:                               
    case TRACEBOX_OPT_STATEFULL:                  
    case TRACEBOX_OPT_SIMPLIFIED_OUTPUT:
    case TRACEBOX_OPT_ICMP_QUOTE_TYPE:
    case TRACEBOX_OPT_RTT:     
    case TRACEBOX_OPT_PYTHON_BINDINGS:        
        tmp=0;
        break; 
    case TRACEBOX_OPT_PROBE: 
        if (!tracebox_param_probe_validate(param))
          goto err;         
        break;

    default:
      return -1;
    }

  /* valid parameter */
  if(out != NULL)
    *out = tmp;
  return 0;

 err:
  return -1;
}

int scamper_do_tracebox_arg_validate(int argc, char *argv[], int *stop)
{

 return scamper_options_validate(opts, opts_cnt, argc, argv, stop,
				  tracebox_arg_param_validate);
}

static int tracebox_app_default(scamper_tracebox_t *tracebox, tracebox_options_t *o)
{

  //dport
  if(tracebox->dport == 0) tracebox->dport = 80;  
  
  tracebox->syn_retx = TRACEBOX_SINGLE_HOP_MAX_REPLAYS;
   
  //random seq number common to all probe
  if (!tracebox->udp) random_u32(&tracebox->seq);

  if (tracebox->ipid) random_u32(&tracebox->ipid_value);

  if (tracebox->ts) {
    struct timeval tv;	      
    gettimeofday_wrap(&tv);
    tracebox->tsval = (tv.tv_sec) * 1000 + tv.tv_usec/1000.0;
    tracebox->tsecr = (tv.tv_sec) * 1000 + tv.tv_usec/1000.0;
  }

  if (tracebox->sack) {
   random_u32(&tracebox->sack_sle);
   random_u32(&tracebox->sack_sre);
  }

  if (tracebox->mpjoin) {
   random_u32(&tracebox->rec_token);
   random_u32(&tracebox->send_rnum);
  }

  if (tracebox->mpcapable) {
   random_u32(&tracebox->h_skey);
   random_u32(&tracebox->l_skey);
  }

  if (tracebox->md5) {
    int i;
    for (i=0;i<4;i++)
      random_u32(&(tracebox->md5digest[i]));
  }

  if (tracebox->ao) {
    random_u8(&tracebox->aokeyid);
    random_u8(&tracebox->aornextkeyid);
    int i;
    for (i=0;i<4;i++)
      random_u32(&(tracebox->aomac[i]));
  }


  /* check for mode inconsistensies */

  if (tracebox->printmode == TRACEBOX_PRINT_MODE_PROXY) {
    tracebox->udp=0;
  }

  if (tracebox->printmode == TRACEBOX_PRINT_MODE_STATEFULL) {
    tracebox->udp=0;
    tracebox->seq+=20;
  }

  if (tracebox->printmode == TRACEBOX_PRINT_MODE_FRAGS) {
    tracebox->udp=0;
    tracebox->ipid=1;
    random_u32(&tracebox->ipid_value); //to id fragments
   }

  return 0;
}

static void parse_probe(scamper_tracebox_t *tracebox) {

  char *token, *subtoken;
  const char * delimiter = "/";

  token = strtok(tracebox->probe, delimiter); 
  
  while(token) {
    if (!strcasecmp(token,"IP"))        tracebox->ipv6 = 0;
    else if (!strcasecmp(token,"IPV6")) tracebox->ipv6 = 1;
    else if (!strcasecmp(token,"TCP"))  tracebox->udp  = 0;
    else if (!strcasecmp(token,"UDP"))  tracebox->udp  = 1;
    //IP options

    else if (!strcasecmp(token,"ipid")) tracebox->ipid = 1;
    else if (!strcasecmp(token,"ect"))  tracebox->ect  = 1;
    else if (!strcasecmp(token,"ece"))  tracebox->ece  = 1;
    else if (!strcasecmp(token,"ce"))   tracebox->ce   = 1;
    else if (!strcasecmp(token,"dscp")) tracebox->dscp = 1;
    
    //tcp options
    else if (!strcasecmp(token,"mss")) tracebox->mss = TRACEBOX_DEFAULT_MSS;
    else if (!strcasecmp(token,"wscale") || !strcasecmp(token,"windowscale")) 
       tracebox->wscale = TRACEBOX_DEFAULT_WSCALE;
    else if (!strcasecmp(token,"mpcapable")) tracebox->mpcapable = 1;
    else if (!strcasecmp(token,"mpjoin"))    tracebox->mpjoin    = 1;
    else if (!strcasecmp(token,"sack"))      tracebox->sack      = 1;
    else if (!strcasecmp(token,"sackp"))     tracebox->sackp     = 1;
    else if (!strcasecmp(token,"ts") || !strcasecmp(token,"timestamp")
               ||!strcasecmp(token,"tstamp")) 
       tracebox->ts = 1;
    else if (!strcasecmp(token,"md5")) 
       tracebox->md5 = 1;
    else if (!strcasecmp(token,"ao") || !strcasecmp(token,"auth")
               ||!strcasecmp(token,"tcpao"))
       tracebox->ao = 1;

    token = strtok(NULL, delimiter); 
  }

  return;
}

/*
 * scamper_do_tracebox_alloc
 *
 * Given a string representing a tracebox task, parse the parameters and assemble
 * a tracebox. Return the tracebox structure so that it is all ready to go.
 */
void *scamper_do_tracebox_alloc(char *str)
{

  static int (* const app_func[])(scamper_tracebox_t *, tracebox_options_t *) = {
    NULL,
    tracebox_app_default,
  };
  scamper_option_out_t *opts_out = NULL, *opt;
  scamper_tracebox_t *tracebox = NULL;
  tracebox_options_t o;
  uint16_t sport  = scamper_sport_default();
  uint32_t userid = 0;
  char *addr;
  long tmp = 0;
  int af;

  memset(&o, 0, sizeof(o));
  /* Parse the options */
  if(scamper_options_parse(str, opts, opts_cnt, &opts_out, &addr) != 0)
    {
      scamper_debug(__func__, "could not parse options");
      goto err;
    }

  /* If there is no IP address after the options string, then stop now */
  if(addr == NULL)
    {
      scamper_debug(__func__, "no address parameter");
      goto err;
    }

  /* Parse the options, do preliminary sanity checks */
  for(opt = opts_out; opt != NULL; opt = opt->next)
    {
      if(opt->type != SCAMPER_OPTION_TYPE_NULL &&
	 tracebox_arg_param_validate(opt->id, opt->str, &tmp) != 0)
	{
	  scamper_debug(__func__, "validation of optid %d failed", opt->id);
	  goto err;
	}

      switch(opt->id)
        {
    case TRACEBOX_OPT_DPORT:
        o.dport = (uint16_t)tmp;
        break;

    case TRACEBOX_OPT_IPV6: 
        o.ipv6 = (uint8_t)1;
        break;       

    case TRACEBOX_OPT_UDP:         
        o.udp = (uint8_t)1;
        break;     
    case TRACEBOX_OPT_RTT:         
        o.rtt = (uint8_t)1;
        break; 
    case TRACEBOX_OPT_ICMP_QUOTE_TYPE:         
        o.icmp_quote_type = (uint8_t)1;
        break; 
    case TRACEBOX_OPT_PYTHON_BINDINGS:
        o.python_bindings = (uint8_t)1;
        break;
    case TRACEBOX_OPT_PROXY_SECONDARY_DPORT:
        o.secondary_dport=(uint16_t)tmp;
        break;      
    case TRACEBOX_OPT_PROBE:  
        o.probe = opt->str;
        break;
    case TRACEBOX_OPT_FRAGS:
        o.printmode = TRACEBOX_PRINT_MODE_FRAGS;
        break;                   
    case TRACEBOX_OPT_PROXY:  
        o.printmode = TRACEBOX_PRINT_MODE_PROXY;
        break;
    case TRACEBOX_OPT_STATEFULL:
        o.printmode = TRACEBOX_PRINT_MODE_STATEFULL;
        break;              
    case TRACEBOX_OPT_SIMPLIFIED_OUTPUT:       
        o.printmode = TRACEBOX_PRINT_MODE_SIMPLIFIED_OUTPUT;
        break;        
    }
    }

  scamper_options_free(opts_out); opts_out = NULL;

  /* sanity check that we don't begin beyond our probe hoplimit */
  /*
  if(firsthop > hoplimit && o.maxhops != 0)
    {
      goto err;
    }
    */

  if((tracebox = scamper_tracebox_alloc()) == NULL)
    {
      printerror(errno, strerror, __func__, "could not alloc tracebox");
      goto err;
    }
  if((tracebox->dst = scamper_addrcache_resolve(addrcache,AF_UNSPEC,addr)) == NULL)
    {
      printerror(EFAULT, strerror, __func__, "could not resolve %s", addr);
      goto err;
    }

    tracebox->sport           = sport;
    tracebox->dport           = o.dport;
    tracebox->udp             = o.udp;
    tracebox->ipv6            = o.ipv6;
    tracebox->probe           = o.probe;
    tracebox->rtt             = o.rtt;
    tracebox->icmp_quote_type = o.icmp_quote_type;
    tracebox->python_bindings = o.python_bindings;
    tracebox->printmode       = o.printmode;
    tracebox->secondary_dport = o.secondary_dport;
    //TODO: parse probe and set params to tracebox-> vars, tout chiffre ou MAX
    if(o.app == 0) o.app = SCAMPER_TRACEBOX_APP_DEFAULT;

    if (tracebox->probe != NULL) parse_probe(tracebox);

    //mode safety
    /*
  tracebox->app_proto = o.app;
  
    if(app_func[o.app] != NULL && app_func[o.app](tracebox, &o) != 0)
    goto err;
    */
  if(app_func[SCAMPER_TRACEBOX_APP_DEFAULT] != NULL && app_func[SCAMPER_TRACEBOX_APP_DEFAULT](tracebox, &o) != 0)
    goto err;

    return tracebox;

err:
  if(tracebox != NULL) scamper_tracebox_free(tracebox);
  if(opts_out != NULL) scamper_options_free(opts_out);
  return NULL;
}



void scamper_do_tracebox_free(void *data)
{ 
  scamper_tracebox_t *tracebox = (scamper_tracebox_t *)data;
  scamper_tracebox_free(tracebox);
  return;
}

scamper_task_t *scamper_do_tracebox_alloctask(void *data, scamper_list_t *list,
					  scamper_cycle_t *cycle)
{  
  scamper_tracebox_t *tracebox = (scamper_tracebox_t *)data;
  scamper_task_sig_t *sig = NULL;
  scamper_task_t *task = NULL;

  /* allocate a task structure and store the tracebox with it */
  if((task = scamper_task_alloc(data, &tracebox_funcs)) == NULL)
    goto err;

  /* declare the signature of the tracebox task */
  if((sig = scamper_task_sig_alloc(SCAMPER_TASK_SIG_TYPE_TX_IP)) == NULL)
    goto err;
  sig->sig_tx_ip_dst = scamper_addr_use(tracebox->dst);
  if(tracebox->src == NULL && (tracebox->src = scamper_getsrc(tracebox->dst,0)) == NULL)
    goto err;
  sig->sig_tx_ip_src = scamper_addr_use(tracebox->src);
  if(scamper_task_sig_add(task, sig) != 0)
    goto err;
  sig = NULL;

  /* associate the list and cycle with the tracebox */
  tracebox->list  = scamper_list_use(list);
  tracebox->cycle = scamper_cycle_use(cycle);

  return task;

 err:
  if(sig != NULL) scamper_task_sig_free(sig);
  if(task != NULL)
    {
      scamper_task_setdatanull(task);
      scamper_task_free(task);
    }
  return NULL;
}

void scamper_do_tracebox_cleanup(void)
{
  return;
}

int scamper_do_tracebox_init(void)
{
  tracebox_funcs.probe          = do_tracebox_probe;
  tracebox_funcs.handle_icmp    = NULL;
  tracebox_funcs.handle_dl      = do_tracebox_handle_dl;
  tracebox_funcs.handle_timeout = do_tracebox_handle_timeout;
  tracebox_funcs.write          = do_tracebox_write;
  tracebox_funcs.task_free      = do_tracebox_free;
  tracebox_funcs.halt           = do_tracebox_halt;

  return 0;
}

