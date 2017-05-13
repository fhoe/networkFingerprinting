/*
 * scamper_tracebox.h
 *
 *
 *
 * @author: K.Edeline
 */

#ifndef __SCAMPER_TRACEBOX_H
#define __SCAMPER_TRACEBOX_H

#define SCAMPER_TRACEBOX_APP_DEFAULT             1

/* generic tracebox results */
#define SCAMPER_TRACEBOX_RESULT_NONE             0 /* no result */
#define SCAMPER_TRACEBOX_RESULT_TCP_NOCONN       1 /* no connection */
#define SCAMPER_TRACEBOX_RESULT_TCP_RST          2 /* Early reset */
#define SCAMPER_TRACEBOX_RESULT_TCP_ERROR        3 /* TCP Error */
#define SCAMPER_TRACEBOX_RESULT_ERROR            4 /* System error */
#define SCAMPER_TRACEBOX_RESULT_ABORTED          5 /* Test aborted */
#define SCAMPER_TRACEBOX_RESULT_DEST_UNREACHABLE 6 /* no connection: rst rx */
#define SCAMPER_TRACEBOX_RESULT_HALTED           7 /* halted */
#define SCAMPER_TRACEBOX_RESULT_TCP_BADOPT       8 /* bad TCP option */
#define SCAMPER_TRACEBOX_RESULT_TCP_FIN          9 /* early fin */
#define SCAMPER_TRACEBOX_RESULT_ICMP_TTL_EXP     11
#define SCAMPER_TRACEBOX_RESULT_SUCCESS          12
#define SCAMPER_TRACEBOX_RESULT_TIMEOUT          13

/* direction of recorded packet */
#define SCAMPER_TRACEBOX_PKT_DIR_TX              1
#define SCAMPER_TRACEBOX_PKT_DIR_RX              2

/* router answer */
#define SCAMPER_TRACEBOX_ANSWER_EMPTY		1
#define SCAMPER_TRACEBOX_ANSWER_ONLY_L3		2
#define SCAMPER_TRACEBOX_ANSWER_8B		    3
#define SCAMPER_TRACEBOX_ANSWER_FULL		4
#define SCAMPER_TRACEBOX_ANSWER_SYNACK      5 


typedef struct scamper_tracebox_pkt
{
  struct timeval       tv;
  uint8_t              dir;
  uint16_t             len;
  uint8_t             *data;
} scamper_tracebox_pkt_t;


/*
 * scamper_tracebox
 *
 * parameters and results of a measurement conducted with tracebox.
 */
typedef struct scamper_tracebox
{
  scamper_list_t      *list;
  scamper_cycle_t     *cycle;
  uint32_t             userid;

  scamper_addr_t      *src;
  scamper_addr_t      *dst;
  uint16_t             sport;
  uint16_t             dport;
  uint16_t             secondary_dport; 

  uint32_t		seq;
  
  uint8_t   python_bindings;
  uint8_t   donotresolv;
  uint8_t   udp;
  uint8_t   ipv6;
  uint16_t  maxhops;
  char     *probe;
  uint8_t   printmode;
  uint8_t   rtt;
  uint8_t   icmp_quote_type;
  //options
  uint8_t ect, ece, ce, dscp, mpcapable, mpjoin, sackp, ts, ipid,  sack, ao, md5,aokeyid,aornextkeyid, srv_ttl;

  
  uint32_t ipid_value, mss,wscale,sack_sle,sack_sre,tsval,tsecr, rec_token, send_rnum, h_skey, l_skey;
  uint32_t md5digest[4], aomac[4];


  struct timeval       start;

  /* outcome of test */
  uint16_t             result;

  /* type of tracebox test and data specific to that test */
  uint8_t              type;
  void                *data;

  /* details of application protocol used */
  uint8_t              app_proto;
  void                *app_data;

  /* client and server mss values advertised */
  uint16_t             client_mss;
  uint16_t             server_mss;

  /* various generic retransmit values */
  uint8_t              syn_retx;
  uint8_t              dat_retx;

  /* packets collected as part of this test */
  scamper_tracebox_pkt_t **pkts;
  uint32_t             pktc;

  /* debug  */
  char* misc;
  uint32_t miscl;

} scamper_tracebox_t;

scamper_tracebox_t *scamper_tracebox_alloc(void);
void scamper_tracebox_free(scamper_tracebox_t *tracebox);

char *scamper_tracebox_res2str(const scamper_tracebox_t *tracebox, char *buf, size_t len);
char *scamper_tracebox_type2str(const scamper_tracebox_t *tracebox, char *buf, size_t len);

scamper_tracebox_pkt_t *scamper_tracebox_pkt_alloc(uint8_t dir, uint8_t *data,
					   uint16_t len, struct timeval *tv);
void scamper_tracebox_pkt_free(scamper_tracebox_pkt_t *pkt);

int scamper_tracebox_pkts_alloc(scamper_tracebox_t *tracebox, uint32_t count);
int scamper_tracebox_record_pkt(scamper_tracebox_t *tracebox, scamper_tracebox_pkt_t *pkt);

#endif /* __SCAMPER_TRACEBOX_H */
