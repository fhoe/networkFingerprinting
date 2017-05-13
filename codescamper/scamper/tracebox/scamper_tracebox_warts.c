/*
 * scamper_tracebox_warts.c
 *
 *
 *
 * @author: K.Edeline
 */

#ifndef lint
static const char rcsid[] =
  "$Id: scamper_tracebox_warts.c,v 1.10 2012/05/04 18:42:51 mjl Exp $";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "internal.h"

#include "scamper_addr.h"
#include "scamper_list.h"
#include "scamper_icmpext.h"
#include "scamper_tracebox.h"
#include "scamper_file.h"
#include "scamper_file_warts.h"
#include "scamper_tracebox_warts.h"
#include "utils.h"

/*
 * tracebox structures conditionally included.
 * the first 2 bytes are the type, the second 2 bytes are the length
 */
#define WARTS_TRACEBOX_STRUCT_EOF   0x0000
#define WARTS_TRACEBOX_STRUCT_TYPE  0x0001
#define WARTS_TRACEBOX_STRUCT_APP   0x0002

#define WARTS_TRACEBOX_LIST      1
#define WARTS_TRACEBOX_CYCLE     2
#define WARTS_TRACEBOX_USERID    3
#define WARTS_TRACEBOX_SRC       4
#define WARTS_TRACEBOX_DST       5
#define WARTS_TRACEBOX_SPORT     6
#define WARTS_TRACEBOX_DPORT     7
#define WARTS_TRACEBOX_START     8
#define WARTS_TRACEBOX_RESULT    9
#define WARTS_TRACEBOX_TYPE      10
#define WARTS_TRACEBOX_APPPROTO  11
#define WARTS_TRACEBOX_CMSS      12
#define WARTS_TRACEBOX_SMSS      13
#define WARTS_TRACEBOX_SYNRETX   14
#define WARTS_TRACEBOX_DATARETX  15
#define WARTS_TRACEBOX_PKTC16    16
#define WARTS_TRACEBOX_PKTC      17

static const warts_var_t tracebox_vars[] =
{
  {WARTS_TRACEBOX_LIST,                  4, -1},
  {WARTS_TRACEBOX_CYCLE,                 4, -1},
  {WARTS_TRACEBOX_USERID,                4, -1},
  {WARTS_TRACEBOX_SRC,                  -1, -1},
  {WARTS_TRACEBOX_DST,                  -1, -1},
  {WARTS_TRACEBOX_SPORT,                 2, -1},
  {WARTS_TRACEBOX_DPORT,                 2, -1},
  {WARTS_TRACEBOX_START,                 8, -1},
  {WARTS_TRACEBOX_RESULT,                2, -1},
  {WARTS_TRACEBOX_TYPE,                  1, -1},
  {WARTS_TRACEBOX_APPPROTO,              1, -1},
  {WARTS_TRACEBOX_CMSS,                  2, -1},
  {WARTS_TRACEBOX_SMSS,                  2, -1},
  {WARTS_TRACEBOX_SYNRETX,               1, -1},
  {WARTS_TRACEBOX_DATARETX,              1, -1},
  {WARTS_TRACEBOX_PKTC16,                2, -1},
  {WARTS_TRACEBOX_PKTC,                  4, -1},
};
#define tracebox_vars_mfb WARTS_VAR_MFB(tracebox_vars)

#define WARTS_TRACEBOX_PKT_DIR      1
#define WARTS_TRACEBOX_PKT_TIME     2
#define WARTS_TRACEBOX_PKT_DATALEN  3
#define WARTS_TRACEBOX_PKT_DATA     4

static const warts_var_t tracebox_pkt_vars[] =
{
  {WARTS_TRACEBOX_PKT_DIR,             1, -1},
  {WARTS_TRACEBOX_PKT_TIME,            8, -1},
  {WARTS_TRACEBOX_PKT_DATALEN,         2, -1},
  {WARTS_TRACEBOX_PKT_DATA,           -1, -1},
};
#define tracebox_pkt_vars_mfb WARTS_VAR_MFB(tracebox_pkt_vars)


typedef struct warts_tracebox_pkt
{
  uint8_t               flags[tracebox_pkt_vars_mfb];
  uint16_t              flags_len;
  uint16_t              params_len;
} warts_tracebox_pkt_t;


static void warts_tracebox_pkt_params(const scamper_tracebox_pkt_t *pkt,
				  warts_tracebox_pkt_t *state, uint32_t *len)
{
  const warts_var_t *var;
  int max_id = 0;
  uint16_t i;

  memset(state->flags, 0, tracebox_pkt_vars_mfb);
  state->params_len = 0;

  for(i=0; i<sizeof(tracebox_pkt_vars) / sizeof(warts_var_t); i++)
    {
      var = &tracebox_pkt_vars[i];

      if(var->id == WARTS_TRACEBOX_PKT_DATA)
        {
	  if(pkt->len == 0)
	    continue;

	  state->params_len += pkt->len;
	  flag_set(state->flags, var->id, &max_id);
	  continue;
        }

      assert(var->size >= 0);
      state->params_len += var->size;
      flag_set(state->flags, var->id, &max_id);
    }

  state->flags_len = fold_flags(state->flags, max_id);

  *len += state->flags_len + state->params_len;

  if(state->params_len != 0)
    *len += 2;

  return;
}

static scamper_tracebox_pkt_t *warts_tracebox_pkt_read(warts_state_t *state,
					       uint8_t *buf, uint32_t *off,
					       uint32_t len)
{
  scamper_tracebox_pkt_t *pkt = NULL;
  uint8_t dir, *data = NULL;
  struct timeval tv;
  uint16_t plen;
  warts_param_reader_t handlers[] = {
    {&dir,  (wpr_t)extract_byte,         NULL},
    {&tv,   (wpr_t)extract_timeval,      NULL},
    {&plen, (wpr_t)extract_uint16,       NULL},
    {&data, (wpr_t)extract_bytes_ptr,   &plen},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_reader_t);

  if(warts_params_read(buf, off, len, handlers, handler_cnt) != 0 ||
     (pkt = scamper_tracebox_pkt_alloc(dir, data, plen, &tv)) == NULL)
    goto err;

  return pkt;

 err:
  if(pkt != NULL) scamper_tracebox_pkt_free(pkt);
  return NULL;
}

static int warts_tracebox_pkt_write(const scamper_tracebox_pkt_t *pkt,
				const scamper_file_t *sf,
				uint8_t *buf,uint32_t *off,const uint32_t len,
				warts_tracebox_pkt_t *state)
{
  uint16_t dl = pkt->len;
  warts_param_writer_t handlers[] = {
    {&pkt->dir, (wpw_t)insert_byte,          NULL},
    {&pkt->tv,  (wpw_t)insert_timeval,       NULL},
    {&pkt->len, (wpw_t)insert_uint16,        NULL},
    {pkt->data, (wpw_t)insert_bytes_uint16, &dl},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_writer_t);
  warts_params_write(buf, off, len, state->flags, state->flags_len,
		     state->params_len, handlers, handler_cnt);
  return 0;
}

static void warts_tracebox_params(const scamper_tracebox_t *tracebox,
			      warts_addrtable_t *table, uint8_t *flags,
			      uint16_t *flags_len, uint16_t *params_len)
{
  const warts_var_t *var;
  int i, max_id = 0;

  /* Unset all flags */
  memset(flags, 0, tracebox_vars_mfb);
  *params_len = 0;

  for(i=0; i<sizeof(tracebox_vars)/sizeof(warts_var_t); i++)
    {
      var = &tracebox_vars[i];

      /* Skip the variables for which we have no data */
      if(var->id == WARTS_TRACEBOX_PKTC16)
	continue;
      else if(var->id == WARTS_TRACEBOX_LIST && tracebox->list == NULL)
	continue;
      else if(var->id == WARTS_TRACEBOX_CYCLE && tracebox->cycle == NULL)
	continue;
      else if(var->id == WARTS_TRACEBOX_USERID && tracebox->userid == 0)
	continue;
      else if(var->id == WARTS_TRACEBOX_SRC && tracebox->src == NULL)
	continue;
      else if(var->id == WARTS_TRACEBOX_DST && tracebox->dst == NULL)
	continue;

      /* Set the flag for the rest of the variables */
      flag_set(flags, var->id, &max_id);

      /* Variables that don't have a fixed size */
      if(var->id == WARTS_TRACEBOX_SRC)
        {
	  *params_len += warts_addr_size(table, tracebox->src);
	  continue;
        }
      else if(var->id == WARTS_TRACEBOX_DST)
        {
	  *params_len += warts_addr_size(table, tracebox->dst);
	  continue;
        }

      /* The rest of the variables have a fixed size */
      *params_len += var->size;
    }

  *flags_len = fold_flags(flags, max_id);
  return;
}

static int warts_tracebox_params_read(scamper_tracebox_t *tracebox,
				  warts_addrtable_t *table,
				  warts_state_t *state,
				  uint8_t *buf, uint32_t *off, uint32_t len)
{
  uint16_t pktc16 = 0;
  uint32_t pktc32 = 0;

  warts_param_reader_t handlers[] = {
    {&tracebox->list,         (wpr_t)extract_list,    state},
    {&tracebox->cycle,        (wpr_t)extract_cycle,   state},
    {&tracebox->userid,       (wpr_t)extract_uint32,  NULL},
    {&tracebox->src,          (wpr_t)extract_addr,    table},
    {&tracebox->dst,          (wpr_t)extract_addr,    table},
    {&tracebox->sport,        (wpr_t)extract_uint16,  NULL},
    {&tracebox->dport,        (wpr_t)extract_uint16,  NULL},
    {&tracebox->start,        (wpr_t)extract_timeval, NULL},
    {&tracebox->result,       (wpr_t)extract_uint16,  NULL},
    {&tracebox->type,         (wpr_t)extract_byte,    NULL},
    {&tracebox->app_proto,    (wpr_t)extract_byte,    NULL},
    {&tracebox->client_mss,   (wpr_t)extract_uint16,  NULL},
    {&tracebox->server_mss,   (wpr_t)extract_uint16,  NULL},
    {&tracebox->syn_retx,     (wpr_t)extract_byte,    NULL},
    {&tracebox->dat_retx,     (wpr_t)extract_byte,    NULL},
    {&pktc16,             (wpr_t)extract_uint16,  NULL},
    {&pktc32,             (wpr_t)extract_uint32,  NULL},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_reader_t);

  if(warts_params_read(buf, off, len, handlers, handler_cnt) != 0)
    return -1;

  /* handle the fact the pktc param changed from 16 to 32 bits */
  if(pktc32 != 0)
    tracebox->pktc = pktc32;
  else if(pktc16 != 0)
    tracebox->pktc = pktc16;

  return 0;
}

static int warts_tracebox_params_write(const scamper_tracebox_t *tracebox,
				   const scamper_file_t *sf,
				   warts_addrtable_t *table,
				   uint8_t *buf, uint32_t *off,
				   const uint32_t len, const uint8_t *flags,
				   const uint16_t flags_len,
				   const uint16_t params_len)
{
  uint32_t list_id, cycle_id;

  /* Specifies how to write each variable to the warts file. */
  warts_param_writer_t handlers[] = {
    {&list_id,            (wpw_t)insert_uint32,  NULL},
    {&cycle_id,           (wpw_t)insert_uint32,  NULL},
    {&tracebox->userid,       (wpw_t)insert_uint32,  NULL},
    {tracebox->src,           (wpw_t)insert_addr,    table},
    {tracebox->dst,           (wpw_t)insert_addr,    table},
    {&tracebox->sport,        (wpw_t)insert_uint16,  NULL},
    {&tracebox->dport,        (wpw_t)insert_uint16,  NULL},
    {&tracebox->start,        (wpw_t)insert_timeval, NULL},
    {&tracebox->result,       (wpw_t)insert_uint16,  NULL},
    {&tracebox->type,         (wpw_t)insert_byte,    NULL},
    {&tracebox->app_proto,    (wpw_t)insert_byte,    NULL},
    {&tracebox->client_mss,   (wpw_t)insert_uint16,  NULL},
    {&tracebox->server_mss,   (wpw_t)insert_uint16,  NULL},
    {&tracebox->syn_retx,     (wpw_t)insert_byte,    NULL},
    {&tracebox->dat_retx,     (wpw_t)insert_byte,    NULL},
    {NULL,                NULL,                  NULL}, /* PKTC16 */
    {&tracebox->pktc,         (wpw_t)insert_uint32,  NULL},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_writer_t);

  if(warts_list_getid(sf,  tracebox->list,  &list_id)  == -1) return -1;
  if(warts_cycle_getid(sf, tracebox->cycle, &cycle_id) == -1) return -1;

  warts_params_write(buf, off, len, flags, flags_len, params_len,
		     handlers, handler_cnt);

  return 0;
}

int scamper_file_warts_tracebox_read(scamper_file_t *sf, const warts_hdr_t *hdr,
				 scamper_tracebox_t **tracebox_out)
{
  scamper_tracebox_t *tracebox = NULL;
  warts_addrtable_t table;
  warts_state_t *state = scamper_file_getstate(sf);
  uint8_t *buf = NULL;
  uint16_t junk16;
  uint32_t junk32;
  uint32_t off = 0;
  uint32_t i;

  memset(&table, 0, sizeof(table));

  /* Read in the header */
  if(warts_read(sf, &buf, hdr->len) != 0)
    {
      goto err;
    }

  if(buf == NULL)
    {
      *tracebox_out = NULL;
      return 0;
    }

  /* Allocate space for a tracebox object */
  if((tracebox = scamper_tracebox_alloc()) == NULL)
    {
      goto err;
    }

  /* Read in the tracebox data from the warts file */
  if(warts_tracebox_params_read(tracebox, &table, state, buf, &off, hdr->len) != 0)
    {
      goto err;
    }
  /* Determine how many tracebox_pkts to read */
  if(tracebox->pktc > 0)
    {
      /* Allocate the tracebox_pkts array */
      if(scamper_tracebox_pkts_alloc(tracebox, tracebox->pktc) != 0)
	goto err;

      /* For each tracebox packet, read it and insert it into the tracebox structure */
      for(i=0; i<tracebox->pktc; i++)
        {
	  tracebox->pkts[i] = warts_tracebox_pkt_read(state, buf, &off, hdr->len);
	  if(tracebox->pkts[i] == NULL)
	    goto err;
        }
    }

  for(;;)
    {
      if(extract_uint16(buf, &off, hdr->len, &junk16, NULL) != 0)
	goto err;
      if(junk16 == WARTS_TRACEBOX_STRUCT_EOF)
	break;
      if(extract_uint32(buf, &off, hdr->len, &junk32, NULL) != 0)
	goto err;

      i = off;
      off += junk32;
    }

  assert(off == hdr->len);
  warts_addrtable_clean(&table);
  *tracebox_out = tracebox;
  free(buf);
  return 0;

 err:
  warts_addrtable_clean(&table);
  if(buf != NULL) free(buf);
  if(tracebox != NULL) scamper_tracebox_free(tracebox);
  return -1;
}

/* Write data from a scamper tracebox object to a warts file */
int scamper_file_warts_tracebox_write(const scamper_file_t *sf,
				  const scamper_tracebox_t *tracebox)
{ 
  warts_addrtable_t table;
  warts_tracebox_pkt_t *pkts = NULL;
  uint8_t *buf = NULL;
  uint8_t  flags[tracebox_vars_mfb];
  uint16_t junk16;
  uint16_t flags_len, params_len;
  uint32_t len, i, off = 0;
  size_t size;
  
  memset(&table, 0, sizeof(table));

  /* Set the tracebox data (not including the packets) */
  warts_tracebox_params(tracebox, &table, flags, &flags_len, &params_len);
  len = 8 + flags_len + params_len + 2;

  if(tracebox->pktc > 0)
    {
      /* Allocate memory for the state */
      size = tracebox->pktc * sizeof(warts_tracebox_pkt_t);
      if((pkts = (warts_tracebox_pkt_t *)malloc_zero(size)) == NULL)
	goto err;

      for(i=0; i<tracebox->pktc; i++)
	warts_tracebox_pkt_params(tracebox->pkts[i], &pkts[i], &len);
    }
  
  /* struct eof */
  len += 2;

  /* Allocate memory to store all of the data (including packets) */
  if((buf = malloc(len)) == NULL)
    goto err;
  insert_wartshdr(buf, &off, len, SCAMPER_FILE_OBJ_TRACEBOX);

  /* Write the tracebox data (excluding packets) to the buffer */
  if(warts_tracebox_params_write(tracebox, sf, &table, buf, &off, len,
			     flags, flags_len, params_len) != 0)
    {
      goto err;
    }

  if(tracebox->pktc > 0)
    {
      for(i=0; i<tracebox->pktc; i++)
	warts_tracebox_pkt_write(tracebox->pkts[i], sf, buf, &off, len, &pkts[i]);
      free(pkts); pkts = NULL;
    }

  junk16 = WARTS_TRACEBOX_STRUCT_EOF;
  insert_uint16(buf, &off, len, &junk16, NULL);

  assert(off == len);

  /* Write the whole buffer to a warts file */
  if(warts_write(sf, buf, len) == -1)
    goto err;

  warts_addrtable_clean(&table);
  free(buf);
  return 0;

err:
  warts_addrtable_clean(&table);
  if(pkts != NULL) free(pkts);
  if(buf != NULL) free(buf);
  return -1;
}
