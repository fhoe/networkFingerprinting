/*
 * scamper_fprinting_warts.c
 *
 * 2014 Gregoire Mathonet
 * 2016 Florian Hoebreck
 *
 * $Id: scamper_fprinting_warts.c,v 1.0 2017/02/20 18:30:08 mjl Exp $
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 2.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#ifndef lint
static const char rcsid[] =
   "$Id: scamper_fprinting_warts.c,v 1.0 2014/06/06 18:30:08 mjl Exp $";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "internal.h"

#include "scamper_addr.h"
#include "scamper_list.h"
#include "scamper_icmpext.h"
#include "scamper_fprinting.h"
#include "scamper_file.h"
#include "scamper_file_warts.h"
#include "scamper_fprinting_warts.h"

#include "mjl_splaytree.h"
#include "utils.h"

#define TCP_REP 0
#define ECHO_REP 1
#define TIME_REP 2
#define TTLEXP_REP 3
#define PTUN_REP 4

/*
 * the optional bits of a fprinting structure
 */
#define WARTS_FPRINTING_ADDR_SRC        1
#define WARTS_FPRINTING_ADDR_DST        2
#define WARTS_FPRINTING_START           3
#define WARTS_FPRINTING_STOP_R          4
#define WARTS_FPRINTING_STOP_D          5
#define WARTS_FPRINTING_IS_ICMPDL       6
#define WARTS_FPRINTING_IS_IPDF         7
#define WARTS_FPRINTING_IS_TOS          8
#define WARTS_FPRINTING_PING            9
#define WARTS_FPRINTING_ITTL            10
#define WARTS_FPRINTING_SPORT           11
#define WARTS_FPRINTING_DPORT           12
#define WARTS_FPRINTING_REPC            13
#define WARTS_FPRINTING_PBMODE          14
#define WARTS_FPRINTING_NFIND           15
#define WARTS_FPRINTING_IS_MPLS         16
#define WARTS_FPRINTING_ISMULTI         17
#define WARTS_FPRINTING_NPROBE          18
#define WARTS_FPRINTING_TABLE_BAD       19
#define WARTS_FPRINTING_ADF             20

static const warts_var_t fprinting_vars[] = {
    { WARTS_FPRINTING_ADDR_SRC,        -1, -1},
    { WARTS_FPRINTING_ADDR_DST,        -1, -1},
    { WARTS_FPRINTING_START,           8, -1},
    { WARTS_FPRINTING_STOP_R,          1, -1},
    { WARTS_FPRINTING_STOP_D,          1, -1},
    { WARTS_FPRINTING_IS_ICMPDL,       1, -1},
    { WARTS_FPRINTING_IS_IPDF,         1, -1},
    { WARTS_FPRINTING_IS_TOS,          1, -1},
    { WARTS_FPRINTING_PING,            1, -1},
    { WARTS_FPRINTING_ITTL,            1, -1},
    { WARTS_FPRINTING_SPORT,           2, -1},
    { WARTS_FPRINTING_DPORT,           2, -1},
    { WARTS_FPRINTING_REPC,            4, -1},
	{ WARTS_FPRINTING_PBMODE,          1, -1},
	{ WARTS_FPRINTING_NFIND,           1, -1},
    { WARTS_FPRINTING_IS_MPLS,         1, -1},
    { WARTS_FPRINTING_ISMULTI,         1, -1},
    { WARTS_FPRINTING_NPROBE,          1, -1},
    { WARTS_FPRINTING_TABLE_BAD,       -1, -1},
    { WARTS_FPRINTING_ADF,             1, -1},
};
#define fprinting_vars_mfb WARTS_VAR_MFB(fprinting_vars)

#define WARTS_FPRINTING_REPLY_FROM            1
#define WARTS_FPRINTING_REPLY_PROTO           2
#define WARTS_FPRINTING_REPLY_REPLY_TTL       3
#define WARTS_FPRINTING_REPLY_OS_TTL          4
#define WARTS_FPRINTING_REPLY_REPLY_TOS       5
#define WARTS_FPRINTING_REPLY_REPLY_DF        6
#define WARTS_FPRINTING_REPLY_REPLY_SIZE      7
#define WARTS_FPRINTING_REPLY_ICMP_T          8
#define WARTS_FPRINTING_REPLY_ICMP_C          9
#define WARTS_FPRINTING_REPLY_TCP_F           10
#define WARTS_FPRINTING_REPLY_ICMP_EXT         11
#define WARTS_FPRINTING_REPLY_Q_TTL           12
#define WARTS_FPRINTING_REPLY_Q_TOS           13
#define WARTS_FPRINTING_REPLY_TCP_WIN         14
#define WARTS_FPRINTING_REPLY_TCP_MSS         15

static const warts_var_t fprinting_reply_vars[] = {
    { WARTS_FPRINTING_REPLY_FROM,            -1, -1},
    { WARTS_FPRINTING_REPLY_PROTO,           1, -1},
    { WARTS_FPRINTING_REPLY_REPLY_TTL,       1, -1},
    { WARTS_FPRINTING_REPLY_OS_TTL,          1, -1},
    { WARTS_FPRINTING_REPLY_REPLY_TOS,       1, -1},
    { WARTS_FPRINTING_REPLY_REPLY_DF,        1, -1},
    { WARTS_FPRINTING_REPLY_REPLY_SIZE,      2, -1},
    { WARTS_FPRINTING_REPLY_ICMP_T,          1, -1},
    { WARTS_FPRINTING_REPLY_ICMP_C,          1, -1},
    { WARTS_FPRINTING_REPLY_TCP_F,           1, -1},
    { WARTS_FPRINTING_REPLY_ICMP_EXT,        -1, -1},
    { WARTS_FPRINTING_REPLY_Q_TTL,           1, -1},
    { WARTS_FPRINTING_REPLY_Q_TOS,           1, -1},
    { WARTS_FPRINTING_REPLY_TCP_WIN,           2, -1},
    { WARTS_FPRINTING_REPLY_TCP_MSS,           2, -1},
};
#define fprinting_reply_vars_mfb WARTS_VAR_MFB(fprinting_reply_vars)

typedef struct warts_fprinting_reply {
    scamper_fprinting_reply_t *reply;
    uint8_t               flags[WARTS_VAR_MFB(fprinting_reply_vars)];
    uint16_t              flags_len;
    uint16_t              params_len;
} warts_fprinting_reply_t;

/* compute the length required by the paramaters we will save in a reply */
static void warts_fprinting_reply_params(const scamper_fprinting_t *fprinting,
      const scamper_fprinting_reply_t *reply,
      warts_addrtable_t *table,
      uint8_t *flags, uint16_t *flags_len,
      uint16_t *params_len) {
    const warts_var_t *var;
    int i, j, max_id = 0;
    scamper_icmpext_t *ie;

    /* unset all the flags possible */
    memset(flags, 0, fprinting_reply_vars_mfb);
    *params_len = 0;

    for(i = 0; i < sizeof(fprinting_reply_vars) / sizeof(warts_var_t); i++) {
        var = &fprinting_reply_vars[i];
        switch(var->id) {
            case WARTS_FPRINTING_REPLY_FROM:
                flag_set(flags, var->id, &max_id);
                *params_len += warts_addr_size(table, reply->addr);
                break;
            case WARTS_FPRINTING_REPLY_PROTO:
            case WARTS_FPRINTING_REPLY_REPLY_TTL:
            case WARTS_FPRINTING_REPLY_OS_TTL:
            case WARTS_FPRINTING_REPLY_REPLY_TOS:
            case WARTS_FPRINTING_REPLY_REPLY_DF:
            case WARTS_FPRINTING_REPLY_REPLY_SIZE:
            case WARTS_FPRINTING_REPLY_ICMP_T:
            case WARTS_FPRINTING_REPLY_ICMP_C:
            case WARTS_FPRINTING_REPLY_TCP_F:
                flag_set(flags, var->id, &max_id);
                assert(var->size >= 0);
                *params_len += var->size;
                break;
            case WARTS_FPRINTING_REPLY_ICMP_EXT:
            
                if(reply->reply_ext != NULL)
	            {
                    flag_set(flags, var->id, &max_id);
	                *params_len += 2;
	                /*in case of more than one labels */
	                for(ie = reply->reply_ext; ie != NULL; ie = ie->ie_next)
	                {
	                    *params_len += (2 + 1 + 1 + ie->ie_dl);
	                }
	                break;
	            }
	            break;
	        case WARTS_FPRINTING_REPLY_Q_TTL:
	        case WARTS_FPRINTING_REPLY_TCP_MSS:
            default:
                flag_set(flags, var->id, &max_id);
                assert(var->size >= 0);
                *params_len += var->size;
                break;
        }
    }

    *flags_len = fold_flags(flags, max_id);
    return;
}

static int warts_fprinting_reply_state(const scamper_file_t *sf,
                                       const scamper_fprinting_t *fprinting,
                                       scamper_fprinting_reply_t *reply,
                                       warts_fprinting_reply_t *state,
                                       warts_addrtable_t *table,
                                       uint32_t *len) {
    warts_fprinting_reply_params(fprinting, reply, table, state->flags,
                                &state->flags_len, &state->params_len);

    state->reply = reply;

    *len += state->flags_len + state->params_len;
    if(state->params_len != 0) {
        *len += 2;
    }

    return 0;
}

/* compute the length required by the parameters we will save in the fprinting structure itself */
static void warts_fprinting_params(const scamper_fprinting_t *fprinting,
                                   warts_addrtable_t *table, uint8_t *flags,
                                   uint16_t *flags_len, uint16_t *params_len) {
    const warts_var_t *var;
    DUAL *els;
    int i, max_id = 0;
    size_t j, l;
    fprinting_ip_replies_t *ip;

    /* unset all the flags possible */
    memset(flags, 0, fprinting_vars_mfb);
    *params_len = 0;

    for(i = 0; i < sizeof(fprinting_vars) / sizeof(warts_var_t); i++) {
        var = &fprinting_vars[i];
        switch(var->id) {
            case WARTS_FPRINTING_ADDR_SRC:
                flag_set(flags, var->id, &max_id);
                *params_len += warts_addr_size(table, fprinting->src);
                break;
            case WARTS_FPRINTING_ADDR_DST:
                flag_set(flags, var->id, &max_id);
                *params_len += warts_addr_size(table, fprinting->dst);
                break;
            case WARTS_FPRINTING_TABLE_BAD:
                flag_set(flags, var->id, &max_id);
                *params_len += 2; /* will code number of record on 2 bytes */
                j = getSize(fprinting->ip_replies);
                els = getElements(fprinting->ip_replies);
                for(l = 0; l < j; l++) {
                    if(els[l].spec != NONE && els[l].spec != DELETED) {
                        ip = (fprinting_ip_replies_t *)els[l].value;
                    if(ip->tcp == (scamper_fprinting_reply_t *)-1)
                        *params_len += warts_addr_size(table, (scamper_addr_t *)els[l].key) + 1;
                    if(ip->echo == (scamper_fprinting_reply_t *)-1)
                        *params_len += warts_addr_size(table, (scamper_addr_t *)els[l].key) + 1;
                    if(ip->ttlexp == (scamper_fprinting_reply_t *)-1)
                        *params_len += warts_addr_size(table, (scamper_addr_t *)els[l].key) + 1;
                    if(ip->time == (scamper_fprinting_reply_t *)-1)
                        *params_len += warts_addr_size(table, (scamper_addr_t *)els[l].key) + 1;
                    if(ip->ptunreach == (scamper_fprinting_reply_t *)-1)
                        *params_len += warts_addr_size(table, (scamper_addr_t *)els[l].key) + 1;
                    }
                }
                break;
            case WARTS_FPRINTING_START:
            case WARTS_FPRINTING_STOP_R:
            case WARTS_FPRINTING_STOP_D:
            case WARTS_FPRINTING_IS_ICMPDL:
            case WARTS_FPRINTING_IS_IPDF:
            case WARTS_FPRINTING_IS_TOS:
            case WARTS_FPRINTING_PING:
            case WARTS_FPRINTING_ITTL:
            case WARTS_FPRINTING_SPORT:
            case WARTS_FPRINTING_DPORT:
            case WARTS_FPRINTING_REPC:
			case WARTS_FPRINTING_PBMODE:
			case WARTS_FPRINTING_NFIND:
            case WARTS_FPRINTING_IS_MPLS:
            case WARTS_FPRINTING_ISMULTI:
            case WARTS_FPRINTING_NPROBE:
            case WARTS_FPRINTING_ADF:
                flag_set(flags, var->id, &max_id);
                assert(var->size >= 0);
                *params_len += var->size;
                break;
            default:
                flag_set(flags, var->id, &max_id);
                assert(var->size >= 0);
                *params_len += var->size;
                break;
        }
    }

    *flags_len = fold_flags(flags, max_id);

    return;
}

static void insert_fprinting_table(uint8_t *buf, uint32_t *off,
				   const uint32_t len,
				   const HASHTABLE *h, void *param) {
    uint16_t i = 0;
    size_t j, l;
    DUAL *els;
    fprinting_ip_replies_t *ip;

    j = getSize(h);
    els = getElements(h);
    for(l = 0; l < j; l++) {
        if(els[l].spec != NONE && els[l].spec != DELETED) {
            ip = (fprinting_ip_replies_t *)els[l].value;
            if(ip->tcp == (scamper_fprinting_reply_t *)-1)
                i++;
            if(ip->echo == (scamper_fprinting_reply_t *)-1)
                i++;
            if(ip->ttlexp == (scamper_fprinting_reply_t *)-1)
                i++;
            if(ip->time == (scamper_fprinting_reply_t *)-1)
                i++;
            if(ip->ptunreach == (scamper_fprinting_reply_t *)-1)
                i++;
        }
    }

    /* insert count */
    insert_uint16(buf, off, len, &i, NULL);

    for(l = 0; l < j; l++) {
        if(els[l].spec != NONE && els[l].spec != DELETED) {
            ip = (fprinting_ip_replies_t *)els[l].value;
            if(ip->tcp == (scamper_fprinting_reply_t *)-1) {
                insert_addr(buf, off, len, (scamper_addr_t *)els[l].key, param);
                buf[(*off)++] = TCP_REP;
            }
            if(ip->echo == (scamper_fprinting_reply_t *)-1) {
                insert_addr(buf, off, len, (scamper_addr_t *)els[l].key, param);
                buf[(*off)++] = ECHO_REP;
            }         
            if(ip->ttlexp == (scamper_fprinting_reply_t *)-1) {
                insert_addr(buf, off, len, (scamper_addr_t *)els[l].key, param);
                buf[(*off)++] = TTLEXP_REP;
            }         
            if(ip->time == (scamper_fprinting_reply_t *)-1) {
                insert_addr(buf, off, len, (scamper_addr_t *)els[l].key, param);
                buf[(*off)++] = TIME_REP;
            }                 
            if(ip->ptunreach == (scamper_fprinting_reply_t *)-1) {
                insert_addr(buf, off, len, (scamper_addr_t *)els[l].key, param);
                buf[(*off)++] = PTUN_REP;
            }      
        }
    }
    return;
}

static int extract_fprinting_table(const uint8_t *buf, uint32_t *off,
				   const uint32_t len,
				   HASHTABLE *out, void *param) {
    scamper_addr_t *addr;
    fprinting_ip_replies_t *t;
    uint16_t i, ipc;

    /* make sure there is room for the count */
    if(len - *off < 2)
        return -1;

    extract_uint16(buf, off, len, &ipc, NULL);

    for(i=0; i<ipc; i++) {
        if(extract_addr(buf, off, len, &addr, param) != 0)
	        return -1;
        t = getValue(out, addr);
        if(t == NULL) {
            t = calloc(1, sizeof(fprinting_ip_replies_t));
        }
        switch(buf[(*off)++]) {
            case TCP_REP:
                t->tcp = (scamper_fprinting_reply_t *)-1;
                break;
            case ECHO_REP:
                t->echo = (scamper_fprinting_reply_t *)-1;
                break;
            case TIME_REP:
                t->time = (scamper_fprinting_reply_t *)-1;
                break;
            case TTLEXP_REP:
                t->ttlexp = (scamper_fprinting_reply_t *)-1;
                break;
            case PTUN_REP:
                t->ptunreach = (scamper_fprinting_reply_t *)-1;
                break;
        }
        insertElement(out, addr, t);
    }

    return 0;
}

/* extract extension of icmp => mpls */
static int extract_fprinting_reply_icmp_ext(const uint8_t *buf, uint32_t *off,
					  uint32_t len,
					  scamper_fprinting_reply_t *reply,
					  void *param)
{
    return warts_icmpext_read(buf, off, len, &reply->reply_ext);
}

/* insert extenseion of icmp => mpls */
static void insert_fprinting_reply_icmp_ext(uint8_t *buf, uint32_t *off,
					  const uint32_t len,
					  const scamper_fprinting_reply_t *reply,
					  void *param)
{
    warts_icmpext_write(buf, off, len, reply->reply_ext);
    return;
}

/******************************

   READ // WRITE OPS

******************************/

static int warts_fprinting_reply_read(const scamper_fprinting_t *fprinting,
                                      scamper_fprinting_reply_t *reply,
                                      warts_state_t *state,
                                      warts_addrtable_t *table, const uint8_t *buf,
                                      uint32_t *off, uint32_t len) {
    warts_param_reader_t handlers[] = {
        {&reply->addr, (wpr_t)extract_addr,                 table},
        {&reply->reply_proto, (wpr_t)extract_byte,                 NULL},
        {&reply->reply_ttl, (wpr_t)extract_byte,                 NULL},
        {&reply->os_ttl, (wpr_t)extract_byte,                 NULL},
        {&reply->reply_tos, (wpr_t)extract_byte,                 NULL},
        {&reply->reply_df, (wpr_t)extract_byte,                 NULL},
        {&reply->reply_size, (wpr_t)extract_uint16,               NULL},
        {&reply->icmp_type, (wpr_t)extract_byte,                 NULL},
        {&reply->icmp_code, (wpr_t)extract_byte,                 NULL},
        {&reply->tcp_flags, (wpr_t)extract_byte,                 NULL},
        {reply, (wpr_t)extract_fprinting_reply_icmp_ext,          NULL},
        {&reply->reply_q_ttl, (wpr_t)extract_byte,                NULL},
        {&reply->reply_q_tos, (wpr_t)extract_byte,                NULL},
        {&reply->reply_tcp_win, (wpr_t)extract_uint16,                NULL},
        {&reply->reply_tcp_mss, (wpr_t)extract_uint16,                NULL},
    };
    const int handler_cnt = sizeof(handlers) / sizeof(warts_param_reader_t);
    uint32_t o = *off;
    int i;

    if((i = warts_params_read(buf, off, len, handlers, handler_cnt)) != 0) {
        return i;
    }

    return 0;
}

static void warts_fprinting_reply_write(const warts_fprinting_reply_t *state,
                                        warts_addrtable_t *table,
                                        uint8_t *buf, uint32_t *off, uint32_t len) {
    scamper_fprinting_reply_t *reply = state->reply;

    warts_param_writer_t handlers[] = {
        {reply->addr, (wpw_t)insert_addr,                 table},
        {&reply->reply_proto, (wpw_t)insert_byte,                 NULL},
        {&reply->reply_ttl, (wpw_t)insert_byte,                 NULL},
        {&reply->os_ttl, (wpw_t)insert_byte,                 NULL},
        {&reply->reply_tos, (wpw_t)insert_byte,                 NULL},
        {&reply->reply_df, (wpw_t)insert_byte,                 NULL},
        {&reply->reply_size, (wpw_t)insert_uint16,               NULL},
        {&reply->icmp_type, (wpw_t)insert_byte,                 NULL},
        {&reply->icmp_code, (wpw_t)insert_byte,                 NULL},
        {&reply->tcp_flags, (wpw_t)insert_byte,                 NULL},
        {reply,                    (wpw_t)insert_fprinting_reply_icmp_ext, NULL},
        {&reply->reply_q_ttl, (wpw_t)insert_byte,                NULL},
        {&reply->reply_q_tos, (wpw_t)insert_byte,                NULL},
        {&reply->reply_tcp_win, (wpw_t)insert_uint16,                NULL},
        {&reply->reply_tcp_mss, (wpw_t)insert_uint16,                NULL},
    };
    const int handler_cnt = sizeof(handlers) / sizeof(warts_param_writer_t);

    warts_params_write(buf, off, len, state->flags, state->flags_len,
                      state->params_len, handlers, handler_cnt);
    return;
}

static int warts_fprinting_params_read(scamper_fprinting_t *fprinting, warts_state_t *state,
                                       warts_addrtable_t *table,
                                       uint8_t *buf, uint32_t *off, uint32_t len) {
    warts_param_reader_t handlers[] = {
        {&fprinting->src, (wpr_t)extract_addr,            table},
        {&fprinting->dst, (wpr_t)extract_addr,            table},
        {&fprinting->start, (wpr_t)extract_timeval,         NULL},
        {&fprinting->stop_reason, (wpr_t)extract_byte,            NULL},
	    {&fprinting->stop_data, (wpr_t)extract_byte,            NULL},
        {&fprinting->add_icmp_len, (wpr_t)extract_byte,            NULL},
        {&fprinting->isipdf, (wpr_t)extract_byte,            NULL},
        {&fprinting->istos, (wpr_t)extract_byte,            NULL},
        {&fprinting->isping, (wpr_t)extract_byte,            NULL},
        {&fprinting->ittl, (wpr_t)extract_byte,            NULL},
        {&fprinting->sport, (wpr_t)extract_uint16,          NULL},
        {&fprinting->dport, (wpr_t)extract_uint16,          NULL},
        {&fprinting->replyc, (wpr_t)extract_uint32,          NULL},
		{&fprinting->pbmode, (wpr_t)extract_byte,         NULL},
		{&fprinting->nfind, (wpr_t)extract_byte,         NULL},
		{&fprinting->ismpls, (wpr_t)extract_byte,   NULL},
        {&fprinting->ismulti, (wpr_t)extract_byte,         NULL},
        {&fprinting->nprobe, (wpr_t)extract_byte,         NULL},
        {fprinting->ip_replies, (wpr_t)extract_fprinting_table, table},
        {&fprinting->isadf, (wpr_t)extract_byte,        NULL},
    };
    const int handler_cnt = sizeof(handlers) / sizeof(warts_param_reader_t);
    uint32_t o = *off;
    int rc;

    if((rc = warts_params_read(buf, off, len, handlers, handler_cnt)) != 0) {
        return rc;
    }

    return 0;
}

static int warts_fprinting_params_write(const scamper_fprinting_t *fprinting,
                                        const scamper_file_t *sf,
                                        warts_addrtable_t *table,
                                        uint8_t *buf, uint32_t *off,
                                        const uint32_t len,
                                        const uint8_t *flags,
                                        const uint16_t flags_len,
                                        const uint16_t params_len) {

    warts_param_writer_t handlers[] = {
        {fprinting->src, (wpw_t)insert_addr,            table},
        {fprinting->dst, (wpw_t)insert_addr,            table},
        {&fprinting->start, (wpw_t)insert_timeval,         NULL},
        {&fprinting->stop_reason, (wpw_t)insert_byte,            NULL},
        {&fprinting->stop_data, (wpw_t)insert_byte,            NULL},
        {&fprinting->add_icmp_len, (wpw_t)insert_byte,            NULL},
        {&fprinting->isipdf, (wpw_t)insert_byte,            NULL},
        {&fprinting->istos, (wpw_t)insert_byte,            NULL},
        {&fprinting->isping, (wpw_t)insert_byte,            NULL},
        {&fprinting->ittl, (wpw_t)insert_byte,            NULL},
        {&fprinting->sport, (wpw_t)insert_uint16,          NULL},
        {&fprinting->dport, (wpw_t)insert_uint16,          NULL},
        {&fprinting->replyc, (wpw_t)insert_uint32,          NULL},
		{&fprinting->pbmode, (wpw_t)insert_byte,          NULL},
		{&fprinting->nfind, (wpw_t)insert_byte,          NULL},
		{&fprinting->ismpls, (wpw_t)insert_byte,    NULL},
        {&fprinting->ismulti, (wpw_t)insert_byte,         NULL},
        {&fprinting->nprobe, (wpw_t)insert_byte,         NULL},
        {fprinting->ip_replies, (wpw_t)insert_fprinting_table, table},
        {&fprinting->isadf, (wpw_t)insert_byte,         NULL},
    };

    const int handler_cnt = sizeof(handlers) / sizeof(warts_param_writer_t);

    warts_params_write(buf, off, len, flags, flags_len, params_len, handlers,
                      handler_cnt);
    return 0;
}

/**********************

   CALLABLE I/O's

**********************/

int scamper_file_warts_fprinting_read(scamper_file_t *sf, const warts_hdr_t *hdr,
                                      scamper_fprinting_t **fprinting_out) {
    warts_state_t *state = scamper_file_getstate(sf);
    scamper_fprinting_t *fprinting = NULL;
    uint8_t *buf = NULL;
    uint32_t off = 0;
    uint16_t i;
    scamper_fprinting_reply_t *reply;
    fprinting_ip_replies_t *t;
    uint16_t reply_count;
    warts_addrtable_t table;

    memset(&table, 0, sizeof(table));

    if(warts_read(sf, &buf, hdr->len) != 0) {
        goto err;
    }
    if(buf == NULL) {
        *fprinting_out = NULL;
        return 0;
    }

    if((fprinting = scamper_fprinting_alloc()) == NULL) {
        goto err;
    }

    if(warts_fprinting_params_read(fprinting, state, &table, buf, &off, hdr->len) != 0) {
        goto err;
    }

    /* determine how many replies to read */
    if(extract_uint16(buf, &off, hdr->len, &reply_count, NULL) != 0) {
        goto err;
    }

    /* if there are no replies, then we are done */
    if(reply_count == 0) {
        goto done;
    }

    /* for each reply, read it and insert it into the fprinting structure */
    for(i = 0; i < reply_count; i++) {
        if((reply = scamper_fprinting_reply_alloc()) == NULL) {
            goto err;
        }

        if(warts_fprinting_reply_read(fprinting, reply, state, &table, buf, &off, hdr->len) != 0) {
            goto err;
        }

        scamper_fprinting_reply_append(fprinting, reply);
    }

    /* now we can fill in completely the table 
        but we do not overwrite if not the same result */
    reply = fprinting->fprinting_replies;
    while(reply != NULL) {
        t = getValue(fprinting->ip_replies, reply->addr);
        if(t == NULL) {
            t = calloc(1, sizeof(fprinting_ip_replies_t));
        }
        if(SCAMPER_FPRINTING_REPLY_IS_TCP(reply) && t->tcp != (scamper_fprinting_reply_t *)-1) {
            t->tcp = reply;
        } else if(SCAMPER_FPRINTING_REPLY_IS_ICMP_TTL_EXP(reply) && t->ttlexp != (scamper_fprinting_reply_t *)-1) {
            t->ttlexp = reply;
        } else if(SCAMPER_FPRINTING_REPLY_IS_ICMP_UNREACH(reply) && t->ptunreach != (scamper_fprinting_reply_t *)-1) {
            t->ptunreach = reply;
        } else if(SCAMPER_FPRINTING_REPLY_IS_ICMP_TSREPLY(reply) && t->time != (scamper_fprinting_reply_t *)-1) {
            t->time = reply;
        } else if(SCAMPER_FPRINTING_REPLY_IS_ICMP_ECHO_REPLY(reply) && t->echo != (scamper_fprinting_reply_t *)-1) {
            t->echo = reply;
        }
        insertElement(fprinting->ip_replies, reply->addr, t);
        reply = reply->next;
    }

    assert(off == hdr->len);

done:
    warts_addrtable_clean(&table);
    *fprinting_out = fprinting;
    free(buf);
    return 0;

err:
    warts_addrtable_clean(&table);
    if(buf != NULL) {
        free(buf);
    }
    if(fprinting != NULL) {
        scamper_fprinting_free(fprinting);
    }
    return -1;
}

int scamper_file_warts_fprinting_write(const scamper_file_t *sf,
                                       const scamper_fprinting_t *fprinting) {
    warts_addrtable_t table;
    warts_fprinting_reply_t *reply_state = NULL;
    scamper_fprinting_reply_t *reply;
    uint8_t *buf = NULL;
    uint8_t  flags[fprinting_vars_mfb];
    uint16_t flags_len, params_len;
    uint32_t len, off = 0;
    uint16_t reply_count;
    size_t   size;
    int      i, j;

    memset(&table, 0, sizeof(table));

    /* figure out which fprinting data items we'll store in this record */
    warts_fprinting_params(fprinting, &table, flags, &flags_len, &params_len);

    /* length of the fprinting's flags, parameters, and number of reply records */
    len = 8 + flags_len + 2 + params_len + 2;

    if((reply_count = scamper_fprinting_reply_count(fprinting)) > 0) {
        size = reply_count * sizeof(warts_fprinting_reply_t);
        if((reply_state = (warts_fprinting_reply_t *)malloc_zero(size)) == NULL) {
            goto err;
        }

        j = 0;
        for(reply = fprinting->fprinting_replies; reply != NULL; reply = reply->next) {
            if(warts_fprinting_reply_state(sf, fprinting, reply, &reply_state[j++],
                                        &table, &len) == -1) {
                goto err;
            }
        }

    }

    if((buf = malloc(len)) == NULL) {
        system("echo \"malloc error file too big\" > ~/scamper_error.txt");
        goto err;
    }

    insert_wartshdr(buf, &off, len, SCAMPER_FILE_OBJ_FPRINTING);

    if(warts_fprinting_params_write(fprinting, sf, &table, buf, &off, len,
                                   flags, flags_len, params_len) == -1) {
        goto err;
    }

    /* reply record count */
    insert_uint16(buf, &off, len, &reply_count, NULL);

    /* write each fprinting reply record */
    for(i = 0; i < reply_count; i++) {
        warts_fprinting_reply_write(&reply_state[i], &table, buf, &off, len);
    }
    if(reply_state != NULL) {
        free(reply_state);
        reply_state = NULL;
    }

    assert(off == len);

    if(warts_write(sf, buf, len) == -1) {
        goto err;
    }

    warts_addrtable_clean(&table);
    free(buf);
    return 0;

err:
    warts_addrtable_clean(&table);
    if(reply_state != NULL) {
        free(reply_state);
    }
    if(buf != NULL) {
        free(buf);
    }
    return -1;
}
