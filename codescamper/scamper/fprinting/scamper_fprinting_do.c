/*
 * scamper_do_fprinting.c
 *
 * $Id: scamper_fprinting_do.c,v 1.0 2017/02/20 11:00:40 mjl Exp $
 *
 * 2014 Gregoire Mathonet
 * 2017 Florian Hoebreck
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
   "$Id: scamper_fprinting_do.c,v 1.0 2014/06/06 11:00:40 mjl Exp $";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "internal.h"

#include "scamper.h"
#include "scamper_addr.h"
#include "scamper_fprinting.h"
#include "scamper_getsrc.h"
#include "scamper_icmp_resp.h"
#include "scamper_icmpext.h"
#include "scamper_fds.h"
#include "scamper_rtsock.h"
#include "scamper_task.h"
#include "scamper_dl.h"
#include "scamper_dlhdr.h"
#include "scamper_probe.h"
#include "scamper_queue.h"
#include "scamper_file.h"
#include "scamper_debug.h"
#include "scamper_fprinting_do.h"
#include "scamper_options.h"
#include "scamper_icmp4.h"
#include "utils.h"

#define SCAMPER_DO_FPRINTING_ITTL_MIN    1
#define SCAMPER_DO_FPRINTING_ITTL_DEF    1
#define SCAMPER_DO_FPRINTING_ITTL_MAX    254

#define SCAMPER_DO_FPRINTING_NFIND_MIN   1
#define SCAMPER_DO_FPRINTING_NFIND_DEF   1
#define SCAMPER_DO_FPRINTING_NFIND_MAX   15

#define SCAMPER_DO_FPRINTING_NPROBE_MIN  1
#define SCAMPER_DO_FPRINTING_NPROBE_DEF  1
#define SCAMPER_DO_FPRINTING_NPROBE_MAX  20

#define FRP_BAD (scamper_fprinting_reply_t *)-1

/* the callback functions registered with the fprinting task */
static scamper_task_funcs_t fprinting_funcs;

/* ICMP ping probes are marked with the process' ID */
#ifndef _WIN32
static pid_t pid;
#else
static DWORD pid;
#endif

/* address cache used to avoid reallocating the same address multiple times */
extern scamper_addrcache_t *addrcache;

/* state of a running fprinting
   dstreached is set once traceroute has reached the destination
   ttl is the ttl probes will use. incrementing until dst is reached
   hops_target is the ttl required to reach dst
   probe2_c is the number of probes sent since traceroute has finished
   read is set to zero when replies we could get are meaningless
   pbs_sent and pbs_got can stop the task if we can't get replies
   pbcount allows to split traffic loads of fprinting->nprobe
   addrs allows to read the addr of the next node to probe in the
      second part of the task */
typedef struct fprinting_state {
    uint8_t dstreached;
    uint8_t ttl;
    uint8_t hops_target;
    uint8_t probe2_c;
    uint8_t read;
    short pbs_sent;
    short pbs_got;
    uint8_t pbcount;

    fprinting_multi_addr_t *addrswarp;
    fprinting_multi_addr_t *addrs;

} fprinting_state_t;


#define FPRINTING_OPT_ICMPDLEN  1
#define FPRINTING_OPT_IPDF      2
#define FPRINTING_OPT_TOS       3
#define FPRINTING_OPT_MPLS      4
#define FPRINTING_OPT_ITTL      5
#define FPRINTING_OPT_PING      6
#define FPRINTING_OPT_FINDPROTO 7
#define FPRINTING_OPT_NFIND     8
#define FPRINTING_OPT_MULTI     9
#define FPRINTING_OPT_NPROBE    10
#define FPRINTING_OPT_DF        11

static const scamper_option_in_t opts[] = {
    {'l', "length", FPRINTING_OPT_ICMPDLEN, SCAMPER_OPTION_TYPE_NULL},
    {'d', "df", FPRINTING_OPT_IPDF,     SCAMPER_OPTION_TYPE_NULL},
    {'t', "tos", FPRINTING_OPT_TOS,      SCAMPER_OPTION_TYPE_NULL},
    {'m', "mpls", FPRINTING_OPT_MPLS, SCAMPER_OPTION_TYPE_NULL},
    {'I', "ittl", FPRINTING_OPT_ITTL,   SCAMPER_OPTION_TYPE_NUM},
    {'p', "ping", FPRINTING_OPT_PING,   SCAMPER_OPTION_TYPE_NULL},
    {'O', "proto", FPRINTING_OPT_FINDPROTO, SCAMPER_OPTION_TYPE_STR},
    {'N', "nfind", FPRINTING_OPT_NFIND, SCAMPER_OPTION_TYPE_NUM},
    {'M', "multi", FPRINTING_OPT_MULTI, SCAMPER_OPTION_TYPE_STR},
    {'P', "pbcount", FPRINTING_OPT_NPROBE, SCAMPER_OPTION_TYPE_NUM},
    {'a', "dfset", FPRINTING_OPT_DF, SCAMPER_OPTION_TYPE_NULL},
};

static const int opts_cnt = SCAMPER_OPTION_COUNT(opts);

const char *scamper_do_fprinting_usage(void) {
    return "fprinting [-ldtmpa] [-I ittl] [-O proto] [-N nfind] [-P pbcount] [-M multi]";
}

static scamper_fprinting_t *fprinting_getdata(const scamper_task_t *task) {
    return scamper_task_getdata(task);
}

static fprinting_state_t *fprinting_getstate(const scamper_task_t *task) {
    return scamper_task_getstate(task);
}

/* kill the task, and record why */
static void fprinting_stop(scamper_task_t *task, uint8_t reason, uint8_t data) {
    scamper_fprinting_t *fprinting = fprinting_getdata(task);
    fprinting->stop_reason = reason;
    fprinting->stop_data   = data;

    scamper_task_queue_done(task, 0);
    return;
}

/* handle errors that occured */
static void fprinting_handleerror(scamper_task_t *task, int error) {
    scamper_debug(__func__, "error in fprinting...");
    fprinting_stop(task, SCAMPER_FPRINTING_STOP_ERROR, error);
    return;
}

/* clean state */
static void fprinting_state_free(fprinting_state_t *state) {
    fprinting_multi_addr_t *t = state->addrswarp;
    while(t != NULL) {
      state->addrs = t;
      t = t->next;
      free(state->addrs);
    }
    free(state);
    return;
}

/* fprinting_dstreached
*
* prepare the state for the second lines of probes.
* make sure reply from ip's along the way can be read by us 
*/
static void fprinting_dstreached(scamper_task_t *task, uint8_t got) {
    scamper_fprinting_t *fprinting = fprinting_getdata(task);
    fprinting_state_t *state = fprinting_getstate(task);
    fprinting_multi_addr_t *addrs;
    scamper_task_sig_t *sig = NULL;

    state->dstreached = 1;
    state->hops_target = state->ttl;
    state->ttl = 255;
    state->probe2_c = 1;
    if(got)
      state->read = 0;
    state->addrswarp = state->addrs;
    /* set the number of pbcount at each destination */
    state->pbcount = 0;

    /* for the node being, the found nodes towards it */
    addrs = state->addrs;
    while(addrs != NULL) {
     
        if((sig = scamper_task_sig_alloc(SCAMPER_TASK_SIG_TYPE_TX_IP)) == NULL) {
         goto err;
        }


        sig->sig_tx_ip_dst = scamper_addr_use(addrs->addr);
        if(scamper_task_sig_add(task, sig) != 0) {
         goto err;
        }
        addrs = addrs->next;
    }
   
   /* if multiple addresses were given */
    if(fprinting->ismulti && fprinting->curdsts->next != NULL) {
        if((sig = scamper_task_sig_alloc(SCAMPER_TASK_SIG_TYPE_TX_IP)) == NULL) {
            goto err;
        }
        sig->sig_tx_ip_dst = scamper_addr_use(fprinting->curdsts->next->addr);
        if(scamper_task_sig_add(task, sig) != 0) {
            goto err;
        }
    }
    scamper_task_sig_install(task);

    return;

err:
    if(sig != NULL)
        scamper_task_sig_free(sig);
    fprinting_handleerror(task, 3);
}

static int fprinting_state_alloc(scamper_task_t *task) {
    scamper_fprinting_t *fprinting = fprinting_getdata(task);
    fprinting_state_t *state = NULL;
    size_t size;
    int i;
    
    /* alloc the struct to keep the state while executing the probing */
    if((state = malloc_zero(sizeof(fprinting_state_t))) == NULL) {
        printerror(errno, strerror, __func__, "could not malloc state");
        goto err;
    }
    state->ttl = fprinting->isping ? 255 : fprinting->ittl;
    state->dstreached = fprinting->isping;
    state->read = 1;

    scamper_task_setstate(task, state);

    return 0;

err:
    return -1;
}
/*
 * the fprinting expired on the pending queue
 * that means it is either time to send the next probe, or write the
 * task out
*/ 
static void do_fprinting_handle_timeout(scamper_task_t *task) {
    scamper_fprinting_t *fprinting = fprinting_getdata(task);
    fprinting_state_t *state = fprinting_getstate(task);
    fprinting_ip_replies_t *t;

	state->read = 1;
    
    /* if list of addresses is finish and if dst has been reached, task is finished */
    if((fprinting->ismulti == 0 || fprinting->curdsts->next == NULL) &&
      state->dstreached &&
      ((state->probe2_c == state->hops_target + 1 || state->addrs == NULL) &&
      (state->pbcount == fprinting->nprobe || state->pbcount == 0))) {
        
        fprinting_stop(task, SCAMPER_FPRINTING_STOP_COMPLETED, 0);
        return;
    
    } else if(!state->dstreached) {
        state->ttl++; /*increase ttl for the traceroute*/
    }

    if(state->dstreached  == 0 && (state->ttl > 32 || state->pbs_sent - state->pbs_got > 4)) {
        if(state->dstreached == 0) {
            /* skip to the nodes we have info on*/
            fprinting_dstreached(task, 0);
        } else if(fprinting->ismulti == 1 && fprinting->curdsts->next != NULL) {
            /* skip to next dest */
            fprinting_state_free(state);
            if(fprinting_state_alloc(task) != 0) {
                fprinting_handleerror(task, 7);
                return;
            }
            gettimeofday_wrap(&fprinting->start);
            fprinting->curdsts = fprinting->curdsts->next;
            fprinting->dst = fprinting->curdsts->addr;
            /* insert new node's tllexp: unkonwn in the record */
            t = calloc(1, sizeof(fprinting_ip_replies_t));
            if(t == NULL) {
                fprinting_handleerror(task, 4);
                return;
            }
            t->ttlexp = FRP_BAD;
            t->alreadyProbed = 0;
            insertElement(fprinting->ip_replies, fprinting->dst, t);
        } else {
            /* should never happen! */
            fprinting_handleerror(task, 5);
        }
    }

    return;
}

/*
* state_multi_addr_add
*
* in case of multiple addresses given. add a new address to the state
*/
static void state_multi_addr_add(fprinting_state_t *fprinting, scamper_addr_t *addr) {
    fprinting_multi_addr_t *t = calloc(1, sizeof(fprinting_multi_addr_t));
    if(fprinting->addrs == NULL) {
        fprinting->addrs = t;
        fprinting->addrs->addr = addr;
    } else {
        t->addr = addr;
        t->next = fprinting->addrs;
        fprinting->addrs = t;
    }
}

static void do_fprinting_write(scamper_file_t *sf, scamper_task_t *task) {
    scamper_file_write_fprinting(sf, fprinting_getdata(task));
    return;
}

/* make sure we can understand the parsed command line options */
static int fprinting_arg_param_validate(int optid, char *param, long *out) {
    long tmp = 0;
    int i;

    switch(optid) {
        /* check if TTL given is in the valid range */
        case FPRINTING_OPT_ITTL:
            if(string_tolong(param, &tmp) == -1 ||
                tmp < SCAMPER_DO_FPRINTING_ITTL_MIN ||
                tmp > SCAMPER_DO_FPRINTING_ITTL_MAX) {
                goto err;
            }
            break;
        /* check if protocol for traceroute is valid, 3 choices possible */    
	    case FPRINTING_OPT_FINDPROTO:
		    if(strncmp("tcp", param, 3) == 0)
				tmp = SCAMPER_DO_FPRINTING_PBTCP;
			else if(strncmp("echo", param, 4) == 0)
				tmp = SCAMPER_DO_FPRINTING_PBECHO;
            else if(strncmp("udp", param, 3) == 0)
                tmp = SCAMPER_DO_FPRINTING_PBUDP;
		    else 
			    goto err;
			break;
	
		case FPRINTING_OPT_NFIND:
			if(string_tolong(param, &tmp) == -1 ||
               tmp < SCAMPER_DO_FPRINTING_NFIND_MIN ||
               tmp > SCAMPER_DO_FPRINTING_NFIND_MAX) {
            goto err;
            }
            break;
            
        case FPRINTING_OPT_NPROBE:
		    if(string_tolong(param, &tmp) == -1 ||
               tmp < SCAMPER_DO_FPRINTING_NPROBE_MIN ||
               tmp > SCAMPER_DO_FPRINTING_NPROBE_MAX) {
            goto err;
            }
            break;
            
      case FPRINTING_OPT_MULTI:
            tmp = 0;
            break;
      default:
            return -1;
    }

    /* valid parameter */
    if(out != NULL) {
        *out = tmp;
    }
    return 0;

err:
    /*non valid parameter(s) */
    return -1;
}

/*
 * scamper_do_fprinting_arg_validate
 *
 */
int scamper_do_fprinting_arg_validate(int argc, char *argv[], int *stop) {
    return scamper_options_validate(opts, opts_cnt, argc, argv, stop,
                                    fprinting_arg_param_validate);
}

/*
 * scamper_do_fprinting_alloc
 *
 * given a string representing a fprinting task, parse the parameters and assemble
 * a fprinting.  return the fprinting structure so that it is all ready to go.
 *
 */
void *scamper_do_fprinting_alloc(char *str) {
    uint8_t ttl = SCAMPER_DO_FPRINTING_ITTL_DEF;
    uint8_t add_icmp_len = 0;
    uint8_t isipdf = 0;
    uint8_t istos = 0;
	uint8_t ismpls = 0;
    uint8_t isping = 0;
    uint8_t isadf = 0;
	uint8_t pbmode = SCAMPER_DO_FPRINTING_PBTCP;
	uint8_t nfind = SCAMPER_DO_FPRINTING_NFIND_DEF;
	uint8_t nprobe = SCAMPER_DO_FPRINTING_NPROBE_DEF;
    uint8_t ismulti = 0;

    mode_t mode;
    int fd;
    FILE *file;
    #ifndef _WIN32
        mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
    #else
        mode = _S_IREAD | _S_IWRITE;
    #endif

    scamper_option_out_t *opts_out = NULL, *opt;
    scamper_fprinting_t *fprinting = NULL;
    fprinting_ip_replies_t *t;
    uint16_t cmps = 0; /* calculated minimum probe size */
    char *addr = NULL;
    size_t size;
    long tmp = 0;
    int i;

    /* try and parse the string passed in */
    if(scamper_options_parse(str, opts, opts_cnt, &opts_out, &addr) != 0) {
        goto err;
    }

    /* allocate fp */
    if((fprinting = scamper_fprinting_alloc()) == NULL) {
        goto err;
    }

    /* parse the options, do preliminary sanity checks */
    for(opt = opts_out; opt != NULL; opt = opt->next) {
        if(opt->type != SCAMPER_OPTION_TYPE_NULL &&
            fprinting_arg_param_validate(opt->id, opt->str, &tmp) != 0) {
            scamper_debug(__func__, "validation of optid %d failed", opt->id);
            goto err;
        }

        switch(opt->id) {

            case FPRINTING_OPT_ICMPDLEN:
                add_icmp_len = 1;
                break;

            case FPRINTING_OPT_IPDF:
                isipdf = 1;
                break;

            case FPRINTING_OPT_TOS:
                istos = 1;
                break;

            case FPRINTING_OPT_ITTL:
                ttl = (uint8_t)tmp;
                break;

            case FPRINTING_OPT_PING:
                isping = 1;
                break;

			
			case FPRINTING_OPT_MPLS:
			    ismpls = 1;
			    break;

			case FPRINTING_OPT_FINDPROTO:
				pbmode = (uint8_t)tmp;
				break;

			case FPRINTING_OPT_NFIND:
				nfind = (uint8_t)tmp;
				break;
				
			case FPRINTING_OPT_NPROBE:
				nprobe = (uint8_t)tmp;
				break;


            case FPRINTING_OPT_DF:
                isadf = 1;
                break;
            /* case multiple addresses, read file given and addresses to the state */
            case FPRINTING_OPT_MULTI:
                ismulti = 1;
                if(addr != NULL) {
                    fprinting_multi_addr_add(fprinting, scamper_addrcache_resolve(addrcache, AF_UNSPEC, addr));
                }
                addr = calloc(255, 1);
                if(addr == NULL) goto err;
                #ifndef WITHOUT_PRIVSEP
                fd = scamper_privsep_open_file(opt->str, O_RDWR, mode);
                #else
                fd = open(opt->str, O_RDWR, mode);
                #endif
                if(fd == -1) {
                    printerror(errno, strerror, __func__, "Bad file");
                    goto err;
                }
                if((file = fdopen(fd, "r")) == NULL) {
                    printerror(errno, strerror, __func__, "Bad file");
                    goto err;
                }
                while(fgets(addr, 254, file)) {
                    fprinting_multi_addr_add(fprinting, scamper_addrcache_resolve(addrcache, AF_UNSPEC, addr));
                    memset(addr, 0, 255);
                }
                free(addr);
                fclose(file);
                fprinting->curdsts = fprinting->mdsts;
                fprinting->dst = fprinting->curdsts->addr;
        }
    }
    scamper_options_free(opts_out); opts_out = NULL;

    /* if there is no IP address after the options string, then stop now */
    if(ismulti == 0 && addr == NULL) {
        goto err;
    }

    if(ismulti == 0 && (fprinting->dst = scamper_addrcache_resolve(addrcache, AF_UNSPEC, addr)) == NULL) {
        goto err;
    } else {
        /* insert new node's tllexp: unkonwn in the record */
        t = calloc(1, sizeof(fprinting_ip_replies_t));
        if(t == NULL) {
            goto err;
        }
        t->ttlexp = FRP_BAD;
        t->alreadyProbed = 0;
        insertElement(fprinting->ip_replies, fprinting->dst, t);
    }
    
    /* update the fprinting struct */
    fprinting->ittl = ttl;
    fprinting->isping = isping;
    fprinting->add_icmp_len = add_icmp_len;
    fprinting->isipdf = isipdf;
    fprinting->istos = istos;
    fprinting->ismpls = ismpls;
    fprinting->pbmode = pbmode;
    fprinting->nfind = nfind;
    fprinting->nprobe = nprobe;
    fprinting->ismulti = ismulti;
    fprinting->isadf = isadf;

    fprinting->sport = (pid & 0xffff) | 0x8000;
    fprinting->dport = 33435;

    return fprinting;

err:
    /* error: => clean data */
    if(fprinting != NULL) {
        scamper_fprinting_free(fprinting);
    }
    if(opts_out != NULL) {
        scamper_options_free(opts_out);
    }
    return NULL;
}

static void do_fprinting_halt(scamper_task_t *task) {
    fprinting_stop(task, SCAMPER_FPRINTING_STOP_HALTED, 0);
    return;
}

static void do_fprinting_free(scamper_task_t *task) {
    scamper_fprinting_t *fprinting;
    fprinting_state_t *state;

    if((fprinting = fprinting_getdata(task)) != NULL) {
        scamper_fprinting_free(fprinting);
    }

    if((state = fprinting_getstate(task)) != NULL) {
        fprinting_state_free(state);
    }

    return;
}

scamper_task_t *scamper_do_fprinting_alloctask(void *data) {
    scamper_fprinting_t *fprinting = (scamper_fprinting_t *)data;
    scamper_task_sig_t *sig = NULL;
    scamper_task_t *task = NULL;

    /* allocate a task structure and store the fprinting with it */
    if((task = scamper_task_alloc(fprinting, &fprinting_funcs)) == NULL) {
        goto err;
    }

    /* declare the signature of the task */
    if(fprinting->ismulti == 0) {
        if((sig = scamper_task_sig_alloc(SCAMPER_TASK_SIG_TYPE_TX_IP)) == NULL) {
            goto err;
        }
        sig->sig_tx_ip_dst = scamper_addr_use(fprinting->dst);
        if(fprinting->src == NULL && (fprinting->src = scamper_getsrc(fprinting->dst, 0)) == NULL) {
            goto err;
        }
        if(scamper_task_sig_add(task, sig) != 0) {
            goto err;
        }
        sig = NULL;
    } else {
        while(fprinting->curdsts != NULL) {
            if((sig = scamper_task_sig_alloc(SCAMPER_TASK_SIG_TYPE_TX_IP)) == NULL) {
                goto err;
            }
            sig->sig_tx_ip_dst = scamper_addr_use(fprinting->curdsts->addr);
            if(fprinting->src == NULL && (fprinting->src = scamper_getsrc(fprinting->dst, 0)) == NULL) {
                goto err;
            }
            if(scamper_task_sig_add(task, sig) != 0) {
                goto err;
            }
            sig = NULL;
            fprinting->curdsts = fprinting->curdsts->next;
        }
        fprinting->curdsts = fprinting->mdsts;
    }

    return task;

err:
    if(sig != NULL) {
        scamper_task_sig_free(sig);
    }
    if(task != NULL) {
        scamper_task_setdatanull(task);
        scamper_task_free(task);
    }
    return NULL;
}

void scamper_do_fprinting_free(void *data) {
    scamper_fprinting_free((scamper_fprinting_t *)data);
    return;
}

void scamper_do_fprinting_cleanup() {
    return;
}

/* return whether the answer has been accepted and is inserted oe is the same*/
static uint8_t fprinting_record(scamper_fprinting_t *fprinting, scamper_fprinting_reply_t *reply) {
    uint8_t fst = 0;/* to indicate that this is the first time that it is seen */
    scamper_fprinting_reply_t *r, *rp;
    fprinting_ip_replies_t *ip = getValue(fprinting->ip_replies, reply->addr);
    
    
 
    /* always keep track of this reply */
    scamper_fprinting_reply_append(fprinting, reply);
   
    if(ip == NULL)
        ip = calloc(1, sizeof(fprinting_ip_replies_t));
    if(ip == NULL)
        goto err; /* allocation error */
   
    if(ip->tcp == NULL && SCAMPER_FPRINTING_REPLY_IS_TCP(reply)) {
        fst = 1;
        ip->tcp = reply;
    } else if(ip->echo == NULL && SCAMPER_FPRINTING_REPLY_IS_ICMP_ECHO_REPLY(reply)) {
        fst = 1;
        ip->echo = reply;
    } else if(ip->ptunreach == NULL && SCAMPER_FPRINTING_REPLY_IS_ICMP_UNREACH(reply)) {
        fst = 1;
        ip->ptunreach = reply;
    } else if(ip->ttlexp == NULL && SCAMPER_FPRINTING_REPLY_IS_ICMP_TTL_EXP(reply)) {
        fst = 1;
        ip->ttlexp = reply;
    } else if(ip->time == NULL && SCAMPER_FPRINTING_REPLY_IS_ICMP_TSREPLY(reply)) {
        fst = 1;
        ip->time = reply;
    }
    /* first answer of this kind */
    if(fst) {
        ip->alreadyProbed = 1;
        insertElement(fprinting->ip_replies, reply->addr, ip);
        return 1;
    }
    fst = 2;
   
   
    /* many answers? make sure they are the same */
    if(ip->tcp != FRP_BAD && SCAMPER_FPRINTING_REPLY_IS_TCP(reply) && ip->tcp->os_ttl != reply->os_ttl) {
        fst = 0;
        ip->tcp = FRP_BAD;
    } else if(ip->echo != FRP_BAD && SCAMPER_FPRINTING_REPLY_IS_ICMP_ECHO_REPLY(reply) && ip->echo->os_ttl != reply->os_ttl) {
        fst = 0;
        ip->echo = FRP_BAD;
    } else if(ip->ptunreach != FRP_BAD && SCAMPER_FPRINTING_REPLY_IS_ICMP_UNREACH(reply) && ip->ptunreach->os_ttl != reply->os_ttl) {
        fst = 0;
        ip->ptunreach = FRP_BAD;
    } else if(ip->ttlexp != FRP_BAD && SCAMPER_FPRINTING_REPLY_IS_ICMP_TTL_EXP(reply) && ip->ttlexp->os_ttl != reply->os_ttl) {
        fst = 0;
        ip->ttlexp = FRP_BAD;
    } else if(ip->time != FRP_BAD && SCAMPER_FPRINTING_REPLY_IS_ICMP_TSREPLY(reply) && ip->time->os_ttl != reply->os_ttl) {
        fst = 0;
        ip->time = FRP_BAD;
    } else {
        goto err;
    }
    return fst;

err:
    return 0;
}

/***************************************

   NOW WHAT TO DO WHEN:
   SENDING PROBES
   GETTING PACKETS

***************************************/

/* guess ittl from a ttl given */
static uint8_t two_up(uint8_t base) {
    uint16_t r = 32;
    while(r < base) {
        r <<= 1;
    }
    return (r > 255) ? 255 : (uint8_t)r;
}

/* 
 * do_fprinting_handle_dl
 *
 * handle a datalink record
 * In this case, handle tcp and some icmp packets
 *
 */
static void do_fprinting_handle_dl(scamper_task_t *task, scamper_dl_rec_t *dl) {
    scamper_fprinting_t       *fprinting  = fprinting_getdata(task);
    fprinting_state_t         *state = fprinting_getstate(task);
    scamper_fprinting_reply_t *reply = NULL;
    uint8_t rec;

    if(dl->dl_ip_off != 0 || state->read == 0) {
        return;
    }
   
   

    /* make sure we want it 
    *  For some ICMP types, sufficient data can be recovered from the datalink itself
    * others will need an more complete icmp inspection (c.f. do_fprinting_handle_icmp)
    */
	if(!( SCAMPER_DL_IS_ICMP_ECHO_REPLY(dl) ||
	      SCAMPER_DL_IS_TCP(dl)             ||
		  SCAMPER_DL_IS_ICMP_UNREACH(dl))   ||
          scamper_addr_cmp(fprinting->src,
          scamper_addrcache_get(addrcache, fprinting->dst->type,
          dl->dl_ip_src)) == 0) {
	    return;
	}
   
    /* consider this reply as valid, we have gone further in our way! */   
    state->pbs_got++;
   

    /* allocate a reply structure for the response */
    if((reply = scamper_fprinting_reply_alloc()) == NULL) {
        printerror(errno, strerror, __func__, "could not alloc fprinting reply");
        goto err;
    }

    /* figure out where the response came from */
    if((reply->addr = scamper_addrcache_get(addrcache, fprinting->dst->type,
                                           dl->dl_ip_src)) == NULL) {
        printerror(errno, strerror, __func__, "could not get reply addr");
        goto err;
    }

    /* put together details of the reply */
    reply->reply_size  = dl->dl_ip_size;
    reply->reply_proto = dl->dl_ip_proto;
    reply->reply_ttl   = dl->dl_ip_ttl;
    reply->os_ttl = two_up(reply->reply_ttl); /* get ittl */
   

    if(SCAMPER_DL_IS_TCP(dl)) {
        scamper_dl_rec_tcp_print(dl);
        reply->tcp_flags = dl->dl_tcp_flags;
        reply->reply_tos = dl->dl_ip_tos;
        reply->reply_df = dl->dl_flags & SCAMPER_DL_IP_FLAG_DF;
        reply->reply_tcp_win = dl->dl_tcp_win;
        reply->reply_tcp_mss = dl->dl_tcp_mss;
    } else if(SCAMPER_DL_IS_ICMP(dl)) {
        scamper_dl_rec_icmp_print(dl);
        reply->icmp_type = dl->dl_icmp_type;
        reply->icmp_code = dl->dl_icmp_code;
    }

    /* we record if we haven't yet anything about this node 
        1 means never seen
        2 means seen and ok
        0 means seen but different */
    rec = fprinting_record(fprinting, reply);
    if(state->dstreached == 0 && scamper_addr_cmp(reply->addr, fprinting->dst) == 0) {
        if(rec == 1)
            state_multi_addr_add(state, reply->addr);
        fprinting_dstreached(task, 1);
    } else if(rec == 1 && SCAMPER_DL_IS_ICMP_TTL_EXP(dl)) {
        state_multi_addr_add(state, reply->addr);
    }

    return;

err:
    fprinting_handleerror(task, 1);
    return;
}

static void do_fprinting_handle_icmp(scamper_task_t *task, scamper_icmp_resp_t *ir) {
    scamper_fprinting_t            *fprinting  = fprinting_getdata(task);
    fprinting_state_t              *state = fprinting_getstate(task);
    scamper_fprinting_reply_t      *reply = NULL;
    scamper_addr_t             addr;
    fprinting_ip_replies_t *ip;
    uint8_t rec;

	if(!(SCAMPER_ICMP_RESP_IS_TIME_REPLY(ir) || SCAMPER_ICMP_RESP_IS_TTL_EXP(ir))) {
		return;
	}
	
	if(scamper_icmp_resp_src(ir, &addr) != 0)
   		goto err;
	
	/* if we sent many probes to the same target, let's record but one of its replies */
	if(state->dstreached == 0) {
	  ip = getValue(fprinting->ip_replies, scamper_addrcache_get
		   (addrcache, addr.type, addr.addr));
		if(SCAMPER_ICMP_RESP_IS_TTL_EXP(ir) && ip && ip->ttlexp)
		 return;
	}

	state->pbs_got++;

	/* allocate a reply structure for the response */
	if((reply = scamper_fprinting_reply_alloc()) == NULL) {
	    printerror(errno, strerror, __func__, "could not alloc fprinting reply");
	    goto err;
    }

    /* figure out where the response came from */

	reply->addr = scamper_addrcache_get(addrcache, addr.type, addr.addr);
	if(reply->addr == NULL)
	    goto err;

	/* put together details of the reply */
	reply->reply_size  = ir->ir_ip_size;
	reply->reply_proto = IPPROTO_ICMP;
	reply->reply_ttl   = ir->ir_ip_ttl;
	reply->os_ttl = two_up(reply->reply_ttl);

	scamper_icmp_resp_print(ir);
	reply->icmp_type = ir->ir_icmp_type;
	reply->icmp_code = ir->ir_icmp_code;
	
	/* add MPLS information */
	if(fprinting->ismpls && SCAMPER_ICMP_RESP_IS_TTL_EXP(ir)){
	    reply->reply_q_ttl = ir->ir_inner_ip_ttl;
		reply->reply_q_tos = ir->ir_inner_ip_tos;
		if(ir->ir_ext != NULL){
		    reply->is_mpls = 1;
		  	if(scamper_icmpext_parse(&reply->reply_ext,
			    ir->ir_ext, ir->ir_extlen) != 0){
      			scamper_fprinting_reply_free(reply);
      			return NULL;
    		}
		}

		else

		    reply->is_mpls = 0;

	}

    /* put the reply into the fprinting table */
    rec = fprinting_record(fprinting, reply);
	if(state->dstreached == 0 && scamper_addr_cmp(reply->addr, fprinting->dst) == 0) {
        if(rec == 1)
            state_multi_addr_add(state, reply->addr);
        fprinting_dstreached(task, 1);
    } else if(rec == 1 && SCAMPER_ICMP_RESP_IS_TTL_EXP(ir)) {
        state_multi_addr_add(state, reply->addr);
    }
	    return;

err:
    if(reply != NULL) scamper_fprinting_reply_free(reply);
        fprinting_handleerror(task, errno);
    return;
}

/* now it's time to send a probe */
static void do_fprinting_probe(scamper_task_t *task) {
    struct timeval   wait_tv;
    scamper_fprinting_t  *fprinting  = fprinting_getdata(task);
    fprinting_state_t    *state = fprinting_getstate(task);
    scamper_probe_t      probe, *probe2;
    fprinting_ip_replies_t *ip;
    uint16_t ipid;
    uint32_t t;

    if(state == NULL) {
        if(fprinting_state_alloc(task) != 0)
            goto err;
        state = fprinting_getstate(task);
        /* timestamp the start time of the fprinting */
        gettimeofday_wrap(&fprinting->start);
    }
    
    
    if(fprinting->ismulti && fprinting->curdsts->next != NULL &&
        state->dstreached &&
        ((state->probe2_c == state->hops_target + 1 || state->addrs == NULL) &&
        (state->pbcount == fprinting->nprobe || state->pbcount == 0))) {
        fprinting_state_free(state);
        state = NULL;
        fprinting->curdsts = fprinting->curdsts->next;
        fprinting->dst = fprinting->curdsts->addr;
        /* insert new node's tllexp: unkonwn in the record */
        ip = calloc(1, sizeof(fprinting_ip_replies_t));
        if(ip == NULL) {
            fprinting_handleerror(task, 4);
            return;
        }
        ip->ttlexp = FRP_BAD;
        ip->alreadyProbed = 0;
        insertElement(fprinting->ip_replies, fprinting->dst, ip);
    }

    if(state == NULL) {
        if(fprinting_state_alloc(task) != 0)
            goto err;
        state = fprinting_getstate(task);
        /* timestamp the start time of the fprinting */
        gettimeofday_wrap(&fprinting->start);
    }

    state->pbs_sent++;

    /* common to all of our probes */
	memset(&probe, 0, sizeof(probe));
    probe.pr_ip_src = fprinting->src;
    probe.pr_ip_dst = fprinting->dst;
    probe.pr_ip_ttl = state->ttl;
	probe.pr_flags = SCAMPER_PROBE_FLAG_IPID;
    if(fprinting->isadf) {
        probe.pr_ip_off  = IP_DF;
    }

	if(state->dstreached == 0) {
        /* we will send but one kind of probe
            based on the mode set for the traceroute */
        probe.pr_ip_id = 7954 - (state->ttl << 8);
	    if(fprinting->pbmode == SCAMPER_DO_FPRINTING_PBTCP) {
			probe.pr_ip_proto = IPPROTO_TCP;
			probe.pr_tcp_sport = fprinting->sport;
			probe.pr_tcp_dport = 80;
			probe.pr_tcp_flags = TH_SYN;
         	probe.pr_tcp_seq = 0;
			probe.pr_tcp_win = 65535;
		} else if(fprinting->pbmode == SCAMPER_DO_FPRINTING_PBECHO) {
			SCAMPER_PROBE_ICMP_ECHO(&probe, 0, 0);
		} else if(fprinting->pbmode == SCAMPER_DO_FPRINTING_PBUDP) {
         probe.pr_ip_proto = IPPROTO_UDP;
         probe.pr_udp_sport = fprinting->sport;
         probe.pr_udp_dport = fprinting->dport + 20000;
      }
      
        /* send probe */
        if(scamper_probe_task(&probe, task) != 0) {
            errno = probe.pr_errno;
            goto err;
        }
	} else {
        /* try no to test multiple times the same routeurs, those at the beginning of the network */
        if(fprinting->ismulti) {
            ip = getValue(fprinting->ip_replies, fprinting->dst);

            if(ip->alreadyProbed == 1){
         
                /* all but ip->ttlexp */
                if(ip && (ip->echo || ip->time || ip->tcp || ip->ptunreach)) {
                    state->probe2_c++;
                    if(!state->dstreached || (state->dstreached && (state->probe2_c == state->hops_target || state->addrs == NULL))) {
                        timeval_add_s(&wait_tv, &probe.pr_tx, 1);
                        scamper_task_queue_wait_tv(task, &wait_tv);
                    } else {
                    scamper_task_queue_probe(task);
                    }
                    return;
                }
            }            
        }
        /* get ready for the good target */
        if(fprinting->isping) {
            state->hops_target = 1;
            state->probe2_c = 0;
        } else {
            if(state->addrs == NULL) {
                goto err_addr;
            }
            /* set the dest address. it will change only when enough probes have been sent */
            probe.pr_ip_dst = state->addrs->addr;
            if(state->pbcount == fprinting->nprobe - 1) {
                state->addrs = state->addrs->next;
                state->pbcount = -1;
            }
        }

        /* send tcp packet for ip/tcp ittl */
        probe.pr_ip_proto = IPPROTO_TCP;
        random_u16(&probe.pr_ip_id);
        probe.pr_tcp_sport = fprinting->sport + state->pbcount;
        probe.pr_tcp_dport = 80;
        probe.pr_tcp_flags = TH_SYN;
        random_u32(&probe.pr_tcp_seq);
        probe.pr_tcp_win = 14600;
        
        if(scamper_probe_task(&probe, task) != 0) {
            errno = probe.pr_errno;
            goto err;
        }


	       
        /* send echo request icmp for echo reply ittl */
        probe2 = probe_dup(&probe);
        uint16_t x;
        random_u16(&x);
        SCAMPER_PROBE_ICMP_ECHO(probe2, x, 1);

        if(scamper_probe_task(probe2, task) != 0) {
            errno = probe2->pr_errno;
            goto err;
        }
        usleep(10000);
     
        
        /* send timestamp request icmp for timestamp reply ittl*/
        probe2 = probe_dup(&probe);
        random_u16(&x);
        SCAMPER_PROBE_ICMP_TIME(probe2, x, 0);
        struct timeval tv;
        gettimeofday_wrap(&tv);
        uint8_t *payload = (uint8_t *)malloc(12 * sizeof(uint8_t));
        memset(payload, 0, 12);
        bytes_htonl(payload,
		    ((tv.tv_sec % 86400) * 1000) + (tv.tv_usec / 1000));
        probe2->pr_data = payload;
        probe2->pr_len = 12;
     
        if(scamper_probe_task(probe2, task) != 0) {
            errno = probe2->pr_errno;
            goto err;
        }
        free(payload);
        usleep(10000);


        /* send udp packet with unlikely port for port unreachable icmp ittl */
        probe2 = probe_dup(&probe);
        probe2->pr_ip_proto = IPPROTO_UDP;
        random_u16(&probe2->pr_ip_id);
        probe2->pr_udp_sport = fprinting->sport;
        probe2->pr_udp_dport = fprinting->dport + 20000;
        if(scamper_probe_task(probe2, task) != 0) {
            errno = probe2->pr_errno;
        goto err;
        }
        usleep(10000);
      

    }


   /* but we will send more to find nodes (before reach), ensure results (after reach) */
    for(ipid = 1; ipid < (state->dstreached? 0 : fprinting->nfind); ipid++) {
        usleep(25000);
        /* if we were asked to send several probes to discover some other
        ways, we vary their ipid and cheksum and send them too.
        but for results relevancy afterwards, we must take the same way */
        if(state->dstreached == 0)
            probe.pr_ip_id += ipid * fprinting->sport;
        if(scamper_probe_task(&probe, task) != 0) {
            errno = probe.pr_errno;
            goto err;
        }
    }

    state->pbcount++;
    /* we go towards dst... but make sure we know the good number of step: 1 step each time pbcount reaches 1 */
    if(state->dstreached && state->pbcount == 1) {
        state->probe2_c++;
    }
    if(!state->dstreached || (state->dstreached && (state->probe2_c == state->hops_target || state->addrs == NULL))) {
        timeval_add_s(&wait_tv, &probe.pr_tx, 1);
        scamper_task_queue_wait_tv(task, &wait_tv);
    } else {
        timeval_add_ms(&wait_tv, &probe.pr_tx, 25);
        scamper_task_queue_wait_tv(task, &wait_tv);
    }
    return;

err:
    fprinting_handleerror(task, 19);
    return;

err_addr:
    fprinting_handleerror(task, 20);
    return;
}

int scamper_do_fprinting_init() {
    fprinting_funcs.probe          = do_fprinting_probe;
    fprinting_funcs.handle_icmp    = do_fprinting_handle_icmp;
    fprinting_funcs.handle_timeout = do_fprinting_handle_timeout;
    fprinting_funcs.handle_dl      = do_fprinting_handle_dl;
    fprinting_funcs.write          = do_fprinting_write;
    fprinting_funcs.task_free      = do_fprinting_free;
    fprinting_funcs.halt           = do_fprinting_halt;

#ifndef _WIN32
    pid = getpid();
#else
    pid = GetCurrentProcessId();
#endif

    return 0;
}
