/*
 * scamper_fprinting_text.c
 *
 * 2014 Gregoire Mathonet
 * 2017 Florian Hoebreck
 *
 * $Id: scamper_fprinting_text.c,v 1.0 2017/02/20 20:40:54 mjl Exp $
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
   "$Id: scamper_fprinting_text.c,v 1.0 2014/06/06 20:40:54 mjl Exp $";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "internal.h"

#include "scamper_addr.h"
#include "scamper_fprinting.h"
#include "scamper_file.h"
#include "scamper_fprinting_text.h"

#include "utils.h"

/* macros to determine response types. for a reason i still don't understand,
   they cannot be read from scamper_fprinting.h... */
#define SCAMPER_FPRINTING_REPLY_IS_ICMP(reply) (        \
 ((reply)->addr->type == SCAMPER_ADDR_TYPE_IPV4 && \
  (reply)->reply_proto == 1) ||                    \
 ((reply)->addr->type == SCAMPER_ADDR_TYPE_IPV6 && \
  (reply)->reply_proto == 58))

#define SCAMPER_FPRINTING_REPLY_IS_TCP(reply) ( \
 ((reply)->reply_proto == 6))

#define SCAMPER_FPRINTING_REPLY_IS_ICMP_ECHO_REPLY(reply) (     \
 ((reply)->addr->type == SCAMPER_ADDR_TYPE_IPV4 &&         \
  (reply)->reply_proto == 1 && (reply)->icmp_type == 0) || \
 ((reply)->addr->type == SCAMPER_ADDR_TYPE_IPV6 &&         \
  (reply)->reply_proto == 58 && (reply)->icmp_type == 129))

#define SCAMPER_FPRINTING_REPLY_IS_ICMP_TTL_EXP(reply) (         \
 ((reply)->addr->type == SCAMPER_ADDR_TYPE_IPV4 &&          \
  (reply)->reply_proto == 1 && (reply)->icmp_type == 11 && (reply)->icmp_code == 0) || \
 ((reply)->addr->type == SCAMPER_ADDR_TYPE_IPV6 &&          \
  (reply)->reply_proto == 58 && (reply)->icmp_type == 3))

#define SCAMPER_FPRINTING_REPLY_IS_ICMP_TIMEF_EXP(reply) (         \
 ((reply)->addr->type == SCAMPER_ADDR_TYPE_IPV4 &&          \
  (reply)->reply_proto == 1 && (reply)->icmp_type == 11 && (reply)->icmp_code == 1) || \
 ((reply)->addr->type == SCAMPER_ADDR_TYPE_IPV6 &&          \
  (reply)->reply_proto == 58 && (reply)->icmp_type == 3))

#define SCAMPER_FPRINTING_REPLY_IS_ICMP_UNREACH(reply) (         \
 ((reply)->addr->type == SCAMPER_ADDR_TYPE_IPV4 &&          \
  (reply)->reply_proto == 1 && (reply)->icmp_type == 3 && (reply)->icmp_code == 3) || \
 ((reply)->addr->type == SCAMPER_ADDR_TYPE_IPV6 &&          \
  (reply)->reply_proto == 58 && (reply)->icmp_type == 1))

#define SCAMPER_FPRINTING_REPLY_IS_ICMP_TSREPLY(reply) ( \
 ((reply)->addr->type == SCAMPER_ADDR_TYPE_IPV4 && \
  (reply)->reply_proto == 1 && (reply)->icmp_type == 14))

/* get a string to represent probe mode */
static char *text_mode(uint8_t m) {
    static char t[4][10] = {"TCP SYN", "ICMP ECHO", "UDP", "UNKNOWN"};
    if(m == SCAMPER_DO_FPRINTING_PBTCP)
        return t[0];
    else if(m == SCAMPER_DO_FPRINTING_PBECHO)
        return t[1];
    else if(m == SCAMPER_DO_FPRINTING_PBUDP)
        return t[2];
    else 
        return t[3];
}

static char *dests_multi(scamper_fprinting_t *fprinting, char *dst) {
    static char ret[] = "SEVERAL IP'S";
    if(fprinting->ismulti == 0)
        return scamper_addr_tostr(fprinting->dst, dst, 64);
    return ret;
}

/* create the text header describing the operation done */
static char *fprinting_header(scamper_fprinting_t *fprinting) {
    char header[192], src[64], dst[64];

    snprintf(header, sizeof(header), "FPRINTING FROM %s TO %s MODE %s (Finding protocol: %s, #Find: %d, #Probe: %d)\n",
            scamper_addr_tostr(fprinting->src, src, sizeof(src)),
            dests_multi(fprinting, dst),
            (fprinting->isping ? "PING" : "TRACEROUTE"), 
				text_mode(fprinting->pbmode), fprinting->nfind, fprinting->nprobe);

    return strdup(header);
}

/* get a string for df */
static char *dfset(uint8_t df) {
	static char names[2][13] = {"[df set]", "[df not set]"};
    if(df) {
        return names[0];
    }
    return names[1];
}

/* get a string for a reply to a probe. the string will depend on reply type */
static char *fprinting_reply(const scamper_fprinting_t *fprinting,
                             const scamper_fprinting_reply_t *reply) {
    char buf[512], a[64];
    uint8_t i;
    size_t off = 0;
    scamper_icmpext_t *ie;
    uint32_t u32 = 0;

    scamper_addr_tostr(reply->addr, a, sizeof(a));

    if(SCAMPER_FPRINTING_REPLY_IS_ICMP_TTL_EXP(reply)) {
        string_concat(buf, sizeof(buf), &off,
                    "as icmp(ttl-exp), %d bytes from %s, ttl=%d. supposed icmp(ttl-exp)-ittl of %s:%d\n",
                    reply->reply_size, a, reply->reply_ttl, a, reply->os_ttl, reply->is_mpls) ;
        if(reply->is_mpls){
            ie = reply->reply_ext;
		    if(SCAMPER_ICMPEXT_IS_MPLS(ie)){
		        for(i=0; i<SCAMPER_ICMPEXT_MPLS_COUNT(ie); i++){
			        u32 = SCAMPER_ICMPEXT_MPLS_LABEL(ie, i);
			        string_concat(buf, sizeof(buf), &off, "%9s ttl: %d, s: %d, exp: %d, label: %d\n",
				                    (i == 0) ? "mpls ext" : "",
				                    SCAMPER_ICMPEXT_MPLS_TTL(ie, i),
				                    SCAMPER_ICMPEXT_MPLS_S(ie, i),
				                    SCAMPER_ICMPEXT_MPLS_EXP(ie, i), u32);
			    }
		    }
        }
      
   } else if(SCAMPER_FPRINTING_REPLY_IS_TCP(reply)) {
        string_concat(buf, sizeof(buf), &off,
                        "as tcp/ip, %d bytes from %s, ttl=%d, tos=%x, . supposed tcp/ip-ittl of %s:%d. win size: %hu. mss size: %hu\n",
                        reply->reply_size, a, reply->reply_ttl, reply->reply_tos,
                        a, reply->os_ttl, reply->reply_tcp_win, reply->reply_tcp_mss);
   } else if(SCAMPER_FPRINTING_REPLY_IS_ICMP_ECHO_REPLY(reply)) {
	    string_concat(buf, sizeof(buf), &off,
                        "as icmp(echo), %d bytes from %s, ttl=%d. supposed icmp(echo)-ittl of %s:%d\n",
                        reply->reply_size, a, reply->reply_ttl, a, reply->os_ttl);
	} else if(SCAMPER_FPRINTING_REPLY_IS_ICMP_TSREPLY(reply)) {
		string_concat(buf, sizeof(buf), &off,
                        "as icmp(timestamp), %d bytes from %s, ttl=%d. supposed icmp(timestamp)-ittl of %s:%d\n",
                        reply->reply_size, a, reply->reply_ttl, a, reply->os_ttl);
	} else if(SCAMPER_FPRINTING_REPLY_IS_ICMP_UNREACH(reply)){		
		string_concat(buf, sizeof(buf), &off,
                        "as icmp(port-unreach), %d bytes from %s, ttl=%d. supposed icmp(port-unreach)-ittl of %s:%d\n",
                        reply->reply_size, a, reply->reply_ttl, a, reply->os_ttl);
   }

   return strdup(buf);
}

/* create a string to explain the created stats */
static char *fprinting_stats(const scamper_fprinting_t *fprinting) {
    scamper_fprinting_stats_t stats;
    size_t off = 0;
    char str[64];
    char buf[1024];
    int rp = 0;

    if(scamper_fprinting_stats(fprinting, &stats) != 0) {
        return NULL;
    }

    string_concat(buf, sizeof(buf), &off, "--- FPRINTING QUICK STATS (BASED ON RECEIVED ANSWERS)---\n");
    string_concat(buf, sizeof(buf), &off,
                 "** icmp time-exp ittl **\n32: %d, 64: %d, 128: %d, 255: %d, unknown: %d\n",
                 stats.nttltimeexciap[1], stats.nttltimeexciap[2], stats.nttltimeexciap[3], stats.nttltimeexciap[4], stats.nttltimeexciap[0]);

    string_concat(buf, sizeof(buf), &off,
                    "** tcp/ip ittl **\n32: %d, 64: %d, 128: %d, 255: %d, unknown: %d\n",
                    stats.nttlsyniap[1], stats.nttlsyniap[2], stats.nttlsyniap[3], stats.nttlsyniap[4], stats.nttlsyniap[0]);

    string_concat(buf, sizeof(buf), &off,
                    "** icmp echo ittl **\n32: %d, 64: %d, 128: %d, 255: %d, unknown: %d\n",
                    stats.nttlecho[1], stats.nttlecho[2], stats.nttlecho[3], stats.nttlecho[4], stats.nttlecho[0]);
    string_concat(buf, sizeof(buf), &off,
                    "** icmp timestamp ittl **\n32: %d, 64: %d, 128: %d, 255: %d, unknown: %d\n",
                    stats.nttlicmptime[1], stats.nttlicmptime[2], stats.nttlicmptime[3], stats.nttlicmptime[4], stats.nttlicmptime[0]);
                    
    string_concat(buf, sizeof(buf), &off,
                    "** icmp port-unreach ittl **\n32: %d, 64: %d, 128: %d, 255: %d, unknown: %d\n",
                    stats.nttludp[1], stats.nttludp[2], stats.nttludp[3], stats.nttludp[4], stats.nttludp[0]);
    if(fprinting->isipdf) {
        string_concat(buf, sizeof(buf), &off, "%d IP_DF set (%f %%)\n", stats.ndf, 100.0f * (float)stats.ndf/(float)stats.ntcp);
    }
    if(fprinting->istos) {
        string_concat(buf, sizeof(buf), &off, "%d IP_TOS not null (%f %%)\n", stats.ntos, 100.0f * (float)stats.ntos/(float)stats.ntcp);
    }
    if(fprinting->add_icmp_len) {
        string_concat(buf, sizeof(buf), &off, "** icmp time_exceeded packet length **\n56: %d, 68: %d, 96: %d, >=168(mpls) : %d, other: %d\n",
                        stats.timeexc_len[0], stats.timeexc_len[1], stats.timeexc_len[2], stats.timeexc_len[3], stats.timeexc_len[4]);
        string_concat(buf, sizeof(buf), &off, "icmp time-exceeded packet avg len: %f bytes\n", stats.timeexc_avglen);
    }
    
    if(fprinting->ismpls){
        string_concat(buf, sizeof(buf), &off, "%d icmp time_exceeded packets contain at least one label MPLS (%f %%)\n", 
                        stats.nmpls, 100.0f * (float)stats.nmpls/(float)stats.nreplies);
    }

    return strdup(buf);
}

/* write out all of our strings */
int scamper_file_text_fprinting_write(const scamper_file_t *sf,
                                      const scamper_fprinting_t *fprinting) {
    scamper_fprinting_reply_t *reply;
    int       fd          = scamper_file_getfd(sf);
    off_t     off         = 0;
    uint32_t  reply_count = scamper_fprinting_reply_count(fprinting);
    char     *header      = NULL;
    size_t    header_len  = 0;
    char    **replies     = NULL;
    size_t   *reply_lens  = NULL;
    char     *stats       = NULL;
    size_t    stats_len   = 0;
    char     *str         = NULL;
    size_t    len         = 0;
    size_t    wc          = 0;
    int       ret         = -1;
    uint32_t  i;

    /* get current position incase trunction is required */
    if(fd != 1 && (off = lseek(fd, 0, SEEK_CUR)) == -1) {
        return -1;
    }

    /* get the header string */
    if((header = fprinting_header(fprinting)) == NULL) {
        goto cleanup;
    }
    len = (header_len = strlen(header));

    /* put together a string for each reply */
    if(reply_count > 0) {
        if((replies    = malloc_zero(sizeof(char *) * reply_count)) == NULL ||
            (reply_lens = malloc_zero(sizeof(size_t) * reply_count)) == NULL) {
            goto cleanup;
        }

        i = 0;
        reply = fprinting->fprinting_replies;
        while(reply != NULL) {
            if((replies[i] = fprinting_reply(fprinting, reply)) == NULL) {
                goto cleanup;
            }
            len += (reply_lens[i] = strlen(replies[i]));
            reply = reply->next;
            i++;
        }
    }

    /* put together the summary stats */
    stats = fprinting_stats(fprinting);
    if(stats != NULL) {
        len += (stats_len = strlen(stats));
    }

    /* allocate a string long enough to combine the above strings */
    if((str = malloc(len)) == NULL) {
        goto cleanup;
    }

    /* combine the strings created above */
    memcpy(str + wc, header, header_len); wc += header_len;
    for(i = 0; i < reply_count; i++) {
        memcpy(str + wc, replies[i], reply_lens[i]);
        wc += reply_lens[i];
    }

    if(stats != NULL) {
        memcpy(str + wc, stats, stats_len);
        wc += stats_len;
    }

    /*
    * try and write the string to disk.  if it fails, then truncate the
    * write and fail
    */
    if(write_wrap(fd, str, &wc, len) != 0) {
        if(fd != 1) {
            if(ftruncate(fd, off) != 0) {
                goto cleanup;
            }
        }
        goto cleanup;
    }

    ret = 0; /* we succeeded */

cleanup:
    if(str != NULL) {
        free(str);
    }
    if(header != NULL) {
        free(header);
    }
    if(stats != NULL) {
        free(stats);
    }
    if(reply_lens != NULL) {
        free(reply_lens);
    }
    if(replies != NULL) {
        for(i = 0; i < reply_count; i++)
            if(replies[i] != NULL) {
                free(replies[i]);
            }
        free(replies);
    }

    return ret;
}
