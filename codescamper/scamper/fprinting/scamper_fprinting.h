/*
 * scamper_fprinting.h
 *
 * $Id: scamper_fprinting.h,v 1.0 2017/02/20 21:53:40 mjl Exp $
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

#ifndef __SCAMPER_FPRINTING_H
#define __SCAMPER_FPRINTING_H

#define fpdbg(x) do{printerror(0, strerror, __func__, x);}while(0)

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


#define SCAMPER_FPRINTING_STOP_NONE      0x00 /* null reason */
#define SCAMPER_FPRINTING_STOP_COMPLETED 0x01 /* sent all probes */
#define SCAMPER_FPRINTING_STOP_ERROR     0x02 /* error occured during ping */
#define SCAMPER_FPRINTING_STOP_HALTED    0x03 /* halted */
#define SCAMPER_FPRINTING_STOP_TIMEOUT   0x04 /* some timeout?? */

#define SCAMPER_DO_FPRINTING_PBTCP       0
#define SCAMPER_DO_FPRINTING_PBECHO      1
#define SCAMPER_DO_FPRINTING_PBUDP       2

#include <stdbool.h>
#include "scamper_icmpext.h"

#define NONE -1
#define DELETED -2
#define USED -3
/**
* \struct DUAL
* \brief Represents a pair key value for a hash table.
*/
typedef struct {
    void *key; /*!< Key */
    void *value; /*!< Value */
    char spec; /*!< Is used? */
} DUAL;
typedef struct HASHTABLE HASHTABLE;

/**
* \fn HASHTABLE* createHashTable(size_t capacity, size_t (*hashFunction)(void *key), int (*compareFunction)(void *a, void *b))
* \brief Creates a hash table that can carry any kinf of pairs key-value.
*
* \param capacity The desired initial capacity.
* \param hashFunction Pointer to a hash function.
* \param compareFunction Pointer to a compare function.
*
* \return Newly allocated HASHTABLE. NULL on failure.
*/
HASHTABLE* createHashTable(size_t capacity, size_t (*hashFunction)(void *key), int (*compareFunction)(void *a, void *b));
/**
* \fn void freeHashTable(HASHTABLE* hashTable, bool freeKey, bool freeValue)
* \brief Frees a HASHTABLE.
*
* \param hashTable The hash table on which to work.
* \param freeKey 1 to free the used keys. 0 otherwise.
* \param freeValue 1 to free the used values. 0 otherwise.
*/
void freeHashTable(HASHTABLE* hashTable, bool freeKey, bool freeValue);
/**
* \fn void* insertElement(HASHTABLE* hashTable, void *key, void* value)
* \brief Inserts an element, overriding it if already present.
*
* \param hashTable The hash table on which to work.
* \param key The key to add.
* \param value The value to add.
*
* \return Old associated value. 0 otherwise.
*/
void* insertElement(HASHTABLE* hashTable, void *key, void* value);
/**
* \fn void* removeElement(HASHTABLE* hashTable, void *key)
* \brief Removes an element from the store.
*
* \param hashTable The hash table on which to work.
* \param key The key to delete.
*
* \return Old associated value. 0 otherwise.
*/
void* removeElement(HASHTABLE* hashTable, void *key);
/**
* \fn bool hasKeyAndValue(const HASHTABLE* hashTable, void* key, void **out)
* \brief Returns whether the key is in and may return the value.
*
* \param hashTable The hash table on which to work.
* \param key The key to check.
* \param out A pointer to receive the value if the key is in. May be NULL.
*
* \return 1 if the key is in. 0 otherwise.
*/
bool hasKeyAndValue(const HASHTABLE* hashTable, void* key, void **out);
/**
* \fn void* getValue(const HASHTABLE* hashTable, void *key)
* \brief Returns the value associated with a key.
*
* \param hashTable The hash table on which to work.
* \param key The key to check.
*
* \return Associated value. 0 otherwise.
*/
void* getValue(const HASHTABLE* hashTable, void *key);
/**
* \fn DUAL* getElements(const HASHTABLE *h)
* \brief Returns the values. Dangerous!!!
*
* \param hashTable The hash table on which to work.
*
* \return Array of values.
*/
DUAL* getElements(const HASHTABLE *h);
/**
* \fn size_t getSize(const HASHTABLE *h)
* \brief Returns the current max size.
*
* \param hashTable The hash table on which to work.
*
* \return Current max size.
*/
size_t getSize(const HASHTABLE *h);


typedef struct fprinting_multi_addr {
    scamper_addr_t *addr;
    struct fprinting_multi_addr *next;
} fprinting_multi_addr_t;
/*
 * scamper_fprinting_reply
 */
typedef struct scamper_fprinting_reply {
   /* where the response came from */
    scamper_addr_t *addr;

    uint8_t reply_proto;

    uint8_t reply_ttl;
    uint8_t os_ttl;
    uint8_t reply_tos;
    uint8_t reply_df;
    uint16_t reply_size;
    uint8_t reply_q_ttl; 
    uint8_t reply_q_tos;
   
    scamper_icmpext_t *reply_ext;
    uint8_t is_mpls;

    /* the icmp type / code returned for first probe */
    uint8_t icmp_type;
    uint8_t icmp_code;

    /* the tcp flags returned for second probe */
    uint8_t tcp_flags;
   
    uint16_t reply_tcp_win;
    uint16_t reply_tcp_mss;

    /* next reply */
    struct scamper_fprinting_reply *next;

} scamper_fprinting_reply_t;

/* used for all replies from same addr */
typedef struct fprinting_ip_replies {
    uint8_t alreadyProbed;
    scamper_fprinting_reply_t *echo, *ptunreach, *time, *ttlexp, *timeexp, *tcp;
} fprinting_ip_replies_t;

/*
 * scamper_fprinting
 */
typedef struct scamper_fprinting {
    /* source and destination addresses of the fprinting */
    scamper_addr_t        *src;
    scamper_addr_t        *dst;
    /* all the dsts */
    fprinting_multi_addr_t *mdsts;
    /* somewhere in all the dsts */
    fprinting_multi_addr_t *curdsts;

    struct timeval        start;
    uint8_t stop_reason;
    uint8_t stop_data;
    uint8_t add_icmp_len;
    uint8_t isipdf;
    uint8_t istos;
    uint8_t ismpls;
    uint8_t isadf;
    uint8_t isping;
	uint8_t pbmode;
    uint8_t ittl;
    uint8_t ismulti;

	uint8_t nfind;
    uint8_t nprobe;

    uint16_t sport;
    uint16_t dport;

    uint32_t               replyc;
    scamper_fprinting_reply_t *fprinting_replies;
    HASHTABLE *ip_replies;
} scamper_fprinting_t;

/* basic routines to allocate and free scamper_fprinting structures */
scamper_fprinting_t *scamper_fprinting_alloc(void);
void scamper_fprinting_free(scamper_fprinting_t *ping);
scamper_addr_t *scamper_fprinting_addr(const void *va);

/* utility function for allocating an array for recording replies */
int scamper_fprinting_replies_alloc(scamper_fprinting_t *ping, int count);

/* basic routines to allocate and free scamper_fprinting_reply structures */
scamper_fprinting_reply_t *scamper_fprinting_reply_alloc(void);
void scamper_fprinting_reply_free(scamper_fprinting_reply_t *reply);
uint32_t scamper_fprinting_reply_count(const scamper_fprinting_t *ping);
/**
* \fn void scamper_fprinting_reply_append(scamper_fprinting_t *fprinting, scamper_fprinting_reply_t *reply)
* \brief Adds a reply to the list of saved replies.
*
* \param fprinting The fprinting struct.
* \param reply The reply to add.
*/
void scamper_fprinting_reply_append(scamper_fprinting_t *fprinting, scamper_fprinting_reply_t *reply);
void fprinting_multi_addr_add(scamper_fprinting_t *fprinting, scamper_addr_t *addr);

int fprinting_addr_cmp(void *a, void *b);
size_t fprinting_addr_hash(void *a);


typedef struct scamper_fprinting_stats {
    uint32_t nreplies;
    uint16_t ntcp;
    uint32_t ntos;
    uint32_t ndf;
    uint32_t nttlsyniap[5];
    uint32_t nttltimeexciap[5];
    uint32_t nttlecho[5];
	uint32_t nttludp[5];
	uint32_t nttlicmptime[5];
	uint32_t timeexc_len[5];
    uint32_t nmpls;
    float timeexc_avglen;
} scamper_fprinting_stats_t;

/**
* \fn int scamper_fprinting_stats(const scamper_fprinting_t *fprinting, scamper_fprinting_stats_t *stats)
* \brief Fills in the stats params once computed.
*
* \param fprinting The fprinting struct.
* \param stats An allocated stats structure.
*
* \return Always zero.
*/
int scamper_fprinting_stats(const scamper_fprinting_t *ping, scamper_fprinting_stats_t *stats);

#endif /* __SCAMPER_FPRINTING_H */
