/*
 * scamper_fprinting.c
 *
 * 2014 Gregoire Mathonet
 * 2017 Florian Hoebreck
 *
 * $Id: scamper_fprinting.c,v 1.0 2017/02/20 23:06:56 mjl Exp $
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
   "$Id: scamper_fprinting.c,v 1.0 2014/06/06 23:06:56 mjl Exp $";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "internal.h"

#include "scamper_icmpext.h"
#include "scamper_addr.h"


#include "scamper_fprinting.h"

#include "utils.h"

#define NONE -1
#define DELETED -2
#define USED -3

struct HASHTABLE {
   DUAL *data; /*!< Pairs key-value */
   size_t lgMax; /*!< Length max */
   size_t lgCurrent; /*!< Current length */

   size_t (*hashFunction)(void *key); /*!< Returns the hash */
   int (*compareFunction)(void *a, void *b); /*!< Compares keys */
};

/**
* \fn static size_t hashFunctionQuadratic(size_t (*hashFunction)(void *key), void *key, const size_t loop, const size_t length)
* \brief This function is a wrapper for the hash function, in order to change the hashed value when loop changes.
*        This function sends the hashed key equiprobally to all places in the array of the table.
*
* \param hashFunction The function that hashes externally.
* \param key The key to be hashed.
* \param loop The number of loop which modifies output.
* \param length The size of the hash table.
*
* \return Hashed value in range 0->length - 1.
*/
static size_t hashFunctionQuadratic(size_t (*hashFunction)(void *key), void *key, const size_t loop, const size_t length);
/**
* \fn static size_t computeRealCapacity(size_t c)
* \brief This function determines the initial capacity. Basically, it is the smallest power of 2 that contains the desired capacity.
*
* \param c The desired capacity.
*
* \return The smallest power of 2 that contains the desired capacity.
*/
static size_t computeRealCapacity(size_t c);
/**
* \fn static void growSize(HASHTABLE *h, void *key, void *value, bool grow)
* \brief This functions changes the size of the table so that it can be more efficient. But it has to rehash all the contained ones.
*  If it is impossible to allocate enough memory, then the former table is not destroyed, and nothing happens.
*
* \param h The hash table on which to work.
* \param key The key to add on success.
* \param value The value to add on success.
* \param grow 1 to increase, 0 to decrease size.
*/
static void growSize(HASHTABLE *h, void *key, void *value, bool grow);
/**
* \fn static void insertElementAt(HASHTABLE *h, void *key, void *value, size_t desired)
* \brief Convenience function for insertion.
*
* \param h The hash table on which to work.
* \param key The key to add.
* \param value The value to add.
* \param desired Where to add (is an index).
*/
static void insertElementAt(HASHTABLE *h, void *key, void *value, size_t desired);

static size_t computeRealCapacity(size_t c) {
   size_t i = 1;
   while(i < c) {
      i *= 2;
   }
   return i;
}

static size_t hashFunctionQuadratic(size_t (*hashFunction)(void *key), void *key, const size_t loop, const size_t length) {
   size_t hash = hashFunction(key);

   hash += (size_t)((float)loop / 2.0 + (float)loop * (float)loop / 2.0);
   hash = hash % length;
   return hash;
}

static void growSize(HASHTABLE *h, void *key, void *value, bool grow) {
   size_t i, to;
   DUAL *hNew, *tmp;

   grow? (h->lgMax *= 2) : (h->lgMax /= 2);
   h->lgCurrent = 0;
   hNew = malloc(h->lgMax * sizeof(DUAL));
   if(!hNew) {
      return;
   }
   memset(hNew, NONE, h->lgMax * sizeof(DUAL));

   /*Swapping memory zones*/
   tmp = h->data;
   h->data = hNew;
   hNew = tmp;

   to = grow? (h->lgMax / 2) : (h->lgMax * 2);
   for(i = 0; i < to; i++) {
      if(hNew[i].spec != NONE && hNew[i].spec != DELETED) {
         insertElement(h, hNew[i].key, hNew[i].value);
      }
   }
   if(key) {
      insertElement(h, key, value);
   }

   free(hNew);
}

static void insertElementAt(HASHTABLE *h, void *key, void *value, size_t desired) {
   h->lgCurrent++;
   h->data[desired].key = key;
   h->data[desired].value = value;
   h->data[desired].spec = USED;
}

HASHTABLE* createHashTable(size_t capacity, size_t (*hashFunction)(void *key), int (*compareFunction)(void *a, void *b)) {
   size_t realCap = computeRealCapacity(capacity);
   HASHTABLE *h = malloc(sizeof(HASHTABLE));
   if(!h) {
      return NULL;
   }

   h->data = malloc(realCap * sizeof(DUAL));
   if(!(h->data)) {
      free(h);
      return NULL;
   }
   memset(h->data, NONE, realCap * sizeof(DUAL));

   h->lgMax = realCap;
   h->lgCurrent = 0;
   h->hashFunction = hashFunction;
   h->compareFunction = compareFunction;
   return h;
}

void freeHashTable(HASHTABLE* hashTable, bool freeKey, bool freeValue) {
   size_t i;

   if(freeValue || freeKey) {
      for(i = 0; i < hashTable->lgMax; i++) {
         if(hashTable->data[i].spec != NONE && hashTable->data[i].spec != DELETED) {
            if(freeKey) {
               free(hashTable->data[i].key);
            }
            if(freeValue && hashTable->data[i].value != NULL) {
               free(hashTable->data[i].value);
            }
         }
      }
   }
   free(hashTable->data);
   free(hashTable);
}

void* insertElement(HASHTABLE* hashTable, void *key, void* value) {
   size_t hash, i = 0, j;
   void *old = NULL;

   if(hashTable->lgCurrent + 1 > hashTable->lgMax >> 1) {
      growSize(hashTable, 0, NULL, true);
   }

   do {
      hash = hashFunctionQuadratic(hashTable->hashFunction, key, i, hashTable->lgMax);
      if(hashTable->data[hash].spec == NONE) {
         insertElementAt(hashTable, key, value, hash);
         return NULL;
      } else if (hashTable->data[hash].spec == DELETED){
         /*We use i to keep the hash value because we need to save hash, and know insertion will be done so far*/
         for(j = i + 1; j < hashTable->lgMax; j++) {
            i = hashFunctionQuadratic(hashTable->hashFunction, key, j, hashTable->lgMax);
            if(hashTable->data[i].spec == NONE) {
               break;
            } else if(!hashTable->compareFunction(hashTable->data[i].key, key)) {
               old = hashTable->data[i].value;
               insertElementAt(hashTable, key, value, i);
               return old;
            }
         }
         insertElementAt(hashTable, key, value, hash);
         return NULL;
      } else if(!hashTable->compareFunction(hashTable->data[hash].key, key)) {
         old = hashTable->data[hash].value;
         insertElementAt(hashTable, key, value, hash);
         hashTable->lgCurrent--;
         return old;
      } else {
         i++;
      }
   } while(i != hashTable->lgMax);
   


   /*We won't ever reach this point as the maximum charge factor is 1/2
     This line would have been meaningful if the max factor was 1.
      If we reached this point, then the table is full,
      This is guaranteed by hashFunctionQuadratic implementation
      growSize(hashTable, key, value, true);
   */
   return NULL;
}

void* removeElement(HASHTABLE* hashTable, void *key) {
   size_t hash, i = 0;
   void *old = NULL;

   do {
      hash = hashFunctionQuadratic(hashTable->hashFunction, key, i, hashTable->lgMax);
      if(hashTable->data[hash].spec != NONE && hashTable->data[hash].spec != DELETED && !hashTable->compareFunction(hashTable->data[hash].key, key)) {
         hashTable->lgCurrent--;
         old = hashTable->data[hash].value;
         hashTable->data[hash].key = (void*)DELETED;
         hashTable->data[hash].value = (void*)NONE;
         hashTable->data[hash].spec = DELETED;

         /*It could have been smaller than size / 4 (max factor 1/2) or size / 2 (max factor 1)
           but this is to be more efficient event of we have to waste some space*/
         if(hashTable->lgMax > 1 && hashTable->lgCurrent < hashTable->lgMax / 8) {
            growSize(hashTable, 0, NULL, false);
         }
         return old;
      } else {
         i++;
      }
   } while(hashTable->data[hash].spec != NONE && i != hashTable->lgMax);
   return NULL;
}

bool hasKeyAndValue(const HASHTABLE* hashTable, void* key, void **out) {
   size_t hash, i = 0;

   do {
      hash = hashFunctionQuadratic(hashTable->hashFunction, key, i, hashTable->lgMax);
      if(hashTable->data[hash].spec != NONE && hashTable->data[hash].spec != DELETED && !hashTable->compareFunction(hashTable->data[hash].key, key)) {
         *out = hashTable->data[hash].value;
         return true;
      } else {
         i++;
      }
   } while(hashTable->data[hash].spec != NONE && i != hashTable->lgMax);
   *out = NULL;
   return false;
}


void* getValue(const HASHTABLE* hashTable, void *key) {
   size_t hash, i = 0;

   do {
      hash = hashFunctionQuadratic(hashTable->hashFunction, key, i, hashTable->lgMax);
      if(hashTable->data[hash].spec != NONE && hashTable->data[hash].spec != DELETED && !hashTable->compareFunction(hashTable->data[hash].key, key)) {
         return hashTable->data[hash].value;
      } else {
         i++;
      }
   } while(hashTable->data[hash].spec != NONE && i != hashTable->lgMax);
   return NULL;
}

DUAL* getElements(const HASHTABLE *h) {
   return h->data;
}

size_t getSize(const HASHTABLE *h) {
   return h->lgMax;
}

/***************************

      OTHER

***************************/

int scamper_fprinting_stats(const scamper_fprinting_t *fprinting, scamper_fprinting_stats_t *stats) {
    scamper_fprinting_reply_t *reply;
    fprinting_ip_replies_t *ip;
    uint16_t i = 0;
    uint32_t n = 0, n2 = 0, n3 = 0, n4 = 0, n5 = 0, n6 = 0, n7 = 0, sum = 0;
    size_t j, l;
    DUAL *els;

    memset(stats, 0, sizeof(scamper_fprinting_stats_t));

    j = getSize(fprinting->ip_replies);
    els = getElements(fprinting->ip_replies);
    for(l = 0; l < j; l++) {
        if(els[l].spec != NONE && els[l].spec != DELETED) {
            ip = (fprinting_ip_replies_t *)els[l].value;
            if(ip == NULL) {
                continue;
            } else {
                i++;
                if(ip->tcp && ip->tcp != (scamper_fprinting_reply_t *)-1) {
                    reply = ip->tcp;
                    n2++;
                    switch(reply->os_ttl) {
                        case 0:
                            stats->nttlsyniap[0]++;
                            break;
                        case 32:
                            stats->nttlsyniap[1]++;
                            break;
                        case 64:
                            stats->nttlsyniap[2]++;
                            break;
                        case 128:
                            stats->nttlsyniap[3]++;
                            break;
                        case 255:
                            stats->nttlsyniap[4]++;
                            break;
                        default:
                            break;
                    }
                    if(reply->reply_tos) {
                        stats->ntos++;
                    }
                    if(reply->reply_df) {
                        stats->ndf++;
                    }
                }
            
                if(ip->echo && ip->echo != (scamper_fprinting_reply_t *)-1) {
                    reply = ip->echo;
                    n3++;
			        switch(reply->os_ttl) {
                        case 0:
                            stats->nttlecho[0]++;
                            break;
                        case 32:
                            stats->nttlecho[1]++;
                            break;
                        case 64:
                            stats->nttlecho[2]++;
                            break;
                        case 128:
                            stats->nttlecho[3]++;
                            break;
                        case 255:
                            stats->nttlecho[4]++;
                            break;
                        default:
                            break;
                    }
                }
            
                if(ip->ttlexp && ip->ttlexp != (scamper_fprinting_reply_t *)-1) {
                    reply = ip->ttlexp;
                    sum += reply->reply_size;
                    n++;
                    switch(reply->os_ttl) {
                        case 0:
                            stats->nttltimeexciap[0]++;
                            break;
                        case 32:
                            stats->nttltimeexciap[1]++;
                            break;
                        case 64:
                            stats->nttltimeexciap[2]++;
                            break;
                        case 128:
                            stats->nttltimeexciap[3]++;
                            break;
                        case 255:
                            stats->nttltimeexciap[4]++;
                            break;
                        default:
                            break;
                    }
                    
                    if(reply->reply_size == 56){
                        stats->timeexc_len[0]++;
                    } else if(reply->reply_size == 68) {
                        stats->timeexc_len[1]++;                       
                    } else if(reply->reply_size == 96) {
                        stats->timeexc_len[2]++;                     
                    } else if(reply->reply_size >= 168) {
                        stats->timeexc_len[3]++;                       
                    } else {
                        stats->timeexc_len[4]++;                        
                    }
                    
                    if(reply->is_mpls)
                        n7++;
                }
                
                if(ip->time && ip->time != (scamper_fprinting_reply_t *)-1) {
                    reply = ip->time;
                    n5++;
			            switch(reply->os_ttl) {
                        case 0:
                            stats->nttlicmptime[0]++;
                            break;
                        case 32:
                            stats->nttlicmptime[1]++;
                            break;
                        case 64:
                            stats->nttlicmptime[2]++;
                            break;
                        case 128:
                            stats->nttlicmptime[3]++;
                            break;
                        case 255:
                            stats->nttlicmptime[4]++;
                            break;
                        default:
                            break;
                    }
                }
            
                if(ip->ptunreach && ip->ptunreach != (scamper_fprinting_reply_t *)-1) {
                    reply = ip->ptunreach;
                    n4++;
			        switch(reply->os_ttl) {
                        case 0:
                            stats->nttludp[0]++;
                            break;
                        case 32:
                            stats->nttludp[1]++;
                            break;
                        case 64:
                            stats->nttludp[2]++;
                            break;
                        case 128:
                            stats->nttludp[3]++;
                            break;
                        case 255:
                            stats->nttludp[4]++;
                            break;
                        default:
                            break;
                    }
                }
            }
        }
    }

    /* here we put the correct number of "unknown" */
    if(fprinting->isping)
        n = 1;
   
    stats->nttlsyniap[0] += (n - n2);
	if(stats->nttlsyniap[0] > 0x0FFFFFFF) {
		stats->nttlsyniap[0] = 0;
	}
	stats->nttlecho[0] += (n - n3);
	if(stats->nttlecho[0] > 0x0FFFFFFF) {
		stats->nttlecho[0] = 0;
	}
	stats->nttludp[0] += (n - n4);
	if(stats->nttludp[0] > 0x0FFFFFFF) {
		stats->nttludp[0] = 0;
	}
	stats->nttlicmptime[0] += (n - n5);
	if(stats->nttlicmptime[0] > 0x0FFFFFFF) {
		stats->nttlicmptime[0] = 0;
	}

    stats->nreplies = i;
	stats->ntcp = n2;
    stats->timeexc_avglen = (n > 0) ? ((float)sum / (float)n) : 0.0f;
    stats->nmpls = n7;

    return 0;
}

scamper_addr_t *scamper_fprinting_addr(const void *va) {
    return ((const scamper_fprinting_t *)va)->dst;
}

scamper_fprinting_t *scamper_fprinting_alloc(void) {
    scamper_fprinting_t *t = malloc_zero(sizeof(scamper_fprinting_t));
    if(t)
        t->ip_replies = createHashTable(200, fprinting_addr_hash, fprinting_addr_cmp);
    return t;
}

void scamper_fprinting_free(scamper_fprinting_t *fprinting) {
    scamper_fprinting_reply_t *reply;
    uint16_t i;

    if(fprinting == NULL) {
        return;
    }

    reply = fprinting->fprinting_replies;
    while(reply != NULL) {
        reply = fprinting->fprinting_replies->next;
        scamper_fprinting_reply_free(fprinting->fprinting_replies);
        fprinting->fprinting_replies = reply;
    }
    if(fprinting->ismulti) {
        while(fprinting->mdsts != NULL) {
            fprinting->curdsts = fprinting->mdsts;
            fprinting->mdsts = fprinting->mdsts->next;
            if(fprinting->curdsts->addr != NULL)
                scamper_addr_free(fprinting->curdsts->addr);
            free(fprinting->curdsts);
        }
    } else {
        if(fprinting->dst != NULL) {
            scamper_addr_free(fprinting->dst);
        }
    }

    if(fprinting->src != NULL) {
        scamper_addr_free(fprinting->src);
    }

    freeHashTable(fprinting->ip_replies, 0, 1);

    free(fprinting);
    return;
}

uint32_t scamper_fprinting_reply_count(const scamper_fprinting_t *fprinting) {
    return fprinting->replyc;
}

scamper_fprinting_reply_t *scamper_fprinting_reply_alloc(void) {
    return (scamper_fprinting_reply_t *)malloc_zero(sizeof(scamper_fprinting_reply_t));
}

void scamper_fprinting_reply_free(scamper_fprinting_reply_t *reply) {
    if(reply->addr != NULL) {
        scamper_addr_free(reply->addr);
    }
    free(reply);
    return;
}

void scamper_fprinting_reply_append(scamper_fprinting_t *fprinting, scamper_fprinting_reply_t *reply) {
    fprinting->replyc++;
    if(fprinting->fprinting_replies == NULL) {
        fprinting->fprinting_replies = reply;
    } else {
        reply->next = fprinting->fprinting_replies;
        fprinting->fprinting_replies = reply;
    }
}

void fprinting_multi_addr_add(scamper_fprinting_t *fprinting, scamper_addr_t *addr) {
    fprinting_multi_addr_t *t = calloc(1, sizeof(fprinting_multi_addr_t));
    if(fprinting->mdsts == NULL) {
        fprinting->mdsts = t;
        fprinting->mdsts->addr = addr;
    } else {
        t->addr = addr;
        t->next = fprinting->mdsts;
        fprinting->mdsts = t;
    }
}

int fprinting_addr_cmp(void *a, void *b) {
    return scamper_addr_cmp((scamper_addr_t *)a, (scamper_addr_t *)b);
}

size_t fprinting_addr_hash(void *a) {
    scamper_addr_t *ad = (scamper_addr_t *)a;
    return ((int)ad->type & (int)ad->addr) | (int)ad->internal;
}

