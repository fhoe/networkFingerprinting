/*
 * scamper_file_text_tracebox.c
 *
 *
 *
 * @author: K.Edeline
 */

#ifndef lint
static const char rcsid[] =
  "$Id";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "internal.h"

#include <string.h>

#include "scamper_addr.h"
#include "scamper_list.h"
#include "scamper_file.h"
#include "scamper_tracebox.h"
#include "scamper_tracebox_text.h"
#include "scamper_debug.h"
#include "utils.h"


#define TRACEBOX_MAX_TCP_OPTIONS 64

static const int modes_len = 7;
static const char *modes[] = {
"standard",
"frags",
"full-icmp",
NULL, // ! //
"proxy",
"statefull",
"simplified-output",
};

/*
 * max tcp options type number
 */
static const int tcp_options_max = 30;
static const char *tcp_options[] = {
"EOL",
"NOP",
"MSS",
"WSOPT-WindowScale",
"SACKPermitted",
"SACK",
"Echo",
"EchoReply",
"TSOPT-TimeStampOption",
"PartialOrderConnectionPermitted",
"PartialOrderServiceProfile",
"CC",
"CC.NEW",
"CC.ECHO",
"TCPAlternateChecksumRequest",
"TCPAlternateChecksumData",
"Skeeter",
"Bubba",
"TrailerChecksumOption",
"MD5SignatureOption",
"SCPSCapabilities",
"SelectiveNegativeAck",
"RecordBoundaries",
"CorruptionExperienced",
"SNAP",
NULL,	
"TCPCompressionFilter",
"Quick-StartResponse",
"UserTimeoutOption",
"TCPAuthenticationOption",
"MultipathTCP",
};

static const int fields_len = 37;
static const char *fields[] = {
 "TCP::AckNumber", 
 "TCP::Offset",
 "TCP::Reserved",
 "TCP::Flags",
 "TCP::Window",
 "TCP::Checksum",
 "TCP::UrgentPtr",
 "TCP::SPort",
 "TCP::DPort",
 "TCP::SeqNumber",
 "UDP::SPort",     /* 10 */
 "UDP::DPort",
 "UDP::Length",
 "UDP::Checksum",
 "IPv6::Version",
 "IPv6::DiffServicesCP", /* 15 */
 "IPv6::ECN",
 "IPv6::FlowLabel",
 "IPv6::PayloadLength",
 "IPv6::NextHeader",
 "IPv6::HopLimit", /* 20 */
 "IPv6::SourceAddr",
 "IPv6::DestAddr",
 "IP::Version",
 "IP::IHL",
 "IP::DiffServicesCP", /* 25 */
 "IP::ECN",
 "IP::Length",
 "IP::ID",
 "IP::Flags",   
 "IP::FragmentOffset",	/* 30 */
 "IP::TTL",
 "IP::Protocol",
 "IP::Checksum",
 "IP::SourceAddr",
 "IP::DestAddr",
 "TCP::Options",
};

static uint8_t fields_size[] = {
 4,//"TCP::AckNumber", 
 1,//"TCP::Offset",
 1,//"TCP::Reserved",
 1,//"TCP::Flags",
 2,//"TCP::Window",
 2,//"TCP::Checksum", 
 2,//"TCP::UrgentPtr",
 2,//"TCP::SPort",
 2,//"TCP::DPort",
 4,//"TCP::SeqNumber",
 2,//"UDP::SPort",     /* 10 */
 2,//"UDP::DPort",
 2,//"UDP::Length",
 2,//"UDP::Checksum",
 1,//"IPv6::Version",
 1,//"IPv6::DiffServicesCP",
 1,//"IPv6::ECN",
 3,//"IPv6::FlowLabel",
 2,//"IPv6::PayloadLength",
 1,//"IPv6::NextHeader",
 1,//"IPv6::HopLimit", /* 20 */
 16,//"IPv6::SourceAddr",
 16,//"IPv6::DestAddr",
 1,//"IP::Version",
 1,//"IP::IHL",
 1,//"IP::DiffServicesCP",
 1,//"IP::ECN",
 2,//"IP::Length",
 2,//"IP::ID",
 1,//"IP::Flags",   
 2,//"IP::FragmentOffset",	/* 30 */
 1,//"IP::TTL",
 1,//"IP::Protocol",
 2,//"IP::Checksum",
 4,//"IP::SourceAddr",
 4,//"IP::DestAddr",
 255, // TCP::OPTIONS /!
};

static const int tcp_fields_len = 10;
static const char *tcp_fields[] = {
 "TCP::AckNumber",
 "TCP::Offset",
 "TCP::Reserved",
 "TCP::Flags",
 "TCP::Window",
 "TCP::Checksum",
 "TCP::UrgentPtr",
 "TCP::SPort",
 "TCP::DPort",
 "TCP::SeqNumber",
};

static const int udp_fields_len = 4;
static const char *udp_fields[] = {
 " UDP::SPort",
 " UDP::DPort",
 " UDP::Length",
 " UDP::Checksum",
};

static const int ipv6_fields_len = 9;
static const char *ipv6_fields[] = {
 " IPv6::Version",
 " IPv6::DiffServicesCP",
 " IPv6::ECN",
 " IPv6::FlowLabel",
 " IPv6::PayloadLength",
 " IPv6::NextHeader",
 " IPv6::HopLimit",
 " IPv6::SourceAddr",
 " IPv6::DestAddr",
};

static const int ipv4_fields_len = 13;
static const char *ipv4_fields[] = {
 "IP::Version",
 "IP::IHL",
 "IP::DiffServicesCP",
 "IP::ECN",
 "IP::Length",
 "IP::ID",
 "IP::Flags",   
 "IP::FragmentOffset",	
 "IP::TTL",
 "IP::Protocol",
 "IP::Checksum",
 "IP::SourceAddr",
 "IP::DestAddr",
};

static int scamper_file_text_tracebox_write_standard(const scamper_tracebox_t *tracebox,char *buf, size_t bufsize, size_t *soff) {

  scamper_tracebox_pkt_t *pkt, *prev_pkt = NULL; 

  char addr[64], *cmp_result;
  struct timeval diff;
  uint32_t i, seq, ack, off;
  uint16_t len;
  uint8_t proto, flags, type, iphlen, tcphlen, *ptr, ttl, v, prev_query = 0, synacked = 0;
  int frag, counter = 1; 

 for(i=0; i<tracebox->pktc; i++)
    {
      pkt = tracebox->pkts[i];
      off = 0;v = 0;

      if(((pkt->data[0] & 0xf0) >> 4) == 4)
        {
          v = 4;
	  iphlen = (pkt->data[0] & 0xf) * 4;
	  len = bytes_ntohs(pkt->data+2);
	  proto = pkt->data[9];
          ttl=pkt->data[8];
	  off = (bytes_ntohs(pkt->data+6) & 0x1fff) * 8;
        }
      else if(((pkt->data[0] & 0xf0) >> 4) == 6)
        {
          v = 6;
	      iphlen = 40;
	      len = bytes_ntohs(pkt->data+4) + iphlen;
	      proto = pkt->data[6];
          ttl= pkt->data[7];   
        } else {
            string_concat(buf, bufsize, soff, " erroneous packet\n");
            //continue;
            return;
        }
       int ip_start, trans_start, dlen;
       if (synacked) {
            string_concat(buf, bufsize, soff, " erroneous packet\n");
            //continue;
            return;
       }
       if(proto == IPPROTO_TCP)
        {
	      flags   = pkt->data[iphlen+13];
	      tcphlen = ((pkt->data[iphlen+12] & 0xf0) >> 4) * 4;

	      if(flags & 0x02) {
                  
	          if(flags & 0x10) {//SYNACK

                      if (v == 4) {
                        scamper_addr_t *a=scamper_addr_alloc(SCAMPER_ADDR_TYPE_IPV4,pkt->data+12);
		                scamper_addr_tostr(a,addr,sizeof(addr));
                        scamper_addr_free(a);
                     } else if (v == 6) {
                        scamper_addr_t *a=scamper_addr_alloc(SCAMPER_ADDR_TYPE_IPV6,pkt->data+8);
		                scamper_addr_tostr(a,addr,sizeof(addr));
                        scamper_addr_free(a);
                     }
                      
                      cmp_result = compute_differences(tracebox, prev_pkt->data, pkt->data,
						    SCAMPER_TRACEBOX_ANSWER_SYNACK, v, proto);
                      string_concat(buf, bufsize, soff, " %s", addr);
                      if (tracebox->rtt) 
                        string_concat(buf, bufsize, soff, " RTT:%.4f",
                         (((pkt->tv.tv_sec - prev_pkt->tv.tv_sec)*1000000L+pkt->tv.tv_usec) - prev_pkt->tv.tv_usec)/1000.0);
                      if (cmp_result) {
                        string_concat(buf, bufsize, soff, cmp_result);
                        free(cmp_result);
                      }
                      synacked=1;
                  } else if (!(flags & 0x01) && !(flags & 0x04)) {//SYN

                      if (prev_query) {
                        string_concat(buf, bufsize, soff, " *\n");
                        counter++;
                      }
                      if (counter<10) string_concat(buf, bufsize, soff, " ", counter); //alignment
                      string_concat(buf, bufsize, soff, " %d:", counter);
                      prev_pkt = pkt;

                      prev_query=(pkt->dir == SCAMPER_TRACEBOX_PKT_DIR_TX);
                      continue;
                  }  else {
                      string_concat(buf, bufsize, soff, " erroneous packet\n");
                        //continue;
                        return;

                  }
          } else if(flags & 0x01)
	        string_concat(buf, bufsize, soff, " FIN");
	      else if(flags & 0x04)
	        string_concat(buf, bufsize, soff, " RST");
          else {
            string_concat(buf, bufsize, soff, " erroneous packet\n");
            //continue;
            return;
        }

      } else if(proto == IPPROTO_ICMP) {
          prev_query=0;

          uint8_t icmp_type = pkt->data[iphlen];
          uint8_t icmp_code = pkt->data[iphlen+1];
          ip_start    = iphlen+8;
          trans_start = ip_start+20;
          dlen        = len-ip_start;

          if (icmp_type == 11 && icmp_code == 0) {

            scamper_addr_t *a=scamper_addr_alloc(SCAMPER_ADDR_TYPE_IPV4,pkt->data+12);
            scamper_addr_tostr(a,addr,sizeof(addr));
            scamper_addr_free(a);
            string_concat(buf, bufsize, soff, " %s ", addr);

            if (len-ip_start <= 0) {
              type = SCAMPER_TRACEBOX_ANSWER_EMPTY;
              if (tracebox->icmp_quote_type)
                string_concat(buf, bufsize, soff, "(0)");
            }else if (len-trans_start <= 0) {
              type = SCAMPER_TRACEBOX_ANSWER_ONLY_L3;
              if (tracebox->icmp_quote_type)
                string_concat(buf, bufsize, soff, "(L3)");
            }else if (len-trans_start == 8) {
              type = SCAMPER_TRACEBOX_ANSWER_8B;
              if (tracebox->icmp_quote_type)
                string_concat(buf, bufsize, soff, "(8B)");
            }else {
              type = SCAMPER_TRACEBOX_ANSWER_FULL;
              if (tracebox->icmp_quote_type)
                string_concat(buf, bufsize, soff, "(full)");
            }
            
            if (tracebox->rtt) 
              string_concat(buf, bufsize, soff, " RTT:%.4f",
               (((pkt->tv.tv_sec - prev_pkt->tv.tv_sec)*1000000L+pkt->tv.tv_usec) - prev_pkt->tv.tv_usec)/1000.0);
            cmp_result = compute_differences(tracebox, prev_pkt->data, &(pkt->data[ip_start]),
						type, v, tracebox->udp ? IPPROTO_UDP : IPPROTO_TCP);
            if (cmp_result) {
                    string_concat(buf, bufsize, soff, cmp_result);
                    free(cmp_result);
            }
        } else if (icmp_type == 3) { // dest unreachable
            string_concat(buf, bufsize, soff, "Destination unreachable\n");
	    } else {
            string_concat(buf, bufsize, soff, " erroneous packet\n");
            //continue;
            return;
        }

       } else if(proto == IPPROTO_UDP) {
                   
	     if (prev_query) {
               string_concat(buf, bufsize, soff, " *\n");
               counter++;
             }
         if (counter<10) string_concat(buf, bufsize, soff, " ", counter); //alignment
         string_concat(buf, bufsize, soff, " %d:", counter);

         prev_pkt = pkt;
         prev_query=(pkt->dir == SCAMPER_TRACEBOX_PKT_DIR_TX);

         continue;
      } else if(proto == IPPROTO_ICMPV6) {
          prev_query=0;

          uint8_t type = pkt->data[iphlen];
          uint8_t code = pkt->data[iphlen+1];
          ip_start    = iphlen+8;
          trans_start = ip_start+40;
          dlen        = len-ip_start;

          if (type == 3 && code == 0) {//hop limit exceeded in transit
            scamper_addr_t *a=scamper_addr_alloc(SCAMPER_ADDR_TYPE_IPV6,pkt->data+8);
            scamper_addr_tostr(a,addr,sizeof(addr));
            scamper_addr_free(a);
            string_concat(buf, bufsize, soff, " %s ", addr);

            if (len-ip_start <= 0) {
              type = SCAMPER_TRACEBOX_ANSWER_EMPTY;
              if (tracebox->icmp_quote_type)
                string_concat(buf, bufsize, soff, "(0)");
            }else if (len-trans_start <= 0){
              type = SCAMPER_TRACEBOX_ANSWER_ONLY_L3;
              if (tracebox->icmp_quote_type)
                string_concat(buf, bufsize, soff, "(L3)");
            }else if (len-trans_start == 8) {
              type = SCAMPER_TRACEBOX_ANSWER_8B;
              if (tracebox->icmp_quote_type)
                string_concat(buf, bufsize, soff, "(8B)");
            }else {
              type = SCAMPER_TRACEBOX_ANSWER_FULL;
              if (tracebox->icmp_quote_type)
                string_concat(buf, bufsize, soff, "(full)");
            }
            if (tracebox->rtt) 
              string_concat(buf, bufsize, soff, " RTT:%.4f",
              (((pkt->tv.tv_sec - prev_pkt->tv.tv_sec)*1000000L+pkt->tv.tv_usec) - prev_pkt->tv.tv_usec)/1000.0);
            cmp_result = compute_differences(tracebox, prev_pkt->data, &(pkt->data[ip_start]),
						type, v, tracebox->udp ? IPPROTO_UDP : IPPROTO_TCP);
            if (cmp_result) {
                    string_concat(buf, bufsize, soff, cmp_result);
                    free(cmp_result);
            }
          }
        } else if (type == 1) { // dest unreachable
            string_concat(buf, bufsize, soff, "Destination unreachable\n");
	    } else {
            string_concat(buf, bufsize, soff, " erroneous packet\n");
            //continue;
            return;
        }

      string_concat(buf, bufsize, soff, "\n");
      counter++;
      prev_pkt = pkt;
    }
  
  /* if no answer for last query */
  if (tracebox->result == SCAMPER_TRACEBOX_RESULT_TIMEOUT)
  	string_concat(buf, bufsize, soff, " *\n");
  else if (tracebox->result == SCAMPER_TRACEBOX_RESULT_TIMEOUT)

  return 0;
}

static int scamper_file_text_tracebox_write_full_icmp(const scamper_tracebox_t *tracebox,char *buf, size_t bufsize, size_t *soff) {
scamper_tracebox_pkt_t *pkt; 

  char addr[64];
  uint32_t i;
  uint16_t len;
  uint8_t proto,iphlen, tcphlen, ttl, v, last_ttl;

 for(i=0; i<tracebox->pktc; i++)
   {
      pkt = tracebox->pkts[i];
      v = 0;

      if(((pkt->data[0] & 0xf0) >> 4) == 4) {
          v = 4;
	  iphlen = (pkt->data[0] & 0xf) * 4;
	  len = bytes_ntohs(pkt->data+2);
	  proto = pkt->data[9];
          ttl=pkt->data[8];
      } else if(((pkt->data[0] & 0xf0) >> 4) == 6) {
          v = 6;
	  iphlen = 40;
	  len = bytes_ntohs(pkt->data+4) + iphlen;
	  proto = pkt->data[6];
          ttl= pkt->data[7];   
      } else continue;

      if(proto == IPPROTO_TCP || proto == IPPROTO_UDP) last_ttl=ttl;
      else if(proto == IPPROTO_ICMP) {

          uint8_t type = pkt->data[iphlen];
          uint8_t code = pkt->data[iphlen+1];
          if (type == 11 && code == 0) {

            int ip_start    = iphlen+8;
            int trans_start = ip_start+20;

           if (len-trans_start > 8) { 
             scamper_addr_t *a=scamper_addr_alloc(SCAMPER_ADDR_TYPE_IPV4,pkt->data+12);
             scamper_addr_tostr(a,addr,sizeof(addr));
             scamper_addr_free(a);

             string_concat(buf, bufsize, soff, " %d: %s\n",last_ttl, addr); 
           }
          }

        } else if(proto == IPPROTO_ICMPV6) {

          uint8_t type = pkt->data[iphlen];
          uint8_t code = pkt->data[iphlen+1];
          if (type == 3 && code == 0) {//hop limit exceeded in transit

            int ip_start    = iphlen+8;
            int trans_start = ip_start+40;
          
            if (len-trans_start > 8) {
             scamper_addr_t *a=scamper_addr_alloc(SCAMPER_ADDR_TYPE_IPV6,pkt->data+8);
             scamper_addr_tostr(a,addr,sizeof(addr));
             scamper_addr_free(a);
              string_concat(buf, bufsize, soff, " %d: %s\n",last_ttl, addr); 
            }
          }
       }
    }

  return 0;
}

static uint8_t **parse_packet(const uint8_t network, const uint8_t transport, const uint8_t type, const uint8_t *pkt) {
  int transoff = (network == 4) ? 20 : 40;
  uint8_t **ppkt = malloc(fields_len * sizeof(uint8_t*)), i;
  for (i=0;i<fields_len-1;i++)
    ppkt[i]=calloc(fields_size[i],sizeof(uint8_t));
  ppkt[fields_len-1]=NULL;

  switch(type)  {
    case SCAMPER_TRACEBOX_ANSWER_FULL:
      if (transport == IPPROTO_TCP) {

        for(i=8;i<12;i++) ppkt[0][i-8] = pkt[transoff];
        ppkt[1][0] = (pkt[transoff+12] & 0xf0) >> 4; 
        ppkt[2][0] = pkt[transoff+12] & 0x0f;        
        ppkt[3][0] = pkt[transoff+13];
        ppkt[4][0] = pkt[transoff+14]; ppkt[4][1] = pkt[transoff+15];
        ppkt[5][0] = pkt[transoff+16]; ppkt[5][1] = pkt[transoff+17];
        ppkt[6][0] = pkt[transoff+18]; ppkt[6][1] = pkt[transoff+19];

        uint8_t tcp_opt_bytes = (ppkt[1][0] - 5)*4;
        fields_size[fields_len-1] = tcp_opt_bytes;
        if (tcp_opt_bytes>0) {
          int optoff = transoff+20;
          ppkt[fields_len-1] = calloc(tcp_opt_bytes,sizeof(uint8_t));
          for(i=0;i<tcp_opt_bytes;i++) ppkt[fields_len-1][i] = pkt[optoff+i]; //
        }
      }     
    case SCAMPER_TRACEBOX_ANSWER_8B:
      if (transport == IPPROTO_TCP) {
        ppkt[7][0] = pkt[transoff];  ppkt[7][1] = pkt[transoff+1];
        ppkt[8][0] = pkt[transoff+2];ppkt[8][1] = pkt[transoff+3];
        for(i=4;i<8;i++) ppkt[9][i-4] = pkt[transoff+i];
      } else if (transport == IPPROTO_UDP) {
        ppkt[10][0] = pkt[transoff];  ppkt[10][1] = pkt[transoff+1];
        ppkt[11][0] = pkt[transoff+2];ppkt[11][1] = pkt[transoff+3];
        ppkt[12][0] = pkt[transoff+4];ppkt[12][1] = pkt[transoff+5];
        ppkt[13][0] = pkt[transoff+6];ppkt[13][1] = pkt[transoff+7];     
      }  
    case SCAMPER_TRACEBOX_ANSWER_ONLY_L3:
      if (network == 4) {
        (ppkt[23][0] = pkt[0] & 0xf0) >> 4;
        ppkt[24][0] = pkt[0] & 0x0f;
        ppkt[25][0] = (pkt[1] & 0xfc) >> 2;
        ppkt[26][0] = pkt[1] & 0x03;   
        ppkt[27][0] = pkt[2]; ppkt[27][1] = pkt[3];
        ppkt[28][0] = pkt[4]; ppkt[28][1] = pkt[5];
        ppkt[29][0] = (pkt[6] & 0xe0) >> 5;   
        ppkt[30][0] = pkt[6] & 0x1f; 
        ppkt[30][1] = pkt[7];  
        ppkt[31][0] = pkt[8];   
        ppkt[32][0] = pkt[9];  
        ppkt[33][0] = pkt[10]; ppkt[33][1] = pkt[11];  
        for(i=12;i<16;i++) ppkt[34][i-12] = pkt[i];
        for(i=16;i<20;i++) ppkt[35][i-16] = pkt[i]; 
      } else if (network == 6) {
        ppkt[14][0] = (pkt[0] & 0xf0) >> 4;
        ppkt[15][0] = ((pkt[0] & 0x0f)<<2) | ((pkt[1] & 0xc0)>>6);
        ppkt[16][0] = (pkt[1] & 0x30)>>4;
        ppkt[17][0] = pkt[1] & 0x0f;
        ppkt[17][1] = pkt[2]; ppkt[17][2] = pkt[3];
        ppkt[18][0] = pkt[4]; ppkt[18][1] = pkt[5];
        ppkt[19][0] = pkt[6];
        ppkt[20][0] = pkt[7];
        for(i=8;i<24;i++) ppkt[21][i-8] = pkt[i];
        for(i=24;i<40;i++) ppkt[22][i-24] = pkt[i];
      }
    default:
      break;         
  }
  
  return ppkt;
}

static void free_array(uint8_t **ppkt, int len) {
  if (!ppkt) return;
  uint8_t i;
  for (i=0;i<len;i++) {
    if (ppkt[i]) free(ppkt[i]);
  }
  free(ppkt);
}

/* return the address of the last router that did include the specified field in the icmp ttl expired
 *
 */
static char *last_observed_value(uint8_t *dlens, char **addrs, uint8_t index, uint8_t field) {
  
  int i;
  uint8_t min_type;
  
  if      (field>=14) min_type = SCAMPER_TRACEBOX_ANSWER_ONLY_L3;
  else if (field>=7)  min_type = SCAMPER_TRACEBOX_ANSWER_8B; 
  else                min_type = SCAMPER_TRACEBOX_ANSWER_FULL;

  for(i=index;i>=0;i--) {
    if (dlens[i] >= min_type) return addrs[i];
  }

  return "you";
}

/* returns [[len1,len2,len3],[modified options list], [removed options list], [added options list]]
 *
 * optlist1 : previous last received (or sent) value
 * optlist2 : received value
 *
 *
 */
static uint8_t **compare_tcp_opt(const uint8_t *optlist1, const uint8_t *optlist2, uint8_t llen1, uint8_t llen2) {
  uint8_t **diff = malloc(4*sizeof(uint8_t*));
  int i, j=0, found = 0, modified = 0, len1, len2;
  diff[0]=calloc(3,1);
  for (i=1;i<4;i++) 
    diff[i]= calloc(TRACEBOX_MAX_TCP_OPTIONS,1);
  
  uint8_t opt_list[TRACEBOX_MAX_TCP_OPTIONS], opt_count=0;
  for (opt_count=0;opt_count<TRACEBOX_MAX_TCP_OPTIONS;opt_count++)
    opt_list[opt_count]=0;
  opt_count=0;i=0;
        
  while (i<llen1) {
    uint8_t type1 = optlist1[i];
    switch (type1) {
      case 0x00:
      case 0x01:
         i++;    
         break;
      case 0x02:case 0x03:case 0x04:case 0x05:case 0x06:case 0x07: 
      case 0x08:case 0x09:case 0x0a:case 0x0b:case 0x0c:case 0x0d:
      case 0x0e:case 0x0f:case 0x10:case 0x11:case 0x12:case 0x13:
      case 0x14:case 0x15:case 0x16:case 0x17:case 0x18:case 0x19:
      case 0x1b:case 0x1c:case 0x1d:case 0x1e:
         j = 0;found = 0; modified = 0;
         len1 = optlist1[i+1];
         opt_list[opt_count++] = type1;

         while (j<llen2) {
            uint8_t type2 = optlist2[j];
            switch (type2) {
              case 0x00:case 0x01:
                j++;
                break;
              case 0x02:case 0x03:case 0x04:case 0x05:case 0x06:case 0x07: 
              case 0x08:case 0x09:case 0x0a:case 0x0b:case 0x0c:case 0x0d:
              case 0x0e:case 0x0f:case 0x12:case 0x13:
              case 0x14:case 0x15:case 0x16:case 0x17:case 0x18:case 0x19:
              case 0x1b:case 0x1c:case 0x1d:case 0x1e:
                len2 = optlist2[j+1];
                 if (!len2) len2++;
                 if (type2 == type1) {//same tcpopt, cmp content
                   int k=0; 
                   found = 1;
                   if (len1 != len2) modified = 1; //diff length => diff content
                   else {//compare byte p byte
                     for (k=0;k<len1;k++) {
                       if (optlist1[i+k] != optlist2[j+k]) {
                         modified = 1;
                         break;
                       }
                     }

                     if (k==len1) { 
                       modified = 0;
                       j=llen2;
                     } 
                   }                    
                 } 

                 j+=len2;                                        
                 break;
               default:
                 j++;
                 break;             

             }
           } // end loop 2

           if (!found) diff[2][diff[0][1]++]=type1;
           if (modified) diff[1][diff[0][0]++]=type1;

           i+=len1;
           break;
        default://should never happen
           i++;
           break;             

       }  // end tcpopt1 switch
    } // end loop 1
 
    // new options ?
    j = 0;
    while (j<llen2) {
      uint8_t type2 = optlist2[j];
      switch (type2) {
        case 0x00:
        case 0x01:
          j++;    
          break;
        case 0x02:case 0x03:case 0x04:case 0x05:case 0x06:case 0x07: 
        case 0x08:case 0x09:case 0x0a:case 0x0b:case 0x0c:case 0x0d:
        case 0x0e:case 0x0f:case 0x12:case 0x13:
        case 0x14:case 0x15:case 0x16:case 0x17:case 0x18:case 0x19:
        case 0x1b:case 0x1c:case 0x1d:case 0x1e:
          found = 0;
          len2 = optlist2[j+1];
          if (!len2) len2++;
          for (i=0; i<opt_count; i++) {
            if (opt_list[i] == type2) found = 1;
          }
          if (!found) diff[3][diff[0][2]++]=type2;
  
          j+=len2;                                       
          break;
        default:
          j++;
          break;             
      }
    } // end loop 2 bis
        
  return diff;
}

static int scamper_file_text_tracebox_write_simplified(const scamper_tracebox_t *tracebox,char *buf, size_t bufsize, size_t *soff, char* dst) {
  scamper_tracebox_pkt_t *pkt; 

  char addr[64];
  uint32_t i, off, nb_bytes;
  uint16_t len;
  uint8_t proto, iphlen, tcphlen, v, tcp_opt, ttl, max_ttl, changed=0, answered=0, prev_proto, type, ttl_index = 0; 
  uint8_t icmp_dlen=SCAMPER_TRACEBOX_ANSWER_EMPTY, prev_icmp_dlen=SCAMPER_TRACEBOX_ANSWER_EMPTY;
  uint8_t **recv_ppkt = NULL, **lastvalue_ppkt = NULL;

  /* compute max_ttl to allocate arrays */
  for(i=0; i<tracebox->pktc; i++) {
      pkt = tracebox->pkts[i];
      if(((pkt->data[0] & 0xf0) >> 4) == 4) ttl=pkt->data[8];
      else if(((pkt->data[0] & 0xf0) >> 4) == 6) ttl= pkt->data[7];  
      else continue;
      if (pkt->dir == SCAMPER_TRACEBOX_PKT_DIR_TX) max_ttl=ttl;
  }

  //answer length per icmp received
  uint8_t *dlens = calloc(max_ttl,1);
  //
  char **addrs = malloc(max_ttl * sizeof(char*));
  for (i=0; i<max_ttl; i++) addrs[i] = malloc(64*sizeof(char));

  for(i=0; i<tracebox->pktc; i++) {
     pkt = tracebox->pkts[i];
     off = 0;v = 0;

     if(((pkt->data[0] & 0xf0) >> 4) == 4) {
          v = 4;
	  iphlen = (pkt->data[0] & 0xf) * 4;
	  len = bytes_ntohs(pkt->data+2);
          ttl=pkt->data[8];
	  proto = pkt->data[9];
          scamper_addr_t *a=scamper_addr_alloc(SCAMPER_ADDR_TYPE_IPV4,pkt->data+12);
          scamper_addr_tostr(a,addr,sizeof(addr));
          scamper_addr_free(a);
	  off = (bytes_ntohs(pkt->data+6) & 0x1fff) * 8;
      } else if(((pkt->data[0] & 0xf0) >> 4) == 6) {
          v = 6;
	  iphlen = 40;
	  len = bytes_ntohs(pkt->data+4) + iphlen;
	  proto = pkt->data[6];   
          ttl= pkt->data[7];  
          scamper_addr_t *a=scamper_addr_alloc(SCAMPER_ADDR_TYPE_IPV6,pkt->data+8);
          scamper_addr_tostr(a,addr,sizeof(addr));
          scamper_addr_free(a);
      } else continue;

      if(proto == IPPROTO_TCP || proto == IPPROTO_UDP) {

        if (pkt->dir == SCAMPER_TRACEBOX_PKT_DIR_TX) {
          if (ttl_index == 0) lastvalue_ppkt = parse_packet(v, proto, SCAMPER_TRACEBOX_ANSWER_FULL, pkt->data);
          prev_proto = proto;
        } else {

          if (recv_ppkt) free_array(recv_ppkt,fields_len);
          recv_ppkt = parse_packet(v, proto, SCAMPER_TRACEBOX_ANSWER_FULL, pkt->data);

          if(recv_ppkt[3][0] & 0x12) { // synack
  
            int index;
            uint8_t **diff = compare_tcp_opt(lastvalue_ppkt[fields_len-1], recv_ppkt[fields_len-1], 
					    (lastvalue_ppkt[1][0]-5)*4, (recv_ppkt[1][0]-5)*4);
            if (diff[0][0]) {
              string_concat(buf, bufsize, soff, " The destination host modified");
              for (index=0;index<diff[0][0];index++) 
                 string_concat(buf, bufsize, soff, " TCP::Options::%s",tcp_options[diff[1][index]]);
              string_concat(buf, bufsize, soff, "\n");
            }
            if (diff[0][1]) {
              string_concat(buf, bufsize, soff, " The destination host removed");
              for (index=0;index<diff[0][1];index++) 
                 string_concat(buf, bufsize, soff, " TCP::Options::%s",tcp_options[diff[2][index]]);
              string_concat(buf, bufsize, soff, "\n");
            }
            if (diff[0][2]) {
              string_concat(buf, bufsize, soff, " The destination host added");
              for (index=0;index<diff[0][2];index++) 
                 string_concat(buf, bufsize, soff, " TCP::Options::%s",tcp_options[diff[3][index]]);
              string_concat(buf, bufsize, soff, "\n");
            }
            free_array(diff,4);
          }
        }

      } else if(proto == IPPROTO_ICMP) {

          uint8_t icmp_type = pkt->data[iphlen];
          uint8_t icmp_code = pkt->data[iphlen+1];

          int ip_start    = iphlen+8;
          int trans_start = ip_start+20;
          int dlen        = len-ip_start;

          if (icmp_type == 11 && icmp_code == 0) {
             if (recv_ppkt) free_array(recv_ppkt,fields_len);
 
              int i, j;           
	      if (len-ip_start <= 0) {
                type = SCAMPER_TRACEBOX_ANSWER_EMPTY; i=fields_len;
	      } else if (len-trans_start <= 0) { 

                type = SCAMPER_TRACEBOX_ANSWER_ONLY_L3; i=14;
	      } else if (len-trans_start == 8) { 
                type = SCAMPER_TRACEBOX_ANSWER_8B; i=7;
	      } else {
                type = SCAMPER_TRACEBOX_ANSWER_FULL; i=0;
              }

 	      recv_ppkt = parse_packet(v, prev_proto, type, &(pkt->data[ip_start]));
              dlens[ttl_index] = type;
              strncpy(addrs[ttl_index++],addr,64);
              answered=1;
              
	      for (;i<fields_len;i++) {
                 if (i == 31 || i == 33) continue; // skip ttl and checksum
                 if (i==36) {//tcp options
                   if (type != SCAMPER_TRACEBOX_ANSWER_FULL) continue;
                   if (!lastvalue_ppkt[i] && !recv_ppkt[i]) continue;

                   if (lastvalue_ppkt[1][0] != recv_ppkt[1][0]) {
                     string_concat(buf, bufsize, soff, " warning: tcp options length change (%d)\n",ttl_index);
                     continue;
                   }

                   uint8_t **diff = compare_tcp_opt(lastvalue_ppkt[i], recv_ppkt[i], (lastvalue_ppkt[1][0]-5)*4, (recv_ppkt[1][0]-5)*4);

                   if ((diff[0][0] || diff[0][1]) || diff[0][2]) {
                     uint8_t index;
                     for (index=0;index<diff[0][0];index++) 
                       string_concat(buf, bufsize, soff, " The %s::%s field was modified between %s and %s (%d)\n",fields[i],tcp_options[diff[1][index]], !answered ? "you" : last_observed_value(dlens, addrs, ttl_index-2, i) ,addr, ttl_index-1); 
                     for (index=0;index<diff[0][1];index++) 
                       string_concat(buf, bufsize, soff, " The %s::%s field was removed between %s and %s (%d)\n",fields[i],tcp_options[diff[2][index]], !answered ? "you" : last_observed_value(dlens, addrs, ttl_index-2, i) ,addr, ttl_index-1);
                     for (index=0;index<diff[0][2];index++) 
                       string_concat(buf, bufsize, soff, " The %s::%s field was added between %s and %s (%d)\n",fields[i],tcp_options[diff[3][index]], !answered ? "you" : last_observed_value(dlens, addrs, ttl_index-2, i) ,addr, ttl_index-1);

                     for (j=0;j<fields_size[i];j++) lastvalue_ppkt[i][j] = recv_ppkt[i][j];
                     changed=1; 
                   }
                   
                   free_array(diff,4);
                   continue;
                 }

	         for (j=0;j<fields_size[i];j++) {                 
                    if (lastvalue_ppkt[i][j] != recv_ppkt[i][j]) {
                        string_concat(buf, bufsize, soff, " The %s field changed between %s and %s (%d)\n",fields[i], (!answered || ttl_index<2) ? "you" : last_observed_value(dlens, addrs, ttl_index-2, i) ,addr,ttl_index);    
                          /* copy new value for the field in lastvalue_ppkt */   
                        for (j=0;j<fields_size[i];j++) lastvalue_ppkt[i][j] = recv_ppkt[i][j]; 
                       changed=1;         
                     }
		     break;
		 }

	       } // end last for
          } // end icmp 11/0
        } else if(proto == IPPROTO_ICMPV6) {

          uint8_t icmp_type = pkt->data[iphlen];
          uint8_t icmp_code = pkt->data[iphlen+1];

          int ip_start    = iphlen+8;
          int trans_start = ip_start+40;
          int dlen        = len-ip_start;

          if (icmp_type == 3 && icmp_code == 0) {//hop limit exceeded in transit
            if (recv_ppkt) free_array(recv_ppkt,fields_len);
            type = SCAMPER_TRACEBOX_ANSWER_FULL;
            recv_ppkt = parse_packet(v, prev_proto, type, &(pkt->data[ip_start]));
            strncpy(addrs[ttl_index++],addr,64);
            answered=1;
            int i = 0, j; 
            for (;i<fields_len;i++) {
              if (i == 20) continue; // skip ttl
              if (i == 36) {

                if (type != SCAMPER_TRACEBOX_ANSWER_FULL) continue;
                if (!lastvalue_ppkt[i] && !recv_ppkt[i]) continue;
                if (lastvalue_ppkt[1][0] != recv_ppkt[1][0]) {
                  string_concat(buf, bufsize, soff, "warning: tcp options length change (%d)\n",ttl_index);
                  continue;
                }

                uint8_t **diff = compare_tcp_opt(lastvalue_ppkt[i], recv_ppkt[i], (lastvalue_ppkt[1][0]-5)*4, (recv_ppkt[1][0]-5)*4);
                if ((diff[0][0] || diff[0][1]) || diff[0][2]) {
                  uint8_t index;
                  for (index=0;index<diff[0][0];index++) 
                     string_concat(buf, bufsize, soff, " The TCP::Options::%s field was modified at %s (%d)\n",tcp_options[diff[1][index]], addrs[ttl_index-1 < 0 ? 0 : ttl_index-1], ttl_index-1); 
                  for (index=0;index<diff[0][1];index++) 
                     string_concat(buf, bufsize, soff, " The TCP::Options::%s field was removed at %s (%d)\n",tcp_options[diff[2][index]], addrs[ttl_index-1 < 0 ? 0 : ttl_index-1], ttl_index-1);
                  for (index=0;index<diff[0][2];index++) 
                     string_concat(buf, bufsize, soff, " The TCP::Options::%s field was added at %s (%d)\n",tcp_options[diff[3][index]], addrs[ttl_index-1 < 0 ? 0 : ttl_index-1], ttl_index-1);

                  for (j=0;j<fields_size[i];j++) lastvalue_ppkt[i][j] = recv_ppkt[i][j];
                  changed=1; 
                }
                free_array(diff,4);
                continue; // skip ttl
              }

	      for (j=0;j<fields_size[i];j++) {  
                  if (lastvalue_ppkt[i][j] != recv_ppkt[i][j]) {
                    string_concat(buf, bufsize, soff, " The %s field was modified at %s (%d)\n",fields[i], !answered ? "yourself" : addrs[ttl_index-2 < 0 ? 0 : ttl_index-2] ,ttl_index-1);    
                    // copy new value for the field in lastvalue_ppkt    
                    for (j=0;j<fields_size[i];j++) lastvalue_ppkt[i][j] = recv_ppkt[i][j]; 
                    changed=1;         
                  }
	          break;
               } // for

	     } //  for
            
          }
	}
    }

    if (answered && !changed) {
      if (tracebox->result == SCAMPER_TRACEBOX_RESULT_TIMEOUT)
        string_concat(buf, bufsize, soff, " No modifications were detected between you and the last router that replied (%s)\n",addrs[ttl_index-1 < 0 ? 0 : ttl_index-1]); 
      else
        string_concat(buf, bufsize, soff, " No modifications were detected between you and the destination (%s)\n",dst); 
    } 

  if (recv_ppkt) free_array(recv_ppkt,fields_len);
  if (lastvalue_ppkt) free_array(lastvalue_ppkt,fields_len);
  for (i=0; i<max_ttl; i++) free(addrs[i]);
  free(addrs); free(dlens);

  return 0;
}

static int scamper_file_text_tracebox_write_frags(const scamper_tracebox_t *tracebox,char *buf, size_t bufsize, size_t *soff, char* dst) {
  
  return 0;
}

static int scamper_file_text_tracebox_write_proxy(const scamper_tracebox_t *tracebox,char *buf, size_t bufsize, size_t *soff) {

  scamper_tracebox_pkt_t *pkt; 
  uint32_t i;
  uint8_t proto, ttl, last_ttl, v, tcp_ttl, udp_ttl, loop = 0;

  for(i=0; i<tracebox->pktc; i++) {
      pkt = tracebox->pkts[i];
      v = 0;

      if(((pkt->data[0] & 0xf0) >> 4) == 4) {
          v = 4;
	  proto = pkt->data[9];
          ttl=pkt->data[8];
      } else if(((pkt->data[0] & 0xf0) >> 4) == 6) {
          v = 6;
	  proto = pkt->data[6];
          ttl= pkt->data[7];   
      } else continue;

      /*if (pkt->dir == SCAMPER_TRACEBOX_PKT_DIR_RX 
          && !scamper_addr_raw_cmp(tracebox->dst, (v == 4) ? pkt->data+12 : pkt->data+8))
          loop++;*/

      if(proto == IPPROTO_TCP) {
        if (pkt->dir == SCAMPER_TRACEBOX_PKT_DIR_TX) 
           tcp_ttl=ttl;//last_ttl=ttl;

        /*else if (pkt->dir == SCAMPER_TRACEBOX_PKT_DIR_RX) 
           tcp_ttl=last_ttl;       
        */
      } else if (proto == IPPROTO_UDP) {

          if (pkt->dir == SCAMPER_TRACEBOX_PKT_DIR_TX) 
           udp_ttl=ttl;//last_ttl=ttl;
          /*else if (pkt->dir == SCAMPER_TRACEBOX_PKT_DIR_RX) 
            udp_ttl=last_ttl; */          

      } /*else if(proto == IPPROTO_ICMP || proto == IPPROTO_ICMPV6) {
        if (pkt->dir == SCAMPER_TRACEBOX_PKT_DIR_RX) {
          if (!loop) tcp_ttl=last_ttl; //tcp loop
	  else udp_ttl=last_ttl; // udp loop
        }
      }*/
  }

  if (tcp_ttl<udp_ttl)
    string_concat(buf, bufsize, soff, " There is a proxy between you and the destination.\n"); 
  else
    string_concat(buf, bufsize, soff, " No proxy between you and the destination was detected.\n");  

  return 0;
}

static int scamper_file_text_tracebox_write_statefull(const scamper_tracebox_t *tracebox,char *buf, size_t bufsize, size_t *soff, char* dst) {

  scamper_tracebox_pkt_t *pkt; 
  uint32_t i;
  uint8_t proto, ttl, last_ttl=0, v, srv_ttl, loop=0, retries=0;

 for(i=0; i<tracebox->pktc; i++)
    {
      pkt = tracebox->pkts[i];v = 0;

      if(((pkt->data[0] & 0xf0) >> 4) == 4)
        {
          v = 4;
	  proto = pkt->data[9];
          ttl=pkt->data[8];
        }
      else if(((pkt->data[0] & 0xf0) >> 4) == 6)
        {
          v = 6;
	  proto = pkt->data[6];
          ttl= pkt->data[7];   
        }
      else continue;

      if(proto == IPPROTO_TCP) {
        if (last_ttl > ttl) { 
           if (loop == 0) srv_ttl=last_ttl;
           loop++;
           retries=0;
        } else if (last_ttl == ttl) retries++;
        else retries=0;

        if (retries == 3) { //if middlebox is first hop, loop number 3 will not satisfy (last_ttl > ttl)
          loop++;      
          retries=0;
        }

        if (pkt->dir == SCAMPER_TRACEBOX_PKT_DIR_RX) {
          if (loop == 2) {
               if (ttl == srv_ttl) {
                 string_concat(buf, bufsize, soff, " There is no statefull middlebox between you and the destination.\n"); 
                 return 0;
               } 

           } else if (loop == 4) {
               if (ttl == srv_ttl) {
                 string_concat(buf, bufsize, soff, " There is a statefull middlebox between you and the destination.\n");
                 return 0;
               }
           } 
        }
        last_ttl=ttl;
      }
    }

  string_concat(buf, bufsize, soff, " An error happened.\n"); 
  return 0;
}

int scamper_file_text_tracebox_write(const scamper_file_t *sf,
				 const scamper_tracebox_t *tracebox)
{ 

  const int bufsize = 131072;
  char buf[bufsize];
  char src[64], dst[64], tmp[256];
  int fd = scamper_file_getfd(sf);
  size_t soff = 0;
  
  string_concat(buf, sizeof(buf), &soff,
        "tracebox %s mode from %s to %s\n result: %s\n", modes[tracebox->printmode],
	scamper_addr_tostr(tracebox->src, src, sizeof(src)),
	scamper_addr_tostr(tracebox->dst, dst, sizeof(dst)),
	scamper_tracebox_res2str(tracebox, tmp, sizeof(tmp)));

  //print modes
  switch (tracebox->printmode) {
    case TRACEBOX_PRINT_MODE_FRAGS:
      scamper_file_text_tracebox_write_frags(tracebox,buf,bufsize,&soff,dst);
      break;                
    case TRACEBOX_PRINT_MODE_FULL_ICMP: 
      scamper_file_text_tracebox_write_full_icmp(tracebox,buf,bufsize,&soff);
      break;                                                         
    case TRACEBOX_PRINT_MODE_PROXY:
      if (tracebox->result == SCAMPER_TRACEBOX_RESULT_SUCCESS) 
        scamper_file_text_tracebox_write_proxy(tracebox,buf,bufsize,&soff);
      break;                               
    case TRACEBOX_PRINT_MODE_STATEFULL:  
      scamper_file_text_tracebox_write_statefull(tracebox,buf,bufsize,&soff,dst);
      break;                         
    case TRACEBOX_PRINT_MODE_SIMPLIFIED_OUTPUT:  
      scamper_file_text_tracebox_write_simplified(tracebox,buf,bufsize,&soff,dst);
      break;                          
    case TRACEBOX_PRINT_MODE_STANDARD:           
    default:
      scamper_file_text_tracebox_write_standard(tracebox,buf,bufsize,&soff);
      break;
  }
   write_wrap(fd, buf, NULL, soff);
   return 0;
}

char *compute_differences(const scamper_tracebox_t *tracebox, const uint8_t *pkt1, const uint8_t *pkt2, const uint8_t type, const uint8_t network, const uint8_t transport) {
  char *buf = malloc(20480*sizeof(char));
  size_t bufsize=20480;
  size_t soff = 0;

  int i,j, transoff;// + ip_opt*4;
  uint8_t **ppkt1 = parse_packet(network, transport, type, pkt1);
  uint8_t **ppkt2 = parse_packet(network, transport, type, pkt2);

  if (network == 4) {
    transoff = 20;
     if (ppkt1[24][0] != ppkt2[24][0]) {
       string_concat(buf, bufsize, &soff, " warning: IPHeaderLength changed\n");
     }
  } else {
    transoff = 40;
    if ((ppkt1[27][0] != ppkt2[27][0]) || (ppkt1[27][1] != ppkt2[27][1])) {
       string_concat(buf, bufsize, &soff, " warning: IPv6Length changed\n");
    }
  }

  switch(type)  {
    case SCAMPER_TRACEBOX_ANSWER_FULL:
      for (i=0;i<7;i++) {
        for (j=0;j<fields_size[i];j++) {
          if (ppkt1[i][j] != ppkt2[i][j]) {
            string_concat(buf, bufsize, &soff, " %s",fields[i]);
            break;
          }
        }
      }
    case SCAMPER_TRACEBOX_ANSWER_SYNACK:
      if (!tracebox->udp) {
        int optoff = transoff+20;
        uint8_t tcp_opt = ((pkt1[transoff+12]& 0xf0) >> 4)-5 ;
        uint8_t tcp_opt2 = ((pkt2[transoff+12]& 0xf0) >> 4)-5 ;
        int nb_bytes = tcp_opt * 4, nb_bytes2 = tcp_opt2 * 4;

        uint8_t **diff = compare_tcp_opt(pkt1+optoff, pkt2+optoff, nb_bytes, nb_bytes2);
        if ((diff[0][0] || diff[0][1]) || diff[0][2]) {
          uint8_t index;
          for (index=0;index<diff[0][0];index++) 
             string_concat(buf, bufsize, &soff, " TCP::Options::%s",tcp_options[diff[1][index]]); 
          for (index=0;index<diff[0][1];index++) 
             string_concat(buf, bufsize, &soff, " -TCP::Options::%s",tcp_options[diff[2][index]]);
          for (index=0;index<diff[0][2];index++) 
             string_concat(buf, bufsize, &soff, " +TCP::Options::%s",tcp_options[diff[3][index]]);
        }
        free_array(diff,4);
      } // end not udp 

    if (type == SCAMPER_TRACEBOX_ANSWER_SYNACK) break;
    case SCAMPER_TRACEBOX_ANSWER_8B:
      for (i=7;i<14;i++) {
        for (j=0;j<fields_size[i];j++) {
          if (ppkt1[i][j] != ppkt2[i][j]) {
            string_concat(buf, bufsize, &soff, " %s",fields[i]);
            break;
          }
        }
      }
    case SCAMPER_TRACEBOX_ANSWER_ONLY_L3:

      for (i=14;i<36;i++) {
        for (j=0;j<fields_size[i];j++) {
          if (ppkt1[i][j] != ppkt2[i][j]) {
            string_concat(buf, bufsize, &soff, " %s",fields[i]);
            break;
          }
        }
      }
  
      case SCAMPER_TRACEBOX_ANSWER_EMPTY:
      break;  
  }
  free_array(ppkt1,fields_len);  free_array(ppkt2,fields_len);
  if (!soff) free(buf);
  return !soff ? NULL : buf;
}
