/*
 * scamper_file_text_tracebox.h
 *
 *
 *
 * @author: K.Edeline
 */

#ifndef __SCAMPER_FILE_TEXT_TRACEBOX_H
#define __SCAMPER_FILE_TEXT_TRACEBOX_H

#define TRACEBOX_PRINT_MODE_STANDARD           0x0
#define TRACEBOX_PRINT_MODE_FRAGS              0x1              
#define TRACEBOX_PRINT_MODE_FULL_ICMP          0x2    
#define TRACEBOX_PRINT_MODE_PROXY              0x4
#define TRACEBOX_PRINT_MODE_STATEFULL          0x5  
#define TRACEBOX_PRINT_MODE_SIMPLIFIED_OUTPUT  0x6 

uint32_t byte_reverse_32(uint32_t num);
uint16_t byte_reverse_16(uint16_t num);
char * compute_differences(const scamper_tracebox_t *tracebox, const uint8_t *pkt1, const uint8_t *pkt2, const uint8_t type, const uint8_t network, const uint8_t transport);

int scamper_file_text_tracebox_write(const scamper_file_t *sf,
				 const scamper_tracebox_t *tracebox);

#endif
