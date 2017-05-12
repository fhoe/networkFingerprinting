/*
 * scamper_file_warts_tracebox.h
 *
 * $Id: scamper_tracebox_warts.h,v 1.1 2010/10/05 02:45:44 mjl Exp $
 *
 * @author: K.Edeline
 *
 */

#ifndef __SCAMPER_FILE_WARTS_TRACEBOX_H
#define __SCAMPER_FILE_WARTS_TRACEBOX_H

int scamper_file_warts_tracebox_write(const scamper_file_t *sf,
				  const scamper_tracebox_t *tracebox);

int scamper_file_warts_tracebox_read(scamper_file_t *sf, const warts_hdr_t *hdr,
				 scamper_tracebox_t **tracebox_out);

#endif
