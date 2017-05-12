/*
 * scamper_file_warts_fprinting.h
 *
 * $Id: scamper_fprinting_warts.h,v 1.0 2017/02/20 03:15:44 mjl Exp $
 *
 * 2014 Gregoire Mathonet
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

#ifndef __SCAMPER_FILE_WARTS_FPRINTING_H
#define __SCAMPER_FILE_WARTS_FPRINTING_H

int scamper_file_warts_fprinting_write(const scamper_file_t *sf,
                                       const scamper_fprinting_t *fprinting);
int scamper_file_warts_fprinting_read(scamper_file_t *sf, const warts_hdr_t *hdr,
                                      scamper_fprinting_t **fprinting_out);

#endif
