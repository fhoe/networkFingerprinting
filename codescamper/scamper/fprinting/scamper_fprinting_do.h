/*
 * scamper_do_fprinting.h
 *
 * $Id: scamper_fprinting_do.h,v 1.0 2014/06/06 11:00:54 mjl Exp $
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

#ifndef __SCAMPER_DO_FPRINTING_H
#define __SCAMPER_DO_FPRINTING_H

void *scamper_do_fprinting_alloc(char *str);

scamper_task_t *scamper_do_fprinting_alloctask(void *data);

/**
* \fn int scamper_do_fprinting_arg_validate(int argc, char *argv[], int *stop)
* \brief Calls fprinting_arg_param_validate to test if the commannd line can be understood.
*
* \param argc Number of parameters.
* \param argv Parameters.
* \param stop Pointer to receive where function failed.
*
* \return Not zero if error.
*/
int scamper_do_fprinting_arg_validate(int argc, char *argv[], int *stop);

void scamper_do_fprinting_free(void *data);

const char *scamper_do_fprinting_usage(void);

void scamper_do_fprinting_cleanup(void);
int scamper_do_fprinting_init(void);

#endif /* __SCAMPER_DO_FPRINTING_H */
