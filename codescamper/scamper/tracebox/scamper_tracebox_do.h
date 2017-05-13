/*
 * scamper_do_tracebox.h
 *
 * Copyright (C) 2003-2006 Matthew Luckie
 * Copyright (C) 2003-2011 The University of Waikato
 * Copyright (C) 2008 Alistair King
 * Copyright (C) 2012      The Regents of the University of California
 * Copyright (C) 2013-2014  Korian Edeline, University of Liège
 *  
 *
 * Authors: Matthew Luckie
 *          Doubletree implementation by Alistair King
 *          Tracebox implementation by Korian Edeline
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
 * This work is funded by the European Commission funded 
 * mPlane ICT-318627 project (http://www.ict-mplane.eu).
 *
 */

#ifndef __SCAMPER_DO_TRACEBOX_H
#define __SCAMPER_DO_TRACEBOX_H

const char *scamper_do_tracebox_usage(void);

void *scamper_do_tracebox_alloc(char *str);

void scamper_do_tracebox_free(void *data);

scamper_task_t *scamper_do_tracebox_alloctask(void *data,
					  scamper_list_t *list,
					  scamper_cycle_t *cycle);

int scamper_do_tracebox_arg_validate(int argc, char *argv[], int *stop);

void scamper_do_tracebox_cleanup(void);
int scamper_do_tracebox_init(void);


#endif /*__SCAMPER_DO_TRACEBOX_H */ * 
