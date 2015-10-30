/*
 * Copyright (c) 2015 Assured Information Security, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

/**
 * @file   main.c
 * @author Jed Lejosne <lejosnej@ainfosec.com>
 * @date   Fri Oct 30 11:32:36 2015
 *
 * @brief  SuperHID entrypoint and misc functions
 *
 * This file contains the main function that initializes the SuperHID
 * backend.
 */

#include "project.h"

void xenstore_handler(int fd, short event, void *priv)
{
  superxenstore_handler();
}

void xenstore_back_handler(int fd, short event, void *priv)
{
  backend_xenstore_handler(NULL);
}

int main(int argc, char **argv)
{
  struct event xs_event, xs_back_event;
  int xs_fd, xs_back_fd;

  if (argc != 1)
    return 1;

  /* Globals init */
  xcg_handle = NULL;

  /* Initialize XenStore */
  xs_fd = superxenstore_init();
  if (xs_fd < 0)
    return 1;

  /* Initialize gnttab */
  if (xcg_handle == NULL) {
    xcg_handle = xc_gnttab_open(NULL, 0);
  }
  if (xcg_handle == NULL) {
    xd_log(LOG_ERR, "Failed to connect to xc");
    return 1;
  }

  /* Initialize SuperHID */
  superhid_init();

  /* Initialize the backend */
  xs_back_fd = superbackend_init();

  input_grabber = -1;

  event_init();

  event_set(&xs_event, xs_fd, EV_READ | EV_PERSIST,
            xenstore_handler, NULL);
  event_add(&xs_event, NULL);

  event_set(&xs_back_event, xs_back_fd, EV_READ | EV_PERSIST,
            xenstore_back_handler, NULL);
  event_add(&xs_back_event, NULL);

  event_dispatch();

  /* Cleanup */
  superxenstore_close();
  xc_gnttab_close(xcg_handle);

  return 0;
}
