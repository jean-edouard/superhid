/*
 * Copyright (c) 2015 Jed Lejosne <lejosnej@ainfosec.com>
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

#include "project.h"

void send_report(int fd, struct superhid_report *report, struct superhid_device *dev)
{
  usbif_response_t rsp;
  char *data, *target;

  while (dev->pendings[dev->pendinghead] == -1 && dev->pendinghead != dev->pendingtail)
    dev->pendinghead = (dev->pendinghead + 1) % 32;

  if (dev->pendinghead == dev->pendingtail)
    return;

  rsp.id            = dev->pendings[dev->pendinghead];
  rsp.actual_length = 6;
  rsp.data          = 0;
  rsp.status        = USBIF_RSP_OKAY;

  target = xc_gnttab_map_grant_ref(xcg_handle,
                                   dev->di.di_domid,
                                   dev->pendingrefs[dev->pendinghead],
                                   PROT_READ | PROT_WRITE);
  data = target + dev->pendingoffsets[dev->pendinghead];
  data[0] = report->report_id;
  data[1] = report->misc;
  data[2] = report->x & 0xFF;
  data[3] = (report->x >> 8);
  data[4] = report->y & 0xFF;
  data[5] = (report->y >> 8);

  printf("sending %02X %02X %02X %02X %02X %02X to %d\n",
         data[0], data[1], data[2], data[3], data[4], data[5], dev->pendings[dev->pendinghead]);

  xc_gnttab_munmap(xcg_handle, target, 1);
  superbackend_send(dev, &rsp);

  dev->pendinghead = (dev->pendinghead + 1) % 32;
}

void send_report_to_frontends(int fd, struct superhid_report *report, struct superhid_backend *superback)
{
  int i;

  for (i = 0; i < BACKEND_DEVICE_MAX; ++i) {
    if (superback->devices[i] != NULL)
      send_report(fd, report, superback->devices[i]);
  }
}

/* void send_stuffs(int fd) */
/* { */
/*   char buf[13]; */
/*   int n; */
/*   int i; */
/*   usbif_response_t rsp; */
/*   char *data, *target; */

/*   while (pendings[pendinghead] == -1 && pendinghead != pendingtail) */
/*     pendinghead = (pendinghead + 1) % 32; */

/*   if (pendinghead == pendingtail) */
/*     return; */

/*   n = read(fd, buf, 13); */
/*   if (n < 12) { */
/*     printf("just got %d: %s\n", n, buf); */
/*     return; */
/*   } */

/*   if (!strncmp(buf, "000000000000", 12)) { */
/*     usleep(10000); */
/*     return; */
/*   } */

/*   rsp.id            = pendings[pendinghead]; */
/*   rsp.actual_length = 6; */
/*   rsp.data          = 0; */
/*   rsp.status        = USBIF_RSP_OKAY; */

/*   target = xc_gnttab_map_grant_ref(xcg_handle, */
/*                                    backend->domid, */
/*                                    pendingrefs[pendinghead], */
/*                                    PROT_READ | PROT_WRITE); */
/*   data = target + pendingoffsets[pendinghead]; */
/*   for (i = 0; i < 12; i += 2) { */
/*     if (buf[i] >= '0' && buf[i] <= '9') */
/*       data[i/2] = (buf[i] - '0') << 4; */
/*     else if (buf[i] >= 'A' && buf[i] <= 'F') */
/*       data[i/2] = (buf[i] - 'A' + 10) << 4; */
/*     else */
/*       return; */
/*     if (buf[i+1] >= '0' && buf[i+1] <= '9') */
/*       data[i/2] |= buf[i+1] - '0'; */
/*     else if (buf[i+1] >= 'A' && buf[i+1] <= 'F') */
/*       data[i/2] |= buf[i+1] - 'A' + 10; */
/*     else */
/*       return; */
/*     printf("%02X\n", data[i/2]); */
/*   } */
/*   xc_gnttab_munmap(xcg_handle, target, 1); */
/*   memcpy(RING_GET_RESPONSE(&back_ring, back_ring.rsp_prod_pvt), &rsp, sizeof(rsp)); */
/*   back_ring.rsp_prod_pvt++; */
/*   RING_PUSH_RESPONSES(&back_ring); */
/*   backend_evtchn_notify(backend->backend, backend->device->devid); */

/*   pendinghead = (pendinghead + 1) % 32; */
/* } */

int main(int argc, char **argv)
{
  usbinfo_t ui;
  dominfo_t di;
  int domid, ret;
  char path[256], token[256];
  char* res;
  int ring, evtchn, superfd;
  xc_evtchn *ec;
  char *page;
  fd_set fds;
  struct superhid_report report;
  int remaining = 0;
  int fd;
  struct superhid_backend superback;
  int i;

  if (argc != 2)
    return 1;

  /* Globals init */
  /* evtfd = -1; */
  /* priv = NULL; */
  /* back_ring_ready = 0; */
  /* pendinghead = 0; */
  /* pendingtail = 0; */
  xcg_handle = NULL;

  if (superxenstore_init() != 0)
    return 1;

  if (xcg_handle == NULL) {
    xcg_handle = xc_gnttab_open(NULL, 0);
  }
  if (xcg_handle == NULL) {
    xd_log(LOG_ERR, "Failed to connect to xc");
    return 1;
  }

  /* Fill the domain info */
  domid = strtol(argv[1], NULL, 10);
  ret = superxenstore_get_dominfo(domid, &di);
  if (ret != 0) {
    xd_log(LOG_ERR, "Invalid domid %d", domid);
    return 1;
  }

  /* Fill the device info */
  ui.usb_virtid = 1;
  ui.usb_bus = 1;
  ui.usb_device = 1;
  ui.usb_vendor = 0x03eb;
  ui.usb_product = 0x211c;

  /* Initialize the backend */
  fd = superbackend_init();
  for (i = 0; i < BACKEND_DEVICE_MAX; ++i)
    superback.devices[i] = NULL;
  superbackend_add(di, &superback);

  /* Create a new device on xenstore */
  superxenstore_create_usb(&di, &ui);

  /* Grab input events for the domain */
  superfd = superplugin_init(di.di_domid);

  do {
    int fdmax = fd;

    FD_ZERO(&fds);
    FD_SET(fd, &fds);
    /* FD_SET(STDIN_FILENO, &fds); */
    FD_SET(superfd, &fds);
    fdmax = fd;
    if (superfd > fdmax)
      fdmax = superfd;
    /* if (evtfd != -1) */
    /* { */
    /*   FD_SET(evtfd, &fds); */
    /*   if (evtfd > fdmax) */
    /*     fdmax = evtfd; */
    /* } */

    select(fdmax + 1, &fds, NULL, NULL, NULL);

    if (FD_ISSET(fd, &fds)) {
      /* printf("fd fired\n"); */
      backend_xenstore_handler(NULL);
    }
    /* if (FD_ISSET(STDIN_FILENO, &fds)) { */
    /*   if (pending != -1 && pendingref != -1) { */
    /*     printf("drawing!\n"); */
    /*     send_stuffs(STDIN_FILENO); */
    /*   } */
    /* } */
    /* if (evtfd != -1 && FD_ISSET(evtfd, &fds)) { */
    /*   /\* printf("evtfd fired\n"); *\/ */
    /*   if (priv != NULL) */
    /*     backend_evtchn_handler(priv); */
    /* } */
    if (FD_ISSET(superfd, &fds) || remaining >= sizeof(report)) {
      /* while (pendings[pendinghead] == -1 && pendinghead != pendingtail) */
      /*   pendinghead = (pendinghead + 1) % 32; */
      /* if (pendinghead != pendingtail) { */
        report.report_id = 0;
        remaining = superplugin_callback(superfd, &report);
        if (report.report_id != 0)
          send_report_to_frontends(superfd, &report, &superback);
      /* } */
    }
  } while (1);
  xc_evtchn_close(ec);

  /* Cleanup */
  superxenstore_close();
  xc_gnttab_close(xcg_handle);

  return 0;
}
