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

static void hexdump(unsigned char *data, int l)
{
  int i;

  for (i = 0; i < l; ++i)
    printf("%02X ", data[i]);
  printf("sent\n");
}

void send_report(int fd, struct superhid_report *report, struct superhid_device *dev)
{
  usbif_response_t rsp;
  unsigned char *data, *target;

  rsp.id            = dev->pendings[dev->pendinghead];
  rsp.actual_length = SUPERHID_REPORT_LENGTH;
  rsp.data          = 0;
  rsp.status        = USBIF_RSP_OKAY;

  target = xc_gnttab_map_grant_ref(xcg_handle,
                                   dev->superback->di.di_domid,
                                   dev->pendingrefs[dev->pendinghead],
                                   PROT_READ | PROT_WRITE);
  if (target == NULL) {
    xd_log(LOG_ERR, "Failed to map gntref %d", dev->pendingrefs[dev->pendinghead]);
    return;
  }
  data = target + dev->pendingoffsets[dev->pendinghead];
  memcpy(data, report, SUPERHID_REPORT_LENGTH);

  xc_gnttab_munmap(xcg_handle, target, 1);
  superbackend_send(dev, &rsp);

  dev->pendinghead = (dev->pendinghead + 1) % 32;
}

bool all_pending(struct superhid_backend *superback)
{
  int i;
  struct superhid_device *dev;

  for (i = 0; i < BACKEND_DEVICE_MAX; ++i) {
    dev = superback->devices[i];
    if (dev != NULL) {
      while (dev->pendinghead != dev->pendingtail && dev->pendings[dev->pendinghead] == -1)
        dev->pendinghead = (dev->pendinghead + 1) % 32;
      if (dev->pendinghead == dev->pendingtail)
        return false;
    }
  }

  return true;
}

void send_report_to_frontends(int fd, struct superhid_report *report, struct superhid_backend *superback)
{
  int i;
  struct superhid_device *dev;

  for (i = 0; i < BACKEND_DEVICE_MAX; ++i) {
    dev = superback->devices[i];
    if (dev != NULL && dev->pendinghead != dev->pendingtail)
      send_report(fd, report, superback->devices[i]);
  }
}

void input_handler(int fd, short event, void *priv)
{
  struct event *me = priv;
  struct superhid_report_multitouch report = { 0 };
  struct superhid_report custom_report = { 0 };
  struct superhid_finger *finger;
  int remaining = EVENT_SIZE;
  int sents = 0;

  /* We send a maximum of 2 packets, because that's usually how
   * many pending INT requests we have. */
  while (sents < 2 && remaining >= EVENT_SIZE && all_pending(&superback))
  {
    finger = &report.fingers[report.count];
    /* I don't think the finger ID can ever be 0xF. Use that to know
     * if superplugin_callback succeeded */
    finger->finger_id = 0xF;
    remaining = superplugin_callback(fd, finger, &custom_report);
    if (custom_report.report_id != 0) {
      send_report_to_frontends(fd, &custom_report, &superback);
      memset(&custom_report, 0, sizeof(report));
      sents++;
      continue;
    }
    if (finger->finger_id != 0xF) {
      report.report_id = REPORT_ID_MULTITOUCH;
      report.count++;
    }
    if (report.count == SUPERHID_FINGER_WIDTH) {
      /* The report is full, let's send it and start a new one */
      send_report_to_frontends(fd, &report, &superback);
      memset(&report, 0, sizeof(report));
      sents++;
    }
  }

  if (report.count > 0) {
    /* The loop ended on a partial report, we need to send it */
    send_report_to_frontends(fd, &report, &superback);
  }

  if (sents == 2 && remaining >= EVENT_SIZE) {
    /* We sent 2 packets and the input buffer still has at least one
     * event, we need to get rescheduled even if no more input comes */
    event_active(me, event, 0);
  }
}

void xenstore_handler(int fd, short event, void *priv)
{
  backend_xenstore_handler(NULL);
}

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
  int fd;
  int i;
  struct event input_event;
  struct event xs_event;

  if (argc != 2)
    return 1;

  /* Globals init */
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
  ui.usb_vendor = SUPERHID_VENDOR;
  ui.usb_product = SUPERHID_DEVICE;

  /* Initialize SuperHID */
  superhid_init();

  /* Initialize the backend */
  fd = superbackend_init();
  for (i = 0; i < BACKEND_DEVICE_MAX; ++i)
    superback.devices[i] = NULL;
  superback.di = di;
  superbackend_add(di, &superback);

  /* Create a new device on xenstore */
  superxenstore_create_usb(&di, &ui);

  /* Grab input events for the domain */
  superfd = superplugin_init(di.di_domid);

  event_init();

  event_set(&xs_event, fd, EV_READ | EV_PERSIST,
            xenstore_handler, NULL);
  event_add(&xs_event, NULL);

  event_set(&input_event, superfd, EV_READ | EV_PERSIST,
            input_handler, &input_event);
  event_add(&input_event, NULL);

  event_dispatch();

  xc_evtchn_close(ec);

  /* Cleanup */
  superxenstore_close();
  xc_gnttab_close(xcg_handle);

  return 0;
}
