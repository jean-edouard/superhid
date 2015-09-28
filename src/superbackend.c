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

void consume_requests(void)
{
  RING_IDX rc, rp;
  usbif_request_t req;
  usbif_response_t rsp;
  int responded;

  if (back_ring_ready != 1) {
    printf("not ready to consume\n");
    return;
  }

  while (RING_HAS_UNCONSUMED_REQUESTS(&back_ring))
  {
    memcpy(&req, RING_GET_REQUEST(&back_ring, back_ring.req_cons), sizeof(req));
#ifdef DEBUG
    printf("***** GOT REQUEST *****\n", req.id, req.type);
    printf("id=%d\n", req.id);
    printf("setup=%X\n", req.setup);
    printf("type=%X\n", req.type);
    printf("endpoint=%d\n", req.endpoint);
    printf("offset=%X\n", req.offset);
    printf("length=%d\n", req.length);
    printf("nr_segments=%d\n", req.nr_segments);
    printf("flags=%X\n", req.flags);
    printf("nr_packets=%d\n", req.nr_packets);
    printf("startframe=%d\n", req.startframe);
#endif
    responded = -1;
    if (req.type == USBIF_T_GET_SPEED) {
      rsp.id            = req.id;
      rsp.actual_length = 0;
      rsp.data          = USBIF_S_HIGH;
      rsp.status        = USBIF_RSP_OKAY;
      responded = 0;
    }
    if (req.type == USBIF_T_RESET) {
      rsp.id            = req.id;
      rsp.actual_length = 0;
      rsp.data          = 0;
      rsp.status        = USBIF_RSP_OKAY;
      responded = 0;
    }
    if (req.setup != 0) {
      struct usb_ctrlrequest setup;
      void *buf = NULL;

      memcpy(&setup, &req.setup, sizeof(struct usb_ctrlrequest));
#ifdef DEBUG
      printf("SETUP.bRequestType=%X\n", setup.bRequestType);
      printf("SETUP.bRequest=%X\n", setup.bRequest);
      printf("SETUP.wValue=%X\n", setup.wValue);
      printf("SETUP.wIndex=%X\n", setup.wIndex);
      printf("SETUP.wLength=%d\n", setup.wLength);
      printf("SETUP ");
#endif
      if (req.nr_segments > 1) {
        xd_log(LOG_ERR, "Multiple segments not supported yet");
        exit(1);
      }
      if (req.nr_segments)
        buf = xc_gnttab_map_grant_ref(xcg_handle,
                                      backend->domid,
                                      req.u.gref[0],
                                      PROT_READ | PROT_WRITE);
      if (buf)
        responded = superhid_setup(&setup, buf + req.offset);
      else
        responded = superhid_setup(&setup, NULL);
      rsp.id            = req.id;
      rsp.actual_length = responded;
      rsp.data          = 0;
      if (responded >= 0)
        rsp.status        = USBIF_RSP_OKAY;
      else
        rsp.status        = USBIF_RSP_EOPNOTSUPP;
      if (buf != NULL)
        xc_gnttab_munmap(xcg_handle, buf, 1);
    }

    if (req.type == 8) {
      uint64_t tocancel = *((uint64_t*)&req.u.data[0]);
      int i;
      for (i = pendinghead; i != pendingtail; i = (i + 1) % 32)
        if (pendings[i] == tocancel)
          break;
      if (tocancel != pendings[i]) {
        rsp.id = req.id;
        rsp.actual_length = 0;
        rsp.data          = 0;
        rsp.status        = USBIF_RSP_ERROR;
        printf("failing to cancel %d\n", tocancel);
      } else {
        rsp.id            = tocancel;
        rsp.actual_length = 0;
        rsp.data          = 0;
        rsp.status        = USBIF_RSP_USB_CANCELED;
        pendings[i] = -1;
        pendingrefs[i] = -1;
        pendingoffsets[i] = -1;
        superbackend_send(backend, &rsp);
        printf("cancelled %d\n", tocancel);
        rsp.id = req.id;
        rsp.actual_length = 0;
        rsp.data          = 0;
        rsp.status        = USBIF_RSP_OKAY;
      }
    }
    if (req.type != 3) {
      superbackend_send(backend, &rsp);
    } else {
      printf("pendings[%d]=%d\n", pendingtail, req.id);
      pendings[pendingtail] = req.id;
      pendingrefs[pendingtail] = req.u.gref[0];
      pendingoffsets[pendingtail] = req.offset;
      pendingtail = (pendingtail + 1) % 32;
    }
    back_ring.req_cons++;
#ifdef DEBUG
    printf("***********************\n");
#endif
  }
}

static xen_device_t
superback_alloc(xen_backend_t backend, int devid, void *priv)
{
  struct superhid_backend *back = priv;
  struct superhid_device *dev = back->device;

  /* printf("alloc %p %d %p\n", backend, devid, priv); */
  dev = malloc(sizeof(*dev));
  memset(dev, 0, sizeof(*dev));

  dev->devid = devid;
  dev->backend = backend;
  back->device = dev;

  return dev;
}

static int
superback_init(xen_device_t xendev)
{
  struct superhid_device *dev = xendev;

  /* printf("init %p\n", xendev); */
  backend_print(dev->backend, dev->devid, "version", "3");
  backend_print(dev->backend, dev->devid, "feature-barrier", "1");

  return 0;
}

static int
superback_connect(xen_device_t xendev)
{
  struct superhid_device *dev = xendev;
  char path[256];
  char *res;

  /* printf("connect %p\n", xendev); */

  evtfd = backend_bind_evtchn(dev->backend, dev->devid);
  priv = backend_evtchn_priv(dev->backend, dev->devid);
  if (evtfd < 0) {
    printf("failed to bind evtchn\n");
    return -1;
  }

  dev->page = backend_map_granted_ring(dev->backend, dev->devid);
  if (!dev->page) {
    printf("failed to map page\n");
    return -1;
  }

  BACK_RING_INIT(&back_ring, (usbif_sring_t *)dev->page, XC_PAGE_SIZE);
  back_ring_ready = 1;

  return 0;
}


static void
superback_disconnect(xen_device_t xendev)
{
  struct superhid_device *dev = xendev;

  /* TODO: something */
  (void)dev;

  printf("disconnect\n");
}

static void superback_backend_changed(xen_device_t xendev,
                                     const char *node,
                                     const char *val)
{
  /* printf("backend changed: %s=%s\n", node, val); */
}

static void superback_frontend_changed(xen_device_t xendev,
                                      const char *node,
                                      const char *val)
{
  /* printf("frontend changed: %s=%s\n", node, val); */
}

static void
superback_event(xen_device_t xendev)
{
  struct superhid_device *dev = xendev;

  /* printf("event %p\n", xendev); */
  consume_requests();
}

static void
superback_free(xen_device_t xendev)
{
  struct superhid_device *dev = xendev;

  /* printf("free %p\n", xendev); */
  superback_disconnect(xendev);

  free(dev);
}

static struct xen_backend_ops superback_ops = {
  superback_alloc,
  superback_init,
  superback_connect,
  superback_disconnect,
  superback_backend_changed,
  superback_frontend_changed,
  superback_event,
  superback_free
};

int superbackend_init(void)
{
  if (backend_init(0)) {
    xd_log(LOG_ERR, "Failed to initialize libxenbackend");
    return -1;
  }
  backend = malloc(sizeof(*backend));
  backend->domid = di.di_domid;
  backend->device = NULL;
  backend->backend = backend_register(BACKEND_NAME, di.di_domid, &superback_ops, backend);
  if (!backend->backend)
  {
    xd_log(LOG_ERR, "Failed to register as a backend");
    free(backend);
    return -1;
  }
  fd = backend_xenstore_fd();

  return fd;
}

void superbackend_send(struct superhid_backend *backend, usbif_response_t *rsp)
{
  memcpy(RING_GET_RESPONSE(&back_ring, back_ring.rsp_prod_pvt), rsp, sizeof(*rsp));
  back_ring.rsp_prod_pvt++;
  RING_PUSH_RESPONSES(&back_ring);
  backend_evtchn_notify(backend->backend, backend->device->devid);
}
