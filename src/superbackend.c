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

static void print_request(usbif_request_t *req)
{
  xd_log(LOG_DEBUG, "***** GOT REQUEST *****");
  xd_log(LOG_DEBUG, "id=%d", req->id);
  xd_log(LOG_DEBUG, "setup=%X", req->setup);
  xd_log(LOG_DEBUG, "type=%X", req->type);
  xd_log(LOG_DEBUG, "endpoint=%d", req->endpoint);
  xd_log(LOG_DEBUG, "offset=%X", req->offset);
  xd_log(LOG_DEBUG, "length=%d", req->length);
  xd_log(LOG_DEBUG, "nr_segments=%d", req->nr_segments);
  xd_log(LOG_DEBUG, "flags=%X", req->flags);
  xd_log(LOG_DEBUG, "nr_packets=%d", req->nr_packets);
  xd_log(LOG_DEBUG, "startframe=%d", req->startframe);
}

static void print_setup(struct usb_ctrlrequest *setup)
{
  xd_log(LOG_DEBUG, "SETUP.bRequestType=%X", setup->bRequestType);
  xd_log(LOG_DEBUG, "SETUP.bRequest=%X", setup->bRequest);
  xd_log(LOG_DEBUG, "SETUP.wValue=%X", setup->wValue);
  xd_log(LOG_DEBUG, "SETUP.wIndex=%X", setup->wIndex);
  xd_log(LOG_DEBUG, "SETUP.wLength=%d", setup->wLength);
}

void consume_requests(struct superhid_device *dev)
{
  RING_IDX rc, rp;
  usbif_request_t req;
  usbif_response_t rsp;
  int responded;
  struct usb_ctrlrequest setup;
  void *buf = NULL;
  uint64_t tocancel;
  int i;
  int domids[32];

  if (dev->back_ring_ready != 1) {
    xd_log(LOG_ERR, "Backend not ready to consume");
    return;
  }

  while (RING_HAS_UNCONSUMED_REQUESTS(&dev->back_ring))
  {
    memcpy(&req, RING_GET_REQUEST(&dev->back_ring, dev->back_ring.req_cons), sizeof(req));
    print_request(&req);
    responded = -1;
    switch (req.type) {
    case USBIF_T_CNTRL: /* Setup request. Ask superhid and reply. */
      memcpy(&setup, &req.setup, sizeof(struct usb_ctrlrequest));
      print_setup(&setup);
      if (req.nr_segments) {
        for (i = 0; i < req.nr_segments; ++i)
          domids[i] = dev->superback->di.di_domid;
        buf = xc_gnttab_map_grant_refs(xcg_handle, req.nr_segments, domids,
                                       req.u.gref, PROT_READ | PROT_WRITE);
      }
      if (buf)
        responded = superhid_setup(&setup, buf + req.offset, dev->type);
      else
        responded = superhid_setup(&setup, NULL, dev->type);
      if (responded >= 0) {
        rsp.id            = req.id;
        rsp.actual_length = responded;
        rsp.data          = 0;
        rsp.status        = USBIF_RSP_OKAY;
      } else {
        rsp.id            = req.id;
        rsp.actual_length = -1;
        rsp.data          = 0;
        rsp.status        = USBIF_RSP_EOPNOTSUPP;
      }
      if (buf != NULL)
        xc_gnttab_munmap(xcg_handle, buf, 1);
      superbackend_send(dev, &rsp);
      break;
    case USBIF_T_INT: /* Interrupt request. Pend it. */
      xd_log(LOG_DEBUG, "%d: pendings[%d]=%d", dev->devid, dev->pendingtail, req.id);
      dev->pendings[dev->pendingtail] = req.id;
      dev->pendingrefs[dev->pendingtail] = req.u.gref[0];
      dev->pendingoffsets[dev->pendingtail] = req.offset;
      dev->pendingtail = (dev->pendingtail + 1) % 32;
      break;
    case USBIF_T_RESET: /* (internal) Reset request, reply and do nothing */
      rsp.id            = req.id;
      rsp.actual_length = 0;
      rsp.data          = 0;
      rsp.status        = USBIF_RSP_OKAY;
      superbackend_send(dev, &rsp);
      break;
    case USBIF_T_ABORT_PIPE: /* Absolutely no idea what this is. Succeeding */
      rsp.id            = req.id;
      rsp.actual_length = 0;
      rsp.data          = 0;
      rsp.status        = USBIF_RSP_OKAY;
      superbackend_send(dev, &rsp);
      break;
    case USBIF_T_GET_SPEED: /* (internal) Speed request, say HIGH (USB2) */
      rsp.id            = req.id;
      rsp.actual_length = 0;
      rsp.data          = USBIF_S_HIGH;
      rsp.status        = USBIF_RSP_OKAY;
      superbackend_send(dev, &rsp);
      break;
    case USBIF_T_CANCEL: /* (internal) Cancel request. Cancel the
                          * requested pending request and reply. */
      tocancel = *((uint64_t*)&req.u.data[0]);
      for (i = dev->pendinghead; i != dev->pendingtail; i = (i + 1) % 32)
        if (dev->pendings[i] == tocancel)
          break;
      if (tocancel != dev->pendings[i]) {
        rsp.id            = req.id;
        rsp.actual_length = 0;
        rsp.data          = 0;
        rsp.status        = USBIF_RSP_ERROR;
        xd_log(LOG_DEBUG, "Failing to cancel %d", tocancel);
        superbackend_send(dev, &rsp);
      } else {
        rsp.id            = tocancel;
        rsp.actual_length = 0;
        rsp.data          = 0;
        rsp.status        = USBIF_RSP_USB_CANCELED;
        superbackend_send(dev, &rsp);
        dev->pendings[i] = -1;
        dev->pendingrefs[i] = -1;
        dev->pendingoffsets[i] = -1;
        xd_log(LOG_DEBUG, "Cancelled %d", tocancel);
        rsp.id = req.id;
        rsp.actual_length = 0;
        rsp.data          = 0;
        rsp.status        = USBIF_RSP_OKAY;
        superbackend_send(dev, &rsp);
      }
      break;
    default:
      xd_log(LOG_DEBUG, "Unknown request type %d", req.type);
      rsp.id = req.id;
      rsp.actual_length = -1;
      rsp.data          = 0;
      rsp.status        = USBIF_RSP_EOPNOTSUPP;
      superbackend_send(dev, &rsp);
      break;
    }

    dev->back_ring.req_cons++;

    xd_log(LOG_DEBUG, "***********************\n");
  }
}

static xen_device_t
superback_alloc(xen_backend_t backend, int devid, void *priv)
{
  struct superhid_device *dev;
  struct superhid_backend *superback = priv;

  dev = malloc(sizeof(*dev));
  memset(dev, 0, sizeof(*dev));
  dev->devid = devid;
  dev->backend = backend;
  dev->evtfd = -1;
  dev->superback = superback;
  dev->type = devid;

  superback->devices[devid] = dev;

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

static void
superback_evtchn_handler(int fd, short event, void *priv)
{
  backend_evtchn_handler(priv);
}

static int
superback_connect(xen_device_t xendev)
{
  struct superhid_device *dev = xendev;
  char path[256];
  char *res;

  /* printf("connect %p\n", xendev); */

  dev->evtfd = backend_bind_evtchn(dev->backend, dev->devid);
  dev->priv = backend_evtchn_priv(dev->backend, dev->devid);
  if (dev->evtfd < 0) {
    printf("failed to bind evtchn\n");
    return -1;
  }

  dev->page = backend_map_granted_ring(dev->backend, dev->devid);
  if (!dev->page) {
    printf("failed to map page\n");
    return -1;
  }

  BACK_RING_INIT(&dev->back_ring, (usbif_sring_t *)dev->page, XC_PAGE_SIZE);
  dev->back_ring_ready = 1;

  event_set(&dev->event, dev->evtfd, EV_READ | EV_PERSIST,
            superback_evtchn_handler,
            backend_evtchn_priv(dev->backend, dev->devid));
  event_add(&dev->event, NULL);

  return 0;
}


static void
superback_disconnect(xen_device_t xendev)
{
  struct superhid_device *dev = xendev;
  usbinfo_t ui;
  int i;
  struct superhid_backend *kill = NULL;

  /* Windows calls this at device creation for some reason. Let's
   * bail if the device is not fully created... */
  /* Also this function seems to get called with bogus values after a
   * backend got killed... */
  if (dev != NULL && dev->priv != NULL && dev->devid > 0 && dev->devid < 6) {
    xd_log(LOG_INFO, "disconnect %d\n", dev->devid);
    event_del(&dev->event);
    backend_unbind_evtchn(dev->backend, dev->devid);
    ui.usb_virtid = dev->type;
    ui.usb_bus = 1;
    ui.usb_device = dev->type;
    ui.usb_vendor = SUPERHID_VENDOR;
    ui.usb_product = SUPERHID_DEVICE;
    superxenstore_destroy_usb(&dev->superback->di, &ui);
    kill = dev->superback;
    for (i = 0; i < BACKEND_DEVICE_MAX; ++i) {
      if (dev->superback->devices[i] == dev)
        dev->superback->devices[i] = NULL;
      if (dev->superback->devices[i] != NULL)
        kill = NULL;
    }
    /* This should really be a call to backend_free_device() */
    free(dev);
  }

  if (kill != NULL) {
    /* No device use that backend anymore, kill it */
    xd_log(LOG_INFO, "KILLING THE BACKEND FOR DOMID %d", kill->di.di_domid);
    /* This will call this function will all the devices it thinks
     * are still alive... We need a backend_free_device() */
    /* backend_release(kill->backend); */
    if (kill->di.di_domid == input_grabber) {
      close(kill->buffers.s);
      input_grabber = -1;
      xd_log(LOG_INFO, "DOMID %d no longer holds the input", kill->di.di_domid);
      /* HACK: Let the VM change to a non-"running" state to make sure we
       * don't re-grab the input... */
      sleep(5);
    }
    memset(kill, 0, sizeof(struct superhid_backend));
  }
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
  consume_requests(dev);
}

static void
superback_free(xen_device_t xendev)
{
  struct superhid_device *dev = xendev;

  /* This function seems to get called with bogus values on shutdown */
  if (dev->devid > 0 && dev->devid < 6) {
    printf("free %d\n", dev->devid);
    superback_disconnect(xendev);
    dev->superback->devices[dev->devid] = NULL;
    free(dev);
  }
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
  int i;

  memset(superbacks, 0, sizeof(struct superhid_backend) * SUPERHID_MAX_BACKENDS);

  if (backend_init(SUPERHID_DOMID)) {
    xd_log(LOG_ERR, "Failed to initialize libxenbackend");
    return -1;
  }

  return backend_xenstore_fd();
}

xen_backend_t superbackend_add(dominfo_t di, struct superhid_backend *superback)
{
  superback->backend = backend_register(SUPERHID_NAME, di.di_domid, &superback_ops, superback);
  if (!superback->backend)
  {
    xd_log(LOG_ERR, "Failed to register as a backend for domid %d", di.di_domid);
    return NULL;
  }

  return superback->backend;
}

void superbackend_send(struct superhid_device *device, usbif_response_t *rsp)
{
  memcpy(RING_GET_RESPONSE(&device->back_ring, device->back_ring.rsp_prod_pvt), rsp, sizeof(*rsp));
  device->back_ring.rsp_prod_pvt++;
  RING_PUSH_RESPONSES(&device->back_ring);
  backend_evtchn_notify(device->backend, device->devid);
}

int superbackend_find_slot(int domid)
{
  int i = 0;

  while (i < SUPERHID_MAX_BACKENDS && superbacks[i].di.di_domid != domid)
    ++i;

  if (i == SUPERHID_MAX_BACKENDS)
    return -1;
  else
    return i;
}

int superbackend_find_free_slot(void)
{
  int i = 0;

  while (i < SUPERHID_MAX_BACKENDS && superbacks[i].di.di_dompath != NULL)
    ++i;

  if (i == SUPERHID_MAX_BACKENDS)
    return -1;
  else
    return i;
}
