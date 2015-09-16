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

#include "config.h"

#ifdef TM_IN_SYS_TIME
#include <sys/time.h>
#ifdef TIME_WITH_SYS_TIME
#include <time.h>
#endif
#else
#ifdef TIME_WITH_SYS_TIME
#include <sys/time.h>
#endif
#include <time.h>
#endif

#include <stdio.h>
#include <stdlib.h>

#ifdef HAVE_MALLOC_H
#include <malloc.h>
#endif

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#if defined(HAVE_STDINT_H)
#include <stdint.h>
#elif defined(HAVE_SYS_INT_TYPES_H)
#include <sys/int_types.h>
#endif

#include <sys/mman.h>
#include <syslog.h>
#include <fcntl.h>
#include <stdarg.h>
#include <getopt.h>
#include <xenstore.h>
#include <xenctrl.h>
#include <xenbackend.h>

#include <linux/usb/ch9.h>
#include <linux/hid.h>
#include <xen/grant_table.h>

#include "usbif.h"

/**
 * The (stupid) logging macro
 */
#define xd_log(I, ...) do { fprintf(stderr, ##__VA_ARGS__); fprintf(stderr, "\n"); } while (0)

/* Report IDs for the various devices */
#define REPORT_ID_KEYBOARD      0x01
#define REPORT_ID_MOUSE         0x02
#define REPORT_ID_TABLET        0x03
#define REPORT_ID_MULTITOUCH    0x04
#define REPORT_ID_STYLUS        0x05
#define REPORT_ID_PUCK          0x06
#define REPORT_ID_FINGER        0x07
#define REPORT_ID_MT_MAX_COUNT  0x10
#define REPORT_ID_CONFIG        0x11
#define REPORT_ID_INVALID       0xff

/* This is a relative mouse with 5 buttons and a vertical wheel. */
#define MOUSE\
  0x05, 0x01,                   /* USAGE_PAGE (Generic Desktop)     */ \
    0x09, 0x02,                 /* USAGE (Mouse)                    */ \
    0xa1, 0x01,                 /* COLLECTION (Application)         */ \
    0x85, REPORT_ID_MOUSE,      /*   REPORT_ID (2)                  */ \
    0x09, 0x01,                 /*   USAGE (Pointer)                */ \
    0xa1, 0x00,                 /*   COLLECTION (Physical)          */ \
    0x05, 0x09,                 /*     USAGE_PAGE (Button)          */ \
    0x19, 0x01,                 /*     USAGE_MINIMUM (Button 1)     */ \
    0x29, 0x05,                 /*     USAGE_MAXIMUM (Button 5)     */ \
    0x15, 0x00,                 /*     LOGICAL_MINIMUM (0)          */ \
    0x25, 0x01,                 /*     LOGICAL_MAXIMUM (1)          */ \
    0x95, 0x05,                 /*     REPORT_COUNT (5)             */ \
    0x75, 0x01,                 /*     REPORT_SIZE (1)              */ \
    0x81, 0x02,                 /*     INPUT (Data,Var,Abs)         */ \
    0x95, 0x01,                 /*     REPORT_COUNT (1)             */ \
    0x75, 0x03,                 /*     REPORT_SIZE (3)              */ \
    0x81, 0x03,                 /*     INPUT (Cnst,Var,Abs)         */ \
    0x05, 0x01,                 /*     USAGE_PAGE (Generic Desktop) */ \
    0x09, 0x30,                 /*     USAGE (X)                    */ \
    0x09, 0x31,                 /*     USAGE (Y)                    */ \
    0x09, 0x38,                 /*     USAGE (Z)                    */ \
    0x15, 0x81,                 /*     LOGICAL_MINIMUM (-127)       */ \
    0x25, 0x7f,                 /*     LOGICAL_MAXIMUM (127)        */ \
    0x75, 0x08,                 /*     REPORT_SIZE (8)              */ \
    0x95, 0x03,                 /*     REPORT_COUNT (3)             */ \
    0x81, 0x06,                 /*     INPUT (Data,Var,Rel)         */ \
    0x95, 0x01,                 /*     REPORT_COUNT (1)             */ \
    0x75, 0x08,                 /*     REPORT_SIZE (8)              */ \
    0x81, 0x03,                 /*     INPUT (Cnst,Var,Abs)         */ \
    0xc0,                       /*   END_COLLECTION                 */ \
    0xc0                        /* END_COLLECTION                   */

typedef struct dominfo
{
  int di_domid;
  char *di_name;
  char *di_dompath;
} dominfo_t;

typedef struct usbinfo
{
  int usb_virtid;
  int usb_bus;              /**< USB bus in the physical machine */
  int usb_device;           /**< USB device in the physical machine */
  int usb_vendor;
  int usb_product;
} usbinfo_t;

enum XenBusStates {
  XB_UNKNOWN, XB_INITTING, XB_INITWAIT, XB_INITTED, XB_CONNECTED,
  XB_CLOSING, XB_CLOSED
};

struct superhid_device
{
  xen_backend_t backend;
  int devid;
  void *page;
};

struct superhid_backend
{
  xen_backend_t backend;
  int domid;
  struct superhid_device *device;
};

static xc_gnttab *xcg_handle = NULL;
static struct xs_handle *xs_handle;
char *xs_dom0path = NULL;
usbif_back_ring_t back_ring;
int back_ring_ready = 0;
struct superhid_backend *backend = NULL;
int evtfd = -1;
void *priv = NULL;

static void*
xmalloc(size_t size)
{
  void *p;

  if ((p = malloc(size)) == NULL) {
    xd_log(LOG_CRIT, "Out of memory");
    exit(2);
  }

  return p;
}

/*
 * Allocating formatted string print.
 * The caller is responsible for returning the returned string.
 */
static char *
xasprintf(const char *fmt, ...)
{
  char *s;
  va_list ap;
  int len;

  va_start(ap, fmt);
  len = vsnprintf(NULL, 0, fmt, ap);
  va_end(ap);

  s = xmalloc(len + 1);

  va_start(ap, fmt);
  vsprintf(s, fmt, ap);
  va_end(ap);

  return s;
}

/*
 * Create a new directory in Xenstore
 */
static int
xenstore_add_dir(xs_transaction_t xt, char *path, int d0, int p0, int d1, int p1)
{
  struct xs_permissions perms[2];

  if (xs_mkdir(xs_handle, xt, path) == false) {
    xd_log(LOG_ERR, "XenStore error mkdir()ing %s", path);
    return -1;
  }

  perms[0].perms = p0;
  perms[0].id = d0;
  perms[1].perms = p1;
  perms[1].id = d1;
  if (xs_set_permissions(xs_handle, xt, path, perms, 2) == false) {
    xd_log(LOG_ERR, "XenStore error setting permissions on %s",
           path);
    xs_rm(xs_handle, xt, path);
    return -1;
  }

  return 0;
}

/**
 * Read the xenstore node of a specific VM (/local/domain/<domid>/<path>)
 *
 * @param domid The domid of the VM
 * @param format The printf format of the subpath to read, followed by
 *        the format parameters
 *
 * @return The value of the key if found, NULL otherwise
 */
char*
xenstore_dom_read(unsigned int domid, const char *format, ...)
{
  char *domain_path;
  va_list arg;
  char *ret = NULL;
  char *buff = NULL;
  int res;

  domain_path = xs_get_domain_path(xs_handle, domid);

  if (!domain_path)
    return NULL;

  buff = xasprintf("%s/%s", domain_path, format);
  free(domain_path);

  if (res == -1)
    return NULL;

  va_start(arg, format);
  ret = xs_read(xs_handle, XBT_NULL, buff, NULL);
  va_end(arg);

  free(buff);

  return ret;
}

/**
 * Fill the domain information for a given VM
 *
 * @param domid The domid of the VM
 * @param di The domain information to fill
 *
 * @return 0 on success, -ENOENT on failure
 */
int
xenstore_get_dominfo(int domid, dominfo_t *di)
{
  di->di_domid = domid;
  di->di_dompath = xs_get_domain_path(xs_handle, di->di_domid);
  if (!di->di_dompath) {
    xd_log(LOG_ERR, "Could not get domain %d path from xenstore", domid);
    return -ENOENT;
  }
  di->di_name = xasprintf("Domain-%d", domid);
  return 0;
}

static char*
xenstore_get_keyval(char *path, char *key)
{
  char tmppath[256];

  snprintf(tmppath, sizeof(tmppath), "%s/%s", path, key);

  return xs_read(xs_handle, XBT_NULL, tmppath, NULL);
}

/**
 * Write a single value into Xenstore.
 */
static int
xenstore_set_keyval(xs_transaction_t xt, char *path, char *key, char *val)
{
  char tmppath[256];

  if (key != NULL) {
    snprintf(tmppath, sizeof (tmppath), "%s/%s", path, key);
    path = tmppath;
  }

  if (xs_write(xs_handle, xt, path, val, strlen(val)) == false) {
    xd_log(LOG_ERR, "XenStore error writing %s", path);
    return -1;
  }

  return 0;
}

static char*
xenstore_dev_fepath(dominfo_t *domp, char *type, int devnum)
{
  return (xasprintf("%s/device/%s/%d", domp->di_dompath, type,
                    devnum));
}

static char*
xenstore_dev_bepath(dominfo_t *domp, char *type, int devnum)
{
  return (xasprintf("%s/backend/%s/%d/%d", xs_dom0path, type,
                    domp->di_domid, devnum));
}

/**
 * Populate Xenstore with the information about a usb device for this domain
 */
int
xenstore_create_usb(dominfo_t *domp, usbinfo_t *usbp)
{
  char *bepath, *fepath;
  char value[32];
  xs_transaction_t trans;

  xd_log(LOG_DEBUG, "Creating VUSB node for %d.%d",
         usbp->usb_bus, usbp->usb_device);

  /*
   * Construct Xenstore paths for both the front and back ends.
   */
  fepath = xenstore_dev_fepath(domp, "vusb", usbp->usb_virtid);
  bepath = xenstore_dev_bepath(domp, "vusb", usbp->usb_virtid);

  for (;;) {
    trans = xs_transaction_start(xs_handle);

    /*
     * Make directories for both front and back ends
     */
    if (xenstore_add_dir(trans, bepath, 0, XS_PERM_NONE, domp->di_domid,
                         XS_PERM_READ))
      break;
    if (xenstore_add_dir(trans, fepath, domp->di_domid, XS_PERM_NONE, 0,
                         XS_PERM_READ))
      break;

    /*
     * Populate frontend device info
     */
    if (xenstore_set_keyval(trans, fepath, "backend-id", "0"))
      break;
    snprintf(value, sizeof (value), "%d", usbp->usb_virtid);
    if (xenstore_set_keyval(trans, fepath, "virtual-device", value))
      break;
    if (xenstore_set_keyval(trans, fepath, "backend", bepath))
      break;
    snprintf(value, sizeof (value), "%d", XB_INITTING);
    if (xenstore_set_keyval(trans, fepath, "state", value))
      break;

    /*
     * Populate backend device info
     */
    if (xenstore_set_keyval(trans, bepath, "domain", domp->di_name))
      break;
    if (xenstore_set_keyval(trans, bepath, "frontend", fepath))
      break;
    snprintf(value, sizeof (value), "%d", XB_INITTING);
    if (xenstore_set_keyval(trans, bepath, "state", value))
      break;
    if (xenstore_set_keyval(trans, bepath, "online", "1"))
      break;
    snprintf(value, sizeof (value), "%d", domp->di_domid);
    if (xenstore_set_keyval(trans, bepath, "frontend-id", value))
      break;
    snprintf(value, sizeof (value), "%d.%d", usbp->usb_bus,
             usbp->usb_device);
    if (xenstore_set_keyval(trans, bepath, "physical-device", value))
      break;

    if (xs_transaction_end(xs_handle, trans, false) == false) {
      if (errno == EAGAIN)
        continue;
      break;
    }
    free(fepath);
    free(bepath);

    return 0;
  }

  xs_transaction_end(xs_handle, trans, true);
  xd_log(LOG_ERR, "Failed to write usb info to XenStore");
  free(fepath);
  free(bepath);

  return -1;
}



struct hid_descriptor {
  __u8  bLength;
  __u8  bDescriptorType;
  __le16 bcdHID;
  __u8  bCountryCode;
  __u8  bNumDescriptors;

  /* struct hid_class_descriptor desc[1]; */
} __attribute__ ((packed));

static struct hid_descriptor hid_dt_desc = {
  .bLength= sizeof(struct hid_descriptor),
  .bDescriptorType= HID_DT_HID,
  .bcdHID= 0x0101,
  .bCountryCode= 0x00,
  .bNumDescriptors= 0x1,
};

struct hid_desc {
  unsigned char         subclass;
  unsigned char         protocol;
  unsigned short        report_length;
  unsigned short        report_desc_length;
  unsigned char         report_desc[];
};

static struct feature_report {
  char feature;
  char value;
};

struct hid_desc superhid_desc = {
  .subclass= 0, /* No subclass */
  .protocol= 0,
  .report_length= 8,
  .report_desc_length= 144,
  /* Length without the mouse: */
  /* .report_desc_length= 84, */
  .report_desc= {
    MOUSE,
    0x05, 0x0D,         /*  Usage Page (Digitizer),             */
    0x09, 0x04,         /*  Usage (Touchscreen),                */
    0xA1, 0x01,         /*  Collection (Application),           */
    0x85, REPORT_ID_MULTITOUCH, /* Report ID (4),               */
    0x09, 0x22,         /*      Usage (Finger),                 */
    0xA1, 0x00,         /*      Collection (Physical),          */
    0x09, 0x42,         /*          Usage (Tip Switch),         */
    0x15, 0x00,         /*          Logical Minimum (0),        */
    0x25, 0x01,         /*          Logical Maximum (1),        */
    0x75, 0x01,         /*          Report Size (1),            */
    0x95, 0x01,         /*          Report Count (1),           */
    0x81, 0x02,         /*          Input (Variable),           */
    0x09, 0x32,         /*          Usage (In Range),           */
    0x81, 0x02,         /*          Input (Variable),           */
    0x09, 0x37,         /*          Usage (Data Valid),         */
    0x81, 0x02,         /*          Input (Variable),           */
    0x25, 0x1F,         /*          Logical Maximum (31),       */
    0x75, 0x05,         /*          Report Size (5),            */
    0x09, 0x51,         /*          Usage (51h),                */
    0x81, 0x02,         /*          Input (Variable),           */
    0x05, 0x01,         /*          Usage Page (Desktop),       */
    0x55, 0x0E,         /*          Unit Exponent (14),         */
    0x65, 0x11,         /*          Unit (Centimeter),          */
    0x35, 0x00,         /*          Physical Minimum (0),       */
    0x75, 0x10,         /*          Report Size (16),           */
    0x46, 0x56, 0x0A,   /*          Physical Maximum (2646),    */
    0x26, 0xFF, 0x0F,   /*          Logical Maximum (4095),     */
    0x09, 0x30,         /*          Usage (X),                  */
    0x81, 0x02,         /*          Input (Variable),           */
    0x46, 0xB2, 0x05,   /*          Physical Maximum (1458),    */
    0x26, 0xFF, 0x0F,   /*          Logical Maximum (4095),     */
    0x09, 0x31,         /*          Usage (Y),                  */
    0x81, 0x02,         /*          Input (Variable),           */
    0x05, 0x0D,         /*          Usage Page (Digitizer),     */
    0x75, 0x08,         /*          Report Size (8),            */
    0x85, REPORT_ID_MT_MAX_COUNT, /* Report ID (10),            */
    0x09, 0x55,         /*          Usage (55h),                */
    0x25, 0x10,         /*          Logical Maximum (16),       */
    0xB1, 0x02,         /*          Feature (Variable),         */
    0xC0,               /*      End Collection,                 */
    0xC0                /*  End Collection                      */
  }
};

static int superhid_setup(struct usb_ctrlrequest *setup, void *buf)
{
  __u16 value, length;
  struct feature_report feature;

  value = setup->wValue;
  length = setup->wLength;

  switch ((setup->bRequestType << 8) | setup->bRequest) {
  case ((USB_DIR_IN | USB_TYPE_CLASS | USB_RECIP_INTERFACE) << 8
        | HID_REQ_GET_REPORT):
    printf("get_report\n");

    if ((value & 0xFF) == 0x10)
    {
      /* All right... We just received feature request 0x10 */
      /* Right now there's no system for handling feature requests */
      /* But Windows 8 needs an answer to that. */
      /* It won't work without knowing how many fingers we handle. */
      /* The device we "emulate" here is the Samsung Slate 7, which
       * handles 8 fingers */
      /* Let's reply that we do the same! */
      feature.feature = 0x10;
      feature.value = 0x08;
      length = 2;
      memcpy(buf, &feature, length);
    }
    else
    {
      /* send an empty report */
      if (superhid_desc.report_length < length)
        length = superhid_desc.report_length;
      memset(buf, 0x0, length);
    }

    goto respond;
    break;

  case ((USB_DIR_IN | USB_TYPE_CLASS | USB_RECIP_INTERFACE) << 8
        | HID_REQ_GET_PROTOCOL):
    printf("get_protocol\n");
    goto stall;
    break;

  case ((USB_DIR_OUT | USB_TYPE_CLASS | USB_RECIP_INTERFACE) << 8
        | HID_REQ_SET_REPORT):
    printf("set_report | wLenght=%d\n", setup->wLength);
    goto stall;
    break;

  case ((USB_DIR_OUT | USB_TYPE_CLASS | USB_RECIP_INTERFACE) << 8
        | HID_REQ_SET_PROTOCOL):
    printf("set_protocol\n");
    goto stall;
    break;

  case ((USB_DIR_IN | USB_TYPE_STANDARD | USB_RECIP_INTERFACE) << 8
        | USB_REQ_GET_DESCRIPTOR):
    switch (value >> 8) {
    case HID_DT_HID:
      printf("USB_REQ_GET_DESCRIPTOR: HID\n");
      if (hid_dt_desc.bLength < length)
        length = hid_dt_desc.bLength;
      memcpy(buf, &hid_dt_desc, length);
      goto respond;
      break;
    case HID_DT_REPORT:
      printf("USB_REQ_GET_DESCRIPTOR: REPORT\n");
      if (superhid_desc.report_desc_length < length)
        length = superhid_desc.report_desc_length;
      memcpy(buf, superhid_desc.report_desc, length);
      goto respond;
      break;

    default:
      printf("Unknown descriptor request 0x%x\n",
           value >> 8);
      goto stall;
      break;
    }
    break;

  default:
    printf("Unknown request 0x%x\n",
         setup->bRequest);
    goto stall;
    break;
  }

stall:
  return 0;

respond:
  return length;
}

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

  /* for (int i = 0; i < 42; ++i) */
  /*   printf("%02X ", ((char *)dev->page)[i]); */
  /* printf("\n"); */

  /* while (!RING_HAS_UNCONSUMED_REQUESTS(&back_ring)) */
  /*   ; */
  while (RING_HAS_UNCONSUMED_REQUESTS(&back_ring))
  {
    memcpy(&req, RING_GET_REQUEST(&back_ring, back_ring.req_cons), sizeof(req));
    printf("***** GOT REQUEST *****\n", req.id, req.type);
    printf("id=%d\n", req.id);
    printf("setup=%d\n", req.setup);
    printf("type=%d\n", req.type);
    printf("endpoint=%d\n", req.endpoint);
    printf("offset=%d\n", req.offset);
    printf("length=%d\n", req.length);
    printf("nr_segments=%d\n", req.nr_segments);
    printf("flags=%d\n", req.flags);
    printf("nr_packets=%d\n", req.nr_packets);
    printf("startframe=%d\n", req.startframe);
    responded = 0;
    if (req.type == USBIF_T_GET_SPEED) {
      rsp.id            = req.id;
      rsp.actual_length = 0;
      rsp.data          = USB_SPEED_HIGH;
      rsp.status        = USBIF_RSP_OKAY;
      responded = 1;
    }
    if (req.type == USBIF_T_RESET) {
      rsp.id            = req.id;
      rsp.actual_length = 0;
      rsp.data          = 0;
      rsp.status        = USBIF_RSP_OKAY;
      responded = 1;
    }
    if (req.setup != 0) {
      struct usb_ctrlrequest setup;
      void *buf;

      memcpy(&setup, &req.setup, sizeof(struct usb_ctrlrequest));
      printf("SETUP.bRequestType=%X\n", setup.bRequestType);
      printf("SETUP.bRequest=%X\n", setup.bRequest);
      printf("SETUP.wValue=%X\n", setup.wValue);
      printf("SETUP.wIndex=%X\n", setup.wIndex);
      printf("SETUP.wLength=%X\n", setup.wLength);
      printf("SETUP ");
      buf = xc_gnttab_map_grant_ref(xcg_handle,
                                    backend->domid,
                                    req.u.gref[req.startframe],
                                    PROT_READ | PROT_WRITE);
      responded = superhid_setup(&setup, buf + req.offset);
    }
    if (responded != 0) {
      memcpy(RING_GET_RESPONSE(&back_ring, back_ring.rsp_prod_pvt), &rsp, sizeof(rsp));
      back_ring.rsp_prod_pvt++;
      RING_PUSH_RESPONSES(&back_ring);
      backend_evtchn_notify(backend->backend, backend->device->devid);
    }
    back_ring.req_cons++;
    printf("***********************\n");
  }
}

static xen_device_t
superhid_alloc(xen_backend_t backend, int devid, void *priv)
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
superhid_init(xen_device_t xendev)
{
  struct superhid_device *dev = xendev;

  /* printf("init %p\n", xendev); */
  backend_print(dev->backend, dev->devid, "version", "3");
  backend_print(dev->backend, dev->devid, "feature-barrier", "1");

  return 0;
}

static int
superhid_connect(xen_device_t xendev)
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
superhid_disconnect(xen_device_t xendev)
{
  struct superhid_device *dev = xendev;

  /* TODO: something */
  (void)dev;

  printf("disconnect\n");
}

static void superhid_backend_changed(xen_device_t xendev,
                                     const char *node,
                                     const char *val)
{
  /* printf("backend changed: %s=%s\n", node, val); */
}

static void superhid_frontend_changed(xen_device_t xendev,
                                      const char *node,
                                      const char *val)
{
  /* printf("frontend changed: %s=%s\n", node, val); */
}

static void
superhid_event(xen_device_t xendev)
{
  struct superhid_device *dev = xendev;

  /* printf("event %p\n", xendev); */
  consume_requests();
}

static void
superhid_free(xen_device_t xendev)
{
  struct superhid_device *dev = xendev;

  /* printf("free %p\n", xendev); */
  superhid_disconnect(xendev);

  free(dev);
}


static struct xen_backend_ops superhid_backend_ops = {
  superhid_alloc,
  superhid_init,
  superhid_connect,
  superhid_disconnect,
  superhid_backend_changed,
  superhid_frontend_changed,
  superhid_event,
  superhid_free
};

int main(int argc, char **argv)
{
  dominfo_t di;
  usbinfo_t ui;
  int domid, ret;
  char path[256], token[256];
  char* res;
  int ring, evtchn, fd;
  xc_evtchn *ec;
  char *page;
  fd_set fds;

  if (argc != 2)
    return 1;

  /* Init XenStore */
  if (xs_handle == NULL) {
    xs_handle = xs_daemon_open();
  }
  if (xs_handle == NULL) {
    xd_log(LOG_ERR, "Failed to connect to xenstore");
    return 1;
  }
  if (xcg_handle == NULL) {
    xcg_handle = xc_gnttab_open(NULL, 0);
  }
  if (xcg_handle == NULL) {
    xd_log(LOG_ERR, "Failed to connect to xc");
    return 1;
  }
  if (xs_dom0path == NULL) {
    xs_dom0path = xs_get_domain_path(xs_handle, 0);
  }
  if (xs_dom0path == NULL) {
    xd_log(LOG_ERR, "Could not get domain 0 path from XenStore");
    return 1;
  }

  /* Fill the domain info */
  domid = strtol(argv[1], NULL, 10);
  ret = xenstore_get_dominfo(domid, &di);
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

  /* Do stuffs */
  if (backend_init(0))
    printf("barf\n");
  backend = malloc(sizeof(*backend));
  backend->domid = di.di_domid;
  backend->device = NULL;
  backend->backend = backend_register("vusb", di.di_domid, &superhid_backend_ops, backend);
  if (!backend->backend)
  {
    printf("failed\n");
    free(backend);
    return 1;
  }
  fd = backend_xenstore_fd();

  xenstore_create_usb(&di, &ui);

  do {
    int fdmax = fd;

    FD_ZERO(&fds);
    FD_SET(fd, &fds);
    if (evtfd != -1)
    {
      FD_SET(evtfd, &fds);
      if (evtfd > fd)
        fdmax = evtfd;
    }

    select(fdmax + 1, &fds, NULL, NULL, NULL);

    if (FD_ISSET(fd, &fds)) {
      /* printf("fd fired\n"); */
      backend_xenstore_handler(NULL);
    }
    if (evtfd != -1 && FD_ISSET(evtfd, &fds)) {
      /* printf("evtfd fired\n"); */
      if (priv != NULL)
        backend_evtchn_handler(priv);
    }
  } while (1);
  xc_evtchn_close(ec);

  /* Cleanup */
  xs_daemon_close(xs_handle);
  xc_gnttab_close(xcg_handle);

  return 0;
}
