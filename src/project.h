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

#ifndef   	PROJECT_H_
# define   	PROJECT_H_

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

#include <event.h>
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

#include "superplugin.h"
#include "usbif.h"

#define DEBUG

#define SUPERHID_NAME           "vusb"
#define SUPERHID_DOMID          0
/* The following is from libxenbackend. It should be exported and bigger */
#define BACKEND_DEVICE_MAX     16

/**
 * The (stupid) logging macro
 */
#define xd_log(I, ...) do { fprintf(stderr, ##__VA_ARGS__); fprintf(stderr, "\n"); } while (0)

typedef struct dominfo
{
  int di_domid;
  char *di_name;
  char *di_dompath;
} dominfo_t;

struct superhid_device
{
  unsigned char devid;
  xen_backend_t backend;
  struct superhid_backend *superback;
  void *page;
  usbif_back_ring_t back_ring;
  unsigned int back_ring_ready:1;
  int evtfd;
  void *priv;
  unsigned char pendings[32]; /* 0 <= slot <= 31 */
  unsigned int pendingrefs[32];
  unsigned int pendingoffsets[32];
  char pendinghead;
  char pendingtail;
  struct event event;
};

struct superhid_backend
{
  struct superhid_device *devices[BACKEND_DEVICE_MAX];
  dominfo_t di;
};

typedef struct usbinfo
{
  int usb_virtid;
  int usb_bus;              /**< USB bus in the physical machine */
  int usb_device;           /**< USB device in the physical machine */
  int usb_vendor;
  int usb_product;
} usbinfo_t;

struct hid_descriptor {
  __u8  bLength;
  __u8  bDescriptorType;
  __le16 bcdHID;
  __u8  bCountryCode;
  __u8  bNumDescriptors;
  __u8  bAddDescriptorType;
  __u16 wAddDescriptorLength;
} __attribute__ ((packed));

struct hid_report_desc {
  unsigned char         subclass;
  unsigned char         protocol;
  unsigned short        report_length;
  unsigned short        report_desc_length;
  unsigned char         report_desc[];
};

struct feature_report {
  char feature;
  char value;
};

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

xc_gnttab *xcg_handle;
struct superhid_backend superback;

void superhid_init(void);
int superhid_setup(struct usb_ctrlrequest *setup, void *buf);
int superxenstore_init(void);
int superxenstore_get_dominfo(int domid, dominfo_t *di);
int superxenstore_create_usb(dominfo_t *domp, usbinfo_t *usbp);
void superxenstore_close(void);
int superbackend_init(void);
xen_backend_t superbackend_add(dominfo_t di, struct superhid_backend *superback);
void superbackend_send(struct superhid_device *device, usbif_response_t *rsp);

#endif 	    /* !PROJECT_H_ */
