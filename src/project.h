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
 * @file   project.h
 * @author Jed Lejosne <lejosnej@ainfosec.com>
 * @date   Fri Oct 30 11:26:10 2015
 *
 * @brief  Main header
 *
 * This is the main SuperHID header, all includes and exported
 * functions live here.
 */

#ifndef   	PROJECT_H_
# define   	PROJECT_H_

/* #define DEBUG */

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

#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <inttypes.h>
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
#include <linux/hiddev.h>
#include <linux/input.h>
#include <xen/grant_table.h>

#include "usbif.h"

#define EVENT_SIZE             12

#define SUPERHID_VM_TYPE       "svm"
#define SUPERHID_NAME          "vhid"
#define SUPERHID_REAL_NAME     "SuperHID"
#define SUPERHID_VENDOR        0x4242
#define SUPERHID_DEVICE        0x4242
#define SUPERHID_DOMID         0
#define SUPERHID_REPORT_LENGTH 12
#define SUPERHID_FINGERS       10
#define SUPERHID_FINGER_WIDTH  2  /* How many fingers in one report */
#define SUPERHID_MAX_BACKENDS  32 /* 32 running VMs should be plenty */
/* The following is from libxenbackend. It should be exported and bigger */
#define BACKEND_DEVICE_MAX     16

#define BIT_FIELD              unsigned int

/**
 * The (stupid) logging macro
 */
#ifdef DEBUG
#define superlog(I, ...) do { fprintf(stderr, ##__VA_ARGS__); fprintf(stderr, "\n"); } while (0)
#else
#define superlog(I, ...) do { if (I != LOG_DEBUG) { fprintf(stderr, ##__VA_ARGS__); fprintf(stderr, "\n"); } } while (0)
#endif

typedef struct dominfo
{
  int   di_domid;
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

enum superhid_type
{
  SUPERHID_TYPE_MULTI = 1,
  SUPERHID_TYPE_MOUSE,
  SUPERHID_TYPE_DIGITIZER,
  SUPERHID_TYPE_TABLET,
  SUPERHID_TYPE_KEYBOARD
};

struct superhid_device
{
  uint8_t                  devid;
  xen_backend_t            backend;
  struct superhid_backend *superback;
  void                    *page;
  usbif_back_ring_t        back_ring;
  bool                     back_ring_ready;
  int                      evtfd;
  void                    *priv;
  uint64_t                 pendings[32];       /* usbif_request_t.id */
  grant_ref_t              pendingrefs[32];    /* usbif_request_t.u.gref */
  uint16_t                 pendingoffsets[32]; /* usbif_request_t.offset */
  uint8_t                  pendinghead;
  uint8_t                  pendingtail;
  struct event             event;
  enum superhid_type       type;
};

#define buffersize              (EVENT_SIZE*20)

struct buffer_t
{
  char buffer[buffersize];
  int bytes_remaining;
  int position;
  int s;
  int copy;
  int block;
};

struct superhid_backend
{
  xen_backend_t backend;
  struct superhid_device *devices[BACKEND_DEVICE_MAX];
  dominfo_t di;
  struct buffer_t buffers;
  struct event input_event;
};

struct hid_descriptor {
  __u8   bLength;
  __u8   bDescriptorType;
  __le16 bcdHID;
  __u8   bCountryCode;
  __u8   bNumDescriptors;
  __u8   bAddDescriptorType;
  __u16  wAddDescriptorLength;
} __attribute__ ((packed));

struct hid_report_desc {
  unsigned char  subclass;
  unsigned char  protocol;
  unsigned short report_length;
  unsigned short report_desc_length;
  unsigned char  report_desc[];
};

struct feature_report {
  char feature;
  char value;
  /* char id; */
};

struct superhid_finger
{
  BIT_FIELD tip_switch:1;  /* Is the finger currently touching? */
  BIT_FIELD placeholder:3; /* 3 spare bytes if we ever want extra
                            * stuffs like IN_RANGE or DATA_VALID */
  BIT_FIELD finger_id:4;   /* The finger ID, should be between 0 and 9 */
  uint16_t  x;             /* Absolute position of the finger on the X axis */
  uint16_t  y;             /* Absolute position of the finger on the Y axis */
} __attribute__ ((__packed__));

struct superhid_report
{
  uint8_t  report_id;
  uint8_t  data[SUPERHID_REPORT_LENGTH - 1];
} __attribute__ ((__packed__));

struct superhid_report_multitouch
{
  uint8_t  report_id;     /* Should always be REPORT_ID_MULTITOUCH */
  uint8_t  count;         /* How many fingers are in the packet (1/2) */
  struct superhid_finger fingers[SUPERHID_FINGER_WIDTH];
} __attribute__ ((__packed__));

struct superhid_report_tablet
{
  uint8_t   report_id;      /* Should always be REPORT_ID_TABLET */
  BIT_FIELD left_click:1;
  BIT_FIELD right_click:1;
  BIT_FIELD middle_click:1;
  BIT_FIELD placeholder:5;
  uint16_t  x;              /* Absolute position on the X axis */
  uint16_t  y;              /* Absolute position on the Y axis */
  /* int8_t    wheel;          /\* Vertical scroll wheel. NOT USED *\/ */
  uint8_t   pad[SUPERHID_REPORT_LENGTH - 6];
} __attribute__ ((__packed__));

struct superhid_report_keyboard
{
  uint8_t  report_id;     /* Should always be REPORT_ID_KEYBOARD */
  uint8_t  modifier;
  uint8_t  reserved;
  uint8_t  keycode[6];
  uint8_t  pad[SUPERHID_REPORT_LENGTH - 9];
} __attribute__ ((__packed__));

struct superhid_report_mouse
{
  uint8_t   report_id;     /* Should always be REPORT_ID_MOUSE */
  BIT_FIELD left_click:1;
  BIT_FIELD right_click:1;
  BIT_FIELD middle_click:1;
  BIT_FIELD fourth_click:1;
  BIT_FIELD fifth_click:1;
  BIT_FIELD placeholder:3;
  uint8_t   x;
  uint8_t   y;
  uint8_t   wheel;
  uint8_t   pad[SUPERHID_REPORT_LENGTH - 5];
} __attribute__ ((__packed__));

/* Report IDs for the various devices */
#define REPORT_ID_KEYBOARD      0x01
#define REPORT_ID_MOUSE         0x02
#define REPORT_ID_TABLET        0x03
#define REPORT_ID_MULTITOUCH    0x04
#define REPORT_ID_STYLUS        0x05
#define REPORT_ID_PUCK          0x06
#define REPORT_ID_FINGER        0x07
/* #define REPORT_ID_MT_MAX_COUNT  0x10 */
#define REPORT_ID_MT_MAX_COUNT  0x04 /* This doesn't need its own ID */
#define REPORT_ID_CONFIG        0x11
#define REPORT_ID_INVALID       0xff

xc_gnttab *xcg_handle;
struct superhid_backend superbacks[SUPERHID_MAX_BACKENDS];
int input_grabber;

void superhid_init(void);
int  superhid_setup(struct usb_ctrlrequest *setup, char *buf, enum superhid_type type);
int  superxenstore_init(void);
int  superxenstore_create_usb(dominfo_t *domp, usbinfo_t *usbp);
int  superxenstore_destroy_usb(dominfo_t *domp, usbinfo_t *usbp);
void superxenstore_handler(void);
void superxenstore_close(void);
int  superbackend_init(void);
void superbackend_send(struct superhid_device *device, usbif_response_t *rsp);
int  superbackend_find_slot(int domid);
int  superbackend_create(dominfo_t di);
bool superbackend_all_pending(struct superhid_backend *superback);
void superbackend_send_report_to_frontends(struct superhid_report *report,
                                           struct superhid_backend *superback);
int  superplugin_create(struct superhid_backend *superback);

#endif 	    /* !PROJECT_H_ */
