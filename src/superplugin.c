/*
 * Copyright (c) 2013 Citrix Systems, Inc.
 * Copyright (c) 2015 Assured Information Security, Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

/**
 * @file   superplugin.c
 * @author Jed Lejosne <lejosnej@ainfosec.com>
 * @date   Fri Oct 30 10:55:56 2015
 *
 * @brief  Input server plugin
 *
 * This file is based on the reference client plugin implementation
 * from the input server repository (testsocketclient.c).
 * It allows to grab input events for a given domid, to send them
 * through SuperHID.
 */

#include "project.h"

#define SOCK_PATH               "/var/run/input_socket"
#define MAGIC                   0xAD9CBCE9

/* Shouldn't that be defined somewhere already? */
#define ABS_MT_SLOT             0x2f
#define EV_DEV                  0x06
#define DEV_SET                 0x01

/* All the following is specific to the superhid digitizer */
#define TIP_SWITCH              0x01

#define LOW_X                   0
#define HIGH_X                  0xFFF
#define LOW_Y                   0
#define HIGH_Y                  0xFFF

/* This is actually 8, but we don't want to segv if input_server sends
 * 10 */
#define MAX_FINGERS             10

struct event_record
{
  uint32_t magic;
  uint16_t itype;
  uint16_t icode;
  uint32_t ivalue;
} __attribute__ ((__packed__));

static uint8_t find_scancode(uint8_t keycode)
{
  int i = 0;
  /* linux/drivers/hid/usbhid/usbkbd.c */
  static const uint8_t keycodes[256] = {
    0,  0,  0,  0, 30, 48, 46, 32, 18, 33, 34, 35, 23, 36, 37, 38,
    50, 49, 24, 25, 16, 19, 31, 20, 22, 47, 17, 45, 21, 44,  2,  3,
    4,  5,  6,  7,  8,  9, 10, 11, 28,  1, 14, 15, 57, 12, 13, 26,
    27, 43, 43, 39, 40, 41, 51, 52, 53, 58, 59, 60, 61, 62, 63, 64,
    65, 66, 67, 68, 87, 88, 99, 70,119,110,102,104,111,107,109,106,
    105,108,103, 69, 98, 55, 74, 78, 96, 79, 80, 81, 75, 76, 77, 71,
    72, 73, 82, 83, 86,127,116,117,183,184,185,186,187,188,189,190,
    191,192,193,194,134,138,130,132,128,129,131,137,133,135,136,113,
    115,114,  0,  0,  0,121,  0, 89, 93,124, 92, 94, 95,  0,  0,  0,
    122,123, 90, 91, 85,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
    0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
    0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
    0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
    0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
    29, 42, 56,125, 97, 54,100,126,164,166,165,163,161,115,114,113,
    150,158,159,128,136,177,178,176,142,152,173,140
  };

  while (i < 256 && keycodes[i] != keycode)
    ++i;

  if (i == 256)
    return 0;

  return (i);
}

static uint8_t find_modifier(uint8_t keycode)
{
  int i = 0;
  static const uint8_t keycodes[8] = {
    KEY_LEFTCTRL, KEY_LEFTSHIFT, KEY_LEFTALT, KEY_LEFTMETA,
    KEY_RIGHTCTRL, KEY_RIGHTSHIFT, KEY_RIGHTALT, KEY_RIGHTMETA
  };

  while (i < 8 && keycodes[i] != keycode)
    ++i;

  if (i == 8)
    return 0;

  return (1 << i);
}

static void process_absolute_event(int dev_set, uint16_t itype, uint16_t icode, uint32_t ivalue,
                                   struct superhid_finger *res, struct superhid_report *report)
{
  static struct superhid_finger fingers[MAX_FINGERS] = { { 0 } };
  static struct superhid_report_tablet tablet = { 0 };
  static struct superhid_report_keyboard keyboard = { 0 };
  static struct superhid_report_mouse mouse = { 0 };
  static int multitouch_dev = -42;
  static int finger = 0;
  int i;
  static char just_syned = 0;
  uint8_t prevtip;
  int scancode, modifier;

  /* Initialize the report array. */
  if (fingers[1].finger_id == 0)
    for (i = 0; i < MAX_FINGERS; ++i)
      fingers[i].finger_id = i;

  if (multitouch_dev == -42)
    if (itype == EV_ABS && icode >= ABS_MT_SLOT && icode <= ABS_MAX)
      multitouch_dev = dev_set;

  switch (itype)
  {
  case EV_REL:
    switch (icode)
    {
    case REL_X:
      mouse.report_id = REPORT_ID_MOUSE;
      mouse.x = ivalue;
      break;
    case REL_Y:
      mouse.report_id = REPORT_ID_MOUSE;
      mouse.y = ivalue;
      break;
    case REL_WHEEL:
      mouse.report_id = REPORT_ID_MOUSE;
      mouse.wheel = ivalue;
      break;
    default:
      printf("%d REL?\n", icode);
      break;
    }
  case EV_ABS:
    switch (icode)
    {
    case ABS_WHEEL:
      /* tablet.report_id = REPORT_ID_TABLET; */
      /* tablet.wheel = ivalue; */
      break;
    case ABS_X:
      /* Sometimes we get ABS_X events from digitizers... */
      if (multitouch_dev == -42 || dev_set != multitouch_dev) {
        tablet.report_id = REPORT_ID_TABLET;
        tablet.x = ivalue;
      }
      break;
    case ABS_Y:
      /* Sometimes we get ABS_Y events from digitizers... */
      if (multitouch_dev == -42 || dev_set != multitouch_dev) {
        tablet.report_id = REPORT_ID_TABLET;
        tablet.y = ivalue;
      }
      break;
    case ABS_MT_POSITION_X:
      fingers[finger].x = ivalue >> 3;
      break;
    case ABS_MT_POSITION_Y:
      fingers[finger].y = ivalue >> 3;
      break;
    case ABS_MT_SLOT:
      /* We force a SYN_REPORT on ABS_MT_SLOT, because the device is
       * serial. */
      /* However, we don't want to send twice the same event for
       * nothing... */
      if (!just_syned)
        memcpy(res, &(fingers[finger]), sizeof(struct superhid_finger));
      finger = ivalue;
      superlog(LOG_DEBUG, "finger %d", finger);
      break;
    case ABS_MT_TRACKING_ID:
      prevtip = fingers[finger].tip_switch;
      if (ivalue == 0xFFFFFFFF)
        fingers[finger].tip_switch = 0;
      else
        fingers[finger].tip_switch = 1;
      if (fingers[finger].tip_switch < prevtip) {
        /* The finger was just released, we may not get another event
         * for a while, let's send it */
        memcpy(res, &(fingers[finger]), sizeof(struct superhid_finger));
      }
      break;
    default:
      printf("%d ABS?\n", icode);
      break;
    }
    break;
  case EV_KEY:
    switch (icode)
    {
    case BTN_LEFT:
      tablet.report_id = REPORT_ID_TABLET;
      tablet.left_click = !!ivalue;
      break;
    case BTN_RIGHT:
      tablet.report_id = REPORT_ID_TABLET;
      tablet.right_click = !!ivalue;
      break;
    case BTN_MIDDLE:
      tablet.report_id = REPORT_ID_TABLET;
      tablet.middle_click = !!ivalue;
      break;
    case BTN_TOUCH:
      /* Am I supposed to do something here? */
      break;
    case KEY_RESERVED:
      /* We get that from the touchscreen... ?! */
      break;
    default:
      if (icode < 0x100) {
        keyboard.report_id = REPORT_ID_KEYBOARD;
        modifier = find_modifier(icode);
        if (ivalue != 0) {
          if (modifier != 0) {
            keyboard.modifier |= modifier;
          } else {
            scancode = find_scancode(icode);
            keyboard.keycode[0] = scancode;
          }
        } else {
          if (modifier != 0)
            keyboard.modifier &= ~modifier;
          else
            keyboard.keycode[0] = 0;
        }
      } else
        printf("%d KEY?\n", icode);
      break;
    }
    break;
  case EV_SYN:
    switch (icode)
    {
    case SYN_REPORT:
      if (tablet.report_id == REPORT_ID_TABLET) {
        memcpy(report, &tablet, sizeof(*report));
        tablet.report_id = 0;
        tablet.wheel = 0;
      } else if (keyboard.report_id == REPORT_ID_KEYBOARD) {
        memcpy(report, &keyboard, sizeof(*report));
        keyboard.report_id = 0;
      } else if (mouse.report_id == REPORT_ID_MOUSE) {
        memcpy(report, &mouse, sizeof(*report));
        memset(&mouse, 0, sizeof(mouse));
      } else {
        memcpy(res, &(fingers[finger]), sizeof(struct superhid_finger));
      }
      just_syned = 1;
      /* re-init */
      /* Nothing to do? */
      superlog(LOG_DEBUG, "SYN_REPORT\n");
      return;
      break;
    default:
      printf("%d SYN?\n", icode);
      break;
    }
  case EV_MSC:
    switch (icode)
    {
    case MSC_SCAN:
      /* This keeps happening, I don't know what it means!! */
      break;
    }
    break;
  default:
    printf("%d %d?\n", itype, icode);
    break;
  }

  just_syned = 0;
}

static void process_event(struct event_record *r,
                          struct buffer_t *b,
                          struct superhid_finger *finger,
                          struct superhid_report *report)
{
  uint16_t itype;
  uint16_t icode;
  uint32_t ivalue;
  static int dev_set;

  itype = r->itype;
  icode = r->icode;
  ivalue = r->ivalue;

  if (itype == EV_DEV)
  {
    if (icode == DEV_SET) {
      dev_set = ivalue;
      printf("DEV_SET %d\n", dev_set);
    } else {
      printf("EV_DEV %d %d?\n", icode, ivalue);
    }
    return;
  }

/* TODO: Here we need to figure out if dev_set is the touchscreen or not. */
/* Then we need to fix input_server and send the non-touch events back. */
#if 0
  if (dev_set != 5) {
    /* process_relative_event() didn't do anything, and this is not a
     * touchscreen event (device 6).
     * At this point we'd want to just send that event to the guest
     * unmodified. Unfortunately, event sending seems to be broken... */
    if (itype == EV_KEY) {
      r->magic = MAGIC;
      send(b->s, r, sizeof(struct event_record), 0);
    }
    return;
  }
#endif

  process_absolute_event(dev_set, itype, icode, ivalue, finger, report);
}

static struct event_record *findnext(struct buffer_t *b)
{
  struct event_record *r = NULL;
  int start = b->position;

  /* Skip junk */
  while (b->bytes_remaining >= EVENT_SIZE &&
         (r = (struct event_record *) &b->buffer[b->position]) && r->magic != MAGIC)
  {
    printf("SKIPPED!\n");
    sleep(1);
    b->bytes_remaining--;
    b->position++;
  }

  if (start != b->position)
    printf ("Warning: Encountered %d bytes of junk.\n", b->position - start);

  if (b->bytes_remaining >= EVENT_SIZE)
  {
    b->bytes_remaining -= EVENT_SIZE;
    b->position += EVENT_SIZE;
    return r;
  }
  else
    return NULL;
}

/**
 * Call this function when there's input events available in the fd or
 * in the remaining buffer. The function will handle one event at
 * most. If it's a touch event, it will return the correponding
 * finger. For any other event, it will fill a generic report.
 *
 * @param superback The SuperHID backend for the domain that select()-ed
 * @param fd        The file descriptor that select()-ed
 * @param finger    A pointer to a SuperHID finger for multitouch events
 * @param report    A pointer to a generic SuperHID report for other events
 *
 * @return It returns the number of bytes remaining in the receiving buffer
 */
static int superplugin_callback(struct superhid_backend *superback,
                                int fd,
                                struct superhid_finger *finger,
                                struct superhid_report *report)
{
  int n = 0;
  struct buffer_t *buf;
  char *b;

  buf = &superback->buffers;
  b = buf->buffer;

  if (buf->bytes_remaining < 0)
    return buf->bytes_remaining;
  if (buf->position != 0 && buf->bytes_remaining != 0)
    memmove(b, b + buf->position, buf->bytes_remaining);
  buf->position = 0;
  if (buf->bytes_remaining < EVENT_SIZE)
    n = recv(fd, &b[buf->bytes_remaining], buffersize - buf->bytes_remaining, 0);

  if (n < 0) {
    superlog(LOG_ERR, "FAILED TO READ THE FD\n");
    perror("recv");
    return buf->bytes_remaining;
  }

  if (n + buf->bytes_remaining >= EVENT_SIZE)
  {
    struct event_record *r = NULL;

    buf->bytes_remaining += n;

    r = findnext(buf);
    if (r != NULL)
      process_event(r, buf, finger, report);
  }
  else
    buf->bytes_remaining += n;

  return buf->bytes_remaining;
}

/**
 * This function tells input_server to send us the events for the
 * domain.
 *
 * @param s An open socket to input_server
 * @param d The domid of the domain that we want to ... suck
 */
static void suck(int s, int d)
{
  struct event_record e;

  e.magic = MAGIC;
  e.itype = 7;
  e.icode = 0x2;
  e.ivalue = d;

  if (send(s, &e, sizeof (struct event_record), 0) == -1)
  {
    perror("send");
    exit(1);
  }
}

static void input_handler(int fd, short event, void *priv)
{
  struct superhid_backend *superback = priv;
  struct superhid_report_multitouch report = { 0 };
  struct superhid_report custom_report = { 0 };
  struct superhid_finger *finger;
  int remaining = EVENT_SIZE;
  int sents = 0;

  /* We send a maximum of 2 packets, because that's usually how
   * many pending INT requests we have. */
  while (sents < 2 && remaining >= EVENT_SIZE && superbackend_all_pending(superback))
  {
    finger = &report.fingers[report.count];
    /* I don't think the finger ID can ever be 0xF. Use that to know
     * if superplugin_callback succeeded */
    finger->finger_id = 0xF;
    remaining = superplugin_callback(superback, fd, finger, &custom_report);
    if (custom_report.report_id != 0) {
      superbackend_send_report_to_frontends(fd, &custom_report, superback);
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
      superbackend_send_report_to_frontends(fd, (struct superhid_report *)&report, superback);
      memset(&report, 0, sizeof(report));
      sents++;
    }
  }

  if (report.count > 0) {
    /* The loop ended on a partial report, we need to send it */
    superbackend_send_report_to_frontends(fd, (struct superhid_report *)&report, superback);
  }

  if (sents == 2 && remaining >= EVENT_SIZE) {
    /* We sent 2 packets and the input buffer still has at least one
     * event, we need to get rescheduled even if no more input comes */
    event_active(&superback->input_event, event, 0);
  }
}

/**
 * Configures a SuperHID backend for input
 *
 * @param superback The SuperHID backend to initialize
 *
 * @return 0 on success, -1 on error
 */
int superplugin_create(struct superhid_backend *superback)
{
  int s, len;
  struct sockaddr_un remote;
  int domid;
  struct event *input_event;

  domid = superback->di.di_domid;

  /* input_server only support one plugin at a time!!??!! :( */
  if (input_grabber >= 0 || input_grabber == -domid)
    return -1;
  input_grabber = domid;

  /* Trying to connect to input_server to get events */
  if ((s = socket(AF_UNIX, SOCK_STREAM, 0)) == -1)
  {
    perror("socket");
    exit(1);
  }

  printf("Trying to grab events for domid %d...\n", domid);

  remote.sun_family = AF_UNIX;
  strcpy(remote.sun_path, SOCK_PATH);
  len = strlen(remote.sun_path) + sizeof(remote.sun_family);
  if (connect(s, (struct sockaddr *) &remote, len) == -1)
  {
    perror("connect");
    exit(1);
  }

  printf("Grabbed.\n");

  superback->buffers.bytes_remaining = 0;
  superback->buffers.position = 0;
  superback->buffers.copy = 0;
  superback->buffers.block = 0;
  superback->buffers.s = s;

  suck(s, domid);

  input_event = &superback->input_event;
  event_set(input_event, s, EV_READ | EV_PERSIST,
            input_handler, superback);
  event_add(input_event, NULL);

  return 0;
}
