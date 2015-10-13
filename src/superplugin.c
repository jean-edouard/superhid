/*
 * Copyright (c) 2013 Citrix Systems, Inc.
 * Copyright (c) 2015 Jed Lejosne <lejosnej@ainfosec.com>
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

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <stdint.h>
#include <event.h>
#include <linux/input.h>
#include <fcntl.h>

#include "project.h"

#define SOCK_PATH               "/var/run/input_socket"
#define MAGIC                   0xAD9CBCE9

#define buffersize              (EVENT_SIZE*20)

/* Shouldn't that be defined somewhere already? */
#define ABS_MT_SLOT             0x2f
#define EV_DEV                  0x06
#define DEV_SET                 0x01

/* All the following is specific to the superhid digitizer */
#define TIP_SWITCH              0x01
#define IN_RANGE                0x02
#define DATA_VALID              0x04
#define FINGER_1                0x08
#define FINGER_2                0x10
#define FINGER_3                0x18

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

struct buffer_t
{
  char buffer[buffersize];
  unsigned int bytes_remaining;
  int position;
  int s;
  int copy;
  int block;
} buffers;

struct event recv_event;

/* Some OSes swap the x,y coordinates for some reason... */
static uint16_t swap_bytes(uint16_t n)
{
  uint16_t res;

  res = ((n << 8) & 0xFF00) + (n >> 8);

  return res;
}

static void process_absolute_event(uint16_t itype, uint16_t icode, uint32_t ivalue,
                                   struct superhid_report *res)
{
  static struct superhid_report report[MAX_FINGERS] = { 0 };
  static int finger = 0;
  int i;
  static char just_syned = 0;
  uint8_t prevmisc;
  /* static int scan_time = 0; */

  /* Initialize the report array */
  if (report[finger].report_id == 0)
  {
    for (i = 0; i < MAX_FINGERS; ++i)
    {
      memset(&report[i], 0, SUPERHID_REPORT_LENGTH);
      report[i].report_id = REPORT_ID_MULTITOUCH;
      report[i].count = 1;
      report[i].misc = 0;
      report[i].finger = i;
    }
  }

  switch (itype)
  {
  case EV_ABS:
    switch (icode)
    {
    case ABS_MT_POSITION_X:
      report[finger].x = ivalue >> 3;
      break;
    case ABS_MT_POSITION_Y:
      report[finger].y = ivalue >> 3;
      break;
    case ABS_MT_SLOT:
      /* We force a SYN_REPORT on ABS_MT_SLOT, because the device is
       * serial. */
      /* However, we don't want to send twice the same event for
       * nothing... */
      if (!just_syned)
        memcpy(res, &(report[finger]), sizeof(struct superhid_report));
      finger = ivalue;
      printf("finger %d\n", finger);
      break;
    case ABS_MT_TRACKING_ID:
      prevmisc = report[finger].misc;
      if (ivalue == 0xFFFFFFFF)
        report[finger].misc = 0;
      else
        report[finger].misc = 1;
      if (report[finger].misc != prevmisc)
        printf("misc %X -> %X\n", prevmisc, report[finger].misc);
      if (report[finger].misc < prevmisc) {
        /* The finger was just released, we may not get another event
         * for a while, let's send it */
        memcpy(res, &(report[finger]), sizeof(struct superhid_report));
      }
      break;
    default:
      if (icode != ABS_X && icode != ABS_Y)
        printf("%d ABS?\n", icode);
      break;
    }
    break;
  case EV_KEY:
    switch (icode)
    {
    default:
      printf("%d KEY?\n", icode);
      break;
    }
    break;
  case EV_SYN:
    switch (icode)
    {
    case SYN_REPORT:
      memcpy(res, &(report[finger]), sizeof(struct superhid_report));
      just_syned = 1;
      /* re-init */
      /* Nothing to do? */
      printf("SYN_REPORT\n");
      return;
      break;
    default:
      printf("%d SYN?\n", icode);
      break;
    }
  default:
    printf("%d %d?\n", itype, icode);
    break;
  }

  just_syned = 0;
}

static void process_event(struct event_record *r,
                          struct buffer_t *b,
                          struct superhid_report *report)
{
  uint16_t itype;
  uint16_t icode;
  uint32_t ivalue;
  static int dev_set;

  itype = r->itype;
  icode = r->icode;
  ivalue = r->ivalue;

  if (itype == EV_DEV && icode == DEV_SET)
  {
    dev_set = ivalue;
    printf("DEV_SET %d\n", dev_set);
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

  process_absolute_event(itype, icode, ivalue, report);
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

int superplugin_callback(int fd, struct superhid_report *report)
{
  int n = 0;
  struct buffer_t *buf = &buffers;
  char *b = buf->buffer;
  size_t nbytes = 0;

  memmove(b, &b[buf->position], buf->bytes_remaining);
  buf->position = 0;
  if (buf->bytes_remaining < EVENT_SIZE)
    n = recv(fd, &b[buf->bytes_remaining], buffersize - buf->bytes_remaining, 0);

  if (n + buf->bytes_remaining >= EVENT_SIZE)
  {
    struct event_record *r = NULL;

    buf->bytes_remaining += n;

    r = findnext(buf);
    if (r != NULL)
      process_event(r, buf, report);
  }
  else
    buf->bytes_remaining += n;

  return buf->bytes_remaining;
}

/* This function tells input_server to send us the events for the
 * domain */
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

int superplugin_init(int domid)
{
  int s, t, len;
  struct sockaddr_un remote;
  char str[100];
  pthread_t output_thread_var;

  /* Trying to connect to input_server to get events */
  if ((s = socket(AF_UNIX, SOCK_STREAM, 0)) == -1)
  {
    perror("socket");
    exit(1);
  }

  printf ("Trying to connect...\n");

  remote.sun_family = AF_UNIX;
  strcpy (remote.sun_path, SOCK_PATH);
  len = strlen(remote.sun_path) + sizeof(remote.sun_family);
  if (connect(s, (struct sockaddr *) &remote, len) == -1)
  {
    perror("connect");
    exit(1);
  }

  printf("Connected.\n");

  buffers.bytes_remaining = 0;
  buffers.position = 0;
  buffers.copy = 0;
  buffers.block = 0;
  buffers.s = s;

  suck(s, domid);

  return s;
}
