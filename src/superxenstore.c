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
 * @file   superxenstore.c
 * @author Jed Lejosne <lejosnej@ainfosec.com>
 * @date   Fri Oct 30 10:36:17 2015
 *
 * @brief  XenStore interaction
 *
 * Functions to read/write various information from/to XenStore
 */

#include "project.h"

enum XenBusStates {
  XB_UNKNOWN, XB_INITTING, XB_INITWAIT, XB_INITTED, XB_CONNECTED,
  XB_CLOSING, XB_CLOSED
};

/**
 * The xenstore handle and dom0 path, set by xenstore_init()
 */
static struct xs_handle *xs_handle;
static char *xs_dom0path = NULL;

static void*
xmalloc(size_t size)
{
  void *p;

  if ((p = malloc(size)) == NULL) {
    superlog(LOG_CRIT, "Out of memory");
    exit(2);
  }

  return p;
}

/**
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

/**
 * Create a new directory in Xenstore
 */
static int
xenstore_add_dir(xs_transaction_t xt, char *path, int d0, int p0, int d1, int p1)
{
  struct xs_permissions perms[2];

  if (xs_mkdir(xs_handle, xt, path) == false) {
    superlog(LOG_ERR, "XenStore error mkdir()ing %s", path);
    return -1;
  }

  perms[0].perms = p0;
  perms[0].id = d0;
  perms[1].perms = p1;
  perms[1].id = d1;
  if (xs_set_permissions(xs_handle, xt, path, perms, 2) == false) {
    superlog(LOG_ERR, "XenStore error setting permissions on %s",
           path);
    xs_rm(xs_handle, xt, path);
    return -1;
  }

  return 0;
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
    superlog(LOG_ERR, "XenStore error writing %s", path);
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
 * Fill the domain information for a given VM
 *
 * @param domid The domid of the VM
 * @param di The domain information to fill
 *
 * @return 0 on success, -ENOENT on failure
 */
static int
superxenstore_get_dominfo(int domid, dominfo_t *di)
{
  di->di_domid = domid;
  di->di_dompath = xs_get_domain_path(xs_handle, di->di_domid);
  if (!di->di_dompath) {
    superlog(LOG_ERR, "Could not get domain %d path from xenstore", domid);
    return -ENOENT;
  }
  di->di_name = xasprintf("Domain-%d", domid);
  return 0;
}

/**
 * Populate Xenstore with the information about a usb device for this domain
 */
int
superxenstore_create_usb(dominfo_t *domp, usbinfo_t *usbp)
{
  char *bepath, *fepath;
  char value[32];
  xs_transaction_t trans;

  superlog(LOG_DEBUG, "Creating VUSB node for %d.%d",
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
  superlog(LOG_ERR, "Failed to write usb info to XenStore");
  free(fepath);
  free(bepath);

  return -1;
}

static int
wait_for_states(char *bepath, char *fepath, enum XenBusStates a, enum XenBusStates b)
{
  char *bstate, *fstate;
  int bstatelen, fstatelen;
  char *buf;
  int fd;
  struct timeval tv = { .tv_sec = 5, .tv_usec = 0 };
  int ret = -1;

  bstatelen = strlen(bepath) + strlen("/state") + 1;
  fstatelen = strlen(fepath) + strlen("/state") + 1;
  bstate = malloc(bstatelen);
  fstate = malloc(fstatelen);
  snprintf(bstate, bstatelen, "%s/state", bepath);
  snprintf(fstate, fstatelen, "%s/state", fepath);
  xs_watch(xs_handle, bstate, bstate);
  xs_watch(xs_handle, fstate, fstate);
  fd = xs_fileno(xs_handle);
  while (tv.tv_sec != 0 || tv.tv_usec != 0)
  {
    int bs, fs;
    fd_set set;
    unsigned int len;
    char **watch_paths;

    FD_ZERO(&set);
    FD_SET(fd, &set);
    if (select(fd + 1, &set, NULL, NULL, &tv) < 0)
      break;
    if (!FD_ISSET(fd, &set))
      continue;
    /* Read the watch to drain the buffer */
    watch_paths = xs_read_watch(xs_handle, &len);
    free(watch_paths);

    buf = xs_read(xs_handle, XBT_NULL, bstate, NULL);
    if (buf == NULL) {
      /* The backend tree is gone, probably because the VM got
       * shutdown and the toolstack cleaned it out. Let's pretend
       * it's all set */
      ret = 1;
      break;
    } else {
      bs = *buf - '0';
    }
    buf = xs_read(xs_handle, XBT_NULL, fstate, NULL);
    if (buf == NULL) {
      /* Same as above */
      ret = 1;
      break;
    } else {
      fs = *buf - '0';
    }
    if ((fs == a || fs == b) &&
        (bs == a || bs == b))
    {
      ret = 0;
      break;
    }
  }
  xs_unwatch(xs_handle, bstate, bstate);
  xs_unwatch(xs_handle, fstate, fstate);
  free(bstate);
  free(fstate);

  return ret;
}

/**
 * Wait until both the frontend and the backend are in a closed
 * state. Fail after 5 seconds.
 *
 * @param di Domain info
 * @param ui USB device info
 *
 * @return 0 on success, -1 on failure
 */
static int
superxenstore_wait_for_offline(dominfo_t *di, usbinfo_t *ui)
{
  char *bepath, *fepath;
  int ret;

  bepath = xenstore_dev_bepath(di, "vusb", ui->usb_virtid);
  fepath = xenstore_dev_fepath(di, "vusb", ui->usb_virtid);
  ret = wait_for_states(bepath, fepath, XB_UNKNOWN, XB_CLOSED);
  free(bepath);
  free(fepath);

  return ret;
}

/**
 * Remove information about a usb device for this domain from Xenstore
 */
int
superxenstore_destroy_usb(dominfo_t *domp, usbinfo_t *usbp)
{
  char value[32];
  char *bepath;
  char *fepath;
  int ret;

  superlog(LOG_INFO, "Deleting VUSB node %d for %d.%d",
         usbp->usb_virtid, usbp->usb_bus, usbp->usb_device);

  bepath = xenstore_dev_bepath(domp, "vusb", usbp->usb_virtid);
  fepath = xenstore_dev_fepath(domp, "vusb", usbp->usb_virtid);

  /* Notify the backend that the device is being shut down */
  xenstore_set_keyval(XBT_NULL, bepath, "online", "0");
  xenstore_set_keyval(XBT_NULL, bepath, "physical-device", "0.0");
  snprintf(value, sizeof (value), "%d", XB_CLOSING);
  xenstore_set_keyval(XBT_NULL, bepath, "state", value);

  if (superxenstore_wait_for_offline(domp, usbp) >= 0)
  {
    xs_rm(xs_handle, XBT_NULL, bepath);
    xs_rm(xs_handle, XBT_NULL, fepath);
    ret = 0;
  } else {
    superlog(LOG_ERR, "Failed to bring the USB device offline");
    /* FIXME: Should we keep the nodes around? Check if the VM is
     * asleep? */
    superlog(LOG_ERR, "Cleaning xenstore nodes anyway");
    xs_rm(xs_handle, XBT_NULL, bepath);
    xs_rm(xs_handle, XBT_NULL, fepath);
    ret = -1;
  }

  free(bepath);
  free(fepath);
  return ret;
}

/**
 * Spawns a device for the given domain. If the domain doesn't already
 * have a backend, start by creating one for it.
 *
 * @param domid The domid of the domain
 * @param type  The type of SuperHID device to spawn
 */
static void spawn(int domid, enum superhid_type type)
{
  usbinfo_t ui;
  dominfo_t di;
  int ret;
  int slot;

  /* Fill the domain info */
  ret = superxenstore_get_dominfo(domid, &di);
  if (ret != 0) {
    superlog(LOG_ERR, "Invalid domid %d", domid);
    return;
  }

  slot = superbackend_find_slot(domid);
  if (slot == -1) {
    /* There's no backend for this domain yet, let's create one */
    slot = superbackend_create(di);
    /* Grab input events for the domain */
    if (superplugin_create(&superbacks[slot]) != 0) {
      superlog(LOG_ERR, "Failed to grab events for %d", domid);
      return;
    }
  }

  /* Fill the device info */
  ui.usb_virtid = type;
  ui.usb_bus = 1;
  ui.usb_device = type;
  ui.usb_vendor = SUPERHID_VENDOR;
  ui.usb_product = SUPERHID_DEVICE;

  /* Create a new device on xenstore */
  superxenstore_create_usb(&di, &ui);
}

/**
 * We're watching "/vm" to know when VM statuses change. We spawn
 * device(s) for every running VM that doesn't have a backend (yet).
 */
void superxenstore_handler(void)
{
  int i;
  unsigned int n, len;
  char **paths;
  char path[256] = { 0 };
  char *state, *value, *type;
  int domid;
  int slot;

  /* Watch away */
  paths = xs_read_watch(xs_handle, &len);
  free(paths);

  /* List VMs */
  paths = xs_directory(xs_handle, XBT_NULL, "/vm", &n);
  for (i = 0; i < n; ++i) {
    /* Ignore non-SVMs */
    snprintf(path, 256, "/xenmgr/vms/%s/type", paths[i]);
    type = xs_read(xs_handle, XBT_NULL, path, &len);
    if (type == NULL)
      continue;
    if (strcmp(type, SUPERHID_VM_TYPE)) {
      free(type);
      continue;
    } else
      free(type);
    /* Check if the VM wants a multiple device */
    /* snprintf(path, 256, "/xenmgr/vms/%s/superhid", paths[i]); */
    /* type = xs_read(xs_handle, XBT_NULL, path, &len); */
    /* if (type == NULL || *type == 'n' || *type == '0') */
    /*   continue; */
    /* Check if the VM is running */
    /* Read the domid */
    snprintf(path, 256, "/xenmgr/vms/%s/domid", paths[i]);
    value = xs_read(xs_handle, XBT_NULL, path, &len);
    if (value == NULL)
      continue;
    domid = strtol(value, NULL, 10);
    free(value);
    /* Read the state */
    snprintf(path, 256, "/vm/%s/state", paths[i]);
    state = xs_read(xs_handle, XBT_NULL, path, &len);
    if (state) {
      if (!strncmp(state, "running", 7)) {
        slot = superbackend_find_slot(domid);
        if (slot == -1) {
          /* There's a new VM, let's create a backend for it */
          /* if (*type == 'm') { */
            spawn(domid, SUPERHID_TYPE_MULTI);
          /* } else { */
          /* spawn(domid, SUPERHID_TYPE_MOUSE); */
          /* spawn(domid, SUPERHID_TYPE_DIGITIZER); */
          /* spawn(domid, SUPERHID_TYPE_TABLET); */
          /* spawn(domid, SUPERHID_TYPE_KEYBOARD); */
          /* } */
        }
      }
      free(state);
    }
  }
  free(paths);
}

/**
 * Initialize the xenstore handle, the dom0 path and a watch.
 *
 * @return The fd to select on for the watch, -1 on error
 */
int superxenstore_init(void)
{
  /* Init XenStore */
  if (xs_handle == NULL) {
    xs_handle = xs_daemon_open();
  }
  if (xs_handle == NULL) {
    superlog(LOG_ERR, "Failed to connect to xenstore");
    return -1;
  }

  if (xs_dom0path == NULL) {
    xs_dom0path = xs_get_domain_path(xs_handle, 0);
  }
  if (xs_dom0path == NULL) {
    superlog(LOG_ERR, "Could not get domain 0 path from XenStore");
    return -1;
  }

  xs_watch(xs_handle, "/vm", "/vm");

  return xs_fileno(xs_handle);
}

/**
 * Close the xenstore handle
 */
void superxenstore_close(void)
{
  xs_daemon_close(xs_handle);
}
