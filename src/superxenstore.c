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

enum XenBusStates {
  XB_UNKNOWN, XB_INITTING, XB_INITWAIT, XB_INITTED, XB_CONNECTED,
  XB_CLOSING, XB_CLOSED
};

static struct xs_handle *xs_handle;
char *xs_dom0path = NULL;

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
static char*
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
 * Fill the domain information for a given VM
 *
 * @param domid The domid of the VM
 * @param di The domain information to fill
 *
 * @return 0 on success, -ENOENT on failure
 */
int
superxenstore_get_dominfo(int domid, dominfo_t *di)
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

/**
 * Populate Xenstore with the information about a usb device for this domain
 */
int
superxenstore_create_usb(dominfo_t *domp, usbinfo_t *usbp)
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

int superxenstore_init(void)
{
  /* Init XenStore */
  if (xs_handle == NULL) {
    xs_handle = xs_daemon_open();
  }
  if (xs_handle == NULL) {
    xd_log(LOG_ERR, "Failed to connect to xenstore");
    return 1;
  }

  if (xs_dom0path == NULL) {
    xs_dom0path = xs_get_domain_path(xs_handle, 0);
  }
  if (xs_dom0path == NULL) {
    xd_log(LOG_ERR, "Could not get domain 0 path from XenStore");
    return 1;
  }

  return 0;
}

void superxenstore_close(void)
{
  xs_daemon_close(xs_handle);
}