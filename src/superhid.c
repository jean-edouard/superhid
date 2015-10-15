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

/* This is a relative mouse with 5 buttons and a vertical wheel. */
#define MOUSE                                                           \
    0x05, 0x01,                 /* USAGE_PAGE (Generic Desktop)     */  \
    0x09, 0x02,                 /* USAGE (Mouse)                    */  \
    0xa1, 0x01,                 /* COLLECTION (Application)         */  \
    0x85, REPORT_ID_MOUSE,      /*   REPORT_ID (2)                  */  \
    0x09, 0x01,                 /*   USAGE (Pointer)                */  \
    0xa1, 0x00,                 /*   COLLECTION (Physical)          */  \
    0x05, 0x09,                 /*     USAGE_PAGE (Button)          */  \
    0x19, 0x01,                 /*     USAGE_MINIMUM (Button 1)     */  \
    0x29, 0x05,                 /*     USAGE_MAXIMUM (Button 5)     */  \
    0x15, 0x00,                 /*     LOGICAL_MINIMUM (0)          */  \
    0x25, 0x01,                 /*     LOGICAL_MAXIMUM (1)          */  \
    0x95, 0x05,                 /*     REPORT_COUNT (5)             */  \
    0x75, 0x01,                 /*     REPORT_SIZE (1)              */  \
    0x81, 0x02,                 /*     INPUT (Data,Var,Abs)         */  \
    0x95, 0x01,                 /*     REPORT_COUNT (1)             */  \
    0x75, 0x03,                 /*     REPORT_SIZE (3)              */  \
    0x81, 0x03,                 /*     INPUT (Cnst,Var,Abs)         */  \
    0x05, 0x01,                 /*     USAGE_PAGE (Generic Desktop) */  \
    0x09, 0x30,                 /*     USAGE (X)                    */  \
    0x09, 0x31,                 /*     USAGE (Y)                    */  \
    0x09, 0x38,                 /*     USAGE (wheel)                */  \
    0x15, 0x81,                 /*     LOGICAL_MINIMUM (-127)       */  \
    0x25, 0x7f,                 /*     LOGICAL_MAXIMUM (127)        */  \
    0x75, 0x08,                 /*     REPORT_SIZE (8)              */  \
    0x95, 0x03,                 /*     REPORT_COUNT (3)             */  \
    0x81, 0x06,                 /*     INPUT (Data,Var,Rel)         */  \
    0x95, 0x07,                 /*     REPORT_COUNT (7)             */  \
    0x75, 0x08,                 /*     REPORT_SIZE (8)              */  \
    0x81, 0x03,                 /*     INPUT (Cnst,Var,Abs)         */  \
    0xc0,                       /*   END_COLLECTION                 */  \
    0xc0                        /* END_COLLECTION                   */

#define MOUSE_LENGTH 60

/* This is an absolute "mouse" with 2 buttons and a vertical wheel. */
#define TABLET                                                          \
0x05, 0x01,                     /* USAGE_PAGE (Generic Desktop)     */  \
0x09, 0x02,                     /* USAGE (Mouse)                    */  \
0xa1, 0x01,                     /* COLLECTION (Application)         */  \
0x85, REPORT_ID_TABLET,         /*   REPORT_ID (3)                  */  \
0x09, 0x01,                     /*   USAGE (Pointer)                */  \
0xa1, 0x00,                     /*   COLLECTION (Physical)          */  \
0x05, 0x09,                     /*     USAGE_PAGE (Button)          */  \
0x19, 0x01,                     /*     USAGE_MINIMUM (1)            */  \
0x29, 0x03,                     /*     USAGE_MAXIMUM (3)            */  \
0x15, 0x00,                     /*     LOGICAL_MINIMUM (0)          */  \
0x25, 0x01,                     /*     LOGICAL_MAXIMUM (1)          */  \
0x75, 0x01,                     /*     REPORT_SIZE (1)              */  \
0x95, 0x03,                     /*     REPORT_COUNT (3)             */  \
0x81, 0x02,                     /*     INPUT (Data, Var, Abs)       */  \
0x95, 0x05,                     /*     REPORT_COUNT (5)             */  \
0x81, 0x03,                     /*     INPUT (Cnst, Var, Abs)       */  \
0x26, 0xff, 0x7f,               /*     LOGICAL_MAXIMUM (32767)      */  \
0x05, 0x01,                     /*     USAGE_PAGE (Generic Desktop) */  \
0x75, 0x10,                     /*     REPORT_SIZE (16)             */  \
0x95, 0x01,                     /*     REPORT_COUNT (1)             */  \
0x09, 0x30,                     /*     USAGE (X)                    */  \
0x81, 0x02,                     /*     INPUT (Data, Var, Abs)       */  \
0x09, 0x31,                     /*     USAGE (Y)                    */  \
0x81, 0x02,                     /*     INPUT (Data, Var, Abs)       */  \
0x75, 0x08,                     /*     REPORT_SIZE (8)              */  \
0x95, 0x05,                     /*     REPORT_COUNT (5)             */  \
0x81, 0x03,                     /*     INPUT (Cnst,Var,Abs)         */  \
0xc0,                           /*   END_COLLECTION                 */  \
0xc0                            /* END_COLLECTION                   */

#define TABLET_LENGTH 57

#define KEYBOARD                                                       \
0x05, 0x01,                /*  Usage Page (Desktop),               */  \
0x09, 0x06,                /*  Usage (Keyboard),                   */  \
0xA1, 0x01,                /*  Collection (Application),           */  \
0x85, REPORT_ID_KEYBOARD,  /*      REPORT_ID (1)                   */  \
0x05, 0x07,                /*      Usage Page (Keyboard),          */  \
0x19, 0xE0,                /*      Usage Minimum (KB Leftcontrol), */  \
0x29, 0xE7,                /*      Usage Maximum (KB Right GUI),   */  \
0x15, 0x00,                /*      Logical Minimum (0),            */  \
0x25, 0x01,                /*      Logical Maximum (1),            */  \
0x75, 0x01,                /*      Report Size (1),                */  \
0x95, 0x08,                /*      Report Count (8),               */  \
0x81, 0x02,                /*      Input (Variable),               */  \
0x81, 0x01,                /*      Input (Constant),               */  \
0x95, 0x06,                /*      Report Count (6),               */  \
0x75, 0x08,                /*      Report Size (8),                */  \
0x15, 0x00,                /*      Logical Minimum (0),            */  \
0x26, 0xFF, 0x00,          /*      Logical Maximum (255),          */  \
0x05, 0x07,                /*      Usage Page (Keyboard),          */  \
0x19, 0x00,                /*      Usage Minimum (None),           */  \
0x2A, 0xFF, 0x00,          /*      Usage Maximum (FFh),            */  \
0x81, 0x00,                /*      Input,                          */  \
0x95, 0x03,                /*      REPORT_COUNT (3)                */  \
0x81, 0x03,                /*      INPUT (Cnst,Var,Abs)            */  \
0xC0                       /*  End Collection                      */

#define KEYBOARD_LENGTH 49

#define FINGER                                                                \
0x05, 0x0D,                     /*      Usage Page (Digitizer),         */    \
0x09, 0x22,                     /*      Usage (Finger),                 */    \
0xA1, 0x02,                     /*      Collection (Logical),           */    \
0x09, 0x42,                     /*          Usage (Tip Switch),         */    \
0x15, 0x00,                     /*          Logical Minimum (0),        */    \
0x25, 0x01,                     /*          Logical Maximum (1),        */    \
0x75, 0x01,                     /*          Report Size (1),            */    \
0x95, 0x01,                     /*          Report Count (1),           */    \
0x81, 0x02,                     /*          Input (Variable),           */    \
0x95, 0x03,                     /*          Report Count (3),           */    \
0x81, 0x03,                     /*          Input (Constant, Variable), */    \
0x09, 0x51,                     /*          Usage (Contact Identifier), */    \
0x75, 0x04,                     /*          Report Size (4),            */    \
0x95, 0x01,                     /*          Report Count (1),           */    \
0x15, 0x00,                     /*          Logical Minimum (0),        */    \
0x25, 0x20,                     /*          Logical Maximum (32),       */    \
0x81, 0x02,                     /*          Input (Variable),           */    \
0x05, 0x01,                     /*          Usage Page (Desktop),       */    \
0x26, 0xFF, 0x0F,               /*          Logical Maximum (4095),     */    \
0x75, 0x10,                     /*          Report Size (16),           */    \
0x55, 0x0E,                     /*          Unit Exponent (14),         */    \
0x65, 0x11,                     /*          Unit (Centimeter),          */    \
0x09, 0x30,                     /*          Usage (X),                  */    \
0x35, 0x00,                     /*          Physical Minimum (0),       */    \
0x46, 0x7E, 0x08,               /*          Physical Maximum (2174),    */    \
0x81, 0x02,                     /*          Input (Variable),           */    \
0x46, 0x4F, 0x05,               /*          Physical Maximum (1359),    */    \
0x09, 0x31,                     /*          Usage (Y),                  */    \
0x81, 0x02,                     /*          Input (Variable),           */    \
0xC0                            /*      End Collection,                 */    \

#define FINGER_LENGTH 62

/* This digitizer should have SUPERHID_FINGER_WIDTH fingers */
#define DIGITIZER                                                             \
0x05, 0x0D,                     /*  Usage Page (Digitizer),             */    \
0x09, 0x04,                     /*  Usage (Touchscreen),                */    \
0xA1, 0x01,                     /*  Collection (Application),           */    \
0x85, REPORT_ID_MULTITOUCH,     /*      Report ID (4),                  */    \
0x05, 0x0D,                     /*      Usage Page (Digitizer),         */    \
0x09, 0x54,                     /*      Usage (Contact Count),          */    \
0x75, 0x08,                     /*      Report Size (8),                */    \
0x15, 0x00,                     /*      Logical Minimum (0),            */    \
0x25, 0x0C,                     /*      Logical Maximum (12),           */    \
0x95, 0x01,                     /*      Report Count (1),               */    \
0x81, 0x02,                     /*      Input (Variable),               */    \
FINGER,                                                                       \
FINGER,                                                                       \
0x05, 0x0D,                     /*      Usage Page (Digitizer),         */    \
0x09, 0x55,                     /*      Usage (Contact Count Max),      */    \
0x15, 0x00,                     /*      Logical Minimum (0),            */    \
0x25, 0x7F,                     /*      Logical Maximum (127),          */    \
0x75, 0x08,                     /*      Report Size (8),                */    \
0x95, 0x01,                     /*      Report Count (1),               */    \
0xB1, 0x02,                     /*      Feature (Variable),             */    \
0xC0                            /*  End Collection,                     */

#define DIGITIZER_LENGTH (37 + SUPERHID_FINGER_WIDTH * FINGER_LENGTH)

struct hid_report_desc superhid_desc = {
  .subclass = 0, /* No subclass */
  .protocol = 0,
  .report_length = SUPERHID_REPORT_LENGTH,
  .report_desc_length = MOUSE_LENGTH + DIGITIZER_LENGTH + TABLET_LENGTH + KEYBOARD_LENGTH,
  .report_desc = {
    MOUSE,
    DIGITIZER,
    TABLET,
    KEYBOARD
  }
};

static struct usb_device_descriptor device_desc = {
  .bLength = USB_DT_DEVICE_SIZE,
  .bDescriptorType = USB_DT_DEVICE,
  .bcdUSB = 0x0200,
  /* .bDeviceClass = USB_CLASS_COMM, */
  /* .bDeviceSubClass = 0, */
  /* .bDeviceProtocol = 0, */
  .bDeviceClass = USB_CLASS_PER_INTERFACE,
  .bDeviceSubClass = 0,
  .bDeviceProtocol = 0,
  .bMaxPacketSize0 = 64,
  /* Vendor and product id can be overridden by module parameters.  */
  .bcdDevice = 0x0001,
  .idVendor = SUPERHID_VENDOR,
  .idProduct = SUPERHID_DEVICE,
  .iManufacturer = 0,
  .iProduct = 0,
  .iSerialNumber = 0,
  .bNumConfigurations = 1,
};

static struct usb_qualifier_descriptor qualifier_desc = {
  .bLength = sizeof(struct usb_qualifier_descriptor),
  .bDescriptorType = USB_DT_DEVICE_QUALIFIER,
  .bcdUSB = 0x0200,
  /* .bDeviceClass = USB_CLASS_COMM, */
  /* .bDeviceSubClass = 0, */
  /* .bDeviceProtocol = 0, */
  .bDeviceClass = USB_CLASS_PER_INTERFACE,
  .bDeviceSubClass = 0,
  .bDeviceProtocol = 0,
  .bMaxPacketSize0 = 64,
  .bNumConfigurations = 1,
};

static struct usb_config_descriptor config_desc = {
  .bLength = USB_DT_CONFIG_SIZE,
  .bDescriptorType = USB_DT_CONFIG,
  .wTotalLength = USB_DT_CONFIG_SIZE +
                  USB_DT_INTERFACE_SIZE +
                  sizeof(struct hid_descriptor) +
                  USB_DT_ENDPOINT_SIZE /* * 2 */,
  .bNumInterfaces = 1,
  .bConfigurationValue = 1,
  .iConfiguration = 0,
  /* .bmAttributes = USB_CONFIG_ATT_ONE | USB_CONFIG_ATT_SELFPOWER, */
  .bmAttributes = USB_CONFIG_ATT_ONE | USB_CONFIG_ATT_WAKEUP,
  .bMaxPower = 50,
};

static struct usb_bos_descriptor bos_desc = {
  .bLength = USB_DT_BOS_SIZE,
  .bDescriptorType = USB_DT_BOS,
  .wTotalLength = USB_DT_BOS_SIZE,
  .bNumDeviceCaps = 0,
};

static struct usb_interface_descriptor interface_desc = {
	.bLength		= USB_DT_INTERFACE_SIZE,
	.bDescriptorType	= USB_DT_INTERFACE,
	.bInterfaceNumber	= 0,
	.bAlternateSetting	= 0,
	/* .bNumEndpoints		= 2, */
	.bNumEndpoints		= 1,
	.bInterfaceClass	= USB_CLASS_HID,
	/* .bInterfaceSubClass	= 0, */
	/* .bInterfaceProtocol	= 0, */
	.bInterfaceSubClass	= 1,
	.bInterfaceProtocol	= 2,
	.iInterface		= 0,
};

static struct hid_descriptor hid_desc = {
  .bLength = sizeof(struct hid_descriptor),
  .bDescriptorType = HID_DT_HID,
  .bcdHID = 0x0111,
  .bCountryCode = 0x00,
  .bNumDescriptors = 0x1,
  .bAddDescriptorType = HID_DT_REPORT,
  /* .bAddDescriptorLength = DYNAMIC, */
};

static struct usb_endpoint_descriptor endpoint_in_desc = {
  .bLength		= USB_DT_ENDPOINT_SIZE,
  .bDescriptorType	= USB_DT_ENDPOINT,
  .bEndpointAddress	= USB_DIR_IN | 0x1,
  .bmAttributes		= USB_ENDPOINT_XFER_INT,
  /* .wMaxPacketSize	= DYNAMIC, */
  /* .bInterval		= 4, */
  .bInterval		= 1,
};

/* static struct usb_endpoint_descriptor endpoint_out_desc = { */
/*   .bLength		= USB_DT_ENDPOINT_SIZE, */
/*   .bDescriptorType	= USB_DT_ENDPOINT, */
/*   .bEndpointAddress	= USB_DIR_OUT | 0x2, */
/*   .bmAttributes		= USB_ENDPOINT_XFER_INT, */
/*   /\* .wMaxPacketSize	= DYNAMIC, *\/ */
/*   .bInterval		= 4, */
/* }; */

void superhid_init(void)
{
  /* DYNAMIC inits */
  hid_desc.wAddDescriptorLength = superhid_desc.report_desc_length;
  endpoint_in_desc.wMaxPacketSize = superhid_desc.report_length;
  /* endpoint_out_desc.wMaxPacketSize = superhid_desc.report_length; */
}

int superhid_setup(struct usb_ctrlrequest *setup, void *buf)
{
  __u16 value, length;
  struct feature_report feature;
  int total;
  char *tmp;

  value = setup->wValue;
  length = setup->wLength;

  switch ((setup->bRequestType << 8) | setup->bRequest) {
  case ((USB_DIR_IN | USB_TYPE_CLASS | USB_RECIP_INTERFACE) << 8
        | HID_REQ_GET_REPORT):
    printf("INTERFACE GET REPORT\n");
    if ((value >> 8) == HID_REPORT_TYPE_FEATURE) {
      if ((value & 0xFF) == REPORT_ID_MT_MAX_COUNT)
      {
        feature.feature = REPORT_ID_MT_MAX_COUNT;
        feature.value = SUPERHID_FINGERS;
        /* feature.id = 0; */
        length = 2;
        memcpy(buf, &feature, length);
        goto respond;
      }/*  else if ((value & 0xFF) == 0x05) { */
      /*   printf("WINDOWS STUFFS REQUESTED!\n"); */
      /*   length = 3; */
      /*   memset(buf, 0x05, 1); */
      /*   memset(buf + 1, 0x02, 1); */
      /*   memset(buf + 2, 0x00, 1); */
      /*   goto respond; */
      /* } */ else {
        printf("Unknown feature request 0x%x\n", value & 0xFF);
        goto stall;
      }
    } else {
      printf("Unknown feature request TYPE 0x%x\n", value >> 8);
      goto stall;
    }
    break;

  case ((USB_DIR_IN | USB_TYPE_CLASS | USB_RECIP_INTERFACE) << 8
        | HID_REQ_GET_PROTOCOL):
    printf("INTERFACE GET PROTOCOL\n");
    goto stall;
    break;

  case ((USB_DIR_OUT | USB_TYPE_CLASS | USB_RECIP_INTERFACE) << 8
        | HID_REQ_SET_REPORT):
    printf("INTERFACE SET REPORT\n");
    if ((value >> 8) == HID_REPORT_TYPE_FEATURE) {
      /* if ((value & 0xFF) == 0x05) { */
      /*   printf("WINDOWS STUFFS SET!\n"); */
      /*   length = 3; */
      /*   tmp = buf; */
      /*   printf("%02X %02X %02X\n", tmp[0], tmp[1], tmp[2]); */
      /*   memset(buf, 0x05, 1); */
      /*   memset(buf + 1, 0x02, 1); */
      /*   memset(buf + 2, 0x00, 1); */
      /*   goto respond; */
      /* } else { */
        printf("Unknown feature SET request 0x%x\n", value & 0xFF);
        goto stall;
      /* } */
    } else {
      printf("Unknown feature SET request TYPE 0x%x\n", value >> 8);
      goto stall;
    }
    break;

  case ((USB_DIR_OUT | USB_TYPE_CLASS | USB_RECIP_INTERFACE) << 8
        | HID_REQ_SET_PROTOCOL):
    printf("INTERFACE SET PROTOCOL\n");
    goto stall;
    break;

  case ((USB_DIR_OUT | USB_TYPE_STANDARD | USB_RECIP_DEVICE) << 8
        | USB_REQ_GET_STATUS):
    printf("DEVICE_GET_STATUS\n");
    goto respond;
    break;

  case ((USB_DIR_IN | USB_TYPE_STANDARD | USB_RECIP_DEVICE) << 8
        | USB_REQ_GET_DESCRIPTOR):
    printf("DEVICE GET DESCRIPTOR\n");
    switch (value >> 8) {
    case USB_DT_DEVICE:
      if (sizeof(device_desc) < length)
        length = sizeof(device_desc);
      memcpy(buf, &device_desc, length);
      goto respond;
      break;
    case USB_DT_DEVICE_QUALIFIER:
      if (sizeof(qualifier_desc) < length)
        length = sizeof(qualifier_desc);
      memcpy(buf, &qualifier_desc, length);
      goto respond;
      break;
    case USB_DT_CONFIG:
      total = 0;
      memcpy(buf + total, &config_desc, sizeof(config_desc));
      total += sizeof(config_desc);
      printf("%d ", total);
      if (total > length) {
        printf("skipping interface\n");
        goto skipshit;
      }
      memcpy(buf + total, &interface_desc, sizeof(interface_desc));
      total += sizeof(interface_desc);
      printf("%d ", total);
      if (total > length) {
        printf("skipping hid\n");
        goto skipshit;
      }
      memcpy(buf + total, &hid_desc, sizeof(hid_desc));
      total += sizeof(hid_desc);
      printf("%d ", total);
      if (total > length) {
        printf("skipping endpoint 1\n");
        goto skipshit;
      }
      memcpy(buf + total, &endpoint_in_desc, USB_DT_ENDPOINT_SIZE);
      total += USB_DT_ENDPOINT_SIZE;
      printf("%d ", total);
      if (total > length) {
        printf("skipping endpoint 2\n");
        goto skipshit;
      }
      /* memcpy(buf + total, &endpoint_out_desc, USB_DT_ENDPOINT_SIZE); */
      /* total += USB_DT_ENDPOINT_SIZE; */
      /* printf("%d\n", total); */
      /* if (total > length) { */
      /*   printf("NOT ENOUGH ROOM!\n"); */
      /* } */
    skipshit:
      if (total < length)
        length = total;
      goto respond;
      break;
    case USB_DT_STRING:
      if (strlen(SUPERHID_REAL_NAME) < length)
        length = strlen(SUPERHID_REAL_NAME);
      memcpy(buf, SUPERHID_REAL_NAME, strlen(SUPERHID_REAL_NAME));
      goto respond;
      break;
    case USB_DT_BOS:
      if (sizeof(bos_desc) < length)
        length = sizeof(bos_desc);
      memcpy(buf, &bos_desc, length);
      goto respond;
      break;
    /* case USB_DT_INTERFACE: */
    /*   if (sizeof(interface_desc) < length) */
    /*     length = sizeof(interface_desc); */
    /*   memcpy(buf, &interface_desc, length); */
    /*   goto respond; */
    /*   break; */
    }
    break;
  case ((USB_DIR_OUT | USB_TYPE_STANDARD | USB_RECIP_DEVICE) << 8
        | USB_REQ_SET_CONFIGURATION):
    printf("DEVICE SET CONFIGURATION\n");
    length = 0;
    goto respond;
    break;
  case ((USB_DIR_IN | USB_TYPE_STANDARD | USB_RECIP_DEVICE) << 8
        | USB_REQ_GET_CONFIGURATION):
    printf("DEVICE GET CONFIGURATION\n");
    length = 1;
    memcpy(buf, "1", length);
    goto respond;
    break;
  case ((USB_DIR_OUT | USB_TYPE_STANDARD | USB_RECIP_INTERFACE) << 8
        | USB_REQ_SET_INTERFACE):
    printf("DEVICE SET INTERFACE\n");
    length = 0;
    goto respond;
    break;
  case ((USB_DIR_IN | USB_TYPE_STANDARD | USB_RECIP_INTERFACE) << 8
        | USB_REQ_GET_INTERFACE):
    printf("DEVICE GET INTERFACE\n");
    length = 1;
    memcpy(buf, "0", length);
    goto respond;
    break;
  case ((USB_DIR_IN | USB_TYPE_STANDARD | USB_RECIP_INTERFACE) << 8
        | USB_REQ_GET_DESCRIPTOR):
    printf("INTERFACE GET DESCRIPTOR\n");
    switch (value >> 8) {
    case HID_DT_HID:
      if (hid_desc.bLength < length)
        length = hid_desc.bLength;
      memcpy(buf, &hid_desc, length);
      goto respond;
      break;
    case HID_DT_REPORT:
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
  printf("STALL\n");
  return -1;

respond:
  return length;
}
