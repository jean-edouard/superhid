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

#ifndef   	SUPERPLUGIN_H_
# define   	SUPERPLUGIN_H_

/* struct superhid_report */
/* { */
/*   uint8_t  report_id; */
/*   uint8_t  count; */
/*   uint8_t  misc; */
/*   uint8_t  finger; */
/*   uint16_t x; */
/*   uint16_t y; */
/*   uint8_t  misc2; */
/*   uint8_t  finger2; */
/*   uint16_t x2; */
/*   uint16_t y2; */
/*   /\* uint8_t  scan_time; *\/ */
/* } __attribute__ ((__packed__)); */

struct superhid_report
{
  uint8_t  report_id;
  uint8_t  count;
  uint8_t  misc;
  uint8_t  finger;
  uint16_t x;
  uint16_t y;
  uint16_t pad1[2];
  uint8_t  misc2;
  uint8_t  finger2;
  uint16_t x2;
  uint16_t y2;
  uint16_t pad2[2];
  uint8_t  f3[10];
  uint8_t  f4[10];
  uint8_t  f5[10];
  uint32_t scan_time;
  uint8_t pad[8];
} __attribute__ ((__packed__));

int superplugin_callback(int fd, struct superhid_report *report);
int superplugin_init(int domid);

#endif 	    /* !SUPERPLUGIN_H_ */
