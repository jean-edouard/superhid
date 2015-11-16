#
# Copyright (c) 2015 Jed Lejosne <lejosnej@ainfosec.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#

AM_CFLAGS = -finput-charset=UTF-8 -std=gnu99 -DROOT_UID=0 -DHAVE_ARCH_STRUCT_FLOCK -DUSE_DBUS -DHAVE_ARCH_STRUCT_FLOCK -Wall -Werror

INCLUDES = 

sbin_PROGRAMS = superhid

PROTO_SRCS = main.c superplugin.c superhid.c superxenstore.c superbackend.c

superhid_SOURCES = ${PROTO_SRCS}

superhid_LDADD = -levent -lxenstore -lxenbackend -lxenctrl
