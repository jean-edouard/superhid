DESCRIPTION = "SuperHID"
LICENSE = "GPLv2"
LIC_FILES_CHKSUM="file://COPYING;md5=4641e94ec96f98fabc56ff9cc48be14b"
DEPENDS = " xen-tools libevent libxenbackend "

PV = "0+git${SRCPV}"

SRCREV = "${AUTOREV}"
SRC_URI = "git://github.com/jean-edouard/superhid.git;protocol=${OPENXT_GIT_PROTOCOL};branch=master \
           file://xenclient-vusb.initscript \
           "

# workaround for broken configure.in
EXTRA_OECONF += "--with-libxenstore=${STAGING_LIBDIR}"

S = "${WORKDIR}/git"

inherit autotools
inherit xenclient
