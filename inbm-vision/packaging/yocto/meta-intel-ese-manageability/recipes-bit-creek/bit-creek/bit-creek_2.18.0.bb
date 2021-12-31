SUMMARY = "Bit Creek Manageability framework"
PR = "r1"
LICENSE = "Proprietary"
LIC_FILES_CHKSUM = "file://LICENSE_BitCreek.Intel;md5=6a16a0f25c928ebc526fe88cbf2b0737"

SRC_URI = "file://${BIT_CREEK_TGZ_PATH}/node-agent-${PV}-1.tar.gz;subdir=${BP} \
        file://LICENSE_BitCreek.Intel;subdir=${BP}"

SRC_URI_append = " file://node-flashless-autoenable.service "
FILES_${PN} += " ${systemd_system_unitdir}/node-flashless-autoenable.service "
SRC_URI_append = " file://node-flashless-autoenable "
FILES_${PN} += " ${bindir}/node-flashless-autoenable "

inherit systemd
SYSTEMD_SERVICE_${PN} = "node-flashless-autoenable.service"
SYSTEMD_AUTO_ENABLE = "enable"

RDEPENDS_${PN} += "bash zlib mosquitto openssl cryptsetup"
INSANE_SKIP_${PN} += " already-stripped ldflags"

inherit bin_package python3-dir useradd
USERADD_PACKAGES = "${PN}"
GROUPADD_PARAM_${PN} = "-f mqtt-broker; node-agent; -f manageability-cache"
USERADD_PARAM_${PN} = "-s /usr/sbin/nologin -g node-agent node-agent"

# TODO: the delayed-a doesn't seem to run on 1st or 2nd boot
pkg_postinst_${PN}-delayed-a () {
    # Actions to carry out on the device go here
    # There might be a better way to do the chmod +x action?
    chmod +x ${PYTHON_SITEPACKAGES_DIR}/node/node
}

do_install_append() {
    chown -R node-agent ${D}${datadir}/node-agent
    chgrp -R node-agent ${D}${datadir}/node-agent
    chmod -R g+rw ${D}${datadir}/node-agent

    install -d ${D}${systemd_system_unitdir}
    install -m 0644 ${WORKDIR}/node-flashless-autoenable.service ${D}${systemd_system_unitdir}
    install -d ${D}${bindir}
    install -m 0755 ${WORKDIR}/node-flashless-autoenable ${D}${bindir}
}

