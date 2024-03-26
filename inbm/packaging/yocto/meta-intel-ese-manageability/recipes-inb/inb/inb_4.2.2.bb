SUMMARY = "Intel(R) In-Band Manageability framework"
PR = "r1"
LICENSE = "Apache-2.0"
LIC_FILES_CHKSUM = "file://LICENSE.Intel;md5=f8dd78b147cad11ff835ec2ffe71aa58"

SRC_URI = "file://${INB_TGZ_PATH}/mqtt-${PV}-1.tar.gz;subdir=${BP} \
        file://LICENSE.Intel;subdir=${BP} \
        file://${INB_TGZ_PATH}/inbm-configuration-agent-${PV}-1.tar.gz;subdir=${BP} \
        file://${INB_TGZ_PATH}/inbm-diagnostic-agent-${PV}-1.tar.gz;subdir=${BP} \
        file://${INB_TGZ_PATH}/inbm-cloudadapter-agent-${PV}-1.tar.gz;subdir=${BP} \
        file://${INB_TGZ_PATH}/inbm-dispatcher-agent-${PV}-1.tar.gz;subdir=${BP} \
        file://${INB_TGZ_PATH}/inbm-telemetry-agent-${PV}-1.tar.gz;subdir=${BP} \
        file://${INB_TGZ_PATH}/inbc-program-${PV}-1.tar.gz;subdir=${BP} \
        file://${INB_TGZ_PATH}/trtl-${PV}-1.tar.gz;subdir=${BP} \
        file://${INB_TGZ_PATH}/yocto-provision-${PV}-1.tar.gz;subdir=${BP}"

SRC_URI:append = " file://manageability-autoenable.service "
FILES:${PN} += " ${systemd_system_unitdir}/manageability-autoenable.service "

inherit systemd
SYSTEMD_SERVICE:${PN} = "manageability-autoenable.service"
SYSTEMD_AUTO_ENABLE = "enable"

SRC_URI:append = " file://manageability-autoenable "
FILES:${PN} += " ${bindir}/manageability-autoenable "

RDEPENDS:${PN} += "bash zlib mosquitto (>= 2.0.0) openssl cryptsetup tpm2-abrmd"
INSANE_SKIP:${PN} += " already-stripped ldflags file-rdeps"

inherit bin_package python3-dir useradd
USERADD_PACKAGES = "${PN}"
GROUPADD_PARAM:${PN} = "-f mqtt-broker"
USERADD_PARAM:${PN} = "-g mqtt-broker -s /usr/sbin/nologin mqtt-broker"

do_install:append() {
    chmod 0700 ${D}/usr/bin/tc-get-tpm-passphrase
    install -d ${D}${systemd_system_unitdir}
    install -m 0644 ${WORKDIR}/manageability-autoenable.service ${D}${systemd_system_unitdir}
    install -d ${D}${bindir}
    install -m 0755 ${WORKDIR}/manageability-autoenable ${D}${bindir}
}
