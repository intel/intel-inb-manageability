SUMMARY = "Intel(R) In-Band Manageability framework"
PR = "r1"
LICENSE = "Proprietary"
LIC_FILES_CHKSUM = "file://LICENSE.Intel;md5=9eeea398d04d3843370f07a2eed5583c"

SRC_URI = "file://${INB_TGZ_PATH}/mqtt-${PV}-1.tar.gz;subdir=${BP} \
        file://LICENSE.Intel;subdir=${BP} \
        file://${INB_TGZ_PATH}/configuration-agent-${PV}-1.tar.gz;subdir=${BP} \
        file://${INB_TGZ_PATH}/diagnostic-agent-${PV}-1.tar.gz;subdir=${BP} \
        file://${INB_TGZ_PATH}/cloudadapter-agent-${PV}-1.tar.gz;subdir=${BP} \
        file://${INB_TGZ_PATH}/inbm-dispatcher-agent-${PV}-1.tar.gz;subdir=${BP} \
        file://${INB_TGZ_PATH}/telemetry-agent-${PV}-1.tar.gz;subdir=${BP} \
        file://${INB_TGZ_PATH}/inbc-program-${PV}-1.tar.gz;subdir=${BP} \
        file://${INB_TGZ_PATH}/trtl-${PV}-1.tar.gz;subdir=${BP} \
        file://${INB_TGZ_PATH}/yocto-provision-1.0-1.tar.gz;subdir=${BP}"

SRC_URI_append = " file://manageability-autoenable.service "
FILES_${PN} += " ${systemd_system_unitdir}/manageability-autoenable.service "

inherit systemd
SYSTEMD_SERVICE_${PN} = "manageability-autoenable.service"
SYSTEMD_AUTO_ENABLE = "enable"

SRC_URI_append = " file://manageability-autoenable "
FILES_${PN} += " ${bindir}/manageability-autoenable "

RDEPENDS_${PN} += "bash zlib mosquitto (>= 2.0.0) openssl cryptsetup tpm2-abrmd"
INSANE_SKIP_${PN} += " already-stripped ldflags file-rdeps"

inherit bin_package python3-dir useradd
USERADD_PACKAGES = "${PN}"
GROUPADD_PARAM_${PN} = "-f mqtt-broker"
USERADD_PARAM_${PN} = "-g mqtt-broker -s /usr/sbin/nologin mqtt-broker"

do_install_append() {
    chmod 0700 ${D}/usr/bin/tc-get-tpm-passphrase
    install -d ${D}${systemd_system_unitdir}
    install -m 0644 ${WORKDIR}/manageability-autoenable.service ${D}${systemd_system_unitdir}
    install -d ${D}${bindir}
    install -m 0755 ${WORKDIR}/manageability-autoenable ${D}${bindir}
}
