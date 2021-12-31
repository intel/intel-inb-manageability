# For handling hddimg, wic class needs to be handled through wic plugins
efi_populate_append() {
        DEST=$1
        install -d ${DEST}${EFIDIR}
	# yes 2 EFIs eg :\efi\EFI\vendor\fwupx64.efi
	cp -r ${DEPLOY_DIR_IMAGE}/fwupdate-boot/boot/efi/* ${DEST}${EFIDIR}/../
}
