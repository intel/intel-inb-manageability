#!/bin/bash
set -e
set -x

dpkg -i /debs-18.04/*.deb

if ! systemctl is-enabled tpm2-simulator ; then
    echo ERROR: tpm2-simulator is not enabled
    exit 1
fi

echo == tpm2-tss ==
[ -f /lib/udev/rules.d/tpm-udev.rules ] || ( echo ERROR: missing tpm-udev.rules && exit 1)

systemctl start tpm2-simulator
rm -f /usr/lib/libtss2-tcti-default.so
sed -i -e 's/ExecStart=\/usr\/sbin\/tpm2-abrmd/ExecStart=\/usr\/sbin\/tpm2-abrmd --tcti=mssim/g' /lib/systemd/system/tpm2-abrmd.service
systemctl daemon-reload
systemctl restart tpm2-simulator

systemctl restart tpm2-abrmd || (journalctl -a -xe  && false)

echo == tpm2-tools ==

tpm2_clear
tpm2_createprimary --quiet --hierarchy=o --key-algorithm=rsa --hash-algorithm=sha256 --key-context=prim.ctx
dd if=/dev/urandom bs=1 count=32 status=none > KEY_IN
tpm2_create --hash-algorithm=sha256 --public=seal.pub --private=seal.priv --parent-context=prim.ctx -i- < KEY_IN
tpm2_load --parent-context=prim.ctx --public=seal.pub --private=seal.priv --name=seal.name --key-context=seal.ctx
tpm2_evictcontrol --hierarchy=o --object-context=seal.ctx 0x81010001
tpm2_unseal -c 0x81010001 >KEY_OUT
sha256sum KEY_IN KEY_OUT
#cmp KEY_IN KEY_OUT

# # TODO: remove tpm2-tss and check that tss user is removed
