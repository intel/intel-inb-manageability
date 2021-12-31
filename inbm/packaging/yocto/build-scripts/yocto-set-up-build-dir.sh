#!/bin/bash
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$DIR"/../../.. # repo top level

set -e
set -x

usage() {
  echo "Usage: $0 [build type] [tgz input] [machine]";
  echo "";
  echo "[build type] = EHL or KMB or GENERIC"
  echo "[tgz input] = directory with inb tgzs; e.g., ./arm_tgzs";
  echo "";
}

if [ $# -ne 3 ]; then
    usage
    exit 1
fi

BUILD_TYPE="$1"
TGZ_INPUT="$2"

YOCTO_WORK_DIR="/yocto/work_dir_$BUILD_TYPE"

if [[ "$BUILD_TYPE" = "EHL" ]] ; then
    YOCTO_SOURCE_DIR="/yocto/ehl-bkc-20200810-0003"
    MANIFEST="meta/recipes-sato/images/core-image-sato-sdk.bbappend"
    IMAGE_TARGET="core-image-sato-sdk"
    IMAGE_OUTPUT_COMMAND="find $YOCTO_WORK_DIR/intel-embedded-system-enabling/build/tmp-glibc/deploy/images -name core-image-sato-*intel-corei7-64-*.hddimg"
    PRE_BUILD_WORKAROUND="true"
elif [[ "$BUILD_TYPE" = "KMB" ]] ; then
    YOCTO_SOURCE_DIR="/yocto/kmb-bkc-20200825-2110"
    MANIFEST="meta/recipes-core/images/core-image-minimal.bb"
    IMAGE_TARGET="core-image-minimal"
    IMAGE_OUTPUT_COMMAND="find $YOCTO_WORK_DIR/build/tmp-glibc/deploy/images -name core-image-minimal-keembay-*.wic"
    PRE_BUILD_WORKAROUND="bitbake vsi-vaapi-driver-unify gstreamer1.0-vaapi-unify libdrm-unify libva-unify"
else
    usage
    exit 1
fi


: Show proxy values -- debug
echo http_proxy: "$http_proxy"
echo https_proxy: "$https_proxy"
echo no_proxy: "$no_proxy"
echo HTTP_PROXY: "$HTTP_PROXY"
echo HTTPS_PROXY: "$HTTPS_PROXY"
echo NO_PROXY: "$NO_PROXY"

: Build machine needs:
: \* Yocto directory set up
: \* Any prereqs for doing yocto builds.
: \* Chameleonsocks or equivalent set up and running

: Copy upstream Yocto source to $YOCTO_WORK_DIR
rsync -a --delete "$YOCTO_SOURCE_DIR"/ "$YOCTO_WORK_DIR"/

: Copy our layer to $YOCTO_WORK_DIR
cp -r packaging/yocto/meta-intel-ese-manageability "$YOCTO_WORK_DIR"/

EXTRA_PATH="intel-embedded-system-enabling"

: Copy our TGZs in and standardize names
TGZS_ABSOLUTE_PATH="$YOCTO_WORK_DIR"/meta-intel-ese-manageability/recipes-inb/inb/files/tgzs
rm -rf "${TGZS_ABSOLUTE_PATH:-/fake/directory}"/
cp -rv "$TGZ_INPUT"/ "$TGZS_ABSOLUTE_PATH"/

: Run the rest as user yocto
chown -R yocto.yocto /yocto
chmod -R ug+rwx,o-rwx /yocto

cat >"$YOCTO_WORK_DIR"/setup-build.sh <<EOF-1
#!/bin/bash
set -e
set -x

cd "$YOCTO_WORK_DIR"/build
set +x
. "$YOCTO_WORK_DIR"/"$EXTRA_PATH"/oe-init-build-env "$YOCTO_WORK_DIR"/build
set -x
[ -f conf/local.conf ]
echo "INB_TGZ_PATH = \"${TGZS_ABSOLUTE_PATH}\"" >>conf/local.conf
EOF-1


if [[ "$BUILD_TYPE" = "EHL" ]]; then
  cat >>"$YOCTO_WORK_DIR"/setup-build.sh <<EOF-2a
: Pull in inb layer
rm -rf "$YOCTO_WORK_DIR"/"$EXTRA_PATH"/meta-intel-embedded-system-enabling/meta-intel-ese-proprietary-pre/meta-intel-ese-manageability-pre
mkdir -p "$YOCTO_WORK_DIR"/"$EXTRA_PATH"/meta-intel-embedded-system-enabling/meta-intel-ese-proprietary-pre/meta-intel-ese-manageability-pre
cp -r "$YOCTO_WORK_DIR"/meta-intel-ese-manageability/* "$YOCTO_WORK_DIR"/"$EXTRA_PATH"/meta-intel-embedded-system-enabling/meta-intel-ese-proprietary-pre/meta-intel-ese-manageability-pre
EOF-2a
elif [[ "$BUILD_TYPE" = "KMB" ]]; then
  cat >>"$YOCTO_WORK_DIR"/setup-build.sh <<EOF-2b
: Pull in inb layer 
rm -rf "$YOCTO_WORK_DIR"/"$EXTRA_PATH"/meta-intel-ese-proprietary/meta-intel-ese-manageability/
mkdir -p "$YOCTO_WORK_DIR"/"$EXTRA_PATH"/meta-intel-ese-proprietary/meta-intel-ese-manageability/
cp -r "$YOCTO_WORK_DIR"/meta-intel-ese-manageability/* "$YOCTO_WORK_DIR"/"$EXTRA_PATH"/meta-intel-ese-proprietary/meta-intel-ese-manageability/
EOF-2b
fi


chmod a+x "$YOCTO_WORK_DIR"/setup-build.sh
sudo -E -H -u yocto -g yocto "$YOCTO_WORK_DIR"/setup-build.sh

cat >"$YOCTO_WORK_DIR"/build-recipe.sh <<EOF
#!/bin/bash
set -e
set -x

cd "$YOCTO_WORK_DIR"/build
. "$YOCTO_WORK_DIR"/"$EXTRA_PATH"/oe-init-build-env "$YOCTO_WORK_DIR"/build

bitbake -k inb
EOF

chmod +x "$YOCTO_WORK_DIR"/build-recipe.sh

  cat >"$YOCTO_WORK_DIR"/build-img.sh <<EOF
#!/bin/bash
set -e
set -x

cd "$YOCTO_WORK_DIR"/build
. "$YOCTO_WORK_DIR"/"$EXTRA_PATH"/oe-init-build-env "$YOCTO_WORK_DIR"/build

$PRE_BUILD_WORKAROUND
bitbake -k ${IMAGE_TARGET}
rm -rf /yocto/output/
mkdir -p /yocto/output/
EOF

echo 'cp $('"${IMAGE_OUTPUT_COMMAND}"') /yocto\/output/' >>"$YOCTO_WORK_DIR"/build-img.sh
echo 'pbzip2 /yocto/output/*' >>"$YOCTO_WORK_DIR"/build-img.sh

chmod +x "$YOCTO_WORK_DIR"/build-img.sh
