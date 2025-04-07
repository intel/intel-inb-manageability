rm -rf ./dist/inbm
earthly +build
earthly +build-deb
earthly +package

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cat >"$DIR"/dist/README.txt <<EOF
Build output files
==================

inbm/install-tc.sh             Installs inbm for Ubuntu
inbm/uninstall-tc.sh           Uninstalls inbm for Ubuntu
inbm/intel-inbm.deb            Intel In-Band Manageability package
inbm/LICENSE                   INBM license
EOF