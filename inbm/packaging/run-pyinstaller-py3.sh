#!/bin/bash
set -exo pipefail

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

SOURCENAME="$1"
SOURCEDIR="$SOURCENAME"
DESTNAME="$2"

if [ "$SOURCEDIR" == "inbm-dispatcher-agent" ] && ! [ -d "$SOURCEDIR" ] ; then SOURCEDIR=dispatcher-agent ; fi
if [ "$SOURCEDIR" == "inbm-telemetry-agent" ] && ! [ -d "$SOURCEDIR" ] ; then SOURCEDIR=telemetry-agent ; fi
if [ "$SOURCEDIR" == "inbm-configuration-agent" ] && ! [ -d "$SOURCEDIR" ] ; then SOURCEDIR=configuration-agent ; fi
if [ "$SOURCEDIR" == "inbm-diagnostic-agent" ] && ! [ -d "$SOURCEDIR" ] ; then SOURCEDIR=diagnostic-agent ; fi
if [ "$SOURCEDIR" == "inbm-cloudadapter-agent" ] && ! [ -d "$SOURCEDIR" ] ; then SOURCEDIR=cloudadapter-agent ; fi

cd "$DIR"/../"$SOURCEDIR"
if [ -f "$SOURCEDIR"/dist/"$DESTNAME"/"$DESTNAME" ] ; then
  echo "Pyinstaller binary for $DESTNAME already built. Exiting."
  echo "(remove $SOURCENAME/dist if you want to rebuild)"
  exit 0
fi

rm -rf dist
rm -rf build

rm -f setup.cfg

VIRTUAL_ENV="${VIRTUAL_ENV:-}"
if [ -d "$VIRTUAL_ENV" ] ; then
  source "$VIRTUAL_ENV"/bin/activate
  SKIP_PIP=1
else
  python3 -m venv env && source env/bin/activate || echo "venv failed; proceeding without a virtual environment"
  SKIP_PIP=0
fi

if [ "$SKIP_PIP" == "1" ]; then
    echo "Skipping pip3"
else
    pip3 install -r requirements.txt 
fi

rm /usr/lib/x86_64-linux-gnu/libtinfo.so.6
pyinstaller "$DESTNAME".spec 
