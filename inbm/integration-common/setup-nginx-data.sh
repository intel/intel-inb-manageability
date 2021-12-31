#!/bin/bash
set -ex
DEST=$1
COMMON=$2

rm -fv ${DEST}/*.tgz
cp -v input/sample-container.tgz ${DEST}
cp -v input/sample-container-load.tgz ${DEST}

rm -f ${DEST}/BIOSUPDATE.fv ${DEST}/BIOSUPDATE.tar
cp -v input/BIOSUPDATE.fv input/BIOSUPDATE.tar ${DEST}

rm -f ${DEST}/U1170000F60X043.tar ${DEST}/U1170000F60X043.bin
cp -v input/U1170000F60X043.tar input/U1170000F60X043.bin ${DEST}

rm -f ${DEST}/sample-application-1.0-1.deb 
cp -v input/sample-application-1.0-1.deb ${DEST}

# set up simple compose test
( cd ${COMMON} && rm -f ${DEST}/simple-compose.tar.gz && tar zcvf ${DEST}/simple-compose.tar.gz simple-compose )

# set up simple compose test with alternate name
( cd ${COMMON} && rm -f ${DEST}/simple-compose-rename.tar.gz && tar zcvf ${DEST}/simple-compose-rename.tar.gz simple-compose-rename )
