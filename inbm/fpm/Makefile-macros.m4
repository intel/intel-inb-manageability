dnl
dnl FPM PACKAGE
dnl Argument 1: name of package
dnl Argument 2: version
dnl Argument 3: iteration
dnl Argument 4: extra command while assembling directory tree for package
dnl Argument 5: dependencies for assembling directory tree for package
dnl Argument 6: extra fpm arguments
define(`fpm_package', `# $1-$2-$3 (from fpm_package macro)
# -----
$1_FULLNAME=$1-$2-$3
$1_DEB = ${$1_FULLNAME}.deb
$1_RPM = ${$1_FULLNAME}.rpm
CLEANUP += "$1/*.deb"
CLEANUP += "$1/*.rpm"
CLEANUP += "$1/files"

$1/files: $5
	rm -rf $1/files
	cp -a $1/template $1/files
	$4
	touch $1/files

DEBS += $1-deb
$1-deb: ${OUTPUT}/${$1_DEB}
${OUTPUT}/${$1_DEB}: Makefile $1/files fpm.sh
	rm -f $1/$1*.deb
	cd $1 && ../fpm.sh $1 $2 $3 deb $6
	chmod og-rwx $1/${$1_DEB}
	mv -f $1/${$1_DEB} ${OUTPUT}

RPMS += $1-rpm
$1-rpm: ${OUTPUT}/${$1_RPM}
${OUTPUT}/${$1_RPM}: Makefile $1/files fpm.sh
	rm -f $1/$1*.rpm
	cd $1 && ../fpm.sh $1 $2 $3 rpm $6
	chmod og-rwx $1/${$1_RPM}
	mv -f $1/${$1_RPM} ${OUTPUT}
# -----')
