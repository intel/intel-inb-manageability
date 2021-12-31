dnl EMPTY FPM PACKAGE
dnl Argument 1: path for RPM 
dnl Argument 2: name
dnl Argument 3: version
dnl Argument 4: iteration
dnl Argument 5: any extra arguments for fpm
dnl Argument 6: extra command before creating the tar file
define(`empty_fpm_package', `# $2-$3-$4 (from empty_fpm_package macro)
# -----
define(`package_name', $2-$3-$4.noarch)

$1/package_name().rpm:
	rm -f $1/package_name().rpm
	cd $1 && fpm -s dir -t rpm -n $2 -v $3 --iteration $4 -a all $5 empty
	cd $1 && $6

RPMS += $2-rpm
$2-rpm: ${OUTPUT}/package_name().rpm
${OUTPUT}/package_name().rpm: $1/$2-$3-$4.noarch.rpm
	cp $1/package_name().rpm ${OUTPUT}
	cp $1/package_name().tar ${OUTPUT}
# -----')
