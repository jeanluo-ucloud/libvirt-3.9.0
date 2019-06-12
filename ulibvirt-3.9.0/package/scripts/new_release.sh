#!/bin/bash
if [ -z "$1" -o -z "$2" -o -z "$3" ]; then
	echo "$(basename $0) <kversion> <version> <package path>" >&2;
	exit 1;
fi

KVERSION="$1";
RELEASE="$2";
NEW_RELEASE="$[RELEASE + 1]";
PKGPATH="$3";

if [ -s "$PKGPATH/libvirt-test.patch" ]; then
	echo "libvirt-test.patch is not empty, aborting" >&2;
	exit 1;
fi
sed -i.bak -e "s/BUILD:=$RELEASE/BUILD:=$NEW_RELEASE/" $PKGPATH/Makefile;
rm -f $PKGPATH/Makefile.bak
