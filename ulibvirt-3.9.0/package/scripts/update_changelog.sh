#!/bin/bash

if [ -z "$1" -o -z "$2" -o -z "$3" ]; then
	echo "$(basename $0) <kversion> <version> <package path> <full version>" >&2
	exit 1
fi

KVERSION="$1"
RELEASE="$2"
PKGPATH="$3"
FULL_VERSION="$4"

tmp=$(mktemp /tmp/tmp.XXXXXXXXXX)
NAME="$(git config user.name)"
EMAIL="$(git config user.email)"

echo "* $(date "+%a %b %d %Y") $NAME <$EMAIL> - $FULL_VERSION" > $tmp
echo "- [ucloud] $FULL_VERSION" >> $tmp
echo "" >> $tmp
sed -i.bak -e "/%changelog/r $tmp" $PKGPATH/sources/libvirt.spec.template
rm -f "$tmp" $PKGPATH/sources/libvirt.spec.template.bak
