#!/bin/bash

set -e
set -x

if type dnf5 2> /dev/null ; then
	DNF=dnf
	BUILDDEP_PROVIDER='dnf5-command(builddep)'
	BUILDDEP='dnf builddep'
elif type dnf 2> /dev/null ; then
	DNF=dnf
	BUILDDEP_PROVIDER='dnf-command(builddep)'
	BUILDDEP='dnf builddep'
elif type yum 2> /dev/null ; then
	DNF=yum
	BUILDDEP_PROVIDER=yum-utils
	BUILDDEP=yum-builddep
else
	exit 1
fi

$DNF install -y --setopt=install_weak_deps=False rpm-build "$BUILDDEP_PROVIDER" libselinux-utils
$BUILDDEP -y --setopt=install_weak_deps=False mod_intercept_form_submit.spec
NAME_VERSION=$( rpm -q --qf '%{name}-%{version}\n' --specfile mod_intercept_form_submit.spec | head -1 )
mkdir .$NAME_VERSION
cp -rp * .$NAME_VERSION
mv .$NAME_VERSION $NAME_VERSION
mkdir -p ~/rpmbuild/SOURCES
tar cvzf ~/rpmbuild/SOURCES/$NAME_VERSION.tar.gz $NAME_VERSION
rpmbuild -bb --define "dist $( rpm --eval '%{dist}' ).localbuild" mod_intercept_form_submit.spec
$DNF install -y ~/rpmbuild/RPMS/*/$NAME_VERSION-*.localbuild.*.rpm
