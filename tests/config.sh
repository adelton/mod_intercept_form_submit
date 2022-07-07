#!/bin/bash

set -e
set -x

sed -i 's/^MaxClients.*/MaxClients 1/' /etc/httpd/conf/httpd.conf
cp -p tests/auth.cgi /var/www/cgi-bin/auth.cgi
cp tests/pam-webl /etc/pam.d/webl
chmod a+x /var/log/httpd
cp tests/auth.conf /etc/httpd/conf.d/
useradd user1
echo user1:heslo1 | chpasswd
useradd bob
echo 'bob:Bobovo heslo' | chpasswd

NAME='liška'
if ! useradd --badname "$NAME" 2> /dev/null ; then
	NAME=liska
	useradd "$NAME"
fi
echo "$NAME:myši & zajíci" | chpasswd
chgrp apache /etc/shadow
chmod g+r /etc/shadow
# In dist-git / Fedora CI testing, we also need the proper SELinux configuration
if selinuxenabled ; then
	setsebool allow_httpd_mod_auth_pam 1
fi
