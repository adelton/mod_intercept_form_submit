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
chgrp apache /etc/shadow
chmod g+r /etc/shadow
