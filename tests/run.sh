#!/bin/bash

set -e
set -x

echo "Wait for the HTTP server to start ..."
for i in $( seq 1 10 ) ; do
	if curl -s -o /dev/null http://localhost/ ; then
		break
	fi
	sleep 3
done

curl -s http://localhost/auth1 | tee /dev/stderr | grep -F 'REMOTE_USER=[]'
curl -u userx:heslox -s http://localhost/auth1 | tee /dev/stderr | grep -F 'REMOTE_USER=[]'
curl --data '' -si http://localhost/auth1 | tee /dev/stderr | grep -F 'REMOTE_USER=[]'
curl --data 'login=user1&password=heslox' -si http://localhost/auth1 | tee /dev/stderr | grep -F -e 'REMOTE_USER=[]' -e 'EXTERNAL_AUTH_ERROR=[Authentication failure]' | wc -l | grep -q 2
curl --data 'login=user2&password=heslox' -si http://localhost/auth1 | tee /dev/stderr | grep -F -e 'REMOTE_USER=[]' -e 'EXTERNAL_AUTH_ERROR=[User not known to the underlying authentication module]' | wc -l | grep -q 2
curl --data 'login=user1&password=heslo1' -si http://localhost/auth1 | tee /dev/stderr | grep -F -e 'REMOTE_USER=[user1]' -e 'login=user1&password=heslo1' | wc -l | grep -q 2
curl --data 'login=bob&password=Bobovo+heslo' -si http://localhost/auth1 | tee /dev/stderr | grep -F -e 'REMOTE_USER=[bob]' -e 'login=bob&password=Bobovo+heslo' | wc -l | grep -q 2
NAME='liška'
XNAME='li%c5%a1ka'
if ! getent passwd "$NAME" ; then
	NAME=liska
	XNAME=$NAME
fi
curl --data "login=$XNAME&password=myši+& zaj%c3%adci" -si http://localhost/auth1 | tee /dev/stderr | grep -F 'REMOTE_USER=[]'
curl --data "login=$XNAME&password=myši %26%20zaj%c3%adci" -si http://localhost/auth1 | tee /dev/stderr | grep -F -e "REMOTE_USER=[$NAME]" -e "login=$XNAME&password=myši %26%20zaj%c3%adci" | wc -l | grep -q 2
curl --data 'something=somewhere&password=heslo1&something=else&login=user1' -si http://localhost/auth1 | tee /dev/stderr | grep -F -e 'REMOTE_USER=[user1]' -e 'something=somewhere&password=heslo1&something=else&login=user1' | wc -l | grep -q 2
curl --data 'login=user1&password=heslo1' -si http://localhost/auth1r | tee /dev/stderr | grep -F -e 'REMOTE_USER=[user1]' -e 'login=user1&password=[REDACTED]' | wc -l | grep -q 2
curl --data 'password=xheslo&login=user1&something=extra' -si http://localhost/auth1r | tee /dev/stderr | grep -F -e 'REMOTE_USER=[]' -e 'EXTERNAL_AUTH_ERROR=[Authentication failure]' -e 'password=[REDACTED]&login=user1&something=extra' | wc -l | grep -q 3
curl --data 'something=somewhere&password=heslo1&something=else&login=user1' -si http://localhost/auth1r | tee /dev/stderr | grep -F -e 'REMOTE_USER=[user1]' -e 'something=somewhere&password=[REDACTED]&something=else&login=user1' | wc -l | grep -q 2
curl --data 'login=bob&password=Bobovo heslo' -si http://localhost/auth1r | tee /dev/stderr | grep -F -e 'REMOTE_USER=[]' -e 'login=bob&password=Bobovo heslo' | wc -l | grep -q 2
curl --data 'login=bob&password=Ne Bobovo heslo' -si http://localhost/auth1r | tee /dev/stderr | grep -F -e 'REMOTE_USER=[]' -e 'login=bob&password=Ne Bobovo heslo' | wc -l | grep -q 2

curl --data 'login=user1&password=heslo1' -si http://localhost/auth1s | tee /dev/stderr | grep -F -e 'REMOTE_USER=[user1]' -e 'login=user1&password=[REDACTED]' | wc -l | grep -q 2
curl --data 'something=somewhere&password=heslo1&something=else&login=user1' -si http://localhost/auth1s | tee /dev/stderr | grep -F -e 'REMOTE_USER=[user1]' -e 'something=somewhere&password=[REDACTED]&something=else&login=user1' | wc -l | grep -q 2
chage -d $(date -d -2days +%Y-%m-%d) -M  1 user1
curl --data 'login=user1&password=heslo1' -si http://localhost/auth1s | tee /dev/stderr | grep -F -e 'HTTP/1.1 303 See Other' -e 'HTTP/1.1 307 Temporary Redirect' -e 'Location: http://localhost/login?backurl=http%3a%2f%2flocalhost%2fauth1s&uid=user1' | wc -l | grep -q 2
curl --data 'something=somewhere&password=heslo1&something=else&login=user1' -si http://localhost/auth1s | tee /dev/stderr | grep -F -e 'HTTP/1.1 303 See Other' -e 'HTTP/1.1 307 Temporary Redirect' -e 'Location: http://localhost/login?backurl=http%3a%2f%2flocalhost%2fauth1s&uid=user1' | wc -l | grep -q 2
chage -d $(date -d -2days +%Y-%m-%d) -M  1 "$NAME"
curl --data "something=somewhere&password=myši+%26%20zaj%C3%adci&something=else&login=$NAME" -si http://localhost/auth1s | tee /dev/stderr | grep -F -e 'HTTP/1.1 303 See Other' -e 'HTTP/1.1 307 Temporary Redirect' -e "Location: http://localhost/login?backurl=http%3a%2f%2flocalhost%2fauth1s&uid=$XNAME" | wc -l | grep -q 2

echo OK $0.
