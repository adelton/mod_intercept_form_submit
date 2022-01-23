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
curl --data 'login=user1&password=heslox' -si http://localhost/auth1 | tee /dev/stderr | grep -F 'REMOTE_USER=[]'
curl --data 'login=user1&password=heslo1' -si http://localhost/auth1 | tee /dev/stderr | grep -F -e 'REMOTE_USER=[user1]' -e 'login=user1&password=heslo1' | wc -l | grep -q 2
curl --data 'something=somewhere&password=heslo1&something=else&login=user1' -si http://localhost/auth1 | tee /dev/stderr | grep -F -e 'REMOTE_USER=[user1]' -e 'something=somewhere&password=heslo1&something=else&login=user1' | wc -l | grep -q 2
curl --data 'login=user1&password=heslo1' -si http://localhost/auth1r | tee /dev/stderr | grep -F -e 'REMOTE_USER=[user1]' -e 'login=user1&password=[REDACTED]' | wc -l | grep -q 2
curl --data 'something=somewhere&password=heslo1&something=else&login=user1' -si http://localhost/auth1r | tee /dev/stderr | grep -F -e 'REMOTE_USER=[user1]' -e 'something=somewhere&password=[REDACTED]&something=else&login=user1' | wc -l | grep -q 2

curl --data 'login=user1&password=heslo1' -si http://localhost/auth1s | tee /dev/stderr | grep -F -e 'REMOTE_USER=[user1]' -e 'login=user1&password=[REDACTED]' | wc -l | grep -q 2
curl --data 'something=somewhere&password=heslo1&something=else&login=user1' -si http://localhost/auth1s | tee /dev/stderr | grep -F -e 'REMOTE_USER=[user1]' -e 'something=somewhere&password=[REDACTED]&something=else&login=user1' | wc -l | grep -q 2
chage -d $(date -d -2days +%Y-%m-%d) -M  1 user1
curl --data 'login=user1&password=heslo1' -si http://localhost/auth1s | tee /dev/stderr | grep -F -e 'HTTP/1.1 307 Temporary Redirect' -e 'Location: http://localhost/login?backurl=http%3a%2f%2flocalhost%2fauth1s&uid=user1' | wc -l | grep -q 2
curl --data 'something=somewhere&password=heslo1&something=else&login=user1' -si http://localhost/auth1s | tee /dev/stderr | grep -F -e 'HTTP/1.1 307 Temporary Redirect' -e 'Location: http://localhost/login?backurl=http%3a%2f%2flocalhost%2fauth1s&uid=user1' | wc -l | grep -q 2

echo OK $0.
