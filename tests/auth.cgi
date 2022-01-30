#!/bin/bash

echo "Content-Type: text/plain"
echo "Pragma: no-cache"
echo
echo "REMOTE_USER=[$REMOTE_USER]"
[ -z "$EXTERNAL_AUTH_ERROR" ] || echo "EXTERNAL_AUTH_ERROR=[$EXTERNAL_AUTH_ERROR]"
echo ---
cat
echo
echo ---
