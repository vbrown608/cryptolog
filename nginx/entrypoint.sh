#!/bin/sh
set -e

cryptolog </var/log/nginx/.access.pipe &

exec "$@"
