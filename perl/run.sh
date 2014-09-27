#!/bin/sh
cd /home/isucon/webapp/perl
exec /home/isucon/env.sh carton exec start_server --path=/tmp/app.sock -- plackup -s Monoceros --max-workers 60 --max-reqs-per-child 50000 -E prod app.psgi
