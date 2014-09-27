#!/bin/sh
cd /home/isucon/webapp/perl
exec /home/isucon/env.sh carton exec start_server --path=/tmp/app.sock -- plackup -s Starlet --max-workers 40 --max-reqs-per-child 50000 -E prod app.psgi
