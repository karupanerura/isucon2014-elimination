#!/bin/sh
cd /home/isucon/webapp/perl
exec /home/isucon/env.sh carton exec start_server --port=8080 -- plackup -s Starlet --max-workers 4 --max-reqs-per-child 50000 -E prod app.psgi
