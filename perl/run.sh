#!/bin/sh
cd /home/isucon/webapp/perl
exec /home/isucon/env.sh carton exec plackup -s Starman --host localhost:8080 -E prod app.psgi
