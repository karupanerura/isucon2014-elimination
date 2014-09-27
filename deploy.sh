#!/bin/sh
set -x
set -e
BASEDIR="/home/isucon/webapp"
cd ${BASEDIR}/perl
git pull
carton install --deployment

sudo -H /etc/init.d/mysql restart
sudo -H supervisorctl restart isucon_perl


