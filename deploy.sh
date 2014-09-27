#!/bin/sh
set -x
set -e
BASEDIR="/home/isucon/webapp"
cd ${BASEDIR}/perl
git pull
carton install --deployment

sudo -H /etc/init.d/mysqld restart
sudo -H /etc/init.d/nginx restart
sudo -H supervisorctl restart isucon_perl


