#!/bin/sh
set -eu

REDIS_VERSION=2.8.17

wget -q http://download.redis.io/releases/redis-$REDIS_VERSION.tar.gz
tar xzf redis-$REDIS_VERSION.tar.gz

cd redis-$REDIS_VERSION
make
sudo -H make install
