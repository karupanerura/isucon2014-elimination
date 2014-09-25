#!/bin/sh
set -eu

H2O_REVISION=696d47e4783281a64d3f2d845354faa458ec0625

wget -q https://github.com/kazuho/h2o/archive/$H2O_REVISION.tar.gz
tar xzf $H2O_REVISION.tar.gz
rm $H2O_REVISION.tar.gz

cd h2o-$H2O_REVISION
cmake .
make h2o

