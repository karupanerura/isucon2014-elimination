#!/bin/bash
git pull
# defaut 1 worklaod
/home/isucon/benchmarker bench --api-key 43-3-ncfwsc-knex-0ce888d78423fc74499c4af51eb51215d51341ad --workload ${1:-1} --init /home/isucon/init.sh
