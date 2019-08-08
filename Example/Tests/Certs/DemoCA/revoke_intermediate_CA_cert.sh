#!/bin/bash

set -o errexit
set -o xtrace

CNF=$PWD/root-ca.cnf

cd ./CA/root

openssl ca -config "$CNF"\
           -revoke intermediate_CA.crt\
           -keyfile root_CA.key\
           -cert root_CA.crt
