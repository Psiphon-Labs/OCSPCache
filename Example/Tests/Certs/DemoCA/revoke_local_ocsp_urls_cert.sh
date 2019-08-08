#!/bin/bash

set -o errexit
set -o xtrace

CNF=$PWD/intermediate-ca.cnf

cd ./CA/intermediate/enduser-certs

openssl ca -config "$CNF"\
           -revoke local_ocsp_urls.crt\
           -keyfile ../../root/intermediate_CA.key\
           -cert ../../root/intermediate_CA.crt
