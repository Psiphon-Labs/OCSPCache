#!/bin/bash -u -x -e

openssl ocsp -index demoCA/index.txt\
             -port 8080\
             -rsigner ocsp_signing.crt\
             -rkey ocsp_signing.key\
             -CA root_CA.crt\
             -text # -out ocsp_server_log.txt
