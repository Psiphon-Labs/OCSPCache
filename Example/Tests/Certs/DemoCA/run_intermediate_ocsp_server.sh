#!/bin/bash -u -x -e

openssl ocsp -index ./CA/intermediate/enduser-certs/certindex\
             -port 8081\
             -rsigner ./CA/intermediate/enduser-certs/ocsp_signing.crt\
             -rkey ./CA/intermediate/enduser-certs/ocsp_signing.key\
             -CA ./CA/root/intermediate_CA.crt\
             -text # -out intermediate_ocsp_server_log.txt
