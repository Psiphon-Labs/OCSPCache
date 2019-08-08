#!/bin/bash -u -x -e

openssl ocsp -index ./CA/root/certindex\
             -port 8080\
             -rsigner ./CA/root/ocsp_signing.crt\
             -rkey ./CA/root/ocsp_signing.key\
             -CA ./CA/root/root_CA.crt\
             -text # -out root_ocsp_server_log.txt
